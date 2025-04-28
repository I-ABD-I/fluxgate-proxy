mod analytics;

pub mod middleware {
    pub use crate::controller::analytics::analytics;
}

use crate::config::Config;
use crate::error::{MiddlewareError, ServerNotFound, UnableToFindUpstream};
use async_std::io;
use async_std::net::TcpStream;
use async_std::sync::Arc;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
use layered::service::Service;
use log::{debug, info};
use std::net::SocketAddr;
use tls::config::ServerConfig;
use tls::futures::LazyAcceptor;
use tls::server::Acceptor;

/// Handles the client connection.
///
/// # Arguments
/// * `socket` - The client socket.
/// * `tls_config` - The TLS configuration.
/// * `proxy_config` - The proxy configuration.
///
/// # Returns
/// An `anyhow::Result` indicating the success or failure of the operation.
pub async fn client_handler(
    socket: TcpStream,
    tls_config: Arc<ServerConfig>,
    proxy_config: Arc<
        Config<
            impl for<'a> Service<&'a [u8], Error = MiddlewareError, Response = ()> + Clone + Send,
        >,
    >,
) -> anyhow::Result<()>
where
{
    let client_hello = {
        let mut log = vec![0u8; 4096];
        let size = socket.peek(log.as_mut_slice()).await?;
        log.truncate(size);
        log
    };

    let acceptor = LazyAcceptor::new(Acceptor::default(), socket);
    let sh = acceptor.await?;
    let sni = sh
        .client_hello()
        .sni()
        .as_ref()
        .ok_or(ServerNotFound)?
        .to_lowercase_owned();

    let server = proxy_config.get(sni.as_ref()).ok_or(ServerNotFound)?;

    let addr = server
        .load_balancer
        .get_upstream()
        .ok_or(UnableToFindUpstream)?
        .addr;

    let should_decrypt = server.should_decrypt();

    info!("Found Server {:?}", sni);
    info!("Found Upstream {:?}", addr);
    info!(
        "Decryption is {} — traffic {} being inspected",
        if should_decrypt {
            "enabled"
        } else {
            "disabled"
        },
        if should_decrypt { "is" } else { "is not" }
    );

    if should_decrypt {
        let stream = sh.into_stream(tls_config.clone()).await?;
        main_loop(
            stream,
            addr,
            Vec::new(), // doesn't allocate so fine to leave like this.
            server.middleware.clone(),
        )
        .await?;
    } else {
        let socket = sh.take_io();
        main_loop(socket, addr, client_hello, server.middleware.clone()).await?;
    };

    proxy_config
        .get(sni.as_ref())
        .unwrap() // unwrap is safe because we looked this up earlier
        .load_balancer
        .release(addr);

    Ok(())
}

/// Main loop for handling the proxying of data between the client and the server.
///
/// # Arguments
/// * `transport` - The transport stream.
/// * `server_addr` - The server address.
/// * `early_data` - The early data to send to the server.
///
/// # Returns
/// An `io::Result` indicating the success or failure of the operation.
async fn main_loop<T>(
    mut transport: T,
    server_addr: SocketAddr,
    early_data: Vec<u8>,
    mut middleware: impl for<'a> Service<&'a [u8], Error = MiddlewareError>,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_stream = TcpStream::connect(server_addr).await?;
    server_stream
        .write_all(&early_data[..early_data.len()])
        .await?;
    let mut buf_client = [0u8; 4096];
    let mut buf_server = [0u8; 4096];

    loop {
        futures::select! {
            res = transport.read(&mut buf_client).fuse() => {
                let len = res?;
                if len == 0 {
                    debug!("Connection Closed");
                    break;
                };

                if let Err(e) = middleware.call(&buf_client[..len]).await {
                    debug!("Error in middleware: {:?}", e);
                    transport.close().await?;
                    break;
                }

                server_stream.write_all(&buf_client[..len]).await?;
            },
            res = server_stream.read(&mut buf_server).fuse() => {
                let len = res?;
                if len == 0 {
                    debug!("Connection Closed");
                    transport.close().await?;
                    break;
                };
                transport.write_all(&buf_server[..len]).await?;
            },
        }
    }

    Ok(())
}
