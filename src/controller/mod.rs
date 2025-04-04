mod handshake_logger;

use crate::config::Config;
use crate::controller::handshake_logger::HandshakeLogger;
use crate::error::{ServerNotFound, UnableToFindUpstream};
use async_std::io;
use async_std::net::TcpStream;
use async_std::sync::{Arc, Mutex};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
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
pub async fn client_handler<T>(
    mut socket: T,
    tls_config: Arc<ServerConfig>,
    proxy_config: Arc<Mutex<Config>>,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let logger = HandshakeLogger::from(&mut socket);
    let acceptor = LazyAcceptor::new(Acceptor::default(), logger);
    let sh = acceptor.await?;
    let sni = sh
        .client_hello()
        .sni()
        .as_ref()
        .ok_or(ServerNotFound)?
        .to_lowercase_owned();

    let mut inner = proxy_config.lock().await;
    let server = inner.get_mut(sni.as_ref()).ok_or(ServerNotFound)?;

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

    drop(inner); // drop lock before main loop

    let res = if should_decrypt {
        let stream = sh.into_stream(tls_config.clone()).await?;
        main_loop(
            stream,
            addr,
            Vec::new(), // doesn't allocate so fine to leave like this.
        )
        .await
    } else {
        let logger = sh.take_io();
        let log = logger.take_log(); // unborrow socket (log contains only ClientHello message)
        main_loop(socket, addr, log).await
    };

    proxy_config
        .lock()
        .await
        .get_mut(sni.as_ref())
        .unwrap() // unwrap is safe because we looked this up earlier
        .load_balancer
        .release(addr);

    Ok(res?)
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
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_stream = TcpStream::connect(server_addr).await?;
    server_stream.write(&early_data[..early_data.len()]).await?;

    loop {
        let mut buf_client = [0u8; 4096];
        let mut buf_server = [0u8; 4096];

        futures::select! {
            res = transport.read(&mut buf_client).fuse() => {
                let len = res?;
                if len == 0 {
                    debug!("Connection Closed");
                    break;
                };
                server_stream.write(&buf_client[..len]).await?;
            },
            res = server_stream.read(&mut buf_server).fuse() => {
                let len = res?;
                if len == 0 {
                    debug!("Connection Closed");
                    break;
                };
                transport.write(&buf_server[..len]).await?;
            },
        }
    }

    Ok(())
}