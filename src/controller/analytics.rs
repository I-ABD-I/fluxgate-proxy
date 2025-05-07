use crate::controller::analytics::ipc::IpcMessage;
use async_std::sync::Mutex;
use futures::executor::block_on;
use layered::layer::Layer;
use layered::service::Service;
use log::error;
use std::sync::Arc;

pub fn analytics(
    channel: Arc<Mutex<async_std::process::ChildStdin>>,
    server_name: Arc<str>,
) -> AnalyticsLayer {
    AnalyticsLayer {
        channel,
        server_name,
    }
}

pub struct AnalyticsLayer {
    // This is a placeholder for the actual IPC channel.
    // In a real-world scenario, this would be replaced with an actual IPC channel.
    channel: Arc<Mutex<async_std::process::ChildStdin>>,
    server_name: Arc<str>,
}

impl<S> Layer<S> for AnalyticsLayer {
    type Service = AnalyticsService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AnalyticsService {
            service,
            server_name: self.server_name.clone(),
            channel: self.channel.clone(),
        }
    }
}

pub struct AnalyticsService<S> {
    server_name: Arc<str>,
    channel: Arc<Mutex<async_std::process::ChildStdin>>,
    service: S,
}

impl<S: Clone> Clone for AnalyticsService<S> {
    fn clone(&self) -> Self {
        block_on(write(
            &self.channel,
            IpcMessage::new_connection(&self.server_name),
        ));
        AnalyticsService {
            server_name: self.server_name.clone(),
            service: self.service.clone(),
            channel: self.channel.clone(),
        }
    }
}

impl<S> Drop for AnalyticsService<S> {
    fn drop(&mut self) {
        block_on(write(
            &self.channel,
            IpcMessage::connection_closed(&self.server_name),
        ));
    }
}

impl<'a, S> Service<&'a [u8]> for AnalyticsService<S>
where
    S: Service<&'a [u8]> + Send,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&mut self, req: &'a [u8]) -> Result<Self::Response, Self::Error> {
        write(
            &self.channel,
            IpcMessage::data_received(&self.server_name, req.len()),
        )
        .await;
        self.service.call(req).await
    }
}

async fn write(channel: &Mutex<async_std::process::ChildStdin>, message: IpcMessage<'_>) {
    match message.send(&mut *channel.lock().await).await {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to send analytics data: {e}");
        }
    }
}
mod ipc {
    use async_std::io;
    use futures::AsyncWriteExt;

    pub enum IpcMessage<'a> {
        NewConnection(&'a str),
        ConnectionClosed(&'a str),
        DataReceived(&'a str, usize),
    }

    impl<'a> IpcMessage<'a> {
        pub fn new_connection(server_name: &'a str) -> Self {
            IpcMessage::NewConnection(server_name)
        }

        pub fn connection_closed(server_name: &'a str) -> Self {
            IpcMessage::ConnectionClosed(server_name)
        }

        pub fn data_received(server_name: &'a str, size: usize) -> Self {
            IpcMessage::DataReceived(server_name, size)
        }

        fn name(&self) -> &[u8] {
            match self {
                IpcMessage::NewConnection(name) => name.as_bytes(),
                IpcMessage::ConnectionClosed(name) => name.as_bytes(),
                IpcMessage::DataReceived(name, _) => name.as_bytes(),
            }
        }
        pub async fn send(
            &self,
            channel: &mut async_std::process::ChildStdin,
        ) -> io::Result<usize> {
            let (typ, extra): (u8, &[u8]) = match self {
                IpcMessage::NewConnection(_) => (1, &[]),
                IpcMessage::ConnectionClosed(_) => (2, &[]),
                IpcMessage::DataReceived(_, size) => (3, &size.to_ne_bytes()),
            };
            let name = self.name();

            // should always uphold, domain name is at most 255 bytes
            debug_assert!(2 + extra.len() + name.len() < 1024);

            let mut buffer = [0; 1024];
            buffer[0] = typ;
            buffer[1..extra.len() + 1].copy_from_slice(extra);
            buffer[1 + extra.len()..1 + extra.len() + name.len()].copy_from_slice(name);
            buffer[1 + extra.len() + name.len()] = b'\n';

            channel.write(&buffer[..2 + extra.len() + name.len()]).await
        }
    }
}
