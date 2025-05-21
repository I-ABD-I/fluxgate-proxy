use super::LoadBalancer;
use crate::config::Upstream;
use agent::{Codec, Message, Reader};
use async_std::net::UdpSocket;
use async_std::sync::RwLock;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug)]

/// Manages a collection of upstream servers and their associated resource metrics,
/// designed for thread-safe access and modification.
///
/// Internally, this struct wraps an `Arc<RwLock<HashMap<Upstream, f32>>>`.
/// The `HashMap` maps each `Upstream` server to an `f32` value, which typically
/// represents a resource-based score, load, or capacity metric.
///
/// The use of `Arc` allows the server data to be shared across multiple threads,
/// while `RwLock` ensures that concurrent reads and exclusive writes are handled safely.
/// This is essential for resource-based load balancers that need to dynamically
/// update and query server status.
struct Servers(Arc<RwLock<HashMap<Upstream, f32>>>);

impl Servers {
    fn new(upstreams: Vec<Upstream>) -> Self {
        Self(Arc::new(RwLock::new(
            upstreams.into_iter().map(|u| (u, 0.0)).collect(),
        )))
    }

    fn dup(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Deref for Servers {
    type Target = Arc<RwLock<HashMap<Upstream, f32>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]

/// A load balancer that distributes requests based on the current resource
/// utilization of the backend servers.
///
/// This strategy aims to send new requests to the server that is currently
/// the least loaded, thereby optimizing resource usage and potentially
/// improving response times.
pub struct ResourceBased {
    servers: Servers,
}

impl From<Vec<Upstream>> for ResourceBased {
    fn from(value: Vec<Upstream>) -> Self {
        let servers = Servers::new(value);
        async_std::task::spawn(updater(servers.dup()));

        Self { servers }
    }
}

impl LoadBalancer for ResourceBased {
    fn get_upstream(&self) -> Option<Upstream> {
        self.servers
            .read_blocking()
            .iter()
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(Ordering::Greater))
            .map(|(k, _)| *k)
    }
}

/// This function is responsible for sending a connection request to each server
/// and listening for metrics updates from them.
/// It uses a `UdpSocket` to communicate with the servers.
/// The function sends a connection request to each server and waits for metrics
/// updates.
/// It updates the CPU usage of each server based on the received metrics.
/// The function runs indefinitely, continuously updating the server metrics.
/// It uses an `async` runtime to handle the asynchronous nature of the UDP communication.
/// The function is designed to be run in a separate thread or task.
/// The function takes a `Servers` instance as an argument, which contains the
/// upstream servers and their current CPU usage.
/// The function returns a `!` type, indicating that it never returns.
/// The function is marked with `async` to allow for asynchronous operations.
async fn updater(servers: Servers) -> ! {
    let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    let mut send_buf = Vec::with_capacity(1);
    Message::Connect.encode(&mut send_buf);

    for server in servers.read().await.keys() {
        let mut addr = server.addr;
        addr.set_port(2749);
        udp.send_to(send_buf.as_slice(), addr).await.unwrap();
        async_std::task::sleep(std::time::Duration::from_secs(1)).await; // create a delay between messages such that both servers wont have same usage
    }

    send_buf.clear();
    Message::Ack.encode(&mut send_buf);
    loop {
        let mut buf = [0u8; 5];
        let (size, addr) = udp.recv_from(&mut buf).await.unwrap();
        let msg = Message::read(&mut Reader::from(&buf[..size]));
        let Ok(msg) = msg else { continue };
        use Message::*;
        match msg {
            Ack => {}
            Metrics(m) => {
                let _ = udp.send_to(&send_buf, addr).await.unwrap();
                let mut servers = servers.write().await;
                if let Some((_, cpu)) = servers.iter_mut().find(|s| s.0.addr.ip() == addr.ip()) {
                    *cpu = m.cpu;
                }
            }
            _ => {}
        }
    }
}
