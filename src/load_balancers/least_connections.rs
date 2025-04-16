use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct LeastConnections {
    upstreams: HashMap<Upstream, AtomicUsize>,
}

impl From<Vec<Upstream>> for LeastConnections {
    /// Creates a `LeastConnections` load balancer from a vector of upstreams.
    ///
    /// # Arguments
    /// * `upstreams` - A vector of upstreams.
    ///
    /// # Returns
    /// A new `LeastConnections` instance.
    fn from(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams: upstreams
                .into_iter()
                .map(|u| (u, AtomicUsize::new(0)))
                .collect(),
        }
    }
}

impl LoadBalancer for LeastConnections {
    fn get_upstream(&self) -> Option<Upstream> {
        let (upstream, conn) = self
            .upstreams
            .iter()
            .min_by_key(|(_, connections)| connections.load(Ordering::Relaxed))?;

        conn.fetch_add(1, Ordering::Relaxed);
        Some(*upstream)
    }

    fn release(&self, addr: SocketAddr) {
        if let Some(connections) = self.upstreams.get(&Upstream { addr }) {
            connections.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
