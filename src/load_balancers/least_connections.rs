use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;
use std::collections::HashMap;
use std::net::SocketAddr;

/// A load balancer that selects the upstream with the least number of connections.
#[derive(Debug)]
pub struct LeastConnections {
    /// A map of upstreams to their current number of connections.
    upstreams: HashMap<Upstream, usize>,
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
            upstreams: upstreams.into_iter().map(|u| (u, 0)).collect(),
        }
    }
}

impl LoadBalancer for LeastConnections {
    /// Gets the upstream with the least number of connections and increments its connection count.
    ///
    /// # Returns
    /// An optional reference to the selected upstream.
    fn get_upstream(&mut self) -> Option<&Upstream> {
        let (upstream, connections) = self
            .upstreams
            .iter_mut()
            .min_by_key(|(_, connections)| **connections)?;

        *connections += 1;
        Some(upstream)
    }

    /// Releases a connection from the specified upstream.
    ///
    /// # Arguments
    /// * `addr` - The address of the upstream to release the connection from.
    fn release(&mut self, addr: SocketAddr) {
        if let Some(connections) = self.upstreams.get_mut(&Upstream { addr }) {
            *connections -= 1;
        }
    }
}
