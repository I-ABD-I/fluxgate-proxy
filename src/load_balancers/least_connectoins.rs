use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct LeastConnections {
    upstreams: HashMap<Upstream, usize>,
}

impl From<Vec<Upstream>> for LeastConnections {
    fn from(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams: upstreams.into_iter().map(|u| (u, 0)).collect(),
        }
    }
}
impl LoadBalancer for LeastConnections {
    fn get_upstream(&mut self) -> Option<&Upstream> {
        let (upstream, connections) = self
            .upstreams
            .iter_mut()
            .min_by_key(|(_, connections)| **connections)?;

        *connections += 1;
        Some(upstream)
    }

    fn release(&mut self, addr: SocketAddr) {
        if let Some(connections) = self.upstreams.get_mut(&Upstream { addr }) {
            *connections -= 1;
        }
    }
}
