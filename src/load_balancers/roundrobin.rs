use std::net::SocketAddr;
use log::debug;
use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;

#[derive(Debug)]
pub struct RoundRobin {
    upstreams: Vec<Upstream>,
    current: usize,
}

impl From<Vec<Upstream>> for RoundRobin {
    fn from(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams,
            current: 0,
        }
    }
}

impl LoadBalancer for RoundRobin {
    fn get_upstream(&mut self) -> Option<&Upstream> {
        if self.current >= self.upstreams.len() {
            None // No upstreams available
        } else {
            let upstream = &self.upstreams[self.current];
            self.current = (self.current + 1) % self.upstreams.len();
            Some(upstream)
        }
    }

    fn release(&mut self, upstream: SocketAddr) {
        debug!("Releasing upstream: {}", upstream);
    }
}
