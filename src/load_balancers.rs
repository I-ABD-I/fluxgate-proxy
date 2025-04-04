mod least_connectoins;
mod roundrobin;

use crate::config::Upstream;
pub use roundrobin::RoundRobin;
pub use least_connectoins::LeastConnections;
use std::fmt::Debug;
use std::net::SocketAddr;

pub trait LoadBalancer: Send + Sync + Debug {
    fn get_upstream(&mut self) -> Option<&Upstream>;
    #[allow(unused_variables)]
    fn release(&mut self, upstream: SocketAddr) {
        // Default implementation does nothing
        // Subclass can override this if needed
    }
}
