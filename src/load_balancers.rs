mod least_connections;
mod round_robin;

use crate::config::Upstream;
pub use round_robin::RoundRobin;
pub use least_connections::LeastConnections;
use std::fmt::Debug;
use std::net::SocketAddr;

/// Trait representing a load balancer.
///
/// # Methods
/// * `get_upstream` - Returns the next upstream server.
/// * `release` - Releases a connection from the specified upstream server.
pub trait LoadBalancer: Send + Sync + Debug {
    /// Gets the next upstream server.
    ///
    /// # Returns
    /// An optional reference to the selected upstream server.
    fn get_upstream(&mut self) -> Option<&Upstream>;

    /// Releases a connection from the specified upstream server.
    ///
    /// # Arguments
    /// * `upstream` - The address of the upstream server to release the connection from.
    #[allow(unused_variables)]
    fn release(&mut self, upstream: SocketAddr) {
        // Default implementation does nothing
        // Subclass can override this if needed
    }
}