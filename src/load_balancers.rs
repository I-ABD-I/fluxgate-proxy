mod least_connections;
mod resource_based;
mod round_robin;

use crate::config::Upstream;
pub use least_connections::LeastConnections;
pub use resource_based::ResourceBased;
pub use round_robin::RoundRobin;
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
    fn get_upstream(&self) -> Option<Upstream>;

    /// Releases a connection from the specified upstream server.
    ///
    /// # Arguments
    /// * `upstream` - The address of the upstream server to release the connection from.
    #[allow(unused_variables)]
    fn release(&self, upstream: SocketAddr) {
        // Default implementation does nothing
        // Subclass can override this if needed
    }
}
