use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;

/// A load balancer that distributes connections using the round-robin algorithm.
#[derive(Debug)]
pub struct RoundRobin {
    /// A list of upstream servers.
    upstreams: Vec<Upstream>,
    /// The index of the current upstream server.
    current: usize,
}

impl From<Vec<Upstream>> for RoundRobin {
    /// Creates a `RoundRobin` load balancer from a vector of upstreams.
    ///
    /// # Arguments
    /// * `upstreams` - A vector of upstream servers.
    ///
    /// # Returns
    /// A new `RoundRobin` instance.
    fn from(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams,
            current: 0,
        }
    }
}

impl LoadBalancer for RoundRobin {
    /// Gets the next upstream server in the round-robin sequence.
    ///
    /// # Returns
    /// An optional reference to the selected upstream server.
    fn get_upstream(&mut self) -> Option<&Upstream> {
        if self.current >= self.upstreams.len() {
            None // No upstreams available
        } else {
            let upstream = &self.upstreams[self.current];
            self.current = (self.current + 1) % self.upstreams.len();
            Some(upstream)
        }
    }
}
