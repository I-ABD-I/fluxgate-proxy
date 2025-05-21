use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;
use std::sync::atomic::AtomicUsize;

#[derive(Debug)]

/// Represents a Round Robin load balancer.
///
/// This load balancer distributes incoming requests sequentially among a list
/// of upstream servers. When the end of the list is reached, it wraps around
/// to the beginning.
///
/// # Fields
///
/// * `upstreams`: A vector of `Upstream` structs, representing the available
///   servers to which requests can be forwarded.
/// * `current`: An `AtomicUsize` that keeps track of the index of the next
///   upstream server to be selected. This ensures thread-safe access and
///   increment for selecting upstreams in a round-robin fashion.
pub struct RoundRobin {
    upstreams: Vec<Upstream>,
    current: AtomicUsize,
}

impl From<Vec<Upstream>> for RoundRobin {
    fn from(value: Vec<Upstream>) -> Self {
        Self {
            upstreams: value,
            current: AtomicUsize::new(0),
        }
    }
}

impl LoadBalancer for RoundRobin {
    fn get_upstream(&self) -> Option<Upstream> {
        let current = self.current.load(std::sync::atomic::Ordering::Relaxed);
        if current >= self.upstreams.len() {
            None
        } else {
            let upstream = &self.upstreams[current];
            self.current.store(
                (current + 1) % self.upstreams.len(),
                std::sync::atomic::Ordering::Relaxed,
            );
            Some(*upstream)
        }
    }
}
