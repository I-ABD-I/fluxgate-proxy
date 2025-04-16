use crate::config::Upstream;
use crate::load_balancers::LoadBalancer;
use std::sync::atomic::AtomicUsize;

#[derive(Debug)]
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
