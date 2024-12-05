use util::{Either, Identity, Stack};

pub mod layer;
pub mod service;
mod util;

pub struct ServiceBuilder<L> {
    inner: L,
}

impl Default for ServiceBuilder<Identity> {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceBuilder<Identity> {
    pub const fn new() -> Self {
        Self { inner: Identity }
    }
}

impl<L> ServiceBuilder<L> {
    pub fn layer<T>(self, layer: T) -> ServiceBuilder<util::Stack<T, L>> {
        ServiceBuilder {
            inner: Stack::new(layer, self.inner),
        }
    }

    pub fn option_layer<T>(
        self,
        layer: Option<T>,
    ) -> ServiceBuilder<util::Stack<Either<T, Identity>, L>> {
        let inner = match layer {
            Some(layer) => Either::Left(layer),
            None => Either::Right(Identity),
        };
        ServiceBuilder {
            inner: Stack::new(inner, self.inner),
        }
    }
}
