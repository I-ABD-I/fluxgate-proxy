use layer::Layer;
use util::{Either, Identity, ServiceFn, Stack};

pub mod layer;
pub mod service;
mod util;

/// A builder for composing layers and services.
pub struct ServiceBuilder<L> {
    inner: L,
}

impl Default for ServiceBuilder<Identity> {
    /// Creates a new `ServiceBuilder` with the `Identity` layer.
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceBuilder<Identity> {
    /// Creates a new `ServiceBuilder` with the `Identity` layer.
    ///
    /// # Returns
    /// A new instance of `ServiceBuilder` with the `Identity` layer.
    pub const fn new() -> Self {
        Self { inner: Identity }
    }
}

impl<L> ServiceBuilder<L> {
    /// Adds a layer to the `ServiceBuilder`.
    ///
    /// # Arguments
    /// * `layer` - The layer to be added.
    ///
    /// # Returns
    /// A new `ServiceBuilder` with the added layer.
    pub fn layer<T>(self, layer: T) -> ServiceBuilder<util::Stack<T, L>> {
        ServiceBuilder {
            inner: Stack::new(layer, self.inner),
        }
    }

    /// Adds an optional layer to the `ServiceBuilder`.
    ///
    /// # Arguments
    /// * `layer` - An optional layer to be added.
    ///
    /// # Returns
    /// A new `ServiceBuilder` with the added layer if present, otherwise with the `Identity` layer.
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

    /// Wraps a service with the composed layers.
    ///
    /// # Arguments
    /// * `service` - The service to be wrapped.
    ///
    /// # Returns
    /// The wrapped service.
    pub fn service<S>(&self, service: S) -> L::Service
    where
        L: Layer<S>,
    {
        self.inner.layer(service)
    }

    /// Wraps a function as a service with the composed layers.
    ///
    /// # Arguments
    /// * `f` - The function to be wrapped as a service.
    ///
    /// # Returns
    /// The wrapped service.
    pub fn service_fn<F>(&self, f: F) -> L::Service
    where
        L: Layer<ServiceFn<F>>,
    {
        self.inner.layer(ServiceFn::new(f))
    }
}
