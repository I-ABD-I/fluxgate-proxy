/// A trait representing a layer that wraps a service.
///
/// # Type Parameters
/// * `S` - The type of the service being wrapped.
pub trait Layer<S> {
    /// The type of the wrapped service.
    type Service;

    /// Wraps the given service with the layer.
    ///
    /// # Arguments
    /// * `service` - The service to be wrapped.
    ///
    /// # Returns
    /// The wrapped service.
    fn layer(&self, service: S) -> Self::Service;
}

impl<S, T> Layer<S> for &T
where
    T: ?Sized + Layer<S>,
{
    type Service = T::Service;

    /// Wraps the given service with the layer.
    ///
    /// # Arguments
    /// * `service` - The service to be wrapped.
    ///
    /// # Returns
    /// The wrapped service.
    fn layer(&self, service: S) -> Self::Service {
        (**self).layer(service)
    }
}
