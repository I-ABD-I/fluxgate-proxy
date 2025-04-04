use super::{layer::Layer, service::Service};
use std::future::Future;

/// A struct representing the identity layer which does not modify the service.
pub struct Identity;

impl<S> Layer<S> for Identity {
    type Service = S;

    /// Wraps the given service with the identity layer.
    ///
    /// # Arguments
    /// * `service` - The service to be wrapped.
    ///
    /// # Returns
    /// The same service without any modifications.
    fn layer(&self, service: S) -> Self::Service {
        service
    }
}

/// A struct representing a stack of two layers.
pub struct Stack<Inner, Outer> {
    inner: Inner,
    outer: Outer,
}

impl<Inner, Outer> Stack<Inner, Outer> {
    /// Creates a new `Stack` with the given inner and outer layers.
    ///
    /// # Arguments
    /// * `inner` - The inner layer.
    /// * `outer` - The outer layer.
    ///
    /// # Returns
    /// A new instance of `Stack`.
    pub const fn new(inner: Inner, outer: Outer) -> Self {
        Self { inner, outer }
    }
}

impl<S, Inner, Outer> Layer<S> for Stack<Inner, Outer>
where
    Inner: Layer<S>,
    Outer: Layer<Inner::Service>,
{
    type Service = Outer::Service;

    /// Wraps the given service with the stack of layers.
    ///
    /// # Arguments
    /// * `service` - The service to be wrapped.
    ///
    /// # Returns
    /// The service wrapped with the inner and outer layers.
    fn layer(&self, service: S) -> Self::Service {
        let inner = self.inner.layer(service);
        self.outer.layer(inner)
    }
}

/// An enum representing either one of two possible services.
pub enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A, B, Request> Service<Request> for Either<A, B>
where
    A: Service<Request> + Send,
    B: Service<Request, Response = A::Response, Error = A::Error> + Send,
    Request: Send,
{
    type Response = A::Response;
    type Error = A::Error;

    /// Processes the given request asynchronously by delegating to either the left or right service.
    ///
    /// # Arguments
    /// * `req` - The request to be processed.
    ///
    /// # Returns
    /// A future that resolves to a result containing either the response or an error.
    async fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        match self {
            Either::Left(a) => a.call(req).await,
            Either::Right(b) => b.call(req).await,
        }
    }
}

/// A struct representing a service function.
#[derive(Clone, Copy)]
pub struct ServiceFn<T> {
    f: T,
}

impl<T> ServiceFn<T> {
    /// Creates a new `ServiceFn` with the given function.
    ///
    /// # Arguments
    /// * `f` - The function to be wrapped as a service.
    ///
    /// # Returns
    /// A new instance of `ServiceFn`.
    pub const fn new(f: T) -> Self {
        Self { f }
    }
}

impl<T, F, Request, R, E> Service<Request> for ServiceFn<T>
where
    T: FnMut(Request) -> F + Send,
    F: Future<Output = Result<R, E>> + Send,
    Request: Send,
{
    type Response = R;
    type Error = E;

    /// Processes the given request asynchronously by calling the wrapped function.
    ///
    /// # Arguments
    /// * `req` - The request to be processed.
    ///
    /// # Returns
    /// A future that resolves to a result containing either the response or an error.
    async fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (self.f)(req).await
    }
}