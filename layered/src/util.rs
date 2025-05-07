use super::{layer::Layer, service::Service};
use std::future::Future;
use std::marker::PhantomData;

/// A struct representing the identity layer which does not modify the service.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityLayer;

impl<S> Layer<S> for IdentityLayer {
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

#[derive(Clone)]
pub struct IdentityService<Error>(PhantomData<Error>);

impl<Error> Default for IdentityService<Error> {
    /// Creates a new `IdentityService` instance.
    ///
    /// # Arguments
    /// * `error` - The error type to be used.
    ///
    /// # Returns
    /// A new instance of `IdentityService`.
    fn default() -> Self {
        Self(PhantomData)
    }
}
impl<Request, Error> Service<Request> for IdentityService<Error>
where
    Request: Send,
    Error: Send,
{
    type Response = ();
    type Error = Error;

    /// Processes the given request asynchronously by returning it unchanged.
    ///
    /// # Arguments
    /// * `req` - The request to be processed.
    ///
    /// # Returns
    /// A future that resolves to the unchanged request.
    async fn call(&mut self, _: Request) -> Result<(), Self::Error> {
        Ok(())
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
#[derive(Clone, Copy, Debug)]
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

impl<S, A, B> Layer<S> for Either<A, B>
where
    A: Layer<S>,
    B: Layer<S>,
{
    type Service = Either<A::Service, B::Service>;

    fn layer(&self, service: S) -> Self::Service {
        match self {
            Either::Left(a) => Either::Left(a.layer(service)),
            Either::Right(b) => Either::Right(b.layer(service)),
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
