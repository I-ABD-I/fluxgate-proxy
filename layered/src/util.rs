use super::{layer::Layer, service::Service};

pub struct Identity;
impl<S> Layer<S> for Identity {
    type Service = S;

    fn layer(&self, service: S) -> Self::Service {
        service
    }
}

pub struct Stack<Inner, Outer> {
    inner: Inner,
    outer: Outer,
}

impl<Inner, Outer> Stack<Inner, Outer> {
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

    fn layer(&self, service: S) -> Self::Service {
        let inner = self.inner.layer(service);
        self.outer.layer(inner)
    }
}

pub enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A, B, Request> Service<Request> for Either<A, B>
where
    A: Service<Request>,
    B: Service<Request, Response = A::Response, Error = A::Error>,
{
    type Response = A::Response;

    type Error = A::Error;

    fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        match self {
            Either::Left(a) => a.call(req),
            Either::Right(b) => b.call(req),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ServiceFn<T> {
    f: T,
}
impl<T> ServiceFn<T> {
    pub const fn new(f: T) -> Self {
        Self { f }
    }
}

impl<T, Request, R, E> Service<Request> for ServiceFn<T>
where
    T: FnMut(Request) -> Result<R, E>,
{
    type Response = R;

    type Error = E;

    fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (self.f)(req)
    }
}
