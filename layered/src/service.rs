pub trait Service<Request> {
    type Response;
    type Error;

    fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error>;
}

impl<S, Request> Service<Request> for &mut S
where
    S: Service<Request>,
{
    type Response = S::Response;

    type Error = S::Error;

    fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (**self).call(req)
    }
}

impl<S, Request> Service<Request> for Box<S>
where
    S: Service<Request>,
{
    type Response = S::Response;

    type Error = S::Error;

    fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (**self).call(req)
    }
}
