pub trait Service<Request> {
    type Response;
    type Error;

    fn call(
        &mut self,
        req: Request,
    ) -> impl std::future::Future<Output = Result<Self::Response, Self::Error>> + Send;
}

impl<S, Request> Service<Request> for &mut S
where
    S: Service<Request> + Send,
    Request: Send,
{
    type Response = S::Response;

    type Error = S::Error;

    async fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (**self).call(req).await
    }
}

impl<S, Request> Service<Request> for Box<S>
where
    S: Service<Request> + Send,
    Request: Send,
{
    type Response = S::Response;

    type Error = S::Error;

    async fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (**self).call(req).await
    }
}
