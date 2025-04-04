/// A trait representing a service that processes requests and produces responses.
///
/// # Type Parameters
/// * `Request` - The type of the request being processed.
pub trait Service<Request> {
    /// The type of the response produced by the service.
    type Response;
    /// The type of the error that may occur during request processing.
    type Error;

    /// Processes the given request asynchronously.
    ///
    /// # Arguments
    /// * `req` - The request to be processed.
    ///
    /// # Returns
    /// A future that resolves to a result containing either the response or an error.
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

    /// Processes the given request asynchronously by delegating to the inner service.
    ///
    /// # Arguments
    /// * `req` - The request to be processed.
    ///
    /// # Returns
    /// A future that resolves to a result containing either the response or an error.
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

    /// Processes the given request asynchronously by delegating to the inner service.
    ///
    /// # Arguments
    /// * `req` - The request to be processed.
    ///
    /// # Returns
    /// A future that resolves to a result containing either the response or an error.
    async fn call(&mut self, req: Request) -> Result<Self::Response, Self::Error> {
        (**self).call(req).await
    }
}