use layered::layer::Layer;
use layered::service::Service;
use log::debug;

pub fn analytics() -> AnalyticsLayer {
    AnalyticsLayer
}

pub struct AnalyticsLayer;

impl<S> Layer<S> for AnalyticsLayer {
    type Service = AnalyticsService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AnalyticsService { service }
    }
}

#[derive(Clone)]
pub struct AnalyticsService<S> {
    service: S,
}

impl<'a, S> Service<&'a [u8]> for AnalyticsService<S>
where
    S: Service<&'a [u8]> + Send,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&mut self, req: &'a [u8]) -> Result<Self::Response, Self::Error> {
        debug!("AnalyticsService: {:?}", String::from_utf8_lossy(req));
        self.service.call(req).await
    }
}
