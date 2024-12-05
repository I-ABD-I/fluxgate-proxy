pub trait Layer<S> {
    type Service;

    fn layer(&self, service: S) -> Self::Service;
}

impl<S, T> Layer<S> for &T
where
    T: ?Sized + Layer<S>,
{
    type Service = T::Service;

    fn layer(&self, service: S) -> Self::Service {
        (**self).layer(service)
    }
}
