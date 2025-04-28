use thiserror::Error;

/// Error indicating that the server was not found.
#[derive(Debug, Error)]
#[error("Server Not Found")]
pub struct ServerNotFound;

/// Error indicating that an upstream server could not be found.
#[derive(Debug, Error)]
#[error("unable to find upstream")]
pub struct UnableToFindUpstream;

#[derive(Clone, Debug, Error)]
#[error("Middleware Error")]
pub struct MiddlewareError;
