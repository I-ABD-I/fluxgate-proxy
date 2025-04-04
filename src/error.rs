use thiserror::Error;

#[derive(Debug, Error)]
#[error("Server Not Found")]
pub struct ServerNotFound;

#[derive(Debug, Error)]
#[error("unable to find upstream")]
pub struct UnableToFindUpstream;
