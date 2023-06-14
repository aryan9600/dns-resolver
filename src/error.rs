use std::error::Error;

use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum DNSResolverError {
    #[error("error while decoding `{0}`: `{1}`")]
    Decode(String, String),
    #[error("error while encoding `{0}`: `{1}`")]
    Encode(String, String),
    #[error("error while parsing bytes")]
    Parse,
    #[error("invalid record type: `{0}`")]
    InvalidRecordType(String),
    #[error("failed while trying to connect to `{0}`: `{1}`")]
    ConnectionFailure(String, String),
    #[error("failed while trying to `{0}` data: `{1}`")]
    IOFailure(String, String),
    #[error("could not lookup `{0}` record of `{1}`")]
    LookupFailure(String, String),
}

pub type Result<T> = std::result::Result<T, DNSResolverError>;

pub fn map_decode_err(step: &str, err: &impl Error) -> DNSResolverError {
    DNSResolverError::Decode(String::from(step), err.to_string())
}

pub fn map_encode_err(step: &str, err: &impl Error) -> DNSResolverError {
    DNSResolverError::Encode(String::from(step), err.to_string())
}
