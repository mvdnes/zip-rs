//! Error types that can be emitted from this library

use std::io;

use thiserror::Error;

/// Generic result type with ZipError as its error variant
pub type ZipResult<T> = Result<T, ZipError>;

/// Error type for Zip
#[derive(Debug, Error)]
pub enum ZipError {
    /// An Error caused by I/O
    #[error(transparent)]
    Io(#[from] io::Error),

    /// This file is probably not a zip archive
    #[error("invalid Zip archive")]
    InvalidArchive(&'static str),

    /// This archive is not supported
    #[error("unsupported Zip archive")]
    UnsupportedArchive(&'static str),

    /// No password was given but the data is encrypted
    #[error("missing password, file in archive is encrypted")]
    PasswordRequired,

    /// The given password is wrong
    #[error("invalid password for file in archive")]
    InvalidPassword,
}

impl From<ZipError> for io::Error {
    fn from(err: ZipError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err)
    }
}
