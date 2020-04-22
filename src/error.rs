use poly_commit::error::Error as PolyCommitError;
use std::io::Error as IOError;
use std::option::NoneError;

#[derive(Debug)]
pub enum Error {
    SetupInvalidDegree(usize),
    CommitmentInvalid,
    KeyNotFound(Vec<u8>),
    EmptyLayerNotFound(Vec<u8>),
    InvalidProof,
    PolyCommitError(PolyCommitError),
    IOError(IOError),
    NoneError(NoneError)
}

impl From<NoneError> for Error {
    fn from(e: NoneError) -> Error {
        Error::NoneError(e)
    }
}

impl From<IOError> for Error {
    fn from(e: IOError) -> Error {
        Error::IOError(e)
    }
}

impl From<PolyCommitError> for Error {
    fn from(e: PolyCommitError) -> Error {
        Error::PolyCommitError(e)
    }
}