//! Enumeration of errors the tool can produce.

use std::io;
use std::io::ErrorKind;
use std::path::StripPrefixError;
use thiserror::Error;

/// Enumeration of errors generated by the tool
#[derive(Debug, Error)]
pub enum ToolError {
    /// Indicates something went wrong with the opening the file.
    #[error("Error reading a file. IO Error Kind: {kind}, path: {filepath}")]
    FileReadError { kind: ErrorKind, filepath: String },

    /// Indicates something went wrong copying file contents into the hasher
    #[error("Error reading file bytes into hasher")]
    ByteCopyError(#[from] io::Error),

    /// Indicates an error unwrapping a path
    #[error("Error stripping a path")]
    StripPrefixError(#[from] StripPrefixError),
}
