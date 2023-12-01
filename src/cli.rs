//! Command line argument parser

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Eq, PartialEq)]
#[command(
    author,
    version,
    about = "Tool for computing hashes and comparing files",
    after_help = "If only one path is supplied, the tool will print out all found files and their hashes. If two paths are supplied, the tool will output the differences between the two paths."
)]
pub struct Arguments {
    /// Path to the first file/directory to scan
    #[arg()]
    pub first_path: PathBuf,

    /// Path to the second file/directory to scan
    #[arg()]
    pub second_path: Option<PathBuf>,
}
