//! Command line argument parser

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Eq, PartialEq)]
#[command(
    author,
    version,
    about = "Tool for computing hashes all files in a directory, and comparing directories.",
    after_help = "If only one path is supplied, the tool will print out all found files and their hashes. If two paths are supplied, the tool will output the differences between the two files."
)]
pub struct Arguments {
    /// Path to the first directory to scan
    #[arg()]
    pub first_path: PathBuf,

    /// Path to the second directory to scan
    #[arg()]
    pub second_path: Option<PathBuf>,
}
