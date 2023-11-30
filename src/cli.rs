//! Command line argument parser

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Eq, PartialEq)]
#[command(
    author,
    version,
    about = "Tool for computing hashes all files in a directory, and comparing directories."
)]
pub struct Arguments {
    // Path to the directory to scan.
    #[arg()]
    pub base_path: PathBuf,
}
