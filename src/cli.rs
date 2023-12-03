/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//! Command line argument parser

use clap::Parser;
use std::path::PathBuf;

/// Struct  of the tool's command line arguments.
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
