/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//!Tool for computing hashes and comparing files
use clap::Parser;
use disk_compare::cli::Arguments;
use disk_compare::{PathComparison, PathInfo};
// TODO: Argument for selecting the hash (SHa256, MD5, etc.)

fn main() {
    // TODO: Parallelize first and second paths?
    // TODO: non-panicking error messages, esp for non existant files
    let args = Arguments::parse();
    println!("Computing hashes for first path");
    let first_path_info = PathInfo::from(args.first_path);

    if let Some(second_path) = args.second_path {
        println!("Computing hashes for second path");
        let second_path_info = PathInfo::from(second_path);

        PathComparison::new(&first_path_info, &second_path_info).print_results();
    } else {
        for (path, hash) in first_path_info.hashmap {
            println!("{path}:\t{hash}");
        }
    }
}
