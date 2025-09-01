/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//!Tool for computing hashes and comparing files
use clap::Parser as _;
use disk_compare::cli::Arguments;
use disk_compare::{PathComparison, compute_hashes_for_dir};
// TODO: Argument for selecting the hash (SHa256, MD5, etc.)

fn main() {
    // TODO: non-panicking error messages, esp for non existant files
    let args = Arguments::parse();

    if let Some(second_path) = args.second_path {
        println!("Finding differeing files between paths.");

        PathComparison::new(&args.first_path, &second_path).print_results();
    } else {
        println!("Computing hashes for all files in the given path.");
        // FIXME: Move some of this into lib so that we can test it
        for hash_result in compute_hashes_for_dir(&args.first_path) {
            match hash_result {
                Ok(hash) => match hash.get_rel_filepath(&args.first_path) {
                    Ok(path) => println!("{}:\t{}", path, hash.get_hash_string()),
                    Err(e) => eprintln!(
                        "Failed getting relative path for {}. Error: {e}",
                        hash.get_filepath()
                    ),
                },
                Err(e) => eprintln!(
                    "Failed computing hash for file '{}'.\n\tError Message: {e}",
                    e.get_filepath().display()
                ),
            }
        }
    }
}
