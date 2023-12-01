/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//!Tool for computing hashes and comparing files
use clap::Parser;
use disk_compare::cli::Arguments;
use disk_compare::errors::ToolError;
use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelIterator;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::{collections::HashMap, fs::File};
use walkdir::{DirEntry, Error, WalkDir};

// TODO: Argument for selecting the hash (SHa256, MD5, etc.)

/// A single file and its hash
struct FileHash {
    /// The path to the file that was hashed
    pub filepath: PathBuf,
    /// The file's hash
    pub hash: Vec<u8>,
}

impl FileHash {
    /// Create the new hash from the given path.
    ///
    /// Arguments
    ///     * `filepath`: The path to the file to hash.
    ///     * `base_path`: The base path the files should be relative to.
    ///
    /// Returns:
    ///     The created `FileHash` instance.
    pub fn new(filepath: PathBuf, base_path: &PathBuf) -> Result<Self, ToolError> {
        // Only compute hash if the path points to a file
        let hash = if filepath.is_file() {
            Self::hash_file(&filepath)?
        } else {
            Vec::new()
        };
        // If the provided path is not the base path, strip the base path
        let filepath = if filepath.eq(base_path) {
            filepath
        } else {
            filepath.strip_prefix(base_path)?.to_path_buf()
        };

        Ok(Self { filepath, hash })
    }

    /// Compute the hash of the given file
    ///
    /// Arguments
    ///     * `filepath`: Path to the file to hash.
    fn hash_file(filepath: &PathBuf) -> Result<Vec<u8>, ToolError> {
        let mut hasher = Sha256::new();
        let mut file = File::open(filepath).map_err(|error| ToolError::FileReadError {
            kind: error.kind(),
            filepath: filepath.display().to_string(),
        })?;

        // This whole io::copy thing came from here
        // https://www.reddit.com/r/rust/comments/tuxpxf/comment/i368ryk/
        // Uses way less memory than reading the file directly
        // Guessing its sending copying the file in chunks?

        io::copy(&mut file, &mut hasher)?;
        Ok(hasher.finalize().to_vec())
    }

    /// Get the file hash as a string
    ///
    /// Returns:
    ///     File hash as a string
    fn hash_string(&self) -> String {
        let mut hash_string = String::new();
        for digit in &self.hash {
            hash_string = format!("{hash_string}{digit:x}");
        }
        hash_string
    }
}

/// Compute hashes of all files in the given directory.
///
/// Arguments:
///     * `directory`: The directory to comptue the hashes of.
fn hash_directory(directory: &PathBuf) -> Vec<FileHash> {
    WalkDir::new(directory)
        .into_iter()
        .par_bridge()
        .map(|entry: Result<DirEntry, Error>| {
            let path = PathBuf::from(entry.unwrap().path());
            FileHash::new(path, directory).unwrap()
        })
        .collect()
}

/// Information about a scanned directory.
struct DirectoryInfo {
    /// Hashmap of all files and their hashes.
    pub hashmap: HashMap<String, String>,

    /// Set of all scanned filepaths.
    /// Corresponds to the keys in the hashmap.
    pub paths: HashSet<String>,
}

impl From<&Vec<FileHash>> for DirectoryInfo {
    fn from(value: &Vec<FileHash>) -> Self {
        let hashmap: HashMap<String, String> = value
            .iter()
            .map(|entry| (entry.filepath.display().to_string(), entry.hash_string()))
            .collect();
        let paths: HashSet<String> = hashmap.keys().cloned().collect();
        Self { hashmap, paths }
    }
}

/// Results from comparing two paths.
struct CompareResult {
    // TODO: Add a member for identical files?
    /// Files in the first path, but not the second.
    first_not_second: Vec<String>,
    /// Files in second path, but not first
    second_not_first: Vec<String>,
    /// Files in both, but with differing hashes.
    different_hashes: Vec<String>,
}

impl CompareResult {
    /// Compute comparasion results
    ///
    /// Arguments:
    ///     * `first_info`: The first directory's results
    ///     * `second_info`: The second directory's results
    ///
    /// Returns:
    ///     Created `CompareResult` instance.
    pub fn new(first_info: &DirectoryInfo, second_info: &DirectoryInfo) -> Self {
        let first_not_second = first_info
            .paths
            .difference(&second_info.paths)
            .map(String::from)
            .collect();

        let second_not_first = second_info
            .paths
            .difference(&first_info.paths)
            .map(String::from)
            .collect();

        // Use filter_map to return the string only for entries where
        // it exists in the other path, but has a different hash.
        let different_hashes = first_info
            .hashmap
            .iter()
            .filter_map(&|(filepath, hash)| {
                if second_info.hashmap.contains_key(filepath)
                    && second_info.hashmap.get(filepath) != Some(hash)
                {
                    Some(String::from(filepath))
                } else {
                    None
                }
            })
            .collect();

        Self {
            first_not_second,
            second_not_first,
            different_hashes,
        }
    }

    /// Print the differencess to stdout
    pub fn print_results(&self) {
        Self::print_vec("In first path, but not second", &self.first_not_second);
        Self::print_vec("In second path, but not first:", &self.second_not_first);
        Self::print_vec("In both paths, but hashes differ:", &self.different_hashes);
    }

    /// Print the given info line and vector values if the vector length > 0
    ///
    /// Arguments:
    ///     * `description`: The description text to print at the start
    ///     * `files`: The vector of the files to print out.
    fn print_vec(description: &str, files: &Vec<String>) {
        if !files.is_empty() {
            println!("{description}");
            for file in files {
                println!("\t{file}");
            }
        }
    }
}

fn main() {
    // TODO: Parallelize first and second directories?
    // TODO: Progress bar of some sort?
    let args = Arguments::parse();
    println!("Computing hashes for first path");
    let first_dir_hashes = hash_directory(&args.first_path);
    let first_dir_info = DirectoryInfo::from(&first_dir_hashes);

    if let Some(second_dir) = args.second_path {
        println!("Computing hashes for second path");
        let second_dir_hashes = hash_directory(&second_dir);
        let second_dir_info = DirectoryInfo::from(&second_dir_hashes);

        CompareResult::new(&first_dir_info, &second_dir_info).print_results();
    } else {
        for (path, hash) in first_dir_info.hashmap {
            println!("{path}:\t{hash}");
        }
    }
}
