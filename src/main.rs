/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//!Tool for computing hashes and comparing files
use clap::Parser;
use disk_compare::cli::Arguments;
use disk_compare::errors::ToolError;
use indicatif::ParallelProgressIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;
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
        // This is more performant than using map and format!
        // See https://rust-lang.github.io/rust-clippy/master/index.html#/format_collect
        self.hash.iter().fold(String::new(), |mut output, digit| {
            write!(output, "{digit:x}").unwrap();
            output
        })
    }
}

/// Compute hashes of all files in the given path.
///
/// Arguments:
///     * `base_path`: The path to comptue the hashes of.
fn hash_path(base_path: PathBuf) -> Vec<FileHash> {
    WalkDir::new(&base_path)
        .into_iter()
        // FIXME: See if we can find a way to not need an intermediate collect
        // Which will speed up parsing
        .collect::<Vec<Result<DirEntry, Error>>>()
        .par_iter()
        .map(|entry: &Result<DirEntry, Error>| {
            let path = PathBuf::from(entry.as_ref().unwrap().path());
            FileHash::new(path, &base_path).unwrap()
        })
        .progress()
        .collect()
}

/// Information about a scanned path.
struct PathInfo {
    /// Hashmap of all files and their hashes.
    pub hashmap: HashMap<String, String>,

    /// Set of all scanned filepaths.
    /// Corresponds to the keys in the hashmap.
    pub paths: HashSet<String>,
}

impl From<Vec<FileHash>> for PathInfo {
    fn from(value: Vec<FileHash>) -> Self {
        let hashmap: HashMap<String, String> = value
            .iter()
            .map(|entry| (entry.filepath.display().to_string(), entry.hash_string()))
            .collect();
        let paths: HashSet<String> = hashmap.keys().cloned().collect();
        Self { hashmap, paths }
    }
}

impl From<PathBuf> for PathInfo {
    fn from(value: PathBuf) -> Self {
        Self::from(hash_path(value))
    }
}

/// Results from comparing two paths.
struct PathComparison {
    // TODO: Add a member for identical files?
    /// Files in the first path, but not the second.
    first_not_second: Vec<String>,
    /// Files in second path, but not first
    second_not_first: Vec<String>,
    /// Files in both, but with differing hashes.
    different_hashes: Vec<String>,
}

impl PathComparison {
    /// Compute comparasion results
    ///
    /// Arguments:
    ///     * `first_info`: The first paths's info
    ///     * `second_info`: The second paths's info
    ///
    /// Returns:
    ///     Created `CompareResult` instance.
    pub fn new(first_info: &PathInfo, second_info: &PathInfo) -> Self {
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
    // TODO: Parallelize first and second paths?
    // TODO: Progress bar of some sort?
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
