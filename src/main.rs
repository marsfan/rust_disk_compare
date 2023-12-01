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
// TODO: Put on github
// TODO: Add MPL license header to all files.

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

fn main() {
    // TODO: Break stuff up into functions
    // TODO: Parallelize first and second directories?
    let args = Arguments::parse();
    let first_dir_hashes = hash_directory(&args.first_path);
    let first_dir_info = DirectoryInfo::from(&first_dir_hashes);

    if let Some(second_dir) = args.second_path {
        let second_dir_hashes = hash_directory(&second_dir);
        let second_dir_info = DirectoryInfo::from(&second_dir_hashes);

        println!("In first dir but not second:");
        for file in first_dir_info.paths.difference(&second_dir_info.paths) {
            println!("\t{file}");
        }
        println!("In second dir but not first:");
        for file in second_dir_info.paths.difference(&first_dir_info.paths) {
            println!("\t{file}");
        }

        println!("In both dirs, but hashes differ:");
        for (filepath, hash) in &first_dir_info.hashmap {
            if second_dir_info.hashmap.contains_key(filepath)
                && second_dir_info.hashmap.get(filepath) != Some(hash)
            {
                println!("\t{filepath}");
            }
        }
    } else {
        for (path, hash) in first_dir_info.hashmap {
            println!("{path}:\t{hash}");
        }
    }
}
