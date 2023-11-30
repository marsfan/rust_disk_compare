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
    ///
    /// Returns:
    ///     The created `FileHash` instance.
    pub fn new(filepath: PathBuf) -> Result<Self, ToolError> {
        // Only compute hash if the path points to a file
        let hash = match filepath.is_file() {
            true => Self::hash_file(&filepath)?,
            false => Vec::new(),
        };

        Ok(Self { filepath, hash })
    }

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
            hash_string = format!("{hash_string}{:x}", digit);
        }
        hash_string
    }

    /// Get the filepath relative to a base directory
    ///
    /// Arguments:
    ///     * `base_dir`: The base directory
    ///
    /// Returns:
    ///     The path relative to the give pase directory
    pub fn relative_path(&self, base_dir: &PathBuf) -> PathBuf {
        return PathBuf::from(self.filepath.strip_prefix(base_dir).unwrap());
    }

    /// Get the printout line for the given hash
    ///
    /// Returns
    ///     `String` that has the path to the file, and the file's hash
    pub fn as_print_line(&self) -> String {
        format!("{}:\t{}", self.filepath.display(), self.hash_string())
    }
}

/// Compute hashes of all files in the given directory.
///
/// Arguments:
///     * `directory`: The directory to comptue the hashes of.
fn hash_directory(directory: PathBuf) -> Vec<FileHash> {
    WalkDir::new(directory)
        .into_iter()
        .par_bridge()
        .map(|entry: Result<DirEntry, Error>| {
            let path = PathBuf::from(entry.unwrap().path());
            FileHash::new(path).unwrap()
        })
        .collect()
}

fn main() {
    let args = Arguments::parse();
    let first_dir_hashes = hash_directory(args.first_path.clone());
    let mut first_dir_hashmap = HashMap::new();

    for hash in &first_dir_hashes {
        // println!("{}", hash.relative_path(&args.first_path).display());
        first_dir_hashmap.insert(
            hash.relative_path(&args.first_path).display().to_string(),
            hash.hash_string(),
        );
    }
    let first_dir_hashset: HashSet<String> = first_dir_hashmap.keys().cloned().collect();

    if let Some(second_dir) = args.second_path {
        let second_dir_hashes = hash_directory(second_dir.clone());
        let mut second_dir_hashmap = HashMap::new();
        for hash in second_dir_hashes {
            second_dir_hashmap.insert(
                hash.relative_path(&second_dir).display().to_string(),
                hash.hash_string(),
            );
        }
        let second_dir_hashset: HashSet<String> = second_dir_hashmap.keys().cloned().collect();
        println!("In first dir but not second:");
        for file in first_dir_hashset.difference(&second_dir_hashset) {
            println!("\t{file}");
        }
        println!("In second dir but not first:");
        for file in second_dir_hashset.difference(&first_dir_hashset) {
            println!("\t{file}");
        }

        println!("In both dirs, but hashes differ:");
        for (filepath, hash) in first_dir_hashmap.iter() {
            if second_dir_hashmap.contains_key(filepath)
                && second_dir_hashmap.get(filepath) != Some(hash)
            {
                println!("\t{filepath}");
            }
        }
    } else {
        for hash in first_dir_hashes {
            println!("{}", hash.as_print_line());
        }
    }

    // println!("{:?}", first_dir_hashmap);
}
