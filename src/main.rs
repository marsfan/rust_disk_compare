use clap::Parser;
use disk_compare::cli::Arguments;
use disk_compare::errors::ToolError;
use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelIterator;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use walkdir::{DirEntry, Error, WalkDir};

// TODO: Argument for selecting the hash (SHa256, MD5, etc.)
// TODO: Actually compare directories
// TODO: Put on github

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

    /// Get the printout line for the given hash
    ///
    /// Returns
    ///     `String` that has the path to the file, and the file's hash
    pub fn as_print_line(&self) -> String {
        let mut hash_string = String::new();
        for digit in &self.hash {
            hash_string = format!("{hash_string}{:x}", digit);
        }
        format!("{}:\t{hash_string}", self.filepath.display())
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
    let hashes = hash_directory(args.base_path.clone());
    for hash in hashes {
        println!("{}", hash.relative_path(&args.base_path).display());
    }
}
