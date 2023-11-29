use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelIterator;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use walkdir::{DirEntry, Error, WalkDir};

// TODO: Proper error handling
// TODO: Argument for specifying the path to use
// TODO: Argument for selecting the hash (SHa256, MD5, etc.)

struct FileHash {
    /// The path to the file that was hashed
    filepath: PathBuf,
    /// The file's hash
    hash: Vec<u8>,
    /// Whether or not the given path is a file. Only files are hashed
    is_file: bool,
}

impl FileHash {
    /// Create the new hash from the given path.
    ///
    /// Arguments
    ///     * `filepath`: The path to the file to hash.
    ///
    /// Returns:
    ///     The created `FileHash`
    pub fn new(filepath: PathBuf) -> Self {
        if filepath.is_file() {
            let mut hasher = Sha256::new();
            let mut file = File::open(&filepath).unwrap();
            // This whole io::copy thing came from here
            // https://www.reddit.com/r/rust/comments/tuxpxf/comment/i368ryk/
            // Uses way less memory than reading the file directly
            // Guessing its sending copying the file in chunks?
            io::copy(&mut file, &mut hasher).unwrap();
            let hash = hasher.finalize().to_vec();
            Self {
                filepath,
                hash,
                is_file: true,
            }
        } else {
            Self {
                filepath,
                hash: Vec::new(),
                is_file: false,
            }
        }
    }

    /// Get the printout line for the given hash
    ///
    /// Returns
    ///     `String` that has the path to the file, and the file's hash
    pub fn as_print_line(&self) -> String {
        if self.is_file {
            let mut hash_string = String::new();
            for digit in &self.hash {
                hash_string = format!("{hash_string}{:x}", digit);
            }
            format!("{}:{}\t", self.filepath.display(), hash_string)
        } else {
            format! {"{}: directory", self.filepath.display()}
        }
    }
}

fn main() {
    WalkDir::new("test_files")
        .into_iter()
        .par_bridge()
        .map(|entry: Result<DirEntry, Error>| {
            let path = PathBuf::from(entry.unwrap().path());
            FileHash::new(path).as_print_line()
        })
        .for_each(|result| println!("{result}"));
}
