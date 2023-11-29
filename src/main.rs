use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use threadpool::ThreadPool;
use walkdir::WalkDir;

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

fn pool_iteration() {
    // FIXME: Switch to rayon for parallelism?
    // Pool with 10 workers.
    let pool = ThreadPool::new(10);
    // Queues for sending data
    let (tx, rx) = channel();
    let mut num_items: usize = 0;

    for entry in WalkDir::new("test_files") {
        num_items += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let entry = entry.unwrap();
            let path = PathBuf::from(entry.path());
            // println!("Hello");
            let hash = FileHash::new(path);
            tx.send(hash.as_print_line()).expect("Hello")
        });
    }
    let results: Vec<String> = rx.iter().take(num_items).collect();
    for result in results {
        println!("{result}")
    }
}

fn linear_iteration() {
    let walker = WalkDir::new("test_files");
    let results: Vec<String> = walker
        .into_iter()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = PathBuf::from(entry.path());
            let hash = FileHash::new(path);
            return hash.as_print_line();
        })
        .collect();
    for result in results {
        println!("{result}")
    }
}

fn main() {
    linear_iteration()
}
