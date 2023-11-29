use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::mpsc::channel;
use threadpool::ThreadPool;
use walkdir::WalkDir;

/// Compute the hash for the given file.
/// Arguments:
///     * `filepath`: The path to the file to compute the hash of
///
/// Returns
///     The file's SHA-1 hash
fn get_hash(filepath: &Path) -> Vec<u8> {
    if filepath.is_file() {
        let mut hasher = Sha256::new();
        let mut file = File::open(filepath).unwrap();

        // This whole io::copy thing came from here
        // https://www.reddit.com/r/rust/comments/tuxpxf/comment/i368ryk/
        // Uses way less memory than reading the file directly
        io::copy(&mut file, &mut hasher).unwrap();
        let result = hasher.finalize();
        return result.to_vec();
    }
    return vec![];
}

/// Get the string representation of the hash
/// Arguments:
///     * `path`: The path of the file that was hashed.
///     * `hash`: The hash itself
///
/// Returns:
///     The hash as a string
fn get_hash_str(path: &Path, hash: Vec<u8>) -> String {
    let mut hash_string = String::new();
    for digit in hash {
        hash_string = format!("{hash_string}{:x}", digit);
    }
    return format!("{}:{}\t", path.display(), hash_string);
}

fn main() {
    // Pool with 10 workers.
    let pool = ThreadPool::new(10);
    // Queues for sending data
    let (tx, rx) = channel();
    let mut num_items: usize = 0;
    for entry in WalkDir::new("test_files") {
        num_items += 1;
        let tx = tx.clone();
        pool.execute(move || {
            let path = entry.unwrap();
            let path = path.path();
            // println!("Hello");
            let hash = get_hash(&path);
            let hash_str = get_hash_str(&path, hash);
            tx.send(hash_str).expect("Hello")
        });
    }
    let results: Vec<String> = rx.iter().take(num_items).collect();
    for result in results {
        println!("{result}")
    }
    // println!("{:?}", results);

    println!("Hello, world!");
}
