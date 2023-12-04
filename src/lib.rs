/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//! Core program functionality

pub mod cli;
pub mod errors;

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs::File;
use std::io;
use std::path::PathBuf;

use crate::errors::ToolError;

use indicatif::ParallelProgressIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, Error, WalkDir};

/// A single file and its hash
#[derive(PartialEq, Debug)]
struct FileHash {
    /// The path to the file that was hashed
    filepath: PathBuf,
    /// The file's hash
    hash: Vec<u8>,
}

impl FileHash {
    /// Create the new hash from the given path.
    ///
    /// # Arguments
    /// * `filepath`: The path to the file to hash.
    /// * `base_path`: The base path the files should be relative to.
    ///
    /// # Returns:
    /// The created `FileHash` instance.
    pub fn new(filepath: &PathBuf, base_path: &PathBuf) -> Result<Self, ToolError> {
        // Only compute hash if the path points to a file
        let hash = if filepath.is_file() {
            Self::hash_file(filepath)?
        } else {
            Vec::new()
        };

        let filepath = if filepath.eq(base_path) && filepath.is_file() {
            PathBuf::from(filepath)
        } else if filepath.eq(base_path) {
            PathBuf::new()
        } else {
            // If the provided path is not the base path, strip the base path
            filepath.strip_prefix(base_path)?.to_path_buf()
        };

        Ok(Self { filepath, hash })
    }

    /// Compute the hash of the given file
    ///
    /// # Arguments
    /// * `filepath`: Path to the file to hash.
    fn hash_file(filepath: &PathBuf) -> Result<Vec<u8>, ToolError> {
        if !filepath.is_file() {
            return Err(ToolError::NotAFileError {
                filepath: filepath.display().to_string(),
            });
        }
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
    /// # Returns:
    /// File hash as a string
    fn hash_string(&self) -> String {
        // This is more performant than using map and format!
        // See https://rust-lang.github.io/rust-clippy/master/index.html#/format_collect
        self.hash.iter().fold(String::new(), |mut output, digit| {
            write!(output, "{digit:02x}").unwrap();
            output
        })
    }
}

/// Information about a scanned path.
pub struct PathInfo {
    /// Hashmap of all files and their hashes.
    hashmap: HashMap<String, String>,

    /// Set of all scanned filepaths.
    /// Corresponds to the keys in the hashmap.
    paths: HashSet<String>,
}

impl PathInfo {
    /// Compute paths in this structure, but not a different one.
    ///
    /// # Arguments:
    /// * `other_info`: The other pathinfo object to compare against.
    ///
    /// # Returns:
    /// Vector of paths in this struct, but no the other one.
    fn path_difference(&self, other_info: &PathInfo) -> Vec<String> {
        self.paths
            .difference(&other_info.paths)
            .map(String::from)
            .collect()
    }

    /// Print all of the files and their hashes to stdout.
    pub fn print_hashes(&self) {
        for (path, hash) in &self.hashmap {
            println!("{path}:\t{hash}");
        }
    }

    /// Compute hashes of all files in the given path.
    ///
    /// # Arguments:
    /// * `base_path`: The path to comptue the hashes of.
    fn hash_path(base_path: &PathBuf) -> Vec<FileHash> {
        WalkDir::new(base_path)
            .into_iter()
            // FIXME: See if we can find a way to not need an intermediate collect
            // Which will speed up parsing
            .collect::<Vec<Result<DirEntry, Error>>>()
            .par_iter()
            .map(|entry: &Result<DirEntry, Error>| {
                let path = PathBuf::from(entry.as_ref().unwrap().path());
                FileHash::new(&path, base_path).unwrap()
            })
            .progress()
            .collect()
    }
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
        Self::from(Self::hash_path(&value))
    }
}

/// Results from comparing two paths.
pub struct PathComparison {
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
    /// # Arguments:
    /// * `first_info`: The first paths's info
    /// * `second_info`: The second paths's info
    ///
    /// # Returns:
    /// Created `CompareResult` instance.
    #[must_use]
    pub fn new(first_info: &PathInfo, second_info: &PathInfo) -> Self {
        let first_not_second = first_info.path_difference(second_info);
        let second_not_first = second_info.path_difference(first_info);

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
    /// # Arguments:
    /// * `description`: The description text to print at the start
    /// * `files`: The vector of the files to print out.
    fn print_vec(description: &str, files: &Vec<String>) {
        if !files.is_empty() {
            println!("{description}");
            for file in files {
                println!("\t{file}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Info used in tests
    pub struct TestData {
        /// Hash for file1.txt
        file1_hash: Vec<u8>,

        /// String of file1.txt hash
        file1_hash_str: String,

        /// Hash for file2.txt
        file2_hash: Vec<u8>,

        /// String of file2.txt hash
        file2_hash_string: String,

        /// Hash for file4.txt
        file4_hash: Vec<u8>,

        /// String of file4.txt hash
        file4_hash_str: String,

        /// Path to dir1
        dir1_path: PathBuf,

        /// Path to file1
        file1_path: PathBuf,

        /// Path to test_files
        test_files_dir: PathBuf,
    }

    impl TestData {
        pub fn new() -> Self {
            Self {
                file1_hash: vec![
                    0xe4, 0xc5, 0x29, 0xa9, 0x0c, 0x31, 0xa1, 0x00, 0x16, 0xd7, 0x33, 0x4d, 0x27,
                    0x18, 0xc1, 0x0c, 0x0b, 0xd3, 0x01, 0x17, 0x0f, 0xea, 0x0f, 0x55, 0x45, 0x70,
                    0xb2, 0xf2, 0x98, 0xec, 0xe9, 0x7f,
                ],
                file1_hash_str: String::from(
                    "e4c529a90c31a10016d7334d2718c10c0bd301170fea0f554570b2f298ece97f",
                ),
                file2_hash: vec![
                    0xa1, 0x02, 0x8f, 0x79, 0x3b, 0x0a, 0xae, 0x9c, 0x51, 0xfa, 0x83, 0xe3, 0x99,
                    0x75, 0xb2, 0x54, 0xd7, 0x89, 0x47, 0x62, 0x08, 0x68, 0xf0, 0x9e, 0x4a, 0x64,
                    0x8e, 0x73, 0x48, 0x6a, 0x62, 0x3c,
                ],
                file2_hash_string: String::from(
                    "a1028f793b0aae9c51fa83e39975b254d78947620868f09e4a648e73486a623c",
                ),
                file4_hash: vec![
                    0xe9, 0x97, 0x19, 0x69, 0xe0, 0xab, 0x8b, 0x9c, 0x44, 0xe0, 0x0e, 0x0e, 0x80,
                    0xc4, 0xad, 0xe9, 0xbe, 0xa5, 0x69, 0x20, 0x5e, 0x42, 0xc8, 0xde, 0xdc, 0xf7,
                    0x67, 0xf2, 0xef, 0x26, 0x85, 0xb0,
                ],
                file4_hash_str: String::from(
                    "e9971969e0ab8b9c44e00e0e80c4ade9bea569205e42c8dedcf767f2ef2685b0",
                ),
                dir1_path: PathBuf::from("test_files/dir1"),
                file1_path: PathBuf::from("test_files/dir1/file1.txt"),
                test_files_dir: PathBuf::from("test_files"),
            }
        }
    }

    mod test_file_hash {
        use crate::{tests::TestData, FileHash};
        use std::path::PathBuf;

        /// Test the `hash_file` method
        #[test]
        fn test_hash_file() {
            let test_data = TestData::new();
            let hash = FileHash::hash_file(&test_data.file1_path).unwrap();
            assert_eq!(hash, test_data.file1_hash);
        }

        /// Test the `hash_file` method on a directory
        #[test]
        #[should_panic(
            expected = "called `Result::unwrap()` on an `Err` value: NotAFileError { filepath: \"test_files/dir1\" }"
        )]
        fn test_hashfile_on_dir() {
            let test_data = TestData::new();
            FileHash::hash_file(&test_data.dir1_path).unwrap();
        }

        /// Test creation and proper hashing.
        #[test]
        fn test_creation() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path, &test_data.dir1_path).unwrap();

            assert_eq!(
                result,
                FileHash {
                    filepath: PathBuf::from("file1.txt"),
                    hash: test_data.file1_hash,
                }
            );
        }

        /// Test creation on an empty dir inside the base dir
        #[test]
        fn test_creation_empty_dir() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.dir1_path, &test_data.test_files_dir).unwrap();
            assert_eq!(
                result,
                FileHash {
                    filepath: PathBuf::from("dir1"),
                    hash: Vec::new(),
                },
            );
        }

        /// Test creation on the base dir
        #[test]
        fn test_creation_base_dir() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.dir1_path, &test_data.dir1_path).unwrap();
            assert_eq!(
                result,
                FileHash {
                    filepath: PathBuf::from(""),
                    hash: Vec::new(),
                }
            );
        }

        /// Test the `hash_string` method
        #[test]
        fn test_hash_str() {
            let test_data = TestData::new();
            let hash_object = FileHash::new(&test_data.file1_path, &test_data.dir1_path).unwrap();
            let hash_string = hash_object.hash_string();
            assert_eq!(hash_string, test_data.file1_hash_str);
        }
    }

    mod test_path_info {
        use std::path::PathBuf;

        use crate::{FileHash, PathInfo};

        use super::TestData;

        /// Test the `hash_path` method
        #[test]
        fn test_hash_path() {
            let test_data = TestData::new();
            let results = PathInfo::hash_path(&test_data.dir1_path);
            let expected = vec![
                FileHash {
                    filepath: PathBuf::from(""),
                    hash: Vec::new(),
                },
                FileHash {
                    filepath: PathBuf::from("file1.txt"),
                    hash: test_data.file1_hash,
                },
                FileHash {
                    filepath: PathBuf::from("file2.txt"),
                    hash: test_data.file2_hash,
                },
                FileHash {
                    filepath: PathBuf::from("file4.txt"),
                    hash: test_data.file4_hash,
                },
            ];
            assert_eq!(results, expected);
        }
        /// Test the `hash_path` method when the path is a file
        #[test]
        fn test_hash_path_file() {
            let test_data = TestData::new();
            let results = PathInfo::hash_path(&test_data.file1_path);
            let expected = vec![FileHash {
                filepath: PathBuf::from("test_files/dir1/file1.txt"),
                hash: test_data.file1_hash,
            }];
            assert_eq!(results, expected);
        }

        // /// Test creating from a vec of hashes.
        // #[test]
        // fn test_from_vec{}
    }
}
