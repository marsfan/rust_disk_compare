/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//! Core program functionality

pub mod cli;
pub mod errors;

use core::fmt::Write as _;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::{collections::HashSet, path::Path};

use crate::errors::ToolError;

use indicatif::ParallelProgressIterator as _;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::prelude::ParallelIterator as _;
use sha2::{Digest as _, Sha256};
use walkdir::{DirEntry, WalkDir};

/// A single file and its hash
#[derive(PartialEq, Debug, Eq, PartialOrd, Ord)]
pub struct FileHash {
    /// The path to the file that was hashed
    filepath: PathBuf,
    /// The file's hash
    hash: String,
}

impl FileHash {
    /// Create the new hash from the given path.
    ///
    /// # Arguments
    ///   * `filepath`: The path to the file to hash.
    ///   * `base_path`: The base path the files should be relative to.
    ///
    /// # Returns:
    ///   The created `FileHash` instance.
    ///
    /// # Errors
    ///   Will error out if an error occurred when computing the hash for the file.
    ///   or converting the path to be relative to the base path.
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

        Ok(Self {
            filepath,
            hash: Self::hash_to_string(&hash),
        })
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

    /// Get the relative path to the file as a string
    ///
    /// # Returns
    ///   The relative file path as a string
    pub fn get_rel_path(&self) -> String {
        self.filepath.display().to_string()
    }

    /// Get the file hash represented as a string
    ///
    /// # Returns
    ///   The file's hash as a string of hexadecimal values
    pub fn get_hash_string(&self) -> String {
        self.hash.clone()
    }

    /// Convert the given vector hash to a string
    ///
    /// Arguments:
    ///   - `hash`: The hash to convert.
    ///
    /// Returns:
    ///   The hash as a string.
    fn hash_to_string(hash: &[u8]) -> String {
        // This is more performant than using map and format!
        // See https://rust-lang.github.io/rust-clippy/master/index.html#/format_collect
        hash.iter().fold(String::new(), |mut output, digit| {
            write!(output, "{digit:02x}").unwrap();
            output
        })
    }
}

/// Recursively find all files in a directory
///
/// # Arguments
///   * `base`: The directory to search
///
/// # Returns
///   Iterator that yields all files in the given directory
fn gather_paths(base: &PathBuf) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(base).into_iter().filter_map(|v| {
        let entry = v.unwrap();
        let path = entry.to_rel_path(base).unwrap();
        if entry.file_type().is_dir() {
            None
        } else {
            Some(path)
        }
    })
}

/// Compute hashes for all files in a directory, recursively
///
/// # Arguments
///   * `base`: The directory to search through
///
/// # Returns
///   Vector of `FileHash` objects for all files found recursively in the directory
pub fn compute_hashes_for_dir(base: &PathBuf) -> Vec<FileHash> {
    // FIXME: Bubble error up further so we can print out all files that
    // failed hashing at the end (outside of parallel loop)
    // Will require modifying the hash_path function to return a
    // vec of result instead of what it currently does.
    let mut hashes: Vec<FileHash> = gather_paths(base)
        .collect::<Vec<PathBuf>>()
        .par_iter()
        .map(|file| FileHash::new(&base.join(file), base).unwrap())
        .progress()
        .collect();

    hashes.sort_by(|a, b| a.get_rel_path().cmp(&b.get_rel_path()));
    hashes
}

/// A pair of files that both have the the same relative path to their bases
struct FilePair {
    /// Relative path to both files
    relative_path: PathBuf,

    // TODO: Store hashes as bytes and only compute string on request?
    /// Hash of the first file
    first_hash: String,

    /// Hash of the second file
    second_hash: String,
}

impl FilePair {
    // FIXME: Bubble error up further so we can print out all files that
    // failed hashing at the end (outside of parallel loop)
    // Will require modifying the hash_path function to return a
    // vec of result instead of what it currently does.
    /// Function that is called on each path to hash
    ///
    pub fn new(relative_path: &PathBuf, first_base: &PathBuf, second_base: &PathBuf) -> Self {
        let first_hash = FileHash::new(&first_base.join(relative_path), first_base)
            .unwrap()
            .get_hash_string();
        let second_hash = FileHash::new(&second_base.join(relative_path), second_base)
            .unwrap()
            .get_hash_string();
        Self {
            relative_path: relative_path.clone(),
            first_hash,
            second_hash,
        }
    }

    /// Check if the two file hashes are identical
    ///
    /// # Returns
    ///   Boolean indicating if the files have matching hashes
    pub fn same_hash(&self) -> bool {
        self.first_hash == self.second_hash
    }

    /// Get the relative path to the file as a string
    ///
    /// Since both files are relative to a base, this is the relative
    /// path for both files from their bases.
    ///
    /// # Returns
    ///   A string holding the relative path to the files
    pub fn relative_path_string(&self) -> String {
        self.relative_path.display().to_string()
    }
}

/// Trait to add a method to the `DirEntry` struct for making the path
/// be relative to a base path.
trait ToRelativePath {
    /// Get a path that is relative to the given base path.
    ///
    /// # Arguments
    ///   * `base_path`: The base path to make the path relative to
    ///
    /// # Returns
    ///   * Path to this file, relative to the given base path
    ///
    /// # Errors
    ///   Will return an error of it is not possible to make the path
    ///   relative to the given base path.
    fn to_rel_path(&self, base_path: &Path) -> Result<PathBuf, ToolError>;
}

// FIXME: Needs tests
impl ToRelativePath for DirEntry {
    fn to_rel_path(&self, base_path: &Path) -> Result<PathBuf, ToolError> {
        Ok(self
            .clone()
            .into_path()
            .strip_prefix(base_path)?
            .to_path_buf())
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
    // Files in both, with matching hashes
    // same_hashes: Vec<String>,
}

impl PathComparison {
    /// Compute comparasion results
    ///
    /// # Arguments
    ///   - `first_path`: The first of the two paths to scan
    ///   - `second_path`: The second of the two paths to scan
    ///
    /// # Returns
    ///   Created `PathComparison` instance.
    pub fn new(first_path: &PathBuf, second_path: &PathBuf) -> Self {
        // Find all files (not folders) under the first path
        let first_files: HashSet<PathBuf> = gather_paths(first_path).collect();

        // Find all files under thew second path.
        let second_files: HashSet<PathBuf> = gather_paths(second_path).collect();

        // Get sets of the files in one or the other path,
        let first_not_second = first_files
            .difference(&second_files)
            .map(|v| v.display().to_string());
        let second_not_first = second_files
            .difference(&first_files)
            .map(|v| v.display().to_string());

        // For files in both paths, create a FilePair object.
        // This will compute hashes for the files.
        let in_both: Vec<FilePair> = first_files
            .intersection(&second_files)
            .map(|v| FilePair::new(v, first_path, second_path))
            .collect();

        // Filter out just the files that have mismatched hashes
        let different_hashes = in_both.par_iter().filter_map(|v| {
            if v.same_hash() {
                None
            } else {
                Some(v.relative_path_string())
            }
        });

        let mut first_not_second: Vec<String> = first_not_second.collect();
        let mut second_not_first: Vec<String> = second_not_first.collect();
        let mut different_hashes: Vec<String> = different_hashes.collect();

        first_not_second.sort();
        second_not_first.sort();
        different_hashes.sort();

        Self {
            first_not_second,
            second_not_first,
            different_hashes,
        }
    }

    /// Print the differencess to stdout
    pub fn print_results(&self) {
        // Print an extra newline
        println!();
        if self.any_differences() {
            Self::print_vec("In first path, but not second", &self.first_not_second);
            Self::print_vec("In second path, but not first:", &self.second_not_first);
            Self::print_vec("In both paths, but hashes differ:", &self.different_hashes);
        } else {
            println!("No differences found between supplied paths.");
        }
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

    /// Get if there are any differences found between supplied paths
    ///
    /// # Returns
    /// Boolean indicating if any differences were found between the supplied paths.
    fn any_differences(&self) -> bool {
        (!self.first_not_second.is_empty())
            || (!self.second_not_first.is_empty())
            || (!self.different_hashes.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{FileHash, compute_hashes_for_dir, gather_paths};

    /// Info used in tests
    pub struct TestData {
        /// Hash for file1.txt
        file1_hash: Vec<u8>,

        /// String of file1.txt hash
        file1_hash_str: String,

        /// String of file2.txt hash
        file2_hash_str: String,

        /// String of file4.txt hash
        file4_hash_str: String,

        /// String of file5.txt hash
        file5_hash_str: String,

        /// Path to dir1
        dir1_path: PathBuf,

        /// Path to dir2
        dir2_path: PathBuf,

        /// Path to file1
        file1_path: PathBuf,

        /// Path to test files
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

                file2_hash_str: String::from(
                    "a1028f793b0aae9c51fa83e39975b254d78947620868f09e4a648e73486a623c",
                ),

                file4_hash_str: String::from(
                    "e9971969e0ab8b9c44e00e0e80c4ade9bea569205e42c8dedcf767f2ef2685b0",
                ),
                file5_hash_str: String::from(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
                dir1_path: PathBuf::from("test_files/dir1"),
                dir2_path: PathBuf::from("test_files/dir2"),
                file1_path: PathBuf::from("test_files/dir1/file1.txt"),
                test_files_dir: PathBuf::from("test_files"),
            }
        }
    }

    mod test_file_hash {
        use crate::{FileHash, tests::TestData};
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
                    hash: test_data.file1_hash_str,
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
                    hash: String::new(),
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
                    hash: String::new(),
                }
            );
        }

        /// Test creation on file where `filepath` == `base_path`
        #[test]
        fn test_create_file_is_base() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path, &test_data.file1_path).unwrap();

            assert_eq!(
                result,
                FileHash {
                    filepath: test_data.file1_path,
                    hash: test_data.file1_hash_str,
                }
            );
        }

        /// Test creation and proper hashing.
        #[test]
        fn test_get_rel_path() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path, &test_data.dir1_path)
                .unwrap()
                .get_rel_path();

            assert_eq!(result, String::from("file1.txt"));
        }

        /// Test creation and proper hashing.
        #[test]
        fn test_get_hash_string() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path, &test_data.dir1_path)
                .unwrap()
                .get_hash_string();

            assert_eq!(result, test_data.file1_hash_str);
        }

        /// Test the `hash_string` method
        #[test]
        fn test_hash_str() {
            let test_data = TestData::new();
            let hash_object = FileHash::new(&test_data.file1_path, &test_data.dir1_path).unwrap();
            let hash_string = hash_object.hash;
            assert_eq!(hash_string, test_data.file1_hash_str);
        }
    }

    /// Basic test of computing hashes for a folder
    #[test]
    fn test_compute_hashes_for_dir() {
        let test_data = TestData::new();
        let results = compute_hashes_for_dir(&test_data.dir1_path);
        let expected = vec![
            FileHash {
                filepath: PathBuf::from("file1.txt"),
                hash: test_data.file1_hash_str,
            },
            FileHash {
                filepath: PathBuf::from("file2.txt"),
                hash: test_data.file2_hash_str,
            },
            FileHash {
                filepath: PathBuf::from("file4.txt"),
                hash: test_data.file4_hash_str,
            },
            FileHash {
                filepath: PathBuf::from("subdir\\file5.txt"),
                hash: test_data.file5_hash_str,
            },
        ];
        assert_eq!(results, expected)
    }

    /// Test the `gather_paths` function
    #[test]
    fn test_gather_paths() {
        let test_data = TestData::new();
        let mut results: Vec<PathBuf> = gather_paths(&test_data.dir1_path).collect();
        results.sort();
        let expected = vec![
            PathBuf::from("file1.txt"),
            PathBuf::from("file2.txt"),
            PathBuf::from("file4.txt"),
            PathBuf::from("subdir\\file5.txt"),
        ];
        assert_eq!(results, expected);
    }

    mod test_path_difference {
        use crate::PathComparison;

        use super::TestData;

        /// Test creation of the struct
        #[test]
        fn test_creation() {
            let test_data = TestData::new();
            let comparsion = PathComparison::new(&test_data.dir1_path, &test_data.dir2_path);
            assert_eq!(
                comparsion.first_not_second,
                vec![String::from("file1.txt"), String::from("subdir\\file5.txt")]
            );
            assert_eq!(comparsion.second_not_first, vec![String::from("file3.txt")]);
            assert_eq!(comparsion.different_hashes, vec![String::from("file2.txt")]);
        }
    }

    mod test_file_pair {
        // FIXME: Need tests for methods on file_pair
    }
}
