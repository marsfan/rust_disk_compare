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
    hash: Vec<u8>,
}

impl FileHash {
    /// Create the new hash from the given path.
    ///
    /// # Arguments
    ///   * `filepath`: The path to the file to hash.
    ///
    /// # Returns:
    ///   The created `FileHash` instance.
    ///
    /// # Errors
    ///   Will error out if an error occurred when computing the hash for the file
    pub fn new(filepath: &PathBuf) -> Result<Self, ToolError> {
        // Only compute hash if the path points to a file
        let hash = if filepath.is_file() {
            Self::hash_file(filepath)?
        } else {
            Vec::new()
        };

        Ok(Self {
            filepath: filepath.clone(),
            hash, // hash: Self::hash_to_string(&hash),
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
    /// # Arguments
    ///   base: Base directory to get path relative to.
    ///
    /// # Returns
    ///   The relative file path as a string
    ///
    /// # Errors
    ///   Will return an error if not able to convert the path to a relative path
    pub fn get_rel_filepath(&self, base: &PathBuf) -> Result<String, ToolError> {
        Ok(self.filepath.strip_prefix(base)?.display().to_string())
    }

    /// # Get the path to the file as a strring
    ///
    /// # Returns
    ///   The path to the file as a string
    pub fn get_filepath(&self) -> String {
        self.filepath.display().to_string()
    }

    /// Get the file hash represented as a string
    ///
    /// # Returns
    ///   The file's hash as a string of hexadecimal values
    pub fn get_hash_string(&self) -> String {
        Self::hash_to_string(&self.hash)
        // self.hash.clone()
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
            #[expect(
                clippy::unwrap_used,
                reason = "As per above link, write!() to a String will never error"
            )]
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
        #[expect(clippy::unwrap_used, reason="WalkDir gives files underneath the base. We are converting all paths to be relative to that base, so this should never panic")]
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
///
/// # Panics
///   Will panic if computing the file hash fails.
pub fn compute_hashes_for_dir(base: &PathBuf) -> Vec<FileHash> {
    // FIXME: Bubble error up further so we can print out all files that
    // failed hashing at the end (outside of parallel loop)
    // Will require modifying the hash_path function to return a
    // vec of result instead of what it currently does.
    let mut hashes: Vec<FileHash> = gather_paths(base)
        .collect::<Vec<PathBuf>>()
        .par_iter()
        .map(|file| FileHash::new(&base.join(file)).unwrap())
        .progress()
        .collect();

    hashes.sort_by_key(FileHash::get_filepath);
    hashes
}

/// A pair of files that both have the the same relative path to their bases
#[derive(Debug, PartialEq, Eq)]
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
    /// Function that is called on each path to hash
    pub fn new(
        relative_path: &PathBuf,
        first_base: &Path,
        second_base: &Path,
    ) -> Result<Self, ToolError> {
        let first_hash = FileHash::new(&first_base.join(relative_path))?.get_hash_string();
        let second_hash = FileHash::new(&second_base.join(relative_path))?.get_hash_string();
        Ok(Self {
            relative_path: relative_path.clone(),
            first_hash,
            second_hash,
        })
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
    pub fn get_relative_path_string(&self) -> String {
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
    ///
    /// # Panics
    ///   Will panic if hashing a file fails.
    pub fn new(first_path: &PathBuf, second_path: &PathBuf) -> Self {
        // Find all files (not folders) under the first path
        let first_files: HashSet<PathBuf> = gather_paths(first_path).collect();

        // Find all files under thew second path.
        let second_files: HashSet<PathBuf> = gather_paths(second_path).collect();

        // Get sets of the files in one or the other path,
        let mut first_not_second: Vec<String> = first_files
            .difference(&second_files)
            .map(|v| v.display().to_string())
            .collect();
        let mut second_not_first: Vec<String> = second_files
            .difference(&first_files)
            .map(|v| v.display().to_string())
            .collect();

        // For files in both paths, create a FilePair object.
        // This will compute hashes for the files.
        let mut different_hashes: Vec<String> = first_files
            .intersection(&second_files)
            // Need to collect to a vec here first so that we know how many elements we are hashing
            // or progress bar won't work
            .collect::<Vec<&PathBuf>>()
            .par_iter()
            // FIXME: Bubble error up further so we can print out all files that
            // failed hashing at the end (outside of parallel loop)
            // Will require modifying the hash_path function to return a
            // vec of result instead of what it currently does.
            .map(|v| {
                let pair = FilePair::new(v, first_path, second_path).unwrap();
                if pair.same_hash() {
                    None
                } else {
                    Some(pair.get_relative_path_string())
                }
            })
            .progress()
            // Have to split up filtering mismatches, and computing hashes, or the progress bar won't worrk
            .flatten() // Calling flatten here is the same as calling `.filter_map(|v| v)`
            .collect();

        // Sort the outputs so that multiple runs produce predictable outputs
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
    ///   Boolean indicating if any differences were found between the supplied paths.
    fn any_differences(&self) -> bool {
        (!self.first_not_second.is_empty())
            || (!self.second_not_first.is_empty())
            || (!self.different_hashes.is_empty())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Unwraps in unit tests are ok, as they will display as failed tests"
)]
mod tests {
    use std::path::MAIN_SEPARATOR;

    use super::*;

    /// Info used in tests
    pub struct TestData {
        /// String of hash for file1.txt
        file1_hash_str: String,

        /// String of hash for file1.txt in dir1
        file2_hash_str_dir1: String,

        /// String of hash for file1.txt in dir2
        file2_hash_str_dir2: String,

        /// File1.txt hash
        file1_hash: Vec<u8>,

        /// File2.txt hash in dir 1
        file2_hash_dir1: Vec<u8>,

        /// File4.txt hash
        file4_hash: Vec<u8>,

        /// File5.txt hash
        file5_hash: Vec<u8>,

        /// Path to dir1
        dir1_path: PathBuf,

        /// Path to dir2
        dir2_path: PathBuf,

        /// Path to dir3
        dir3_path: PathBuf,

        /// Path to file1
        file1_path: PathBuf,

        /// Path to file2
        file2_dir1_path: PathBuf,

        /// Path to file4
        file4_dir1_path: PathBuf,

        /// Path to file5
        file5_path: PathBuf,
    }

    impl TestData {
        pub fn new() -> Self {
            Self {
                file1_hash_str: String::from(
                    "e4c529a90c31a10016d7334d2718c10c0bd301170fea0f554570b2f298ece97f",
                ),
                file2_hash_str_dir1: String::from(
                    "a1028f793b0aae9c51fa83e39975b254d78947620868f09e4a648e73486a623c",
                ),
                file2_hash_str_dir2: String::from(
                    "ab749da57d403a26c3e1a173aeb533119156dfa06bf1b276e820d14d8b875068",
                ),
                file1_hash: Vec::from([
                    0xe4, 0xc5, 0x29, 0xa9, 0x0c, 0x31, 0xa1, 0x00, 0x16, 0xd7, 0x33, 0x4d, 0x27,
                    0x18, 0xc1, 0x0c, 0x0b, 0xd3, 0x01, 0x17, 0x0f, 0xea, 0x0f, 0x55, 0x45, 0x70,
                    0xb2, 0xf2, 0x98, 0xec, 0xe9, 0x7f,
                ]),

                file2_hash_dir1: Vec::from([
                    0xa1, 0x02, 0x8f, 0x79, 0x3b, 0x0a, 0xae, 0x9c, 0x51, 0xfa, 0x83, 0xe3, 0x99,
                    0x75, 0xb2, 0x54, 0xd7, 0x89, 0x47, 0x62, 0x08, 0x68, 0xf0, 0x9e, 0x4a, 0x64,
                    0x8e, 0x73, 0x48, 0x6a, 0x62, 0x3c,
                ]),

                file4_hash: Vec::from([
                    0xe9, 0x97, 0x19, 0x69, 0xe0, 0xab, 0x8b, 0x9c, 0x44, 0xe0, 0x0e, 0x0e, 0x80,
                    0xc4, 0xad, 0xe9, 0xbe, 0xa5, 0x69, 0x20, 0x5e, 0x42, 0xc8, 0xde, 0xdc, 0xf7,
                    0x67, 0xf2, 0xef, 0x26, 0x85, 0xb0,
                ]),
                file5_hash: Vec::from([
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                    0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                    0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ]),
                dir1_path: PathBuf::from("test_files/dir1"),
                dir2_path: PathBuf::from("test_files/dir2"),
                dir3_path: PathBuf::from("test_files/dir3"),
                file1_path: PathBuf::from("test_files/dir1/file1.txt"),
                file2_dir1_path: PathBuf::from("test_files/dir1/file2.txt"),
                file4_dir1_path: PathBuf::from("test_files/dir1/file4.txt"),
                file5_path: PathBuf::from("test_files/dir1/subdir/file5.txt"),
            }
        }
    }

    mod test_file_hash {
        use super::*;

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
            let result = FileHash::new(&test_data.file1_path).unwrap();

            assert_eq!(
                result,
                FileHash {
                    filepath: test_data.file1_path,
                    hash: test_data.file1_hash,
                }
            );
        }

        /// Test creation on the base dir
        #[test]
        fn test_creation_base_dir() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.dir1_path).unwrap();
            assert_eq!(
                result,
                FileHash {
                    filepath: test_data.dir1_path,
                    hash: Vec::new(),
                }
            );
        }

        /// Test `get_rel_filepath` method
        #[test]
        fn test_get_rel_filepath() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path)
                .unwrap()
                .get_rel_filepath(&test_data.dir1_path);
            assert_eq!(result.unwrap(), "file1.txt");
        }

        /// Test `get_filepath` method
        #[test]
        fn test_get_filepath() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path).unwrap().get_filepath();

            assert_eq!(result, test_data.file1_path.display().to_string());
        }

        /// Test `get_hash_string` method
        #[test]
        fn test_get_hash_string() {
            let test_data = TestData::new();
            let result = FileHash::new(&test_data.file1_path)
                .unwrap()
                .get_hash_string();

            assert_eq!(result, test_data.file1_hash_str);
        }
    }

    /// Basic test of computing hashes for a folder
    #[test]
    fn test_compute_hashes_for_dir() {
        let test_data = TestData::new();
        let results = compute_hashes_for_dir(&test_data.dir1_path);
        let expected = vec![
            FileHash {
                filepath: test_data.file1_path,
                hash: test_data.file1_hash,
            },
            FileHash {
                filepath: test_data.file2_dir1_path,
                hash: test_data.file2_hash_dir1,
            },
            FileHash {
                filepath: test_data.file4_dir1_path,
                hash: test_data.file4_hash,
            },
            FileHash {
                filepath: test_data.file5_path,
                hash: test_data.file5_hash,
            },
        ];
        assert_eq!(results, expected);
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
            PathBuf::from(format!("subdir{MAIN_SEPARATOR}file5.txt")),
        ];
        assert_eq!(results, expected);
    }

    mod test_file_pair {
        use super::*;

        /// Test creation of a new file pair
        #[test]
        fn test_new() {
            let test_data = TestData::new();

            let result = FilePair::new(
                &PathBuf::from("file2.txt"),
                &test_data.dir1_path,
                &test_data.dir2_path,
            );

            let expected = FilePair {
                relative_path: PathBuf::from("file2.txt"),
                first_hash: test_data.file2_hash_str_dir1.clone(),
                second_hash: test_data.file2_hash_str_dir2.clone(),
            };

            assert_eq!(result.unwrap(), expected);
        }

        /// Test the `same_hash` method when file hashes are the same
        #[test]
        fn test_same_hash_true() {
            let test_data = TestData::new();

            let pair = FilePair::new(
                &PathBuf::from("file4.txt"),
                &test_data.dir1_path,
                &test_data.dir2_path,
            );

            assert_eq!(pair.unwrap().same_hash(), true);
        }

        /// Test the `same_hash` method when file hashes are not the same
        #[test]
        fn test_same_hash_false() {
            let test_data = TestData::new();

            let pair = FilePair::new(
                &PathBuf::from("file2.txt"),
                &test_data.dir1_path,
                &test_data.dir2_path,
            );

            assert_eq!(pair.unwrap().same_hash(), false);
        }

        /// Test getting the relative path string
        #[test]
        fn test_get_relative_path_string() {
            let test_data = TestData::new();

            let pair = FilePair::new(
                &PathBuf::from("file2.txt"),
                &test_data.dir1_path,
                &test_data.dir2_path,
            );

            assert_eq!(pair.unwrap().get_relative_path_string(), "file2.txt");
        }
    }

    /// Test the `to_rel_path` function that is implemented on `DirEntry`
    #[test]
    fn test_to_rel_path() {
        let test_data = TestData::new();
        let walked = WalkDir::new(&test_data.dir2_path);
        let mut files = walked
            .into_iter()
            .map(|v| v.unwrap().to_rel_path(&test_data.dir2_path).unwrap())
            .collect::<Vec<_>>();

        // Sort the results so testing is deterministic
        files.sort();

        let expected = vec![
            PathBuf::from(""),
            PathBuf::from("file2.txt"),
            PathBuf::from("file3.txt"),
            PathBuf::from("file4.txt"),
        ];

        assert_eq!(files, expected);
    }

    mod test_path_comparsion {
        use super::*;

        /// Test creation of the struct
        #[test]
        fn test_creation() {
            let test_data = TestData::new();
            let comparsion = PathComparison::new(&test_data.dir1_path, &test_data.dir2_path);
            assert_eq!(
                comparsion.first_not_second,
                vec![
                    String::from("file1.txt"),
                    format!("subdir{MAIN_SEPARATOR}file5.txt")
                ]
            );
            assert_eq!(comparsion.second_not_first, vec![String::from("file3.txt")]);
            assert_eq!(comparsion.different_hashes, vec![String::from("file2.txt")]);
        }

        /// Tests for the `any_differences` method
        mod test_any_differences {
            use super::*;

            /// Test the `any_differences` method when there is an additional file in the first directory
            #[test]
            fn test_extra_in_first() {
                let comparsion = PathComparison {
                    first_not_second: Vec::from([String::from("abc")]),
                    second_not_first: Vec::new(),
                    different_hashes: Vec::new(),
                };
                assert_eq!(comparsion.any_differences(), true);
            }

            /// Test the `any_differences` method when there is an additional file in the second directory
            #[test]
            fn test_true_extra_in_second() {
                let comparsion = PathComparison {
                    first_not_second: Vec::new(),
                    second_not_first: Vec::from([String::from("abc")]),
                    different_hashes: Vec::new(),
                };
                assert_eq!(comparsion.any_differences(), true);
            }

            /// Test the `any_differences` method when there are files with differing hashes
            #[test]
            fn test_true_differing_hashes() {
                let comparsion = PathComparison {
                    first_not_second: Vec::new(),
                    second_not_first: Vec::new(),
                    different_hashes: Vec::from([String::from("abc")]),
                };
                assert_eq!(comparsion.any_differences(), true);
            }

            /// Test the `any_differences` method when there are no differences
            #[test]
            fn test_false() {
                let test_data = TestData::new();
                let comparsion = PathComparison::new(&test_data.dir2_path, &test_data.dir3_path);
                assert_eq!(comparsion.any_differences(), false);
            }
        }
    }
}
