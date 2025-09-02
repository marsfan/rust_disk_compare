/*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https: //mozilla.org/MPL/2.0/.
*/
//! Code for computing file hashes
use crate::ToolError;
use core::cmp::Ordering;
use core::fmt::Write as _;
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io;
use std::path::PathBuf;

/// A single file and its hash
#[derive(PartialEq, Debug, Eq, PartialOrd, Ord)]
pub struct FileHash {
    /// The path to the file that was hashed
    filepath: PathBuf,
    /// The file's hash
    hash: Vec<u8>,
}

impl FileHash {
    /// Create a new instance of the struct
    ///
    /// # Arguments
    ///   * `filepath`: Path to the file being hashed
    ///   * `hash`: The bytes of the computed hash
    ///
    /// # Returns:
    ///   The created `FileHash` instance.
    ///
    /// # Note
    ///   This does not automatically compute the hash from the file. It is instead for
    ///   creating a new instance from pre-existing values. For computing the hash from
    ///   a file, use [`FileHash::try_from`]
    pub fn new(filepath: PathBuf, hash: Vec<u8>) -> Self {
        Self { filepath, hash }
    }

    /// Compute the hash of the given file
    ///
    /// # Arguments
    /// * `filepath`: Path to the file to hash.
    fn hash_file(filepath: &PathBuf) -> Result<Vec<u8>, ToolError> {
        if !filepath.is_file() {
            return Err(ToolError::NotAFileError {
                filepath: filepath.clone(),
            });
        }
        let mut hasher = Sha256::new();
        let mut file = File::open(filepath).map_err(|error| ToolError::FileReadError {
            source: error,
            filepath: filepath.clone(),
        })?;

        // This whole io::copy thing came from here
        // https://www.reddit.com/r/rust/comments/tuxpxf/comment/i368ryk/
        // Uses way less memory than reading the file directly
        // Guessing its sending copying the file in chunks?

        io::copy(&mut file, &mut hasher).map_err(|e| ToolError::ByteCopyError {
            source: e,
            filepath: filepath.clone(),
        })?;
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
        Ok(self
            .filepath
            .strip_prefix(base)
            .map_err(|e| ToolError::StripPrefixError {
                source: e,
                filepath: self.filepath.clone(),
                base: base.clone(),
            })?
            .display()
            .to_string())
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

impl TryFrom<&PathBuf> for FileHash {
    type Error = ToolError;

    /// Create the new hash from the given path.
    ///
    /// # Arguments
    ///   * `value`: The path to the file to hash.
    ///
    /// # Returns:
    ///   The created `FileHash` instance.
    ///
    /// # Errors
    ///   Will error out if an error occurred when computing the hash for the file
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        Ok(Self {
            filepath: value.clone(),
            hash: Self::hash_file(value)?,
        })
    }
}

/// Compare two `Result<FileHash, ToolError>` elements by their filepaths
///
/// If both elements are the same [`Result`] variant, then the filepaths are compare
/// if they are not of the same varriant, then the element that is [`Ok`] is considered smaller
///
/// # Arguments
///   * `a`: The first of the two elements to compare
///   * `b`: The second of the two elements to compare
///
/// # Returns
///   [`Ordering`] variant according to aforementioned sorting rules
pub fn compare_hash_result(
    a: &Result<FileHash, ToolError>,
    b: &Result<FileHash, ToolError>,
) -> Ordering {
    match (a, b) {
        (Ok(hash_a), Ok(hash_b)) => hash_a.get_filepath().cmp(&hash_b.get_filepath()),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(err_a), Err(err_b)) => err_a.get_filepath().cmp(&err_b.get_filepath()),
    }
}

#[expect(
    clippy::panic,
    reason = "Panicing in unit tests are ok, as they will display as failed tests"
)]
#[cfg(test)]
mod tests {
    use crate::tests::TestData;

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
    fn test_hashfile_on_dir() {
        let test_data = TestData::new();
        let result = FileHash::hash_file(&test_data.dir1_path).unwrap_err();
        if let ToolError::NotAFileError { filepath } = result {
            assert_eq!(filepath, test_data.dir1_path);
        } else {
            panic!("Wrong enum variant");
        }
    }

    /// Test creation and proper hashing.
    #[test]
    fn test_creation() {
        let test_data = TestData::new();
        let result = FileHash::try_from(&test_data.file1_path).unwrap();

        assert_eq!(
            result,
            FileHash {
                filepath: test_data.file1_path,
                hash: test_data.file1_hash,
            }
        );
    }

    /// Test `get_rel_filepath` method
    #[test]
    fn test_get_rel_filepath() {
        let test_data = TestData::new();
        let result = FileHash::try_from(&test_data.file1_path)
            .unwrap()
            .get_rel_filepath(&test_data.dir1_path);
        assert_eq!(result.unwrap(), "file1.txt");
    }

    /// Test `get_filepath` method
    #[test]
    fn test_get_filepath() {
        let test_data = TestData::new();
        let result = FileHash::try_from(&test_data.file1_path)
            .unwrap()
            .get_filepath();

        assert_eq!(result, test_data.file1_path.display().to_string());
    }

    /// Test `get_hash_string` method
    #[test]
    fn test_get_hash_string() {
        let test_data = TestData::new();
        let result = FileHash::try_from(&test_data.file1_path)
            .unwrap()
            .get_hash_string();

        assert_eq!(result, test_data.file1_hash_str);
    }

    /// Test [`compare_hash_result`] function
    #[test]
    fn test_compare_hash_result() {
        let cases = [
            (
                Ok(FileHash::new(
                    PathBuf::from("hello/world"),
                    vec![0x01, 0x02],
                )),
                Ok(FileHash::new(
                    PathBuf::from("hello/apple"),
                    vec![0x01, 0x02],
                )),
                Ordering::Greater,
            ),
            (
                Err(ToolError::FileReadError {
                    source: io::Error::new(io::ErrorKind::AddrInUse, "oh no"),
                    filepath: PathBuf::from("hello/apple"),
                }),
                Err(ToolError::FileReadError {
                    source: io::Error::new(io::ErrorKind::AddrInUse, "oh no"),
                    filepath: PathBuf::from("hello/world"),
                }),
                Ordering::Less,
            ),
            (
                Ok(FileHash::new(
                    PathBuf::from("hello/apple"),
                    vec![0x01, 0x02],
                )),
                Err(ToolError::FileReadError {
                    source: io::Error::new(io::ErrorKind::AddrInUse, "oh no"),
                    filepath: PathBuf::from("hello/world"),
                }),
                Ordering::Less,
            ),
            (
                Err(ToolError::FileReadError {
                    source: io::Error::new(io::ErrorKind::AddrInUse, "oh no"),
                    filepath: PathBuf::from("hello/world"),
                }),
                Ok(FileHash::new(
                    PathBuf::from("hello/apple"),
                    vec![0x01, 0x02],
                )),
                Ordering::Greater,
            ),
        ];

        for (a, b, expected) in cases {
            assert_eq!(compare_hash_result(&a, &b), expected);
        }
    }
}
