# Disk Compare

A tool for quickly comparing files by hash. Currently the tool uses
SHA256, as that has hardware acceleration on x86_64. I've found that it
will saturate my CPU and SSD when hashing large files.


## Usage

The tool is designed to be used in one of two ways.

* Directory Comparsion: In this mode, the tool is invoked with two
  command-line arguments (e.g. `rust_disk_compare DIR1 DIR2`).
  Each argument should point to a directory.
  The tool will gather all files in both directories recursively, and then
  output which files are in only one directory or the other, and which files
  are in both directories, but are not identical.
* Directory Hashing: In this mode, only a single argument is supplied to
  the tool (e.g. `rust_disk_compare DIR1`). The tool will gather all files
  in the directory recursively, and then print out the hashes for them