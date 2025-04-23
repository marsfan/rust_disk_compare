# Disk Compare

A tool for quickly comparing files by hash. Currently the tool uses
SHA256, as that has hardware acceleration on x86_64. I've found that it
will saturate my CPU and SSD when hashing large files.