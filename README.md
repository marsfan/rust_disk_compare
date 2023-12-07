# Disk Compare

A tool for quickly comparing files by hash.


## ASM issue

I should be able to get the SHA extensions working with mingw build using `cargo +stable-x86_64-pc-windows-gnu build --release`
However, from testing, I'm not sure that I'm using the extension. Seems to be falling back to soft implementation, even though my CPU has SHA support. Need to file a bug