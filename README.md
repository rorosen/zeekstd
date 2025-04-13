# Zeekstd

Rust implementation of the
[Zstandard Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format).

The seekable format splits compressed data into a series of independent "frames", each compressed
individually, so that decompression of a section in the middle of an archive only requires zstd to
decompress at most a frame's worth of extra data, instead of the entire archive.

## Compression

Use the `Encoder` struct for streaming data compression.

```rust no_run
use std::{fs::File, io};
use zeekstd::Encoder;

fn main() -> zeekstd::Result<()> {
    let mut input = File::open("foo")?;
    let output = File::create("foo.zst")?;
    let mut encoder = Encoder::new(output)?;
    io::copy(&mut input, &mut encoder)?;
    // End compression and write the seek table
    encoder.finish()?;

    Ok(())
}
```

## Decompression

Streaming decompression can be achieved using the `Decoder` struct.

```rust no_run
use std::{fs::File, io};
use zeekstd::Decoder;

fn main() -> zeekstd::Result<()> {
    let input = File::open("seekable.zst")?;
    let mut output = File::create("data")?;
    let mut decoder = Decoder::from_seekable(input)?;
    io::copy(&mut decoder, &mut output)?;

    Ok(())
}
```

## CLI

This repo also contains a [CLI tool](./cli) for the seekable format that is packaged in nixpkgs.

```bash
nix-shell -p zeekstd
zeekstd --help
```

## License

- The zstd C library is under a dual BSD/GPLv2 license.
- Zeekstd is under a BSD 2-Clause License.
