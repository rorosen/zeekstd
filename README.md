# Zeekstd

[![Crates.io](https://img.shields.io/crates/v/zeekstd.svg)](https://crates.io/crates/zeekstd)
[![Documentation](https://docs.rs/zeekstd/badge.svg)](https://docs.rs/zeekstd)

A Rust implementation of the Zstandard Seekable Format.

The seekable format splits compressed data into a series of independent "frames", each compressed
individually, so that decompression of a section in the middle of an archive only requires zstd to
decompress at most a frame's worth of extra data, instead of the entire archive.

Zeekstd makes additions to the seekable format by implementing an updated version of the
[specification][zeekstd_spec], however, it is fully compatible with the
[initial version of the seekable format][zstd_spec].

[zeekstd_spec]: ./seekable_format.md
[zstd_spec]: <https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md>

## Compression

A seekable `Encoder` will start new frames automatically at 2MiB of uncompressed data. See
`EncodeOptions` to change this and other compression parameters.

```rust no_run
use std::{fs::File, io};
use zeekstd::Encoder;

fn main() -> zeekstd::Result<()> {
    let mut input = File::open("data")?;
    let output = File::create("seekable.zst")?;
    let mut encoder = Encoder::new(output)?;
    io::copy(&mut input, &mut encoder)?;
    // End compression and write the seek table to the end of the seekable
    encoder.finish()?;

    Ok(())
}
```

## Decompression

By default, the seekable `Decoder` decompresses everything, from the first to the last frame, but
can also be configured to decompress only specific frames.

```rust no_run
use std::{fs::File, io};
use zeekstd::Decoder;

fn main() -> zeekstd::Result<()> {
    let input = File::open("seekable.zst")?;
    let mut output = File::create("decompressed")?;
    let mut decoder = Decoder::new(input)?;
    // Decompress everything
    io::copy(&mut decoder, &mut output)?;

    let mut partial = File::create("partial")?;
    // Decompress only specific frames
    decoder.set_lower_frame(2);
    decoder.set_upper_frame(5);
    io::copy(&mut decoder, &mut partial)?;

    Ok(())
}
```

## CLI

This repo also contains a [CLI tool](./cli) that uses the library.

## License

- The zstd C library is under a dual BSD/GPLv2 license.
- Zeekstd is under a BSD 2-Clause License.
