# Zeekstd

[![Nix](https://github.com/rorosen/zeekstd/actions/workflows/nix.yaml/badge.svg)](https://github.com/rorosen/zeekstd/actions/workflows/nix.yaml)
[![Linux](https://github.com/rorosen/zeekstd/actions/workflows/linux.yaml/badge.svg)](https://github.com/rorosen/zeekstd/actions/workflows/linux.yaml)
[![Windows](https://github.com/rorosen/zeekstd/actions/workflows/windows.yaml/badge.svg)](https://github.com/rorosen/zeekstd/actions/workflows/windows.yaml)
[![Documentation](https://docs.rs/zeekstd/badge.svg)](https://docs.rs/zeekstd)

[![Crates.io](https://img.shields.io/crates/v/zeekstd.svg)](https://crates.io/crates/zeekstd)
[![MSRV 1.85.1](https://img.shields.io/badge/msrv-1.85.1-dea584.svg?logo=rust)](https://github.com/rust-lang/rust/releases/tag/1.85.1)

[![](https://img.shields.io/badge/Packaged_for-Nix-5277C3.svg?logo=nixos&labelColor=73C3D5)](https://search.nixos.org/packages?size=1&show=zeekstd)

Rust implementation of the Zstandard Seekable Format.

The seekable format splits compressed data into a series of independent frames, each compressed
individually, so that decompression of a section in the middle of an archive only requires zstd to
decompress at most a frame's worth of extra data, instead of the entire archive.

The format also specifies a seek table that allows seekable decoders to efficiently jump to
requested data. The seek table is placed in a [Zstandard Skippable Frame] and can be appended to the
end of a seekable archive or written to a standalone file.

Any compliant zstd decoder can restore the original content of a seekable archive by decompressing
it. As the seek table is placed in a skippable frame, it is simply ignored by decoders that are
unaware of the seekable format.

Zeekstd makes additions to the seekable format by implementing an updated version of the
[specification][zeekstd_spec], however, it is fully compatible with the
[initial version of the seekable format][zstd_spec].

[Zstandard Skippable Frame]: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#skippable-frames
[zeekstd_spec]: ./seekable_format.md
[zstd_spec]: <https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md>

## Finding the Right Frame Size

Every frame adds a small amount of metadata depending on compression parameters (e.g. whether frame
checksums are used) and increases the size of the seek table. Hence, small frame sizes impact the
compression ratio negatively, but also reduce decompression cost when requesting small segments of
data, so there is a balance to find.

Very small frame sizes below a few KiB should be avoided in general, as they can hurt the
compression ratio notably.

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
can also be configured to decompress only specific data.

```rust no_run
use std::{fs::File, io};
use zeekstd::Decoder;

fn main() -> zeekstd::Result<()> {
    let input = File::open("seekable.zst")?;
    let mut output = File::create("decompressed")?;
    let mut decoder = Decoder::new(input)?;
    // Decompress everything
    io::copy(&mut decoder, &mut output)?;

    let mut frames = File::create("decompressed_frames")?;
    // Decompress only specific frames
    decoder.set_lower_frame(2)?;
    decoder.set_upper_frame(5)?;
    io::copy(&mut decoder, &mut frames)?;

    let mut offset = File::create("decompressed_offset")?;
    // Decompress between arbitrary byte offsets
    decoder.set_offset(123)?;
    decoder.set_offset_limit(456)?;
    io::copy(&mut decoder, &mut offset)?;

    Ok(())
}
```

## CLI

This repo also contains a [CLI tool](./cli) that uses the library.

## License

- The zstd C library is under a dual BSD/GPLv2 license.
- Zeekstd is under a BSD 2-Clause License.
