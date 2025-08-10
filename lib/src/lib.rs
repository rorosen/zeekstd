//! This crate provides a Rust implementation of the Zstandard Seekable Format, as outlined in
//! the [specification].
//!
//! The seekable format splits compressed data into a series of independent "frames", each
//! compressed individually, so that decompression of a section in the middle of an archive only
//! requires zstd to decompress at most a frame's worth of extra data, instead of the entire
//! archive.
//!
//! The frames are appended, so that the decompression of the entire payload still regenerates the
//! original content, using any compliant zstd decoder.
//!
//! Zeekstd uses the bindings from the [zstd_safe] crate.
//!
//! # Compression
//!
//! A seekable [`Encoder`] will start new frames automatically at 2MiB of uncompressed data. See
//! [`EncodeOptions`] to change this and other compression parameters.
//!
//! ```no_run
//! use std::{fs::File, io};
//! use zeekstd::Encoder;
//!
//! let mut input = File::open("foo")?;
//! let output = File::create("foo.zst")?;
//! let mut encoder = Encoder::new(output)?;
//! io::copy(&mut input, &mut encoder)?;
//! // End compression and write the seek table
//! encoder.finish()?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//! # Decompression
//!
//! By default, the seekable [`Decoder`] decompresses everything, from the first to the last frame.
//!
//! ```no_run
//! use std::{fs::File, io};
//! use zeekstd::Decoder;
//!
//! let input = File::open("seekable.zst")?;
//! let mut output = File::create("data")?;
//! let mut decoder = Decoder::new(input)?;
//! io::copy(&mut decoder, &mut output)?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! It can also decompress only specific frames.
//!
//! ```no_run
//! # use std::{fs::File, io};
//! # use zeekstd::Decoder;
//! # let seekable = File::open("seekable.zst")?;
//! # let mut decoder = Decoder::new(seekable)?;
//! decoder.set_lower_frame(2)?;
//! decoder.set_upper_frame(3)?;
//! io::copy(&mut decoder, &mut io::stdout())?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! Or between arbitrary byte offsets.
//!
//! ```no_run
//! # use std::{fs::File, io};
//! # use zeekstd::Decoder;
//! # let seekable = File::open("seekable.zst")?;
//! # let mut decoder = Decoder::new(seekable)?;
//! decoder.set_offset(123)?;
//! decoder.set_offset_limit(456)?;
//! io::copy(&mut decoder, &mut io::stdout())?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! [specification]: https://github.com/rorosen/zeekstd/blob/main/seekable_format.md
//! [zstd_safe]: https://docs.rs/zstd-safe/latest/zstd_safe/

mod decode;
mod encode;
mod error;
pub mod seek_table;
mod seekable;

pub use decode::{DecodeOptions, Decoder};
pub use encode::{EncodeOptions, Encoder, FrameSizePolicy, RawEncoder};
pub use error::{Error, Result};
pub use seek_table::SeekTable;
pub use seekable::{BytesWrapper, OffsetFrom, Seekable};
// Re-export as it's part of the API.
pub use zstd_safe::CompressionLevel;

/// The magic number of the seek table integrity field.
pub const SEEKABLE_MAGIC_NUMBER: u32 = 0x8F92_EAB1;
/// The maximum number of frames in a seekable archive.
pub const SEEKABLE_MAX_FRAMES: u32 = 0x0800_0000;
/// The size of the seek table integrity field.
pub const SEEK_TABLE_INTEGRITY_SIZE: usize = 9;
/// The maximum size of the uncompressed data of a frame.
pub const SEEKABLE_MAX_FRAME_SIZE: usize = 0x4000_0000;
/// The size of the skippable frame header.
///
/// Skippable magic number (4 bytes) + frame size field (4 bytes)
pub(crate) const SKIPPABLE_HEADER_SIZE: usize = 8;

#[doc = include_str!("../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor, Write},
        path::PathBuf,
    };

    use proptest::prelude::*;
    use zstd_safe::DCtx;

    use crate::seek_table::Format;

    use super::*;

    pub const LINE_LEN: u32 = 23;
    pub const LINES_IN_DOC: u32 = 200_384;

    pub fn test_input() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../assets/kaestner.txt")
    }

    fn test_cycle(frame_size_policy: Option<FrameSizePolicy>) {
        let input = fs::read(test_input()).unwrap();
        let mut seekable = Cursor::new(vec![]);
        let mut opts = EncodeOptions::new();
        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }

        let mut encoder = opts.into_encoder(&mut seekable).unwrap();

        // Compress the input in multiple steps
        encoder.compress(&input[..input.len() / 2]).unwrap();
        encoder.compress(&input[input.len() / 2..]).unwrap();

        let n = encoder.finish().unwrap();
        assert_eq!(n, seekable.position());

        let mut decoder = DecodeOptions::new(seekable).into_decoder().unwrap();
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        // Decompress the complete seekable
        io::copy(&mut decoder, &mut output).unwrap();

        assert_eq!(&input, output.get_ref());
    }

    #[test]
    fn cycle() {
        test_cycle(None);
    }

    proptest! {
        #[test]
        fn cycle_custom_compressed_frame_size(frame_size in 1..256u32) {
            test_cycle(Some(FrameSizePolicy::Compressed(frame_size)));
        }

        #[test]
        fn cycle_custom_decompressed_frame_size(frame_size in 1..512u32) {
            test_cycle(Some(FrameSizePolicy::Uncompressed(frame_size)));
        }
    }

    #[test]
    fn patch_cycle() {
        let old = fs::read(test_input()).unwrap();
        let mut new = fs::read(test_input()).unwrap();
        new.extend_from_slice(b"The End");
        let mut patch = Cursor::new(vec![]);

        let mut encoder = Encoder::new(&mut patch).unwrap();
        // Create a binary patch
        let mut input_progress = 0;
        loop {
            let n = encoder
                .compress_with_prefix(&new[input_progress..], Some(&old))
                .unwrap();
            if n == 0 {
                break;
            }
            input_progress += n;
        }
        let n = encoder.finish().unwrap();
        assert_eq!(n, patch.position());

        let mut decoder = Decoder::new(patch).unwrap();
        let mut output = vec![];
        let mut buf = vec![0; DCtx::out_size()];
        let mut buf_pos = 0;

        // Apply the binary patch
        loop {
            let n = decoder
                .decompress_with_prefix(&mut buf[buf_pos..], Some(&old))
                .unwrap();
            if n == 0 {
                break;
            }
            buf_pos += n;
            if buf_pos == buf.len() {
                output.extend_from_slice(&buf);
                buf_pos = 0;
            }
        }

        output.extend_from_slice(&buf[..buf_pos]);
        assert_eq!(new, output);
    }

    #[test]
    fn cycle_with_stand_alone_seek_table() {
        let input = fs::read(test_input()).unwrap();
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = Encoder::new(&mut seekable).unwrap();

        encoder.compress(&input).unwrap();
        encoder.end_frame().unwrap();
        encoder.flush().unwrap();

        let written_compressed = encoder.written_compressed();
        let mut st_ser = encoder
            .into_seek_table()
            .into_format_serializer(Format::Head);
        let mut st_reader = Cursor::new(vec![]);
        io::copy(&mut st_ser, &mut st_reader).unwrap();

        assert_eq!(written_compressed, seekable.position());
        st_reader.set_position(0);

        let seek_table = SeekTable::from_reader(&mut st_reader).unwrap();
        let mut decoder = DecodeOptions::new(seekable)
            .seek_table(seek_table)
            .into_decoder()
            .unwrap();

        let mut output = vec![0; input.len()];
        decoder.decompress(&mut output).unwrap();

        assert_eq!(&input, &output);
    }
}
