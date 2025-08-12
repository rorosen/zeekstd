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

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod decode;
mod encode;
mod error;
pub mod seek_table;
mod seekable;

pub use decode::{DecodeOptions, Decoder};
#[cfg(feature = "std")]
pub use encode::Encoder;
pub use encode::{
    CompressionProgress, EncodeOptions, EpilogueProgress, FrameSizePolicy, RawEncoder,
};
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
    use alloc::vec;
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use crate::seek_table::Format;

    use super::*;

    pub const INPUT: &str = include_str!("./lib.rs");

    fn test_cycle(frame_size_policy: Option<FrameSizePolicy>) {
        let mut seekable = vec![];
        let mut opts = EncodeOptions::new();

        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }
        let mut encoder = opts.into_raw_encoder().unwrap();

        // Make buf small enough to compress/end frame/write seek table/decompress in multiple
        // steps
        let mut buf = vec![0; INPUT.len() / 500];

        let mut in_progress = 0;
        while in_progress < INPUT.len() {
            let progress = encoder
                .compress(&INPUT.as_bytes()[in_progress..], &mut buf)
                .unwrap();
            seekable.extend(&buf[..progress.output]);
            in_progress += progress.input;
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            seekable.extend(&buf[..prog.output]);
            if prog.left == 0 {
                break;
            }
        }

        let mut ser = encoder.into_seek_table().into_serializer();
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            seekable.extend(&buf[..n]);
        }

        let wrapper = BytesWrapper::new(&seekable);
        let mut decoder = Decoder::new(wrapper).unwrap();
        let mut output = Vec::with_capacity(INPUT.len());

        loop {
            let n = decoder.decompress(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend(&buf[..n]);
        }

        assert_eq!(&INPUT.as_bytes(), &output);
    }

    fn test_cycle_stand_alone_seek_table(
        frame_size_policy: Option<FrameSizePolicy>,
        format: Format,
    ) {
        let mut seekable = vec![];
        let mut opts = EncodeOptions::new();

        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }
        let mut encoder = opts.into_raw_encoder().unwrap();

        // Make buf small enough to compress/end frame/write seek table/decompress in multiple
        // steps
        let mut buf = vec![0; INPUT.len() / 500];

        let mut in_progress = 0;
        while in_progress < INPUT.len() {
            let progress = encoder
                .compress(&INPUT.as_bytes()[in_progress..], &mut buf)
                .unwrap();
            seekable.extend(&buf[..progress.output]);
            in_progress += progress.input;
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            seekable.extend(&buf[..prog.output]);
            if prog.left == 0 {
                break;
            }
        }

        let mut ser = encoder.into_seek_table().into_format_serializer(format);
        let mut seek_table = Vec::with_capacity(ser.encoded_len());
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            seek_table.extend(&buf[..n]);
        }

        assert_eq!(seek_table.len(), ser.encoded_len());

        let mut seek_table_wrapper = BytesWrapper::new(&seek_table);
        let seek_table = SeekTable::from_bytes(&seek_table).unwrap();
        assert_eq!(
            seek_table,
            SeekTable::from_seekable_format(&mut seek_table_wrapper, format).unwrap()
        );

        let wrapper = BytesWrapper::new(&seekable);
        let mut decoder = DecodeOptions::new(wrapper)
            .seek_table(seek_table)
            .into_decoder()
            .unwrap();
        let mut output = Vec::with_capacity(INPUT.len());

        loop {
            let n = decoder.decompress(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend(&buf[..n]);
        }

        assert_eq!(&INPUT.as_bytes(), &output);
    }

    fn test_patch_cycle(frame_size_policy: Option<FrameSizePolicy>) {
        let old = INPUT;
        let new = alloc::format!("{INPUT}\nThe End");
        let mut patch = vec![];
        let mut opts = EncodeOptions::new();

        if let Some(policy) = frame_size_policy {
            opts = opts.frame_size_policy(policy);
        }
        let mut encoder = opts.into_raw_encoder().unwrap();

        // Make buf small enough to compress/end frame/write seek table/decompress in multiple
        // steps
        let mut buf = vec![0; INPUT.len() / 500];

        // Create a binary patch
        let mut in_progress = 0;
        while in_progress < new.len() {
            let progress = encoder
                .compress_with_prefix(
                    &new.as_bytes()[in_progress..],
                    &mut buf,
                    Some(old.as_bytes()),
                )
                .unwrap();
            patch.extend(&buf[..progress.output]);
            in_progress += progress.input;
        }

        loop {
            let prog = encoder.end_frame(&mut buf).unwrap();
            patch.extend(&buf[..prog.output]);
            if prog.left == 0 {
                break;
            }
        }

        let mut ser = encoder.into_seek_table().into_serializer();
        loop {
            let n = ser.write_into(&mut buf);
            if n == 0 {
                break;
            }
            patch.extend(&buf[..n]);
        }

        let wrapper = BytesWrapper::new(&patch);
        let mut decoder = Decoder::new(wrapper).unwrap();
        let mut output: Vec<u8> = Vec::with_capacity(new.len());

        loop {
            let n = decoder
                .decompress_with_prefix(&mut buf, Some(old.as_bytes()))
                .unwrap();
            if n == 0 {
                break;
            }
            output.extend(&buf[..n]);
        }

        assert_eq!(new.as_bytes(), &output);
    }

    #[test]
    fn cycle() {
        test_cycle(None);
    }

    #[test]
    fn patch_cycle() {
        test_patch_cycle(None);
    }

    #[test]
    fn cycle_stand_alone_seek_table_head() {
        test_cycle_stand_alone_seek_table(None, Format::Head);
    }

    #[test]
    fn cycle_stand_alone_seek_table_foot() {
        test_cycle_stand_alone_seek_table(None, Format::Foot);
    }

    proptest! {
        #[test]
        fn cycle_custom_compressed_frame_size(frame_size in 1..1024u32) {
            test_cycle(Some(FrameSizePolicy::Compressed(frame_size)));
        }

        #[test]
        fn cycle_custom_decompressed_frame_size(frame_size in 1..1024u32) {
            test_cycle(Some(FrameSizePolicy::Uncompressed(frame_size)));
        }

        #[test]
        fn cycle_stand_alone_seek_table_foot_custom_compressed_frame_size(frame_size in 1..1024u32) {
            test_cycle_stand_alone_seek_table(Some(FrameSizePolicy::Compressed(frame_size)), Format::Head);
        }

        #[test]
        fn cycle_stand_alone_seek_table_foot_custom_decompressed_frame_size(frame_size in 1..1024u32) {
            test_cycle_stand_alone_seek_table(Some(FrameSizePolicy::Uncompressed(frame_size)), Format::Foot);
        }

        #[test]
        fn patch_cycle_custom_compressed_frame_size(frame_size in 1..1024u32) {
            test_patch_cycle(Some(FrameSizePolicy::Compressed(frame_size)));
        }

        #[test]
        fn patch_cycle_custom_decompressed_frame_size(frame_size in 1..1024u32) {
            test_patch_cycle(Some(FrameSizePolicy::Uncompressed(frame_size)));
        }
    }
}
