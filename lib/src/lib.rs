//! This crate provides a Rust implementation of the [Zstandard Seekable Format], as outlined in
//! the [specification][zstd_specification].
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
//! Use the [`Encoder`] struct for streaming data compression.
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
//! Streaming decompression can be achieved using the [`Decoder`] struct.
//!
//! ```no_run
//! use std::{fs::File, io};
//! use zeekstd::Decoder;
//!
//! let input = File::open("seekable.zst")?;
//! let mut output = File::create("data")?;
//! let mut decoder = Decoder::from_seekable(input)?;
//! io::copy(&mut decoder, &mut output)?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! Or decompress only specific frames.
//!
//! ```no_run
//! # use std::{fs::File, io};
//! # use zeekstd::Decoder;
//! # let seekable = File::open("seekable.zst")?;
//! # let mut decoder = Decoder::from_seekable(seekable)?;
//! decoder.set_lower_frame(2);
//! decoder.set_upper_frame(3);
//! io::copy(&mut decoder, &mut io::stdout())?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! [Zstandard Seekable Format]: https://github.com/facebook/zstd/tree/dev/contrib/seekable_format
//! [zstd_specification]: https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md
//! [zstd_safe]: https://docs.rs/zstd-safe/latest/zstd_safe/

mod decode;
mod encode;
mod error;
mod frame_log;
mod seek_table;
mod seekable;

pub use decode::{DecodeOptions, Decoder, RawDecoder};
pub use encode::{EncodeOptions, RawEncoder, Encoder, FrameSizePolicy};
pub use error::{Error, Result};
pub use frame_log::FrameLog;
pub use seek_table::SeekTable;
pub use seekable::Seekable;
// Re-export as it's part of the API.
pub use zstd_safe::CompressionLevel;

/// The skippable magic number of a skippable frame containing the seek table.
pub const SKIPPABLE_MAGIC_NUMBER: u32 = zstd_safe::zstd_sys::ZSTD_MAGIC_SKIPPABLE_START | 0xE;
/// The magic number placed at the end of the seek table.
pub const SEEKABLE_MAGIC_NUMBER: u32 = 0x8F92EAB1;
/// The size of skippable frame header.
pub const SKIPPABLE_HEADER_SIZE: usize = 8;
/// The size of the seekable footer a the end of the seek table.
pub const SEEK_TABLE_FOOTER_SIZE: usize = 9;
/// The maximum number of frames in a seekable archive.
pub const SEEKABLE_MAX_FRAMES: usize = 0x8000000;
/// The maximum size of the decompressed data of a frame.
pub const SEEKABLE_MAX_FRAME_SIZE: usize = 0x40000000;

#[doc = include_str!("../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, BufRead, Cursor, Write};

    use zstd_safe::{CCtx, CParameter};

    use crate::{
        decode::{DecodeOptions, Decoder},
        encode::{EncodeOptions, Encoder, FrameSizePolicy},
        error::Result,
        frame_log::FrameLog,
        seek_table::SeekTable,
    };

    const LINE_LEN: u32 = 23;
    const LINES_IN_DOC: u32 = 200_384;

    fn highbit_64(mut v: usize) -> u32 {
        if v == 0 {
            panic!("Cannot get highest bit position of zero");
        }

        let mut count = 0;
        v >>= 1;
        while v > 0 {
            v >>= 1;
            count += 1;
        }

        count
    }

    fn generate_input(num_lines: u32) -> Cursor<Vec<u8>> {
        let mut input = Cursor::new(Vec::with_capacity((LINE_LEN * num_lines) as usize));
        for i in 0..num_lines {
            writeln!(&mut input, "Hello from line {:06}", i).unwrap();
        }

        input.set_position(0);
        input
    }

    #[test]
    fn seek_table_from_frame_log() -> Result<()> {
        const NUM_FRAMES: u32 = 4096;
        let mut fl = FrameLog::new(true);

        for i in 1..=NUM_FRAMES {
            fl.log_frame(i * 5, i * 10, Some(i))?;
        }

        let mut seek_table = Cursor::new(Vec::with_capacity(
            // The size of the seek table
            12 * NUM_FRAMES as usize + SKIPPABLE_HEADER_SIZE + SEEK_TABLE_FOOTER_SIZE,
        ));
        io::copy(&mut fl, &mut seek_table)?;

        let st = SeekTable::from_seekable(&mut seek_table)?;
        assert_eq!(st.num_frames(), NUM_FRAMES);

        let mut c_offset = 0;
        let mut d_offset = 0;
        for i in 1..=NUM_FRAMES {
            assert_eq!(st.frame_checksum(i - 1)?, Some(i));
            assert_eq!(st.frame_compressed_end(i - 1)?, c_offset + i as u64 * 5);
            assert_eq!(st.frame_compressed_size(i - 1)?, i as u64 * 5);
            assert_eq!(st.frame_compressed_start(i - 1)?, c_offset);
            assert_eq!(st.frame_decompressed_end(i - 1)?, d_offset + i as u64 * 10);
            assert_eq!(st.frame_decompressed_size(i - 1)?, i as u64 * 10);
            assert_eq!(st.frame_decompressed_start(i - 1)?, d_offset);
            assert_eq!(st.frame_index_at_compressed_offset(c_offset), i - 1);
            assert_eq!(st.frame_index_at_decompressed_offset(d_offset), i - 1);
            c_offset += i as u64 * 5;
            d_offset += i as u64 * 10;
        }

        Ok(())
    }

    #[test]
    fn seekable_cycle() -> Result<()> {
        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = Encoder::new(&mut seekable)?;
        // let mut encoder = CompressOptions::new()
        //     .frame_size_policy(FrameSizePolicy::Decompressed(512))
        //     .into_encoder(&mut seekable)?;

        // Compress the input
        io::copy(&mut input, &mut encoder)?;
        encoder.finish()?;

        let mut decoder = DecodeOptions::new().into_decoder(seekable)?;
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        // Decompress the complete seekable
        io::copy(&mut decoder, &mut output)?;
        output.set_position(0);

        let mut num_line = 0;
        for line in output.clone().lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);
        assert_eq!(input.get_ref(), output.get_ref());

        Ok(())
    }

    #[test]
    fn seekable_partly_decompression() {
        const LINES_IN_FRAME: u32 = 1143;

        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(FrameSizePolicy::Decompressed(LINE_LEN * LINES_IN_FRAME))
            .into_encoder(&mut seekable)
            .unwrap();

        // Compress the input
        io::copy(&mut input, &mut encoder).unwrap();
        encoder.finish().unwrap();

        let mut decoder = Decoder::from_seekable(seekable).unwrap();

        // Add one for the last frame
        let num_frames = LINES_IN_DOC / LINES_IN_FRAME + 1;
        assert_eq!(num_frames, decoder.num_frames());

        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);

        let mut num_line = 0;
        for line in output.clone().lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);
        assert_eq!(input.get_ref(), output.get_ref());

        // Decompress until frame 6 (inclusive)
        decoder.set_lower_frame(0).unwrap();
        decoder.set_upper_frame(6);
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_FRAME) as usize * 7));
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);
        let mut num_line = 0;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, 7 * LINES_IN_FRAME);

        // Decompress the last 13 frames
        decoder.set_lower_frame(num_frames - 14).unwrap();
        decoder.set_upper_frame(num_frames - 1);
        let mut output = Cursor::new(Vec::with_capacity(
            (LINE_LEN * LINES_IN_FRAME) as usize * 13,
        ));
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);
        let mut num_line = (num_frames - 14) * LINES_IN_FRAME;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);

        // Start frame greater end frame, expect zero bytes read
        decoder.set_lower_frame(9).unwrap();
        decoder.set_upper_frame(8);
        let mut output = Cursor::new(vec![]);
        let n = io::copy(&mut decoder, &mut output).unwrap();
        assert_eq!(0, n);
        output.set_position(0);
        assert_eq!(0, output.lines().collect::<Vec<_>>().len());

        // Start frame index too large
        decoder.set_lower_frame(num_frames).unwrap();
        let mut output = Cursor::new(vec![]);
        assert!(io::copy(&mut decoder, &mut output).is_err());

        // End frame index too large
        decoder.set_lower_frame(0).unwrap();
        decoder.set_upper_frame(num_frames);
        let mut output = Cursor::new(vec![]);
        assert!(io::copy(&mut decoder, &mut output).is_err());

        // Decompress all frames
        decoder.set_upper_frame(num_frames - 1);
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        io::copy(&mut decoder, &mut output).unwrap();
        output.set_position(0);

        let mut num_line = 0;
        for line in output.clone().lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);
        assert_eq!(input.get_ref(), output.get_ref());
    }

    #[test]
    fn seekable_diff_cycle() -> Result<()> {
        let old = generate_input(LINES_IN_DOC - 1);
        let mut new = generate_input(LINES_IN_DOC);
        let mut patch = Cursor::new(vec![]);

        let window_log = highbit_64(old.get_ref().len() + 1024);
        let mut cctx = CCtx::create();
        cctx.set_parameter(CParameter::WindowLog(window_log))?;
        cctx.set_parameter(CParameter::EnableLongDistanceMatching(true))?;
        let mut encoder = EncodeOptions::new()
            .cctx(cctx)
            .prefix(old.get_ref())
            .into_encoder(&mut patch)?;

        // Create a binary diff
        io::copy(&mut new, &mut encoder)?;
        encoder.finish()?;

        let mut decoder = DecodeOptions::new()
            .prefix(old.get_ref())
            .into_decoder(patch)?;
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        io::copy(&mut decoder, &mut output)?;
        output.set_position(0);

        let mut num_line = 0;
        for line in output.clone().lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);
        assert_eq!(new.get_ref(), output.get_ref());

        Ok(())
    }
}
