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
//! Use the [`Compressor`] struct for streaming data compression.
//!
//! ```no_run
//! use std::{fs::File, io};
//! use zeekstd::Compressor;
//!
//! let mut input = File::open("foo")?;
//! let output = File::create("foo.zst")?;
//! let mut compressor = Compressor::new(output)?;
//! io::copy(&mut input, &mut compressor)?;
//! // End compression and write the seek table
//! compressor.finish()?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//! # Decompression
//!
//! Streaming decompression can be achieved using the [`Decompressor`] struct.
//!
//! ```no_run
//! use std::{fs::File, io::{self, BufReader}};
//! use zeekstd::Decompressor;
//!
//! let input = File::open("seekable.zst")?;
//! let mut output = File::create("data")?;
//! let mut decompressor = Decompressor::new(BufReader::new(input))?;
//! io::copy(&mut decompressor, &mut output)?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! Or decompress only specific frames.
//!
//! ```no_run
//! # use std::{fs::File, io::{self, BufReader}};
//! # use zeekstd::Decompressor;
//! # let seekable = File::open("seekable.zst")?;
//! # let mut decompressor = Decompressor::new(BufReader::new(seekable))?;
//! decompressor.set_start_frame(2);
//! decompressor.set_end_frame(3);
//! io::copy(&mut decompressor, &mut io::stdout())?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! [Zstandard Seekable Format]: https://github.com/facebook/zstd/tree/dev/contrib/seekable_format
//! [zstd_specification]: https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md
//! [zstd_safe]: https://docs.rs/zstd-safe/latest/zstd_safe/

mod compress;
mod decompress;
mod error;
mod frame_log;
mod seek_table;

pub use compress::{Compressor, CompressorBuilder, FrameSizePolicy};
pub use decompress::{Decompressor, DecompressorBuilder};
pub use error::{Error, Result};
pub use frame_log::{FrameLog, FrameLogReader};
pub use seek_table::SeekTable;
// Re-export as it's part of the API.
pub use zstd_safe::CompressionLevel;

const SKIPPABLE_MAGIC_NUMBER: u32 = zstd_safe::zstd_sys::ZSTD_MAGIC_SKIPPABLE_START | 0xE;
const SKIPPABLE_HEADER_SIZE: u32 = 8;
const SEEK_TABLE_FOOTER_SIZE: u32 = 9;
const SEEKABLE_MAGIC_NUMBER: u32 = 0x8F92EAB1;
const SEEKABLE_MAX_FRAMES: usize = 0x8000000;

#[doc = include_str!("../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, BufRead, BufReader, Cursor, Write};

    use zstd_safe::{CCtx, CParameter};

    use crate::{
        compress::{Compressor, CompressorBuilder, FrameSizePolicy},
        decompress::{Decompressor, DecompressorBuilder},
        error::Result,
        frame_log::{FrameLog, FrameLogReader},
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
        let mut fl = FrameLog::new(true);

        for i in 1..=1024 {
            fl.log_frame(i * 5, i * 10, Some(i))?;
        }

        let mut cursor = Cursor::new(Vec::with_capacity(
            // The size of the seek table
            12 * 1024 + SKIPPABLE_HEADER_SIZE as usize + SEEK_TABLE_FOOTER_SIZE as usize,
        ));
        let mut fl_reader = FrameLogReader::from(fl);
        io::copy(&mut fl_reader, &mut cursor)?;

        let mut src = BufReader::new(cursor);
        let st = SeekTable::from_seekable(&mut src)?;
        assert_eq!(st.num_frames(), 1024);

        let mut c_offset = 0;
        let mut d_offset = 0;
        for i in 1..=1024 {
            // dbg!(i);
            assert_eq!(st.frame_compressed_size(i - 1)?, i as u64 * 5);
            assert_eq!(st.frame_decompressed_size(i - 1)?, i as u64 * 10);
            assert_eq!(st.frame_compressed_start(i - 1)?, c_offset);
            assert_eq!(st.frame_decompressed_start(i - 1)?, d_offset);
            assert_eq!(st.frame_compressed_end(i - 1)?, c_offset + i as u64 * 5);
            assert_eq!(st.frame_decompressed_end(i - 1)?, d_offset + i as u64 * 10);
            assert_eq!(st.frame_index_at_compressed_offset(c_offset), i - 1);
            assert_eq!(st.frame_index_at_decompressed_offset(d_offset), i - 1);
            assert_eq!(st.frame_checksum(i - 1)?, i);
            c_offset += i as u64 * 5;
            d_offset += i as u64 * 10;
        }

        Ok(())
    }

    #[test]
    fn seekable_cycle() -> Result<()> {
        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut compressor = Compressor::new(&mut seekable)?;

        // Compress the input
        io::copy(&mut input, &mut compressor)?;
        compressor.finish()?;

        let mut decompressor = Decompressor::new(BufReader::new(seekable))?;
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        // Decompress the complete seekable
        io::copy(&mut decompressor, &mut output)?;
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
    fn seekable_partly_decompression() -> Result<()> {
        const LINES_IN_FRAME: u32 = 1143;

        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut compressor = CompressorBuilder::new()
            .frame_size_policy(FrameSizePolicy::decompressed(LINE_LEN * LINES_IN_FRAME)?)
            .build(&mut seekable)?;

        // Compress the input
        io::copy(&mut input, &mut compressor)?;
        compressor.finish()?;

        // Decompress frames 6 to 9 (inclusive) initially
        let mut decompressor = DecompressorBuilder::new()
            .start_frame(6)
            .end_frame(9)
            .build(BufReader::new(seekable))?;

        // Add one for the last frame
        let num_frames = LINES_IN_DOC / LINES_IN_FRAME + 1;
        assert_eq!(num_frames, decompressor.num_frames());

        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_FRAME) as usize * 4));
        io::copy(&mut decompressor, &mut output)?;
        output.set_position(0);
        let mut num_line = 6 * LINES_IN_FRAME;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, 10 * LINES_IN_FRAME);

        // Decompress until frame 6 (inclusive)
        decompressor.set_start_frame(0);
        decompressor.set_end_frame(6);
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_FRAME) as usize * 7));
        io::copy(&mut decompressor, &mut output)?;
        output.set_position(0);
        let mut num_line = 0;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, 7 * LINES_IN_FRAME);

        // Decompress the last 13 frames
        decompressor.set_start_frame(num_frames - 14);
        decompressor.set_end_frame(num_frames - 1);
        let mut output = Cursor::new(Vec::with_capacity(
            (LINE_LEN * LINES_IN_FRAME) as usize * 13,
        ));
        io::copy(&mut decompressor, &mut output)?;
        output.set_position(0);
        let mut num_line = (num_frames - 14) * LINES_IN_FRAME;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {:06}", num_line));
            num_line += 1;
        }
        assert_eq!(num_line, LINES_IN_DOC);

        // Start frame greater end frame, expect zero bytes read
        decompressor.set_start_frame(9);
        decompressor.set_end_frame(8);
        let mut output = Cursor::new(vec![]);
        let n = io::copy(&mut decompressor, &mut output)?;
        assert_eq!(0, n);
        output.set_position(0);
        assert_eq!(0, output.lines().collect::<Vec<_>>().len());

        // Start frame index too large
        decompressor.set_start_frame(num_frames);
        let mut output = Cursor::new(vec![]);
        assert!(io::copy(&mut decompressor, &mut output).is_err());

        // End frame index too large
        decompressor.set_start_frame(0);
        decompressor.set_end_frame(num_frames);
        let mut output = Cursor::new(vec![]);
        assert!(io::copy(&mut decompressor, &mut output).is_err());

        // Decompress all frames
        decompressor.set_end_frame(num_frames - 1);
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        io::copy(&mut decompressor, &mut output)?;
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
    fn seekable_diff_cycle() -> Result<()> {
        let old = generate_input(LINES_IN_DOC - 1);
        let mut new = generate_input(LINES_IN_DOC);
        let mut patch = Cursor::new(vec![]);

        let window_log = highbit_64(old.get_ref().len() + 1024);
        let mut cctx = CCtx::create();
        cctx.set_parameter(CParameter::WindowLog(window_log))?;
        cctx.set_parameter(CParameter::EnableLongDistanceMatching(true))?;
        let mut compressor = CompressorBuilder::new()
            .cctx(cctx)
            .prefix(old.get_ref())
            .build(&mut patch)?;

        // Create a binary diff
        io::copy(&mut new, &mut compressor)?;
        compressor.finish()?;

        let mut decompressor = DecompressorBuilder::new()
            .prefix(old.get_ref())
            .build(BufReader::new(patch))?;
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        io::copy(&mut decompressor, &mut output)?;
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
