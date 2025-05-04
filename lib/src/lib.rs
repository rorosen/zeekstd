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
//! let mut decoder = Decoder::new(input)?;
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
//! # let mut decoder = Decoder::new(seekable)?;
//! decoder.set_lower_frame(2);
//! decoder.set_upper_frame(3);
//! io::copy(&mut decoder, &mut io::stdout())?;
//! # Ok::<(), zeekstd::Error>(())
//! ```
//!
//! [specification]: https://github.com/rorosen/zeekstd/seekable_format.md
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
pub use seekable::{BytesWrapper, Seekable};
// Re-export as it's part of the API.
pub use zstd_safe::CompressionLevel;

/// The magic number of the seek table integrity field.
pub const SEEKABLE_MAGIC_NUMBER: u32 = 0x8F92EAB1;
/// The maximum number of frames in a seekable archive.
pub const SEEKABLE_MAX_FRAMES: u32 = 0x8000000;
/// The size of the seek table integrity field.
pub const SEEK_TABLE_INTEGRITY_SIZE: usize = 9;
/// The maximum size of the uncompressed data of a frame.
pub const SEEKABLE_MAX_FRAME_SIZE: usize = 0x40000000;

#[doc = include_str!("../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, Cursor, Write};

    use zstd_safe::{CCtx, CParameter, DCtx};

    use crate::seek_table::SeekTableFormat;

    use super::*;

    pub const LINE_LEN: u32 = 23;
    pub const LINES_IN_DOC: u32 = 200_384;

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

    pub fn generate_input(num_lines: u32) -> Cursor<Vec<u8>> {
        let mut input = Cursor::new(Vec::with_capacity((LINE_LEN * num_lines) as usize));
        for i in 0..num_lines {
            writeln!(&mut input, "Hello from line {:06}", i).unwrap();
        }

        input.set_position(0);
        input
    }

    #[test]
    fn cycle() -> Result<()> {
        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = Encoder::new(&mut seekable)?;

        // Compress the input
        io::copy(&mut input, &mut encoder)?;
        let n = encoder.finish()?;
        assert_eq!(n, seekable.position());

        let mut decoder = DecodeOptions::new(seekable).into_decoder()?;
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
    fn patch_cycle() -> Result<()> {
        let old = generate_input(LINES_IN_DOC - 1);
        let new = generate_input(LINES_IN_DOC);
        let mut patch = Cursor::new(vec![]);

        let window_log = highbit_64(old.get_ref().len() + 1024);
        let mut cctx = CCtx::create();
        cctx.set_parameter(CParameter::WindowLog(window_log))?;
        cctx.set_parameter(CParameter::EnableLongDistanceMatching(true))?;
        let mut encoder = EncodeOptions::new()
            .cctx(cctx)
            .into_encoder(&mut patch)
            .unwrap();

        // Create a binary diff
        let mut input_progress = 0;
        loop {
            let n = encoder
                .compress_with_prefix(&new.get_ref()[input_progress..], Some(old.get_ref()))
                .unwrap();
            if n == 0 {
                break;
            }
            input_progress += n;
        }
        let n = encoder.finish()?;
        assert_eq!(n, patch.position());

        let mut decoder = Decoder::new(patch).unwrap();
        let mut output = Cursor::new(Vec::with_capacity((LINE_LEN * LINES_IN_DOC) as usize));
        let mut buf = vec![0; DCtx::out_size()];
        let mut buf_pos = 0;

        // Apply a binary diff
        loop {
            let n = decoder
                .decompress_with_prefix(&mut buf[buf_pos..], Some(old.get_ref()))
                .unwrap();
            if n == 0 {
                break;
            }
            buf_pos += n;
            if buf_pos == buf.len() {
                output.write_all(&buf).unwrap();
                buf_pos = 0;
            }
        }
        output.write_all(&buf[..buf_pos]).unwrap();

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

    #[test]
    fn cycle_with_stand_alone_seek_table() {
        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = Encoder::new(&mut seekable).unwrap();

        io::copy(&mut input, &mut encoder).unwrap();
        encoder.end_frame().unwrap();
        encoder.flush().unwrap();

        let written_compressed = encoder.written_compressed();
        let mut st_ser = encoder
            .into_seek_table()
            .into_format_serializer(SeekTableFormat::Head);
        let mut st_reader = Cursor::new(vec![]);
        io::copy(&mut st_ser, &mut st_reader).unwrap();

        assert_eq!(written_compressed, seekable.position());
        st_reader.set_position(0);

        let seek_table = SeekTable::from_reader(&mut st_reader).unwrap();
        let mut decoder = DecodeOptions::new(seekable)
            .seek_table(seek_table)
            .into_decoder()
            .unwrap();
        let mut output = Cursor::new(vec![]);
        io::copy(&mut decoder, &mut output).unwrap();

        assert_eq!(input, output);
    }
}
