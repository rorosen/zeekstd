use std::{fs::File, io::Write};

use anyhow::{Context, Result};
use indicatif::ProgressBar;
use zeekstd::{DecodeOptions, Decoder, SeekTable};
use zstd_safe::DCtx;

use crate::args::DecompressArgs;

pub struct Decompressor<'a> {
    decoder: Decoder<'a, File>,
}

impl Decompressor<'_> {
    pub fn new(args: &DecompressArgs) -> Result<Self> {
        let mut src = File::open(&args.input_file).context("Failed to open input file")?;
        let seek_table =
            SeekTable::from_seekable(&mut src).context("Failed to parse seek table")?;
        let lower_frame = match args.from_frame {
            Some(idx) => idx,
            None => seek_table.frame_index_decomp(args.from.as_u64()),
        };
        let upper_frame = match args.to_frame {
            Some(idx) => idx,
            None => seek_table.frame_index_decomp(args.to.as_u64()),
        };
        let decoder = DecodeOptions::try_new(src)
            .context("Failed to create decode options")?
            .seek_table(seek_table)
            .lower_frame(lower_frame)
            .upper_frame(upper_frame)
            .into_decoder()
            .context("Failed to create decoder")?;

        Ok(Self { decoder })
    }
}

impl<'a> Decompressor<'a> {
    pub fn decompress_into<'b: 'a, W: Write>(
        mut self,
        writer: &mut W,
        prefix: Option<&'b [u8]>,
        bar: Option<&ProgressBar>,
    ) -> Result<u64> {
        let mut buf = vec![0; DCtx::out_size()];
        let mut buf_pos = 0;
        let mut written = 0;

        loop {
            let n = self
                .decoder
                .decompress_with_prefix(&mut buf[buf_pos..], prefix)
                .context("Failed to decompress data")?;
            if n == 0 {
                break;
            }
            if let Some(b) = bar {
                b.inc(n as u64);
            }
            buf_pos += n;
            if buf_pos == buf.len() {
                writer
                    .write_all(&buf)
                    .context("Failed to write decompressed data")?;
                written += buf_pos as u64;
                buf_pos = 0;
            }
        }
        writer
            .write_all(&buf[..buf_pos])
            .context("Failed to write decompressed data")?;
        written += buf_pos as u64;
        if let Some(b) = bar {
            b.finish_and_clear();
        }

        Ok(written)
    }
}
