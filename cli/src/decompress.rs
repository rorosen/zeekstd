use std::{fs::File, io::Write};

use anyhow::{Context, Result, anyhow};
use indicatif::ProgressBar;
use zeekstd::{DecodeOptions, Decoder, SeekTable};
use zstd_safe::{DCtx, DParameter};

use crate::{args::DecompressArgs, highbit_64};

pub struct Decompressor<'a> {
    decoder: Decoder<'a, File>,
}

impl Decompressor<'_> {
    pub fn new(args: &DecompressArgs, prefix_len: Option<u64>) -> Result<Self> {
        let mut src = File::open(&args.input_file).context("Failed to open input file")?;
        let seek_table = match &args.shared.seek_table_file {
            Some(path) => {
                let mut file = File::open(path).context("Failed to open seek table file")?;
                SeekTable::from_reader(&mut file)
            }
            None => SeekTable::from_seekable(&mut src),
        }
        .context("Failed to parse seek table")?;

        let upper_frame = if args.to > seek_table.num_frames() {
            seek_table.num_frames() - 1
        } else {
            args.to
        };

        let mut dctx = DCtx::try_create().context("Failed to create decompression context")?;
        if let Some(len) = prefix_len {
            dctx.set_parameter(DParameter::WindowLogMax(highbit_64(len)))
                .map_err(|c| {
                    anyhow!(
                        "Failed to set max window log: {}",
                        zstd_safe::get_error_name(c)
                    )
                })?;
        }

        let decoder = DecodeOptions::with_dctx(src, dctx)
            .seek_table(seek_table)
            .lower_frame(args.from)
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
