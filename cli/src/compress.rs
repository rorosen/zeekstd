use std::{
    fs::File,
    io::{self, Read, Write},
};

use anyhow::{Context, Result, anyhow};
use indicatif::ProgressBar;
use zeekstd::{EncodeOptions, Encoder, seek_table::Format};
use zstd_safe::{CCtx, CParameter};

use crate::{args::CompressArgs, highbit_64};

pub struct Compressor<'a, W> {
    encoder: Encoder<'a, W>,
    seek_table_file: Option<File>,
}

impl<W> Compressor<'_, W> {
    pub fn new(
        args: &CompressArgs,
        prefix_len: Option<u64>,
        seek_table_file: Option<File>,
        writer: W,
    ) -> Result<Self> {
        let cctx_err = |msg, c| anyhow!("{msg}: {}", zstd_safe::get_error_name(c));
        let mut cctx = CCtx::try_create().context("Failed to create compression context")?;

        if let Some(len) = prefix_len {
            cctx.set_parameter(CParameter::WindowLog(highbit_64(len)))
                .map_err(|c| cctx_err("Failed to set window log", c))?;
            cctx.set_parameter(CParameter::EnableLongDistanceMatching(true))
                .map_err(|c| cctx_err("Failed to enable long distance matching", c))?;
        }

        let encoder = EncodeOptions::with_cctx(cctx)
            .frame_size_policy(args.to_frame_size_policy())
            .checksum_flag(!args.no_checksum)
            .compression_level(args.compression_level)
            .into_encoder(writer)
            .context("Failed to create encoder")?;

        Ok(Self {
            encoder,
            seek_table_file,
        })
    }
}

impl<'a, W: Write> Compressor<'a, W> {
    pub fn compress_reader<'b: 'a, R: Read>(
        mut self,
        reader: &mut R,
        prefix: Option<&'b [u8]>,
        bar: Option<&ProgressBar>,
    ) -> Result<(u64, u64)> {
        let mut buf = vec![0; CCtx::in_size()];
        let mut bytes_read = 0;

        loop {
            let limit = reader.read(&mut buf).context("Failed to read input")?;
            if limit == 0 {
                break;
            }
            bytes_read += limit as u64;
            if let Some(b) = bar {
                b.inc(limit as u64);
            }

            let mut buf_pos = 0;
            while buf_pos < limit {
                let input = &buf[buf_pos..limit];
                let n = self
                    .encoder
                    .compress_with_prefix(input, prefix)
                    .context("Failed to compress data")?;
                buf_pos += n;
            }
        }

        let bytes_written = match self.seek_table_file {
            Some(mut file) => {
                self.encoder
                    .end_frame()
                    .context("Failed to end last frame")?;
                self.encoder.flush().context("Failed to flush encoder")?;
                let written = self.encoder.written_compressed();
                let st = self.encoder.into_seek_table();
                let mut ser = st.into_format_serializer(Format::Head);
                let n = io::copy(&mut ser, &mut file).context("Failed to write seek table")?;
                written + n
            }
            None => self
                .encoder
                .finish()
                .context("Failed to finish compression")?,
        };

        if let Some(b) = bar {
            b.finish_and_clear();
        }
        Ok((bytes_read, bytes_written))
    }
}
