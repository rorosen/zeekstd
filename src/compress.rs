use std::{
    cmp,
    io::{Read, Write},
};

use anyhow::{anyhow, Context, Result};
use indicatif::ProgressBar;
use zstd_safe::{seekable::SeekableCStream, CompressionLevel, InBuffer, OutBuffer};

pub struct Compressor {
    stream: SeekableCStream,
    max_frame_size: u32,
}

impl Compressor {
    pub fn new(
        compression_level: CompressionLevel,
        checksum_flag: bool,
        max_frame_size: u32,
    ) -> Result<Self> {
        let mut stream = SeekableCStream::try_create()
            .context("Failed to create seekable compression stream")?;
        stream
            .init(compression_level, checksum_flag, max_frame_size)
            .map_err(|c| {
                anyhow!(
                    "Failed to initialize seekable compression stream: {}",
                    zstd_safe::get_error_name(c)
                )
            })?;

        Ok(Self {
            stream,
            max_frame_size,
        })
    }

    pub fn compress_reader(
        &mut self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
        bar: &Option<ProgressBar>,
    ) -> Result<()> {
        let cap = cmp::min(self.max_frame_size, 8192) as usize;
        let mut in_buf = vec![0u8; cap];
        let mut out_buf = vec![0u8; cap];

        loop {
            let n = reader.read(&mut in_buf).context("Failed to read")?;
            if n == 0 {
                break;
            }
            if let Some(b) = bar {
                b.inc(n as u64);
            }
            let mut in_buffer = InBuffer::around(&in_buf[..n]);

            while in_buffer.pos() < n {
                let mut out_buffer = OutBuffer::around(&mut out_buf);
                self.stream
                    .compress_stream(&mut out_buffer, &mut in_buffer)
                    .map_err(|c| {
                        anyhow!(
                            "Failed to compress stream: {}",
                            zstd_safe::get_error_name(c)
                        )
                    })?;
                writer
                    .write(out_buffer.as_slice())
                    .context("Failed to write compressed data")?;
            }
        }

        loop {
            let mut out_buffer = OutBuffer::around(&mut out_buf);
            let n = self
                .stream
                .end_stream(&mut out_buffer)
                .map_err(|c| anyhow!("Failed to end stream: {}", zstd_safe::get_error_name(c)))?;
            writer
                .write(out_buffer.as_slice())
                .context("Failed to write seek table")?;
            if n == 0 {
                break;
            }
        }

        writer.flush().context("Failed to flush output")
    }
}
