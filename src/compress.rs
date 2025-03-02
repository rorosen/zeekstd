use std::{
    cmp,
    io::{self, Write},
};

use anyhow::{anyhow, Context, Result};
use zstd_safe::{seekable::SeekableCStream, InBuffer, OutBuffer};

use crate::args::CompressArgs;

pub struct Compressor<W> {
    out: W,
    stream: SeekableCStream,
    buf: Vec<u8>,
}

impl<W: Write> Compressor<W> {
    pub fn new(args: &CompressArgs, out: W) -> Result<Self> {
        let mut stream = SeekableCStream::try_create()
            .context("Failed to create seekable compression stream")?;
        stream
            .init(
                args.compression_level,
                !args.no_checksum,
                args.max_frame_size.as_u32(),
            )
            .map_err(|c| {
                anyhow!(
                    "Failed to initialize seekable compression stream: {}",
                    zstd_safe::get_error_name(c)
                )
            })?;

        Ok(Self {
            out,
            stream,
            buf: vec![0u8; cmp::min(args.max_frame_size.as_u32(), 8192) as usize],
        })
    }

    pub fn end_stream(&mut self) -> Result<()> {
        loop {
            let mut out_buffer = OutBuffer::around(&mut self.buf);
            let n = self
                .stream
                .end_stream(&mut out_buffer)
                .map_err(|c| anyhow!("Failed to end stream: {}", zstd_safe::get_error_name(c)))?;
            self.out
                .write(out_buffer.as_slice())
                .context("Failed to write seek table")?;
            if n == 0 {
                break;
            }
        }

        self.out.flush().context("Failed to flush output")
    }
}

impl<W: Write> Write for Compressor<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut in_buffer = InBuffer::around(buf);

        while in_buffer.pos() < buf.len() {
            let mut out_buffer = OutBuffer::around(&mut self.buf);
            self.stream
                .compress_stream(&mut out_buffer, &mut in_buffer)
                .map_err(|c| {
                    io::Error::other(format!(
                        "Failed to compress data: {}",
                        zstd_safe::get_error_name(c)
                    ))
                })?;
            self.out.write(out_buffer.as_slice())?;
        }

        Ok(in_buffer.pos())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}
