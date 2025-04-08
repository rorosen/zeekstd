use std::{
    cmp,
    io::{self, Write},
};

use anyhow::{Context, Result, anyhow};
use zstd_safe::{InBuffer, OutBuffer, seekable::SeekableCStream};

use crate::args::CompressArgs;

pub struct Compressor<W> {
    out: W,
    stream: SeekableCStream,
    buf: Vec<u8>,
    bytes_written: u64,
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
            bytes_written: 0,
        })
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    #[cfg(test)]
    pub fn into_out(self) -> W {
        self.out
    }
}

impl<W: Write> Write for Compressor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
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
            self.out.write_all(out_buffer.as_slice())?;
            self.bytes_written += out_buffer.as_slice().len() as u64;
        }

        Ok(in_buffer.pos())
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            let mut out_buffer = OutBuffer::around(&mut self.buf);
            let remaining = self.stream.end_stream(&mut out_buffer).map_err(|c| {
                io::Error::other(format!(
                    "Failed to end stream: {}",
                    zstd_safe::get_error_name(c),
                ))
            })?;
            let n = self.out.write(out_buffer.as_slice())?;
            self.bytes_written += n as u64;
            if remaining == 0 {
                break;
            }
        }

        self.out.flush()
    }
}
