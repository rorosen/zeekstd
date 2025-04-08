use std::io::{self, Write};

use xxhash_rust::xxh64::Xxh64;
use zstd_safe::{
    CCtx, InBuffer, OutBuffer, ResetDirective,
    zstd_sys::{ZSTD_EndDirective, ZSTD_ErrorCode},
};

use crate::{
    error::{Error, Result},
    frame_log::{FrameLog, FrameLogReader},
};

enum FramePolicy {
    Compressed(u32),
    Decompressed(u32),
}

/// A policy that controls when new frames are started automatically.
pub struct FrameSizePolicy(FramePolicy);

impl Default for FrameSizePolicy {
    fn default() -> Self {
        // 2 MiB
        Self(FramePolicy::Decompressed(0x200_000))
    }
}

impl FrameSizePolicy {
    /// Start a new frame when the compressed size of the current frame exceeds `size`. Note that
    /// the compressed frames will be slightly larger than `size`, depending on the write buffer
    /// size.
    ///
    /// Make sure that the uncompressed frame is always smaller than 1GiB. This cannot be known
    /// based on the compressed size and will not be checked during compression.
    ///
    /// # Errors
    ///
    /// This method fails if `size` exceeds 1GiB.
    pub fn compressed(size: u32) -> Result<Self> {
        Self::check_size(size)?;
        Ok(Self(FramePolicy::Compressed(size)))
    }

    /// Start a new frame when the decompressed data of the current frame reaches `limit`.
    ///
    /// # Errors
    ///
    /// This method fails if `limit` exceeds 1GiB.
    pub fn decompressed(limit: u32) -> Result<Self> {
        Self::check_size(limit)?;
        Ok(Self(FramePolicy::Decompressed(limit)))
    }

    fn check_size(size: u32) -> Result<()> {
        if size > 0x40000000 {
            return Err(Error::zstd(
                ZSTD_ErrorCode::ZSTD_error_frameParameter_unsupported,
            ));
        }

        Ok(())
    }
}

struct FrameSize {
    compressed: u32,
    decompressed: u32,
    policy: FramePolicy,
}

impl FrameSize {
    fn update_compressed(&mut self, delta: u32) {
        self.compressed += delta;
    }

    fn update_decompressed(&mut self, delta: u32) {
        self.decompressed += delta;
    }

    fn until_limit(&self) -> usize {
        match self.policy {
            FramePolicy::Compressed(_) => usize::MAX,
            FramePolicy::Decompressed(limit) => (limit - self.decompressed) as usize,
        }
    }

    fn is_frame_complete(&self) -> bool {
        match self.policy {
            FramePolicy::Compressed(size) => size <= self.compressed,
            FramePolicy::Decompressed(limit) => limit == self.decompressed,
        }
    }

    fn reset(&mut self) {
        self.compressed = 0;
        self.decompressed = 0;
    }
}

impl From<FrameSizePolicy> for FrameSize {
    fn from(value: FrameSizePolicy) -> Self {
        Self {
            compressed: 0,
            decompressed: 0,
            policy: value.0,
        }
    }
}

/// A builder that creates a [`Compressor`] with custom configuration.
pub struct CompressorBuilder<'c, 'p> {
    cctx: Option<CCtx<'c>>,
    frame_size_policy: Option<FrameSizePolicy>,
    with_checksum: bool,
    prefix: Option<&'p [u8]>,
}

impl Default for CompressorBuilder<'_, '_> {
    fn default() -> Self {
        Self {
            cctx: None,
            frame_size_policy: None,
            with_checksum: true,
            prefix: None,
        }
    }
}

impl<'c, 'p> CompressorBuilder<'c, 'p>
where
    'p: 'c,
{
    /// Creates a new [`CompressorBuilder`] with default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`CCtx`] of this builder.
    pub fn cctx(mut self, cctx: CCtx<'c>) -> Self {
        self.cctx = Some(cctx);
        self
    }

    /// Set the [`FrameSizePolicy`] of this builder.
    pub fn frame_size_policy(mut self, policy: FrameSizePolicy) -> Self {
        self.frame_size_policy = Some(policy);
        self
    }

    /// Whether or not the seek table should include checksums on the uncompressed data.
    ///
    /// The least significant 32 bits of the XXH64 hash of the uncompressed frame data are used as
    /// checksum. Each frame has an individual checksum.
    pub fn with_checksum(mut self, with_checksum: bool) -> Self {
        self.with_checksum = with_checksum;
        self
    }

    /// Reference a prefix for every frame.
    ///
    /// Decompression will need same prefix to properly regenerate data. Referencing a prefix
    /// involves building tables, which are dependent on compression parameters. It's a CPU
    /// consuming operation, with non-negligible impact on latency, this shouldn't be used for
    /// small frame sizes. Adding any prefix invalidates any previous prefix or dictionary of
    /// [`CCtx`].
    pub fn prefix(mut self, prefix: &'p [u8]) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Create a [`Compressor`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn build<W>(self, writer: W) -> Result<Compressor<'c, 'p, W>> {
        let mut cctx = if let Some(cctx) = self.cctx {
            cctx
        } else {
            CCtx::try_create().ok_or(Error::zstd_create("compression context"))?
        };

        if let Some(prefix) = self.prefix {
            cctx.ref_prefix(prefix)?;
        }

        let capacity = CCtx::out_size();
        let frame_size = self.frame_size_policy.unwrap_or_default().into();
        let xxh64 = self.with_checksum.then(|| Xxh64::new(0));

        Ok(Compressor {
            cctx,
            frame_size,
            out_buf: Vec::with_capacity(capacity),
            prefix: self.prefix,
            frame_log: FrameLog::new(self.with_checksum),
            writer,
            xxh64,
        })
    }
}

/// A compression stream.
///
/// Data written to `Compressor` will be compressed and automatically split into frames according
/// to the [`FrameSizePolicy`] in use.
pub struct Compressor<'c, 'p, W> {
    cctx: CCtx<'c>,
    frame_size: FrameSize,
    out_buf: Vec<u8>,
    prefix: Option<&'p [u8]>,
    frame_log: FrameLog,
    writer: W,
    xxh64: Option<Xxh64>,
}

impl<W> Compressor<'_, '_, W> {
    /// Create a new `Compressor` with default parameters.
    pub fn new(writer: W) -> Result<Self> {
        CompressorBuilder::default().build(writer)
    }
}

impl<'c, 'p, W: Write> Compressor<'c, 'p, W>
where
    'p: 'c,
{
    /// End the current frame and start a new one.
    ///
    /// # Returns
    ///
    /// The number of bytes written.
    pub fn end_frame(&mut self) -> Result<u64> {
        let mut written = 0;
        let mut empty_buffer = InBuffer::around(&[]);
        loop {
            let mut out_buffer = OutBuffer::around(&mut self.out_buf);
            let n = self.cctx.compress_stream2(
                &mut out_buffer,
                &mut empty_buffer,
                ZSTD_EndDirective::ZSTD_e_end,
            )?;
            self.writer.write_all(out_buffer.as_slice())?;
            written += out_buffer.pos();
            self.frame_size.update_compressed(out_buffer.pos() as u32);

            if n == 0 {
                break;
            }
        }

        let checksum = self
            .xxh64
            .as_ref()
            .map(|x| (x.digest() & 0xFFFFFFFF) as u32);
        self.frame_log.log_frame(
            self.frame_size.compressed,
            self.frame_size.decompressed,
            checksum,
        )?;

        self.frame_size.reset();
        self.cctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");
        if let Some(xxh) = &mut self.xxh64 {
            xxh.reset(0);
        }
        if let Some(prefix) = self.prefix {
            self.cctx.ref_prefix(prefix)?;
        }

        Ok(written as u64)
    }

    /// End the current frame and write the seek table.
    ///
    /// # Returns
    ///
    /// The number of bytes written.
    pub fn finish(mut self) -> Result<u64> {
        // Drop the prefix so it doesn't get set again.
        let _ = self.prefix.take();
        let mut written = self.end_frame()?;

        let mut reader = FrameLogReader::from(self.frame_log);
        loop {
            let n = io::copy(&mut reader, &mut self.writer)?;
            if n == 0 {
                break;
            }
            written += n;
        }
        self.writer.flush()?;

        Ok(written)
    }
}

impl<'c, 'p, W: Write> Write for Compressor<'c, 'p, W>
where
    'p: 'c,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let limit = buf.len().min(self.frame_size.until_limit());
        let mut in_buffer = InBuffer::around(&buf[..limit]);

        while in_buffer.pos() < limit {
            let mut out_buffer = OutBuffer::around(&mut self.out_buf);
            self.cctx
                .compress_stream2(
                    &mut out_buffer,
                    &mut in_buffer,
                    ZSTD_EndDirective::ZSTD_e_continue,
                )
                .map_err(|c| {
                    io::Error::other(format!(
                        "failed to compress data: {}",
                        zstd_safe::get_error_name(c)
                    ))
                })?;
            self.writer.write_all(out_buffer.as_slice())?;
            self.frame_size.update_compressed(out_buffer.pos() as u32);
        }

        self.frame_size.update_decompressed(in_buffer.pos() as u32);
        if let Some(xxh) = &mut self.xxh64 {
            xxh.update(&buf[..in_buffer.pos()]);
        }

        if self.frame_size.is_frame_complete() {
            self.end_frame()
                .map_err(|err| io::Error::other(format!("failed to end frame: {err}")))?;
        }

        Ok(in_buffer.pos())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
