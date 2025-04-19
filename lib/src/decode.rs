use core::ops::Deref;

use xxhash_rust::xxh64::Xxh64;
use zstd_safe::{DCtx, InBuffer, OutBuffer, ResetDirective, zstd_sys::ZSTD_ErrorCode};

use crate::{
    error::{Error, Result},
    seek_table::SeekTable,
    seekable::{BytesWrapper, Seekable},
};

/// Options that configure how data is decompressed.
#[derive(Default)]
pub struct DecodeOptions<'d, 'p> {
    dctx: Option<DCtx<'d>>,
    prefix: Option<&'p [u8]>,
}

impl<'d, 'p> DecodeOptions<'d, 'p> {
    /// Creates a set of options with default initial values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a [`DCtx`].
    pub fn dctx(mut self, dctx: DCtx<'d>) -> Self {
        self.dctx = Some(dctx);
        self
    }

    /// References a prefix that gets re-applied to every frame.
    ///
    /// This is the reverse operation of setting a prefix during compression and must be the same
    /// prefix as the one used during compression. Referencing a raw content prefix has almost no
    /// cpu nor memory cost.
    pub fn prefix(mut self, prefix: &'p [u8]) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Creates a [`RawDecoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn into_raw_decoder(self, with_checksum: bool) -> Result<RawDecoder<'d, 'p>>
    where
        'p: 'd,
    {
        let mut dctx = if let Some(dctx) = self.dctx {
            dctx
        } else {
            DCtx::try_create().ok_or(Error::zstd_create("decompression context"))?
        };

        if let Some(prefix) = self.prefix {
            dctx.ref_prefix(prefix)?;
        }
        let xxh64 = with_checksum.then(|| Xxh64::new(0));

        Ok(RawDecoder {
            dctx,
            prefix: self.prefix,
            xxh64,
        })
    }

    /// Create a [`Decoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if zstd returns an error.
    pub fn into_decoder<S: Seekable>(self, mut src: S) -> Result<Decoder<'p, 'd, S>>
    where
        'p: 'd,
    {
        let seek_table = SeekTable::from_seekable(&mut src)?;
        let decomp = self.into_raw_decoder(seek_table.with_checksum())?;
        let upper_frame = seek_table.num_frames() - 1;

        Ok(Decoder {
            decomp,
            seek_table,
            src,
            src_pos: 0,
            lower_frame: 0,
            upper_frame,
            in_buf: vec![0; DCtx::in_size()],
            in_buf_pos: 0,
            in_buf_limit: 0,
        })
    }
}

/// A seekable decompressor.
///
/// Performs low level in-memory seekable decompression for streams of data.
pub struct RawDecoder<'d, 'p> {
    dctx: DCtx<'d>,
    prefix: Option<&'p [u8]>,
    xxh64: Option<Xxh64>,
}

impl RawDecoder<'_, '_> {
    /// Create a new `Decompressor` with default parameters.
    pub fn new(with_checksum: bool) -> Result<Self> {
        DecodeOptions::new().into_raw_decoder(with_checksum)
    }
}

impl<'d, 'p> RawDecoder<'d, 'p>
where
    'p: 'd,
{
    /// Performs a step of a streaming decompression from `input` to `output`.
    ///
    /// Call this repetitively to consume the input stream. Will return two numbers `(i, o)` where
    /// `i` is the input progress, i.e. the number of bytes that were consumed from `input`, and
    /// `o` is the output progress, i.e. the number of bytes written to `output`. The caller
    /// must check if `input` has been entirely consumed. If not, the caller must make some room
    /// to receive more decompressed data, and then present again remaining input data.
    ///
    /// `validate_checksum` gets called on every frame end with two parameters, `pos` and
    /// `checksum`, where `pos` is the current position in the input buffer and `checksum` are the
    /// least 32 bit of the XXH64 hash of the decompressed frame data. An `Ok(())` result of
    /// `validate_checksum` indicates that `checksum` was verified successfully, any other return
    /// value will result in a failed decompression immediately.
    pub fn decompress<F>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        validate_checksum: F,
    ) -> Result<(usize, usize)>
    where
        F: Fn(usize, u32) -> Result<()>,
    {
        let mut in_buf = InBuffer::around(input);
        let mut out_buf = OutBuffer::around(output);

        while in_buf.pos() < input.len() && out_buf.pos() < out_buf.capacity() {
            let prev_out_pos = out_buf.pos();
            let n = self.dctx.decompress_stream(&mut out_buf, &mut in_buf)?;

            if let Some(xxh) = &mut self.xxh64 {
                xxh.update(&out_buf.as_slice()[prev_out_pos..]);
            }

            // Frame end
            if n == 0 {
                if let Some(xxh) = &mut self.xxh64 {
                    // Only the least significant 32 bits of the hash are needed, so casting to
                    // u32 is ok.
                    validate_checksum(in_buf.pos(), xxh.digest() as u32)?;
                }

                self.reset_frame()?;
            }
        }

        Ok((in_buf.pos(), out_buf.pos()))
    }

    /// Resets the current frame.
    ///
    /// This will discard any decompression progress tracked for the current frame and resets
    /// the decompression context.
    pub fn reset_frame(&mut self) -> Result<()> {
        if let Some(prefix) = self.prefix {
            self.dctx
                .reset(ResetDirective::SessionOnly)
                .expect("Resetting session never fails");

            self.dctx.ref_prefix(prefix)?;
        }

        if let Some(xxh) = &mut self.xxh64 {
            xxh.reset(0);
        }

        Ok(())
    }
}

/// Decompresses data from a seekable source.
pub struct Decoder<'p, 'd, S> {
    decomp: RawDecoder<'d, 'p>,
    seek_table: SeekTable,
    src: S,
    src_pos: u64,
    lower_frame: u32,
    upper_frame: u32,
    in_buf: Vec<u8>,
    in_buf_pos: usize,
    in_buf_limit: usize,
}

impl<S: Seekable> Decoder<'_, '_, S> {
    /// Creates a new `Decoder` with default parameters and `src` as source.
    pub fn from_seekable(src: S) -> Result<Self> {
        DecodeOptions::new().into_decoder(src)
    }

    /// Creates a new `Decoder` with default parameters and a slice as source.
    ///
    /// The slice needs to hold the complete seekable data, including the seek table.
    pub fn from_bytes(src: &[u8]) -> Result<Decoder<'_, '_, BytesWrapper<'_>>> {
        let wrapper = BytesWrapper::new(src);
        DecodeOptions::new().into_decoder(wrapper)
    }
}

impl<'d, 'p, S> Decoder<'d, 'p, S>
where
    S: Seekable,
    'd: 'p,
{
    /// Decompresses data from the internal source and writes it to `buf`.
    ///
    /// Call this repetitively to decompress data. Returns the number of bytes written to `buf`.
    pub fn decode(&mut self, buf: &mut [u8]) -> Result<usize> {
        let end_pos = self.seek_table.frame_end_comp(self.upper_frame)?;
        if self.src_pos == 0 {
            let start_pos = self.seek_table.frame_start_comp(self.lower_frame)?;
            self.src.set_offset(start_pos)?;
            self.src_pos = start_pos;
            self.decomp.reset_frame()?;
        }

        let mut output_progress = 0;
        while self.src_pos < end_pos && output_progress < buf.len() {
            if self.in_buf_pos == self.in_buf_limit {
                // Casting is ok because max value is buf.len()
                let limit = (end_pos - self.src_pos).min(self.in_buf.len() as u64) as usize;
                self.in_buf_limit = self.src.read(&mut self.in_buf[..limit])?;
                self.in_buf_pos = 0;
            }

            let (inp_prog, out_prog) = self.decomp.decompress(
                &self.in_buf[self.in_buf_pos..self.in_buf_limit],
                &mut buf[output_progress..],
                // This gets only called if the seek table has checksums, we can expect every frame
                // to have a checksum inside the callback.
                |offset: usize, checksum: u32| {
                    let index = self
                        .seek_table
                        // self.src_pos + offset will be the ending of the frame we just finished,
                        // which is also the start of the next frame. Subtract 1 to get the index
                        // of the right frame.
                        .frame_index_comp(self.src_pos + offset as u64 - 1);
                    let expected = self
                        .seek_table
                        .frame_checksum(index)?
                        .expect("Frame has a checksum");

                    if checksum == expected {
                        Ok(())
                    } else {
                        Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected))
                    }
                },
            )?;

            self.src_pos += inp_prog as u64;
            self.in_buf_pos += inp_prog;
            output_progress += out_prog;
        }
        Ok(output_progress)
    }

    /// Resets the current frame.
    ///
    /// This will discard any decompression progress tracked for the current frame and resets
    /// the decompression context.
    pub fn reset_frame(&mut self) -> Result<()> {
        self.decomp.reset_frame()?;
        self.src_pos = 0;
        self.in_buf_pos = 0;
        self.in_buf_limit = 0;

        Ok(())
    }

    /// Sets the index of the frame where decompression starts.
    ///
    /// Resets the current frame decompression progress, this shouldn't be called in the middle of
    /// a decompression operation.
    pub fn set_lower_frame(&mut self, index: u32) -> Result<()> {
        self.lower_frame = index;
        self.reset_frame()?;

        Ok(())
    }

    /// Set the index of the last frame that is included in decompression.
    pub fn set_upper_frame(&mut self, index: u32) {
        self.upper_frame = index;
    }
}

impl<S> Deref for Decoder<'_, '_, S> {
    type Target = SeekTable;

    fn deref(&self) -> &Self::Target {
        &self.seek_table
    }
}

impl<'d, 'p, S> std::io::Read for Decoder<'d, 'p, S>
where
    S: Seekable,
    'd: 'p,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decode(buf).map_err(std::io::Error::other)
    }
}
