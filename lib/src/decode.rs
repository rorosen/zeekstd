use zstd_safe::{DCtx, InBuffer, OutBuffer, ResetDirective};

use crate::{Error, error::Result, seek_table::SeekTable, seekable::Seekable};

/// Options that configure how data is decompressed.
///
/// # Examples
///
/// Supports builder like chaining.
///
/// ```no_run
/// use std::fs::File;
/// use zeekstd::{DecodeOptions, FrameSizePolicy};
///
/// let mut seekable = File::open("seekable.zst")?;
/// let decoder = DecodeOptions::new(&mut seekable)
///     .lower_frame(2)
///     .upper_frame(6)
///     .into_decoder()?;
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct DecodeOptions<'a, S> {
    dctx: DCtx<'a>,
    src: S,
    seek_table: Option<SeekTable>,
    lower_frame: Option<u32>,
    offset: Option<u64>,
    upper_frame: Option<u32>,
    offset_limit: Option<u64>,
}

impl<'a, S> DecodeOptions<'a, S> {
    /// Creates a set of options with default initial values.
    ///
    /// # Panics
    ///
    /// If allocation of [`DCtx`] fails.
    pub fn new(src: S) -> Self {
        Self::with_dctx(src, DCtx::create())
    }

    /// Tries to create new options.
    ///
    /// Returns `None` if allocation of [`DCtx`] fails.
    pub fn try_new(src: S) -> Option<Self> {
        let dctx = DCtx::try_create()?;
        Some(Self::with_dctx(src, dctx))
    }

    /// Creates options with the given decompression context.
    pub fn with_dctx(src: S, dctx: DCtx<'a>) -> Self {
        Self {
            dctx,
            src,
            seek_table: None,
            lower_frame: None,
            offset: None,
            upper_frame: None,
            offset_limit: None,
        }
    }

    /// Sets a [`DCtx`].
    pub fn dctx(mut self, dctx: DCtx<'a>) -> Self {
        self.dctx = dctx;
        self
    }

    /// Sets the [`SeekTable`] for this options.
    ///
    /// If a seek table is set, it will be used directly during decompression instead of reading
    /// the seek table from the seekable `src`.
    pub fn seek_table(mut self, seek_table: SeekTable) -> Self {
        self.seek_table = Some(seek_table);
        self
    }

    /// Sets the frame where decompression starts.
    ///
    /// Overrides the offset set with [`Self::offset`] if both are specified.
    pub fn lower_frame(mut self, index: u32) -> Self {
        self.lower_frame = Some(index);
        self
    }

    /// Sets the last frame that is included in decompression.
    ///
    /// Overrides the offset limit set with [`Self::offset_limit`] if both are specified.
    pub fn upper_frame(mut self, index: u32) -> Self {
        self.upper_frame = Some(index);
        self
    }

    /// Sets the decompression offset.
    ///
    /// The offset is the position in the decompressed data of the seekable source from which
    /// decompression starts.
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Sets a limit for the decompression offset.
    ///
    /// The limit is the position in the decompressed data of the seekable source at which
    /// decompresion stops.
    pub fn offset_limit(mut self, limit: u64) -> Self {
        self.offset_limit = Some(limit);
        self
    }
}

impl<'a, S: Seekable> DecodeOptions<'a, S> {
    /// Builds a [`Decoder`] with the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the decoder could not created.
    pub fn into_decoder(self) -> Result<Decoder<'a, S>> {
        Decoder::with_opts(self)
    }
}

/// Decompresses data from a seekable source.
///
/// A decoder reads compressed data from a seekable source.
pub struct Decoder<'a, S> {
    dctx: DCtx<'a>,
    seek_table: SeekTable,
    src: S,
    decomp_pos: u64,
    offset: u64,
    offset_limit: u64,
    in_buf: Vec<u8>,
    in_buf_pos: usize,
    in_buf_limit: usize,
    out_buf: Vec<u8>,
    read_compressed: u64,
}

impl<'a, S: Seekable> Decoder<'a, S> {
    /// Creates a new `Decoder` with default parameters and `src` as source.
    ///
    /// This is equivalent to calling `DecodeOptions::new(src).into_decoder()`.
    ///
    /// # Errors
    ///
    /// Fails if the decoder could not be created.
    pub fn new(src: S) -> Result<Self> {
        Self::with_opts(DecodeOptions::new(src))
    }

    /// Creates a new `Decoder` with the given [`DecodeOptions`].
    ///
    /// # Errors
    ///
    /// Fails if the decoder could not be created.
    pub fn with_opts(mut opts: DecodeOptions<'a, S>) -> Result<Self> {
        let seek_table = opts
            .seek_table
            .map_or_else(|| SeekTable::from_seekable(&mut opts.src), Ok)?;

        let offset = if let Some(index) = opts.lower_frame {
            seek_table.frame_start_decomp(index)?
        } else {
            opts.offset.unwrap_or(0)
        };

        Self::check_offset(offset, &seek_table)?;

        let offset_limit = if let Some(index) = opts.upper_frame {
            seek_table.frame_end_decomp(index)?
        } else {
            opts.offset_limit
                .unwrap_or_else(|| seek_table.size_decomp())
        };

        Self::check_offset(offset_limit, &seek_table)?;

        Ok(Self {
            dctx: opts.dctx,
            seek_table,
            src: opts.src,
            decomp_pos: 0,
            offset,
            offset_limit,
            in_buf: vec![0; DCtx::in_size()],
            in_buf_pos: 0,
            in_buf_limit: 0,
            out_buf: vec![0; DCtx::out_size()],
            read_compressed: 0,
        })
    }

    /// Decompresses data from the internal source.
    ///
    /// Call this repetetively to fill `buf` with decompressed data. Returns the number of bytes
    /// written to `buf`.
    ///
    /// If a `prefix` is passed, it will be re-applied to every frame, as tables are discarded at
    /// end of frame. Referencing a raw content prefix has almost no cpu nor memory cost.
    ///
    /// # Errors
    ///
    /// If decompression fails or any parameter is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn decompress_with_prefix<'b: 'a>(
        &mut self,
        buf: &mut [u8],
        prefix: Option<&'b [u8]>,
    ) -> Result<usize> {
        if self.read_compressed == 0 {
            let frame_idx = self.seek_table.frame_index_decomp(self.offset);
            let start_pos = self.seek_table.frame_start_comp(frame_idx)?;
            self.src.set_offset(start_pos)?;
            self.decomp_pos = self.seek_table.frame_start_decomp(frame_idx)?;
            // Reference prefix at the beginning of decompression
            if let Some(pref) = prefix {
                self.dctx.ref_prefix(pref)?;
            }
            // Trigger reading from src
            self.in_buf_pos = 0;
            self.in_buf_limit = 0;
        }

        let mut output_progress = 0;
        while self.offset < self.offset_limit && output_progress < buf.len() {
            if self.in_buf_pos == self.in_buf_limit {
                self.in_buf_limit = self.src.read(&mut self.in_buf)?;
                self.in_buf_pos = 0;
            }

            let mut in_buffer = InBuffer::around(&self.in_buf[self.in_buf_pos..self.in_buf_limit]);
            let mut out_buffer = if self.decomp_pos < self.offset {
                // Dummy decompression until we get to offset
                let limit = (self.offset - self.decomp_pos).min(self.out_buf.len() as u64) as usize;
                OutBuffer::around(&mut self.out_buf[..limit])
            } else {
                let limit = (self.offset_limit - self.decomp_pos).min(buf.len() as u64) as usize;
                OutBuffer::around(&mut buf[output_progress..limit])
            };

            let in_len = self.in_buf_limit - self.in_buf_pos;
            while in_buffer.pos() < in_len && out_buffer.pos() < out_buffer.capacity() {
                let n = self
                    .dctx
                    .decompress_stream(&mut out_buffer, &mut in_buffer)?;
                // Frame end
                // TODO: chain when stable
                if n == 0 {
                    if let Some(pref) = prefix {
                        self.dctx
                            .reset(ResetDirective::SessionOnly)
                            .expect("Resetting session never fails");
                        self.dctx.ref_prefix(pref)?;
                    }
                }
            }

            self.decomp_pos += out_buffer.pos() as u64;
            self.in_buf_pos += in_buffer.pos();
            self.read_compressed += in_buffer.pos() as u64;

            // Only add progress if we actually wrote something to buf
            if self.decomp_pos > self.offset {
                self.offset += out_buffer.pos() as u64;
                output_progress += out_buffer.pos();
            }
        }

        Ok(output_progress)
    }
}

impl<S: Seekable> Decoder<'_, S> {
    /// Decompresses data from the internal source.
    ///
    /// Call this repetetively to fill `buf` with decompressed data. Returns the number of bytes
    /// written to `buf`.
    ///
    /// # Errors
    ///
    /// If decompression fails or any parameter is invalid.
    pub fn decompress(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.decompress_with_prefix(buf, None)
    }

    /// Resets the current decompresion status.
    ///
    /// This resets the internal decompression context as well as decompression offset and limit.
    /// The next decompression after this function will start from the beginning of the seekable
    /// source.
    pub fn reset(&mut self) {
        self.reset_dctx();
        self.offset = 0;
        self.offset_limit = self.seek_table().size_decomp();
    }

    fn reset_dctx(&mut self) {
        self.read_compressed = 0;
        self.dctx
            .reset(ResetDirective::SessionOnly)
            .expect("Resetting session never fails");
    }

    /// Sets the decompression offset to the beginning of the frame at `index`.
    ///
    /// This has the same effect as calling [`Self::set_offset`] with the decompressed start
    /// position of the frame at `index`.
    ///
    /// # Errors
    ///
    /// When the the passed frame index is out of range.
    pub fn set_lower_frame(&mut self, index: u32) -> Result<u64> {
        let offset = self.seek_table.frame_start_decomp(index)?;
        self.set_offset(offset)?;

        Ok(offset)
    }

    /// Sets the limit for the decompression offset to the end of the frame at `index`.
    ///
    /// This has the same effect as calling [`Self::set_offset_limit`] with the decompressed end
    /// position of the frame at `index`. The current decompression state will not be reset, it is
    /// possible to change the upper frame in the middle of a decompression operation.
    ///
    /// # Errors
    ///
    /// When the the passed frame index is out of range.
    pub fn set_upper_frame(&mut self, index: u32) -> Result<u64> {
        let offset = self.seek_table.frame_end_decomp(index)?;
        self.set_offset_limit(offset)?;

        Ok(offset)
    }

    /// Sets the decompression offset.
    ///
    /// The offset is the position in the _decompressed_ data of the seekable source from which
    /// decompression starts. If possible, the decoder will continue decompression from the current
    /// internal state.
    ///
    /// **Note**: If the passed offset is not the beginning of a frame, the decoder will perform a
    /// dummy decompression from the beginning of the frame up to the offset position.
    ///
    /// # Errors
    ///
    /// When the passed offset is out of range.
    pub fn set_offset(&mut self, offset: u64) -> Result<()> {
        Self::check_offset(offset, self.seek_table())?;
        let current_frame = self.seek_table().frame_index_decomp(self.offset);
        let target_frame = self.seek_table().frame_index_decomp(offset);

        // Only reset if we cannot continue from previous decompression
        if current_frame != target_frame || offset < self.offset {
            self.reset_dctx();
        }
        self.offset = offset;

        Ok(())
    }

    /// Sets a limit for the decompression offset.
    ///
    /// The limit is the position in the _decompressed_ data of the seekable source at which
    /// decompresion stops. This does not reset the current decompression state, the limit can be
    /// changed in the middle of a decompression operation without interrupting an ongoing
    /// decompression operation. It is possible to set a limit that is lower than the applied
    /// offset. However, it will lead to any decompression operation making no progress, i.e.
    /// it will produce zero decompressed bytes.
    ///
    /// **Note**: The decoder will immediately stop decompression at the specified limit. The
    /// frame checksum of the last decompressed frame will not be verified, if the limit isn't at
    /// the end of a frame.
    ///
    /// # Errors
    ///
    /// When the passed limit is out of range.
    pub fn set_offset_limit(&mut self, limit: u64) -> Result<()> {
        Self::check_offset(limit, self.seek_table())?;
        self.offset_limit = limit;

        Ok(())
    }

    fn check_offset(offset: u64, seek_table: &SeekTable) -> Result<()> {
        if offset > seek_table.size_decomp() {
            Err(Error::offset_out_of_range())
        } else {
            Ok(())
        }
    }

    /// Gets the total number of compressed bytes read since the last reset.
    pub fn read_compressed(&self) -> u64 {
        self.read_compressed
    }

    /// Gets a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.seek_table
    }

    /// Gets the current offset of this decoder.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Gets the offset limit of this decoder.
    pub fn offset_limit(&self) -> u64 {
        self.offset_limit
    }
}

impl<S: Seekable> std::io::Read for Decoder<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decompress(buf).map_err(std::io::Error::other)
    }
}

impl<S: Seekable> std::io::Seek for Decoder<'_, S> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::{self, SeekFrom};

        match pos {
            SeekFrom::Start(offset) => {
                self.set_offset(offset).map_err(io::Error::other)?;
                Ok(offset)
            }
            SeekFrom::End(n) => {
                if n > 0 {
                    return Err(io::Error::other(Error::offset_out_of_range()));
                }

                let offset = self
                    .seek_table()
                    .size_decomp()
                    .checked_add_signed(n)
                    .ok_or(io::Error::other(Error::offset_out_of_range()))?;
                self.set_offset(offset).map_err(io::Error::other)?;

                Ok(offset)
            }
            SeekFrom::Current(n) => {
                let offset = self
                    .offset
                    .checked_add_signed(n)
                    .ok_or(io::Error::other(Error::offset_out_of_range()))?;
                self.set_offset(offset).map_err(io::Error::other)?;

                Ok(offset)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Cursor, Read, Seek, SeekFrom},
    };

    use crate::{EncodeOptions, FrameSizePolicy, tests::test_input};

    use super::*;

    fn new_seekable(input: &[u8], frame_size_policy: Option<FrameSizePolicy>) -> Cursor<Vec<u8>> {
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(frame_size_policy.unwrap_or_default())
            .into_encoder(&mut seekable)
            .unwrap();

        // Compress the input
        let n = encoder.compress(input).unwrap();
        assert_eq!(n, input.len());
        let n = encoder.finish().unwrap();
        assert_eq!(n, seekable.position());

        seekable
    }

    #[test]
    fn options() {
        let input = fs::read(test_input()).unwrap();
        let seekable = new_seekable(&input, None);
        let st = SeekTable::from_seekable(&mut seekable.clone()).unwrap();

        let oks = [
            DecodeOptions::new(seekable.clone()),
            DecodeOptions::new(seekable.clone()).lower_frame(st.num_frames() - 1),
            DecodeOptions::new(seekable.clone()).upper_frame(st.num_frames() - 1),
            DecodeOptions::new(seekable.clone()).offset(st.size_decomp()),
            DecodeOptions::new(seekable.clone()).offset_limit(st.size_decomp()),
            DecodeOptions::new(Cursor::new(vec![128, 0])).seek_table(st.clone()),
        ];

        let errs = [
            DecodeOptions::new(Cursor::new(vec![128, 0])),
            DecodeOptions::new(seekable.clone()).lower_frame(st.num_frames()),
            DecodeOptions::new(seekable.clone()).upper_frame(st.num_frames()),
            DecodeOptions::new(seekable.clone()).offset(st.size_decomp() + 1),
            DecodeOptions::new(seekable.clone()).offset_limit(st.size_decomp() + 1),
        ];

        for opts in oks {
            assert!(opts.into_decoder().is_ok());
        }

        for opts in errs {
            assert!(opts.into_decoder().is_err());
        }
    }

    #[test]
    fn decompress_and_reset() {
        let input = fs::read(test_input()).unwrap();
        let seekable = new_seekable(&input, None);
        let mut decoder = Decoder::new(seekable).unwrap();

        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();

        assert_eq!(n, output.len());
        assert_eq!(input, output);

        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, 0);

        decoder.reset();
        let n = decoder.decompress(&mut output).unwrap();

        assert_eq!(n, output.len());
        assert_eq!(input, output);
    }

    #[test]
    fn decompress_until_upper_frame() {
        let input = fs::read(test_input()).unwrap();
        let frame_size = input.len() / 7;
        let seekable = new_seekable(
            &input,
            Some(FrameSizePolicy::Uncompressed(frame_size as u32)),
        );
        let mut decoder = Decoder::new(seekable).unwrap();

        // Decompress until frame 5 (inclusive)
        decoder.set_lower_frame(0).unwrap();
        decoder.set_upper_frame(5).unwrap();

        let len = frame_size * 6;
        let mut output = vec![0; len];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, len);
        assert_eq!(&input[..n], &output);
    }

    #[test]
    fn decompress_last_frames() {
        let input = fs::read(test_input()).unwrap();
        let frame_size = input.len() / 9;
        let seekable = new_seekable(
            &input,
            Some(FrameSizePolicy::Uncompressed(frame_size as u32)),
        );
        let mut decoder = Decoder::new(seekable).unwrap();

        // Decompress the last 4 frames
        decoder.set_lower_frame(5).unwrap();
        decoder.set_upper_frame(9).unwrap();

        let len = input.len() - frame_size * 5;
        let mut output = vec![0; len];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, len);
        assert_eq!(&input[input.len() - n..], &output);
    }

    #[test]
    fn upper_frame_greater_than_lower_frame() {
        let input = fs::read(test_input()).unwrap();
        let frame_size = input.len() / 13;
        let seekable = new_seekable(
            &input,
            Some(FrameSizePolicy::Uncompressed(frame_size as u32)),
        );
        let mut decoder = Decoder::new(seekable).unwrap();

        // Lower frame greater than upper frame, expect zero bytes read
        decoder.set_lower_frame(9).unwrap();
        decoder.set_upper_frame(8).unwrap();
        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(0, n);
    }

    #[test]
    fn reset_decompression() {
        let input = fs::read(test_input()).unwrap();
        let seekable = new_seekable(&input, None);
        let mut decoder = Decoder::new(seekable).unwrap();

        // Dummy decompression so we can reset something
        decoder.decompress(&mut [0; 128]).unwrap();
        decoder.reset();
        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, input.len());
        assert_eq!(input, output);
    }

    #[test]
    fn decompress_everything_after_partly_decompression() {
        let input = fs::read(test_input()).unwrap();
        let frame_size = input.len() / 32;
        let seekable = new_seekable(
            &input,
            Some(FrameSizePolicy::Uncompressed(frame_size as u32)),
        );
        let mut decoder = Decoder::new(seekable).unwrap();

        decoder.set_lower_frame(23).unwrap();
        decoder.set_upper_frame(29).unwrap();

        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, frame_size * 30 - frame_size * 23);
        assert_eq!(input[frame_size * 23..frame_size * 30], output[..n]);

        // Decompress all frames
        decoder.set_lower_frame(0).unwrap();
        decoder
            .set_upper_frame(decoder.seek_table().num_frames() - 1)
            .unwrap();
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, input.len());
        assert_eq!(input, output);
    }

    #[test]
    fn set_frame_boundaries() {
        let input = fs::read(test_input()).unwrap();
        let seekable = new_seekable(&input, None);
        let mut decoder = Decoder::new(seekable).unwrap();
        let num_frames = decoder.seek_table().num_frames();

        assert!(decoder.set_lower_frame(num_frames - 1).is_ok());
        assert!(decoder.set_upper_frame(num_frames - 1).is_ok());

        // Frame index out of range
        assert!(
            decoder
                .set_lower_frame(num_frames)
                .unwrap_err()
                .is_frame_index_too_large()
        );
        assert!(
            decoder
                .set_upper_frame(num_frames)
                .unwrap_err()
                .is_frame_index_too_large()
        );
    }

    #[test]
    fn set_offset_boundaries() {
        let input = fs::read(test_input()).unwrap();
        let seekable = new_seekable(&input, None);
        let mut decoder = Decoder::new(seekable).unwrap();

        let mut offset = decoder.seek_table().size_decomp();
        assert!(decoder.set_offset(offset).is_ok());
        assert!(decoder.set_offset_limit(offset).is_ok());

        offset += 1;
        assert!(
            decoder
                .set_offset(offset)
                .unwrap_err()
                .is_offset_out_of_range()
        );
        assert!(
            decoder
                .set_offset_limit(offset)
                .unwrap_err()
                .is_offset_out_of_range()
        );
    }

    #[test]
    fn decompress_within_offset_boundaries() {
        let input = fs::read(test_input()).unwrap();
        let frame_size = input.len() / 34;
        let seekable = new_seekable(
            &input,
            Some(FrameSizePolicy::Uncompressed(frame_size as u32)),
        );
        let mut decoder = Decoder::new(seekable).unwrap();

        let offset = input.len() / 3;
        let offset_limit = 2 * offset;
        decoder.set_offset(offset as u64).unwrap();
        decoder.set_offset_limit(offset_limit as u64).unwrap();

        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, offset_limit - offset);
        assert_eq!(input[offset..offset_limit], output[..n]);

        // Limit stays unchanged
        decoder.set_offset(3).unwrap();
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, offset_limit - 3);
        assert_eq!(input[3..offset_limit], output[..n]);

        // Reset unsets offset and limit
        decoder.reset();
        assert_eq!(decoder.offset(), 0);
        assert_eq!(decoder.offset_limit(), decoder.seek_table().size_decomp());
        assert_eq!(decoder.read_compressed(), 0);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, input.len());
        assert_eq!(input, output);
    }

    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn seek_decoder() {
        let input = fs::read(test_input()).unwrap();
        let frame_size = input.len() / 52;
        let seekable = new_seekable(
            &input,
            Some(FrameSizePolicy::Uncompressed(frame_size as u32)),
        );
        let mut decoder = Decoder::new(seekable).unwrap();

        // Set the offset limit to make sure it isn't changed by seeking
        let seek_pos = frame_size * 13;
        let end = frame_size * 51;
        decoder.set_offset_limit(end as u64).unwrap();

        // Seek from start
        decoder.seek(SeekFrom::Start(seek_pos as u64)).unwrap();
        assert_eq!(decoder.offset(), seek_pos as u64);
        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - seek_pos);
        assert_eq!(input[seek_pos..end], output[..n]);
        // Reading moves offset accordingly
        assert_eq!(decoder.offset(), end as u64);

        // Seek from end
        let seek_pos = -123;
        let start = (input.len() as i64 + seek_pos) as usize;
        assert_ne!(decoder.read_compressed(), 0);
        decoder.seek(SeekFrom::End(seek_pos)).unwrap();
        assert_eq!(decoder.offset(), input.len() as u64 - 123);
        assert_eq!(decoder.read_compressed(), 0);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - start);
        assert_eq!(input[start..end], output[..n]);

        // Positive seek from current
        decoder.seek(SeekFrom::Start(69)).unwrap();
        decoder.seek(SeekFrom::Current(10)).unwrap();
        assert_eq!(decoder.offset(), 79);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - 79);
        assert_eq!(input[79..end], output[..n]);

        // Negative seek from current
        decoder.seek(SeekFrom::Start(69)).unwrap();
        decoder.seek(SeekFrom::Current(-10)).unwrap();
        assert_eq!(decoder.offset(), 59);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, end - 59);
        assert_eq!(input[59..end], output[..n]);
    }

    #[test]
    fn set_offset_within_frame_continues_decompression() {
        let input = fs::read(test_input()).unwrap();
        let seekable = new_seekable(&input, Some(FrameSizePolicy::Uncompressed(100)));
        let mut decoder = Decoder::new(seekable).unwrap();
        assert_eq!(decoder.read_compressed(), 0);

        decoder.set_offset(10).unwrap();
        decoder.read_exact(&mut [0; 10]).unwrap();
        assert_ne!(decoder.read_compressed(), 0);

        // No reset when frame doesn't change and offset > current offset
        decoder.set_offset(30).unwrap();
        assert_eq!(decoder.offset(), 30);
        assert_ne!(decoder.read_compressed(), 0);
        let mut output = vec![0; input.len()];
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, input.len() - 30);
        assert_eq!(input[30..], output[..n]);

        // Reset when offset is in another frame
        decoder.set_offset(101).unwrap();
        assert_eq!(decoder.offset(), 101);
        assert_eq!(decoder.read_compressed(), 0);
        let n = decoder.decompress(&mut output).unwrap();
        assert_eq!(n, input.len() - 101);
        assert_eq!(input[101..], output[..n]);
    }
}
