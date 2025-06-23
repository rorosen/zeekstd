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
    lower_offset: Option<u64>,
    upper_frame: Option<u32>,
    upper_offset: Option<u64>,
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
            lower_offset: None,
            upper_frame: None,
            upper_offset: None,
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
        self.lower_offset = Some(offset);
        self
    }

    /// Sets a limit for the decompression offset.
    ///
    /// The limit is the position in the decompressed data of the seekable source at which
    /// decompresion stops.
    pub fn offset_limit(mut self, offset: u64) -> Self {
        self.upper_offset = Some(offset);
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
    /// Fails if the decoder could not created.
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
            opts.lower_offset.unwrap_or(0)
        };

        if offset > seek_table.size_decomp() {
            return Err(Error::offset_out_of_range());
        }

        let offset_limit = if let Some(index) = opts.upper_frame {
            seek_table.frame_end_decomp(index)?
        } else {
            opts.upper_offset
                .unwrap_or_else(|| seek_table.size_decomp())
        };

        if offset_limit > seek_table.size_decomp() {
            return Err(Error::offset_out_of_range());
        }

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
                // dummy decompression until we get to lower offset
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
            // Only add to progress if we actually wrote something to buf
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
    /// This resets the offset and limit. The next decompression after this function will start
    /// from the beginning of the seekable source.
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

    /// Sets the index of the frame where decompression starts.
    ///
    /// # Errors
    ///
    /// When the the passed frame index is out of range.
    pub fn set_lower_frame(&mut self, index: u32) -> Result<u64> {
        let offset = self.seek_table.frame_start_decomp(index)?;
        self.set_offset(offset)?;

        Ok(offset)
    }

    /// Sets the index of the last frame that is included in decompression.
    ///
    /// This does not reset the current decompression state, it is possible to change the upper
    /// frame in the middle of a decompression operation.
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
    /// The offset is the position in the decompressed data of the seekable source from which
    /// decompression starts. If possible, the decoder will continue decompression from the current
    /// internal state.
    ///
    /// Notice that the decoder will perform a dummy decompression up to the offset position, if
    /// the passed offset is not the beginning of a frame.
    ///
    /// # Errors
    ///
    /// When the passed offset is out of range.
    pub fn set_offset(&mut self, offset: u64) -> Result<()> {
        if offset > self.seek_table().size_decomp() {
            return Err(Error::offset_out_of_range());
        }

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
    /// The limit is the position in the decompressed data of the seekable source at which
    /// decompresion stops. This does not reset the current decompression state, the limit can be
    /// changed in the middle of a decompression operation without interrupting an ongoing
    /// decompression operation.
    ///
    /// Notice that the decoder will immediately stop decompression at the specified limit. The
    /// frame checksum of the last decompressed frame will not be verified, if the limit isn't at
    /// the end of a frame.
    ///
    /// # Errors
    ///
    /// When the passed limit is out of range.
    pub fn set_offset_limit(&mut self, limit: u64) -> Result<()> {
        if limit > self.seek_table().size_decomp() {
            return Err(Error::offset_out_of_range());
        }
        self.offset_limit = limit;

        Ok(())
    }

    /// Gets the total number of compressed bytes read since the last reset.
    pub fn read_compressed(&self) -> u64 {
        self.read_compressed
    }

    /// Returns a reference to the internal [`SeekTable`].
    pub fn seek_table(&self) -> &SeekTable {
        &self.seek_table
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
    use std::io::{self, BufRead, Cursor, Read, Seek, SeekFrom};

    use crate::{
        EncodeOptions, FrameSizePolicy,
        tests::{LINE_LEN, LINES_IN_DOC, generate_input},
    };

    use super::*;

    const LINES_IN_FRAME: u32 = 1143;
    // Add one for the last frame
    const NUM_FRAMES: u32 = LINES_IN_DOC / LINES_IN_FRAME + 1;

    fn input_and_seekable() -> (Cursor<Vec<u8>>, Cursor<Vec<u8>>) {
        let mut input = generate_input(LINES_IN_DOC);
        let mut seekable = Cursor::new(vec![]);
        let mut encoder = EncodeOptions::new()
            .frame_size_policy(FrameSizePolicy::Uncompressed(LINE_LEN * LINES_IN_FRAME))
            .into_encoder(&mut seekable)
            .unwrap();

        // Compress the input
        io::copy(&mut input, &mut encoder).unwrap();
        let n = encoder.finish().unwrap();
        assert_eq!(n, seekable.position());

        (input, seekable)
    }

    fn verify_decomp<S: Seekable>(decoder: &mut Decoder<'_, S>, start_line: u32, last_line: u32) {
        let mut output = Cursor::new(vec![]);
        io::copy(decoder, &mut output).unwrap();
        output.set_position(0);

        // Iterating makes it easier to see differences
        let mut num_line = start_line;
        for line in output.lines().map(|l| l.unwrap()) {
            assert_eq!(line, format!("Hello from line {num_line:06}"));
            num_line += 1;
        }
        assert_eq!(num_line, last_line);
    }

    #[test]
    fn decompress_and_reset() {
        let (input, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        assert_eq!(NUM_FRAMES, decoder.seek_table().num_frames());

        verify_decomp(&mut decoder, 0, LINES_IN_DOC);

        let mut output = Cursor::new(vec![]);
        decoder.reset();
        io::copy(&mut decoder, &mut output).unwrap();
        assert_eq!(input.get_ref(), output.get_ref());
    }

    #[test]
    fn decompress_until_upper_frame() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        // Decompress until frame 6 (inclusive)
        decoder.set_lower_frame(0).unwrap();
        decoder.set_upper_frame(6).unwrap();

        verify_decomp(&mut decoder, 0, 7 * LINES_IN_FRAME);
    }

    #[test]
    fn decompress_last_frames() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        // Decompress the last 13 frames
        decoder.set_lower_frame(NUM_FRAMES - 14).unwrap();
        decoder.set_upper_frame(NUM_FRAMES - 1).unwrap();

        verify_decomp(
            &mut decoder,
            (NUM_FRAMES - 14) * LINES_IN_FRAME,
            LINES_IN_DOC,
        );
    }

    #[test]
    fn upper_frame_greater_than_lower_frame() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        // Lower frame greater than upper frame, expect zero bytes read
        decoder.set_lower_frame(9).unwrap();
        decoder.set_upper_frame(8).unwrap();
        let mut output = Cursor::new(vec![]);
        let n = io::copy(&mut decoder, &mut output).unwrap();
        assert_eq!(0, n);
        output.set_position(0);
        assert_eq!(0, output.lines().collect::<Vec<_>>().len());
    }

    #[test]
    fn reset_decompression() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        // Dummy decompression so we can reset something
        decoder.decompress(&mut [0; 1024]).unwrap();
        decoder.reset();
        verify_decomp(&mut decoder, 0, LINES_IN_DOC);
    }

    #[test]
    fn decompress_everything_after_partly_decompression() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        decoder.set_lower_frame(44).unwrap();
        decoder.set_upper_frame(88).unwrap();

        verify_decomp(&mut decoder, 44 * LINES_IN_FRAME, 89 * LINES_IN_FRAME);

        // Decompress all frames
        decoder.set_lower_frame(0).unwrap();
        decoder.set_upper_frame(NUM_FRAMES - 1).unwrap();
        verify_decomp(&mut decoder, 0, LINES_IN_DOC);
    }

    #[test]
    fn set_frame_boundaries() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        assert!(decoder.set_lower_frame(NUM_FRAMES - 1).is_ok());
        assert!(decoder.set_upper_frame(NUM_FRAMES - 1).is_ok());

        // Frame index out of range
        assert!(
            decoder
                .set_lower_frame(NUM_FRAMES)
                .unwrap_err()
                .is_frame_index_too_large()
        );
        assert!(
            decoder
                .set_upper_frame(NUM_FRAMES)
                .unwrap_err()
                .is_frame_index_too_large()
        );
    }

    #[test]
    fn set_offset_boundaries() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        let mut offset = decoder.seek_table().size_decomp();
        assert!(decoder.set_offset(offset).is_ok());
        assert!(decoder.set_offset_limit(offset).is_ok());

        // Offset out of range
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
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        decoder.set_offset(43 * LINE_LEN as u64).unwrap();
        decoder.set_offset_limit(200_001 * LINE_LEN as u64).unwrap();
        verify_decomp(&mut decoder, 43, 200_001);

        // Limit stays unchanged
        decoder.set_offset(44 * LINE_LEN as u64).unwrap();
        verify_decomp(&mut decoder, 44, 200_001);

        // Reset unsets offset and limit
        decoder.reset();
        verify_decomp(&mut decoder, 0, LINES_IN_DOC);
    }

    #[test]
    fn seek_decoder() {
        let (_, seekable) = input_and_seekable();
        let mut decoder = Decoder::new(seekable).unwrap();

        // Make sure that the offset limit isn't changed by seeking
        decoder
            .set_offset_limit(((LINES_IN_DOC - 1) * LINE_LEN).into())
            .unwrap();

        decoder.seek(SeekFrom::Start(69 * LINE_LEN as u64)).unwrap();
        verify_decomp(&mut decoder, 69, LINES_IN_DOC - 1);

        decoder
            .seek(SeekFrom::End(-(111 * LINE_LEN as i64)))
            .unwrap();
        verify_decomp(&mut decoder, LINES_IN_DOC - 111, LINES_IN_DOC - 1);

        // Positive seek from current
        decoder.seek(SeekFrom::Start(69 * LINE_LEN as u64)).unwrap();
        decoder.seek(SeekFrom::Current(LINE_LEN as i64)).unwrap();
        verify_decomp(&mut decoder, 70, LINES_IN_DOC - 1);

        // Negative seek from current
        decoder.seek(SeekFrom::Start(69 * LINE_LEN as u64)).unwrap();
        decoder.seek(SeekFrom::Current(-(LINE_LEN as i64))).unwrap();
        verify_decomp(&mut decoder, 68, LINES_IN_DOC - 1);

        // Reading moves offset accordingly
        decoder.seek(SeekFrom::End(-(2 * LINE_LEN as i64))).unwrap();
        decoder.read_exact(&mut [0; LINE_LEN as usize]).unwrap();
        verify_decomp(&mut decoder, LINES_IN_DOC - 1, LINES_IN_DOC - 1);
    }
}
