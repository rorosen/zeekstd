use alloc::vec;
use alloc::vec::Vec;

use zstd_safe::zstd_sys::ZSTD_ErrorCode;

use crate::{
    SEEK_TABLE_INTEGRITY_SIZE, SEEKABLE_MAGIC_NUMBER, SEEKABLE_MAX_FRAMES, SKIPPABLE_HEADER_SIZE,
    error::{Error, Result},
    seekable::{OffsetFrom, Seekable},
};

// Reads 4 bytes (little endian) from buf starting at offset into an u32
macro_rules! read_le32 {
    ($buf:expr, $offset:expr) => {
        ($buf[$offset] as u32)
            | (($buf[$offset + 1] as u32) << 8)
            | (($buf[$offset + 2] as u32) << 16)
            | (($buf[$offset + 3] as u32) << 24)
    };
}

// Writes a 32 bit value in little endian to buf
macro_rules! write_le32 {
    ($buf:expr, $buf_pos:expr, $write_pos:expr, $value:expr, $offset:expr) => {
        // Only write if this hasn't been written before
        if $write_pos < $offset + 4 {
            // Minimum of remaining buffer space and number of bytes we want to write
            let len = usize::min($buf.len() - $buf_pos, $offset + 4 - $write_pos);
            // val_offset is > 0 if we wrote the value partially in a previous run (because of
            // little buffer space remaining)
            let val_offset = $write_pos - $offset;
            // Copy the important parts of value to buf
            $buf[$buf_pos..$buf_pos + len]
                .copy_from_slice(&$value.to_le_bytes()[val_offset..val_offset + len]);
            $buf_pos += len;
            $write_pos += len;
            // Return if the buffer is full
            if $buf_pos == $buf.len() {
                return $buf_pos;
            }
        }
    };
}

// Writes a frame entry
macro_rules! write_frame {
    ($buf:expr, $buf_pos:expr, $self:expr, $offset:expr) => {
        write_le32!(
            $buf,
            $buf_pos,
            $self.write_pos,
            $self.frames[$self.frame_index].c_size,
            $offset
        );
        write_le32!(
            $buf,
            $buf_pos,
            $self.write_pos,
            $self.frames[$self.frame_index].d_size,
            $offset + 4
        );
        $self.frame_index += 1;
    };
}

// Writes the integrity field of the seek table
macro_rules! write_integrity {
    ($buf:expr, $buf_pos:expr, $self:expr, $num_frames:expr, $offset:expr) => {
        write_le32!($buf, $buf_pos, $self.write_pos, $num_frames, $offset);
        // Write the "seek table descriptor", always 0
        if $self.write_pos < $offset + 5 {
            $buf[$buf_pos] = 0;
            $buf_pos += 1;
            $self.write_pos += 1;
        }
        write_le32!(
            $buf,
            $buf_pos,
            $self.write_pos,
            SEEKABLE_MAGIC_NUMBER,
            $offset + 5
        );
    };
}

/// The size of each frame entry in the seek table.
const SIZE_PER_FRAME: usize = 8;
/// The skippable magic number of the skippable frame containing the seek table.
const SKIPPABLE_MAGIC_NUMBER: u32 = zstd_safe::zstd_sys::ZSTD_MAGIC_SKIPPABLE_START | 0xE;

struct Frame {
    c_size: u32,
    d_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    c_offset: u64,
    d_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entries(Vec<Entry>);

impl Entries {
    fn with_num_frames(num_frames: usize) -> Self {
        // Make sure there is always space for one frame
        let num_frames = num_frames.max(1);
        let cap = core::mem::size_of::<Entry>() * num_frames;
        Self(Vec::with_capacity(cap))
    }

    fn into_frames(self) -> Vec<Frame> {
        self.0
            .windows(2)
            .map(|w| Frame {
                c_size: (w[1].c_offset - w[0].c_offset) as u32,
                d_size: (w[1].d_offset - w[0].d_offset) as u32,
            })
            .collect()
    }
}

impl core::ops::Index<u32> for Entries {
    type Output = Entry;

    fn index(&self, index: u32) -> &Self::Output {
        let idx = usize::try_from(index).expect("Frame index can be transformed to uisze");
        &self.0[idx]
    }
}

#[derive(Debug)]
struct Parser {
    num_frames: usize,
    size_per_frame: usize,
    seek_table_size: usize,
    entries: Entries,
    c_offset: u64,
    d_offset: u64,
}

impl Parser {
    fn from_bytes(buf: &[u8]) -> Result<Self> {
        if read_le32!(buf, 5) != SEEKABLE_MAGIC_NUMBER {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }

        // Check reserved descriptor bits are not set
        if ((buf[4] >> 2) & 0x1f) > 0 {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
        }

        let with_checksum = (buf[4] & (1 << 7)) > 0;
        let num_frames = read_le32!(buf, 0);
        if num_frames > SEEKABLE_MAX_FRAMES {
            return Err(Error::frame_index_too_large());
        }
        let num_frames = usize::try_from(num_frames).expect("Number of frames never exceeds usize");
        let size_per_frame: usize = if with_checksum { 12 } else { 8 };
        let seek_table_size =
            num_frames * size_per_frame + SKIPPABLE_HEADER_SIZE + SEEK_TABLE_INTEGRITY_SIZE;

        Ok(Self {
            num_frames,
            size_per_frame,
            seek_table_size,
            entries: Entries::with_num_frames(num_frames),
            c_offset: 0,
            d_offset: 0,
        })
    }

    fn verify_skippable_header(&self, buf: &[u8]) -> Result<()> {
        if read_le32!(buf, 0) != SKIPPABLE_MAGIC_NUMBER {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }
        let size = usize::try_from(read_le32!(buf, 4)).expect("frame size fits in usize");
        if size + SKIPPABLE_HEADER_SIZE != self.seek_table_size {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
        }

        Ok(())
    }

    /// Parses entries from `buf`.
    ///
    /// Only parses complete frames, returns the number of bytes consumed.
    fn parse_entries(&mut self, buf: &[u8]) -> usize {
        let mut pos: usize = 0;
        while self.entries.0.len() < self.num_frames {
            if pos + self.size_per_frame > buf.len() {
                return pos;
            }

            self.log_entry();
            // Casting u32 to u64 is fine
            self.c_offset += read_le32!(buf, pos) as u64;
            self.d_offset += read_le32!(buf, pos + 4) as u64;
            pos += self.size_per_frame;
        }

        // Add a final entry that marks the end of the last frame
        self.log_entry();

        pos
    }

    fn log_entry(&mut self) {
        self.entries.0.push(Entry {
            c_offset: self.c_offset,
            d_offset: self.d_offset,
        });
    }

    fn verify(&self) -> Result<()> {
        if self.entries.0.len() == self.num_frames + 1 {
            Ok(())
        } else {
            Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected))
        }
    }
}

/// The format that should be used when serializing or deserializing the seek table.
#[derive(Debug, Clone, Copy, Default)]
pub enum Format {
    /// Suitable for stand-alone seek tables.
    ///
    /// In `Head` format, the seek table integrity field is placed directly after the skippable
    /// header, i.e. before any frame data, in the seek table frame.
    Head,
    /// Suitable for seek tables that are appended to compressed data.
    ///
    /// In `Foot` format, the integrity field is placed at the end of the seek table frame, after
    /// any frame data.
    #[default]
    Foot,
}

/// Holds information of the frames of a seekable archive.
///
/// The `SeekTable` allows decompressors to jump directly to the beginning of frames. It is
/// typically placed in a Zstandard skippable frame at the end of a seekable archive.
///
/// # Examples
///
/// ```no_run
/// # use std::fs::File;
/// # use zeekstd::SeekTable;
/// let mut seekable = File::open("seekable.zst")?;
/// let seek_table = SeekTable::from_seekable(&mut seekable)?;
///
/// let num_frames = seek_table.num_frames();
/// # Ok::<(), zeekstd::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeekTable {
    entries: Entries,
}

impl Default for SeekTable {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Parser> for SeekTable {
    fn from(value: Parser) -> Self {
        SeekTable {
            entries: value.entries,
        }
    }
}

impl SeekTable {
    /// Create a new, empty seek table.
    pub fn new() -> Self {
        let entries = Entries(vec![Entry {
            c_offset: 0,
            d_offset: 0,
        }]);

        Self { entries }
    }

    /// Parses the seek table from a seekable archive.
    ///
    /// This only works if the seek table is in [`Foot`] format.
    ///
    /// # Errors
    ///
    /// Fails if the seek table is not in [`Foot`] format, or if verification fails for another
    /// reason.
    ///
    /// [`Foot`]: Format#variant.Foot
    ///
    /// # Examples
    ///
    /// Use a [`crate::BytesWrapper`] to parse the seek table from a byte slice.
    ///
    /// ```
    /// # let mut seek_table = SeekTable::new();
    /// # seek_table.log_frame(123, 456)?;
    /// # let mut ser = seek_table.into_serializer();
    /// # let mut buf = [0u8; 32];
    /// # let n = ser.write_into(&mut buf);
    /// # let seek_table_bytes = &buf[..n];
    /// use zeekstd::{BytesWrapper, SeekTable};
    ///
    /// let mut wrapper = BytesWrapper::new(seek_table_bytes);
    /// let seek_table = SeekTable::from_seekable(&mut wrapper)?;
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    ///
    /// Anything that implements [`std::io::Read`] and [`std::io::Seek`] implements [`Seekable`]
    /// and can be used as `src`.
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::SeekTable;
    ///
    /// let mut seekable = File::open("seekable.zst")?;
    /// let seek_table = SeekTable::from_seekable(&mut seekable)?;
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn from_seekable(src: &mut impl Seekable) -> Result<Self> {
        Self::from_seekable_format(src, Format::Foot)
    }

    /// Parses the seek table from a seekable archive, expecting the given `format`.
    ///
    /// # Errors
    ///
    /// Fails if the seek table is in the wrong format, or if verification fails for another reason.
    ///
    /// # Examples
    ///
    /// Use a [`crate::BytesWrapper`] to parse the seek table from a byte slice.
    ///
    /// ```
    /// # let mut seek_table = SeekTable::new();
    /// # seek_table.log_frame(123, 456)?;
    /// # let mut ser = seek_table.into_format_serializer(Format::Head);
    /// # let mut buf = [0u8; 32];
    /// # let n = ser.write_into(&mut buf);
    /// # let seek_table_bytes = &buf[..n];
    /// use zeekstd::{BytesWrapper, SeekTable, seek_table::Format};
    ///
    /// let mut wrapper = BytesWrapper::new(seek_table_bytes);
    /// let seek_table = SeekTable::from_seekable_format(&mut wrapper, Format::Head)?;
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    ///
    /// Anything that implements [`std::io::Read`] and [`std::io::Seek`] implements [`Seekable`]
    /// and can be used as `src`.
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::seek_table::{Format, SeekTable};
    ///
    /// let mut seekable = File::open("seekable.zst")?;
    /// let seek_table = SeekTable::from_seekable_format(&mut seekable, Format::Head)?;
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn from_seekable_format(src: &mut impl Seekable, format: Format) -> Result<Self> {
        let integrity = src.seek_table_integrity(format)?;
        let mut parser = Parser::from_bytes(&integrity)?;

        match format {
            Format::Head => src.set_offset(OffsetFrom::Start(0))?,
            Format::Foot => src.set_offset(OffsetFrom::End(-(parser.seek_table_size as i64)))?,
        };

        let len = 8192.min(parser.seek_table_size);
        let mut buf = vec![0u8; len];
        let mut read = 0;
        while read < SKIPPABLE_HEADER_SIZE {
            let n = src.read(&mut buf)?;
            if n == 0 {
                // Error if src is EOF already
                return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
            }
            read += n;
        }
        parser.verify_skippable_header(&buf[..SKIPPABLE_HEADER_SIZE])?;

        let mut consumed = SKIPPABLE_HEADER_SIZE;
        if matches!(format, Format::Head) {
            consumed += SEEK_TABLE_INTEGRITY_SIZE;
        }

        // Drain the range we have already consumed (skippable header + integrity field)
        buf.drain(..consumed);
        let buf_len = buf.len();

        // Data that still has to be parsed
        let mut remaining =
            parser.seek_table_size - SKIPPABLE_HEADER_SIZE - SEEK_TABLE_INTEGRITY_SIZE;

        loop {
            let n = parser.parse_entries(&buf);
            remaining -= n;
            if remaining == 0 {
                break;
            }
            buf.copy_within(n.., 0);
            if remaining > 0 && src.read(&mut buf[buf_len - n..buf_len.min(remaining)])? == 0 {
                // Error if src is EOF but there is data remaining
                return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
            }
        }
        parser.verify()?;

        Ok(parser.into())
    }

    /// Reads and parses a seek table from `reader`.
    ///
    /// Only works if the seek table is in [`Head`] format.
    ///
    /// # Errors
    ///
    /// Fails if the seek table is not in [`Head`] format, or if verification fails for another
    /// reason.
    ///
    /// [`Head`]: Format#variant.Head
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use zeekstd::SeekTable;
    ///
    /// let mut reader = File::open("my/seek_table")?;
    /// let seek_table = SeekTable::from_reader(&mut reader)?;
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    #[cfg(feature = "std")]
    pub fn from_reader(reader: &mut impl std::io::Read) -> Result<Self> {
        let mut buf = [0u8; SKIPPABLE_HEADER_SIZE + SEEK_TABLE_INTEGRITY_SIZE];
        reader.read_exact(&mut buf)?;

        let mut parser = Parser::from_bytes(&buf[SKIPPABLE_HEADER_SIZE..])?;
        parser.verify_skippable_header(&buf)?;

        // Data that is left to be parsed
        let mut remaining =
            parser.seek_table_size - SKIPPABLE_HEADER_SIZE - SEEK_TABLE_INTEGRITY_SIZE;
        let mut buf = vec![0u8; 8192.min(remaining)];
        let buf_len = buf.len();

        let mut offset = 0;
        loop {
            if remaining > 0 && reader.read(&mut buf[offset..buf_len.min(remaining)])? == 0 {
                // Error if src is EOF but there is data remaining
                return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
            }

            let n = parser.parse_entries(&buf);
            remaining -= n;
            if remaining == 0 {
                break;
            }

            offset = buf_len - n;
            buf.copy_within(n.., 0);
        }
        parser.verify()?;

        Ok(parser.into())
    }

    /// Adds a frame to this seek table.
    ///
    /// # Errors
    ///
    /// Fails if [`Self::num_frames()`] reaches [`SEEKABLE_MAX_FRAMES`].
    pub fn log_frame(&mut self, c_size: u32, d_size: u32) -> Result<()> {
        if self.num_frames() >= SEEKABLE_MAX_FRAMES {
            return Err(Error::frame_index_too_large());
        }

        let last = &self.entries[self.num_frames()];
        self.entries.0.push(Entry {
            c_offset: last.c_offset + c_size as u64,
            d_offset: last.d_offset + d_size as u64,
        });

        Ok(())
    }

    /// The number of frames in the seek table.
    pub fn num_frames(&self) -> u32 {
        // Cast is always possible (max value SEEKABLE_MAX_FRAMES)
        (self.entries.0.len() - 1) as u32
    }

    /// The frame index at the given compressed offset.
    pub fn frame_index_comp(&self, offset: u64) -> u32 {
        self.frame_index_at(offset, |i| self.entries[i].c_offset)
    }

    /// The frame index at the given decompressed offset.
    pub fn frame_index_decomp(&self, offset: u64) -> u32 {
        self.frame_index_at(offset, |i| self.entries[i].d_offset)
    }

    /// The start position of frame `index` in the compressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_start_comp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames() {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index].c_offset)
    }

    /// The start position of frame `index` in the decompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_start_decomp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames() {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index].d_offset)
    }

    /// The end position of frame `index` in the compressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_end_comp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames() {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index + 1].c_offset)
    }

    /// The end position of frame `index` in the decompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_end_decomp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames() {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index + 1].d_offset)
    }

    /// The compressed size of frame `index`.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_size_comp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames() {
            return Err(Error::frame_index_too_large());
        }

        let size = self.entries[index + 1].c_offset - self.entries[index].c_offset;
        Ok(size)
    }

    /// The decompressed size of frame `index`.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_size_decomp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames() {
            return Err(Error::frame_index_too_large());
        }

        let size = self.entries[index + 1].d_offset - self.entries[index].d_offset;
        Ok(size)
    }

    /// The maximum compressed frame size.
    #[allow(clippy::missing_panics_doc)]
    pub fn max_frame_size_comp(&self) -> u64 {
        (0..self.num_frames())
            .map(|i| {
                self.frame_size_comp(i)
                    .expect("Frame index is never out of range")
            })
            .max()
            .unwrap_or(0)
    }

    /// The maximum decompressed frame size.
    #[allow(clippy::missing_panics_doc)]
    pub fn max_frame_size_decomp(&self) -> u64 {
        (0..self.num_frames())
            .map(|i| {
                self.frame_size_decomp(i)
                    .expect("Frame index is never out of range")
            })
            .max()
            .unwrap_or(0)
    }

    /// The compressed size of the seekable archive.
    ///
    /// This is equivalent to calling [`Self::frame_end_comp`] with the index of the last frame.
    #[allow(clippy::missing_panics_doc)]
    pub fn size_comp(&self) -> u64 {
        self.entries
            .0
            .last()
            .expect("Seek table entries are never empty")
            .c_offset
    }

    /// The decompressed size of the seekable archive.
    ///
    /// This is equivalent to calling [`Self::frame_end_decomp`] with the index of the last frame.
    #[allow(clippy::missing_panics_doc)]
    pub fn size_decomp(&self) -> u64 {
        self.entries
            .0
            .last()
            .expect("Seek table entries are never empty")
            .d_offset
    }

    /// Convert this seek table into an immutable, serializable form.
    ///
    /// The seek table will be serialized with the seekable integrity field placed as a
    /// footer after any frame data. This is the typical seek table that can be appended to a
    /// seekable archive, however, parses need to seek the input for deserialization.
    pub fn into_serializer(self) -> Serializer {
        self.into_format_serializer(Format::Foot)
    }

    /// Convert this seek table into an immutable, serializable form.
    ///
    /// The seek table will be serialized with the seekable integrity field placed as a
    /// header before any frame data. This is useful for creating a stand-alone seek table that
    /// can be parsed in a streaming fashion, i.e. without seeking the input.
    pub fn into_format_serializer(self, format: Format) -> Serializer {
        Serializer {
            frames: self.entries.into_frames(),
            frame_index: 0,
            write_pos: 0,
            format,
        }
    }

    fn frame_index_at(&self, offset: u64, offset_at: impl Fn(u32) -> u64) -> u32 {
        if offset >= offset_at(self.num_frames()) {
            return self.num_frames() - 1;
        }

        let mut low = 0;
        let mut high = self.num_frames();

        while low + 1 < high {
            let mid = low.midpoint(high);
            if offset_at(mid) <= offset {
                low = mid;
            } else {
                high = mid;
            }
        }

        low
    }
}

/// A serializable, immutable form of a [`SeekTable`].
///
/// # Examples
///
/// ```
/// use zeekstd::SeekTable;
///
/// let mut seek_table = SeekTable::new();
/// seek_table.log_frame(123, 456)?;
/// seek_table.log_frame(333, 444)?;
///
/// let mut ser = seek_table.into_serializer();
/// let mut buf = vec![0; ser.encoded_len()];
///
/// let n = ser.write_into(&mut buf);
/// assert_eq!(n, ser.encoded_len());
///
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct Serializer {
    frames: Vec<Frame>,
    frame_index: usize,
    write_pos: usize,
    format: Format,
}

impl Serializer {
    /// Write the seek table into `buf`.
    ///
    /// Returns the number of bytes written. Call this repetitively until `0` is returned to
    /// serialize the entire seek table.
    pub fn write_into(&mut self, buf: &mut [u8]) -> usize {
        let mut buf_pos = 0;

        // Write skipable header
        write_le32!(buf, buf_pos, self.write_pos, SKIPPABLE_MAGIC_NUMBER, 0);
        write_le32!(buf, buf_pos, self.write_pos, self.frame_size(), 4);

        // Write the integrity field before the frame data in Head format
        if matches!(self.format, Format::Head) {
            write_integrity!(
                buf,
                buf_pos,
                self,
                self.frames.len() as u32,
                SKIPPABLE_HEADER_SIZE
            );
        }

        // Write frames
        while self.frame_index < self.frames.len() {
            let offset = SKIPPABLE_HEADER_SIZE + SIZE_PER_FRAME * self.frame_index;
            match self.format {
                Format::Head => {
                    write_frame!(buf, buf_pos, self, offset + SEEK_TABLE_INTEGRITY_SIZE);
                }
                Format::Foot => {
                    write_frame!(buf, buf_pos, self, offset);
                }
            }
        }

        // Write the integrity field after the frame data in Foot format
        if matches!(self.format, Format::Foot) {
            let offset = SKIPPABLE_HEADER_SIZE + SIZE_PER_FRAME * self.frames.len();
            write_integrity!(buf, buf_pos, self, self.frames.len() as u32, offset);
        }

        buf_pos
    }

    /// Reset the serialization progress.
    ///
    /// Serialization starts from the beginning after this. Can be called at any time.
    ///
    /// # Examples
    ///
    /// ```
    /// use zeekstd::SeekTable;
    ///
    /// # let mut seek_table = SeekTable::new();
    /// # seek_table.log_frame(123, 456)?;
    /// # seek_table.log_frame(333, 444)?;
    /// let mut ser = seek_table.into_serializer();
    /// let mut first = vec![0; ser.encoded_len()];
    /// let mut second = vec![0; ser.encoded_len()];
    ///
    /// let n = ser.write_into(&mut first);
    /// assert_eq!(n, ser.encoded_len());
    ///
    /// ser.reset();
    ///
    /// let n = ser.write_into(&mut second);
    /// assert_eq!(n, ser.encoded_len());
    ///
    /// # Ok::<(), zeekstd::Error>(())
    /// ```
    pub fn reset(&mut self) {
        self.write_pos = 0;
        self.frame_index = 0;
    }

    /// The length of the entire skippable frame, including skippable header and frame size.
    pub fn encoded_len(&self) -> usize {
        SKIPPABLE_HEADER_SIZE + SEEK_TABLE_INTEGRITY_SIZE + self.frames.len() * SIZE_PER_FRAME
    }

    // The length of the seek table frame, not including the SKIPPABLE_MAGIC_NUMBER and
    // the size of the skippable frame. Should always fit in u32.
    fn frame_size(&self) -> u32 {
        (self.encoded_len() - SKIPPABLE_HEADER_SIZE) as u32
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::io::Read for Serializer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.write_into(buf))
    }
}

#[cfg(test)]
mod tests {
    use crate::BytesWrapper;

    use super::*;

    use proptest::prelude::*;
    use zstd_safe::OutBuffer;

    fn seek_table(num_frames: u32) -> SeekTable {
        let mut st = SeekTable::new();

        let mut c_size = 3;
        let mut d_size = 6;
        for _ in 0..num_frames {
            st.log_frame(c_size, d_size).unwrap();
            c_size += 1;
            d_size += 1;
        }

        st
    }

    #[test]
    fn frame_functions() {
        const NUM_FRAMES: u32 = 1234;
        let mut st = SeekTable::new();

        for i in 1..=NUM_FRAMES {
            st.log_frame(i * 7, i * 13).unwrap();
        }
        assert_eq!(st.num_frames(), NUM_FRAMES);

        let mut c_offset = 0;
        let mut d_offset = 0;
        for i in 1..=NUM_FRAMES {
            let j = i - 1;
            let c_size = i as u64 * 7;
            let d_size = i as u64 * 13;

            assert_eq!(st.frame_index_comp(c_offset), j);
            assert_eq!(st.frame_index_decomp(d_offset), j);
            assert_eq!(st.frame_start_comp(j).unwrap(), c_offset);
            assert_eq!(st.frame_start_decomp(j).unwrap(), d_offset);
            assert_eq!(st.frame_end_comp(j).unwrap(), c_offset + c_size);
            assert_eq!(st.frame_end_decomp(j).unwrap(), d_offset + d_size);
            assert_eq!(st.frame_size_comp(j).unwrap(), c_size);
            assert_eq!(st.frame_size_decomp(j).unwrap(), d_size);
            c_offset += c_size;
            d_offset += d_size;
        }

        assert_eq!(st.max_frame_size_comp(), NUM_FRAMES as u64 * 7);
        assert_eq!(st.max_frame_size_decomp(), NUM_FRAMES as u64 * 13);
    }

    fn test_serialize(format: Format, num_frames: u32, buf_len: usize) {
        let mut ser = seek_table(num_frames)
            .clone()
            .into_format_serializer(format);

        // Complete serialization
        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, buf.len());

        // Further calls write zero bytes
        let n = ser.write_into(&mut buf);
        assert_eq!(n, 0);

        ser.reset();

        // Multiple write calls with changing buffer sizes
        let mut buf = vec![0; buf_len];
        let mut pos = 0;
        while pos < ser.encoded_len() {
            let n = ser.write_into(&mut buf);
            pos += n;
        }

        assert_eq!(pos, ser.encoded_len());
    }

    fn test_serde_cycle(format: Format, num_frames: u32) {
        let st = seek_table(num_frames);
        let mut ser = st.clone().into_format_serializer(format);

        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, ser.encoded_len());

        let mut wrapper = BytesWrapper::new(&buf);
        let from_seekable = SeekTable::from_seekable_format(&mut wrapper, format).unwrap();
        assert_eq!(from_seekable, st);
    }

    fn test_serialize_compatible_with_zstd_seekable(num_frames: u32) {
        let st = seek_table(num_frames);
        let mut ser = st.clone().into_serializer();
        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, ser.encoded_len());

        let mut seekable = zstd_safe::seekable::Seekable::create();
        seekable.init_buff(&buf).unwrap();

        assert_eq!(st.num_frames(), seekable.num_frames());
        for i in 0..st.num_frames() {
            assert_eq!(
                st.frame_start_comp(i).unwrap(),
                seekable.frame_compressed_offset(i).unwrap()
            );
            assert_eq!(
                st.frame_start_decomp(i).unwrap(),
                seekable.frame_decompressed_offset(i).unwrap()
            );
            assert_eq!(
                st.frame_size_comp(i).unwrap(),
                seekable.frame_compressed_size(i).unwrap() as u64
            );
            assert_eq!(
                st.frame_size_decomp(i).unwrap(),
                seekable.frame_decompressed_size(i).unwrap() as u64
            );
        }
    }

    fn test_deserialize_compatible_with_zstd_seekable(num_frames: u32) {
        let mut fl = zstd_safe::seekable::FrameLog::create(true);

        for i in 1..=num_frames {
            fl.log_frame(i * 7, i * 13, Some(i)).unwrap();
        }

        // frame size of zstd seekable is 12,  c_size, d_size, checksum each 4
        let cap = SKIPPABLE_HEADER_SIZE + (num_frames * 12) as usize + SEEK_TABLE_INTEGRITY_SIZE;
        let mut buf = vec![0; cap];
        let mut out_buf = OutBuffer::around(&mut buf);
        let n = fl.write_seek_table(&mut out_buf).unwrap();
        // Verify that the entire seek table got written
        assert_eq!(n, 0);

        let mut wrapper = BytesWrapper::new(&buf);
        let st = SeekTable::from_seekable(&mut wrapper).unwrap();
        assert_eq!(st.num_frames(), num_frames);

        for i in 1..=num_frames {
            let c_size = i as u64 * 7;
            let d_size = i as u64 * 13;
            assert_eq!(st.frame_size_comp(i - 1).unwrap(), c_size);
            assert_eq!(st.frame_size_decomp(i - 1).unwrap(), d_size);
        }
    }

    #[cfg(feature = "std")]
    fn test_serde_cycle_std(format: Format, num_frames: u32) {
        let st = seek_table(num_frames);
        let mut ser = st.clone().into_format_serializer(format);
        let mut buf = std::io::Cursor::new(Vec::with_capacity(ser.encoded_len()));
        let n = std::io::copy(&mut ser, &mut buf).unwrap();
        assert_eq!(n, ser.encoded_len() as u64);

        let mut wrapper = BytesWrapper::new(buf.get_ref());
        let from_bytes = SeekTable::from_seekable_format(&mut wrapper, format).unwrap();
        assert_eq!(from_bytes, st);
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn serde_cycle_std(num_frames in 0..2048u32) {
            test_serde_cycle_std(Format::Head, num_frames);
            test_serde_cycle_std(Format::Foot, num_frames);
        }
    }

    // Test with varying number of frames. More frames slow down tests, the used range should
    // cover all edge cases.
    proptest! {
        #[test]
        fn serialize(num_frames in 0..2048u32, buf_len in 1..64usize) {
            test_serialize(Format::Head, num_frames, buf_len);
            test_serialize(Format::Foot, num_frames, buf_len);
        }

        #[test]
        fn serde_cycle(num_frames in 0..2048u32) {
            test_serde_cycle(Format::Head, num_frames);
            test_serde_cycle(Format::Foot, num_frames);
        }

        #[test]
        fn serialize_compatible_with_zstd_seekable(num_frames in 0..2048u32) {
            test_serialize_compatible_with_zstd_seekable(num_frames);
        }

        #[test]
        fn deserialize_compatible_with_zstd_seekable(num_frames in 1..2048u32) {
            test_deserialize_compatible_with_zstd_seekable(num_frames);
        }
    }
}
