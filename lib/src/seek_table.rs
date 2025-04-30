use zstd_safe::zstd_sys::ZSTD_ErrorCode;

use crate::{
    SEEK_TABLE_INTEGRITY_SIZE, SEEKABLE_MAGIC_NUMBER, SEEKABLE_MAX_FRAMES,
    error::{Error, Result},
    seekable::Seekable,
};

// Reads 4 bytes from buf starting at offset into an u32
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

// Writes the header of a zstd skippable frame
macro_rules! write_skippable_header {
    ($buf:expr, $buf_pos:expr, $self:expr) => {
        write_le32!($buf, $buf_pos, $self.write_pos, SKIPPABLE_MAGIC_NUMBER, 0);
        write_le32!($buf, $buf_pos, $self.write_pos, $self.frame_size(), 4);
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
/// The size of the skippable frame header.
const SKIPPABLE_HEADER_SIZE: usize = 8;
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
        let cap = core::mem::size_of::<Entry>() * num_frames;
        Self(Vec::with_capacity(cap))
    }

    fn into_frames(self) -> Vec<Frame> {
        let len = self.0.len() - 1;
        let cap = core::mem::size_of::<Frame>() * len;
        let mut frames = Vec::with_capacity(cap);

        let mut idx = 0;
        while idx < len {
            let frame = Frame {
                c_size: (self.0[idx + 1].c_offset - self.0[idx].c_offset) as u32,
                d_size: (self.0[idx + 1].d_offset - self.0[idx].d_offset) as u32,
            };
            frames.push(frame);
            idx += 1;
        }

        frames
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
    fn from_integrity(buf: &[u8]) -> Result<Self> {
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
        let Self {
            entries,
            c_offset,
            d_offset,
            ..
        } = self;

        let mut pos: usize = 0;
        while entries.0.len() < self.num_frames {
            if pos + self.size_per_frame > buf.len() {
                return pos;
            }

            entries.0.push(Entry {
                c_offset: *c_offset,
                d_offset: *d_offset,
            });
            // Casting u32 to u64 is fine
            *c_offset += read_le32!(buf, pos) as u64;
            *d_offset += read_le32!(buf, pos + 4) as u64;
            pos += self.size_per_frame;
        }

        // Add a final entry that marks the end of the last frame
        entries.0.push(Entry {
            c_offset: *c_offset,
            d_offset: *d_offset,
        });

        pos
    }

    fn verify(&self) -> Result<()> {
        if self.entries.0.len() == self.num_frames + 1 {
            Ok(())
        } else {
            Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected))
        }
    }
}

impl From<Parser> for SeekTable {
    fn from(value: Parser) -> Self {
        SeekTable {
            entries: value.entries,
        }
    }
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

impl SeekTable {
    // Create a new, empty seek table.
    pub fn new() -> Self {
        let entries = Entries(vec![Entry {
            c_offset: 0,
            d_offset: 0,
        }]);

        Self { entries }
    }

    /// Parses the seek table from a seekable archive.
    ///
    /// This only works if the seek table has the descriptor section at the end as a footer and is
    /// appended to the end of the archive.
    ///
    /// # Errors
    ///
    /// Returns an error if the seek table cannot be parsed or validation fails.
    pub fn from_seekable(src: &mut impl Seekable) -> Result<Self> {
        let footer = src.seek_table_footer()?;
        let mut parser = Parser::from_integrity(&footer)?;
        src.seek_to_seek_table_start(parser.seek_table_size)?;

        let len = 8192.min(parser.seek_table_size + SKIPPABLE_HEADER_SIZE);
        let mut buf = vec![0u8; len];
        let mut read = 0;
        while read < 8 {
            let n = src.read(&mut buf)?;
            if n == 0 {
                // Error if src is EOF already
                return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
            }
            read += n;
        }
        parser.verify_skippable_header(&buf[..SKIPPABLE_HEADER_SIZE])?;
        buf.drain(..SKIPPABLE_HEADER_SIZE);
        let len = buf.len();

        loop {
            let n = parser.parse_entries(&buf);
            if n == 0 {
                break;
            }
            buf.copy_within(n.., 0);
            if src.read(&mut buf[len - n..])? == 0 {
                break;
            };
        }
        parser.verify()?;

        Ok(parser.into())
    }

    /// Parses a seek table from a byte slice.
    ///
    /// The passed `buf` should only contain the seek table, not the complete seekable archive.
    /// Will first look for the seekable integrity field at the start of `buf` (header), if
    /// that fails, it will try to find the integrity field at the end of `buf` (footer).
    ///
    /// # Errors
    ///
    /// Fails if the integrity field is neither present as header nor as footer, or if
    /// verification fails.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut offset = SKIPPABLE_HEADER_SIZE;
        let mut parser = if read_le32!(buf, SKIPPABLE_HEADER_SIZE + 5) == SEEKABLE_MAGIC_NUMBER {
            offset += SEEK_TABLE_INTEGRITY_SIZE;
            Parser::from_integrity(&buf[SKIPPABLE_HEADER_SIZE..])?
        } else {
            let mut integrity = [0u8; SEEK_TABLE_INTEGRITY_SIZE];
            integrity.copy_from_slice(&buf[buf.len() - SEEK_TABLE_INTEGRITY_SIZE..]);
            Parser::from_integrity(&integrity)?
        };

        parser.verify_skippable_header(&buf[..SKIPPABLE_HEADER_SIZE])?;
        parser.parse_entries(&buf[offset..]);
        parser.verify()?;

        Ok(parser.into())
    }

    /// Parses a seek table from a reader.
    ///
    /// The passed `reader` should only read the seek table, not the complete seekable archive.
    /// Creating a `SeekTable` from a reader only works with seek tables that have the seekable
    /// integrity field placed as a header.
    ///
    /// # Errors
    ///
    /// Fails if the integrity field is not present as header, or if verification fails.
    pub fn from_reader(mut reader: impl std::io::Read) -> Result<Self> {
        let mut buf = [0u8; SKIPPABLE_HEADER_SIZE + SEEK_TABLE_INTEGRITY_SIZE];
        reader.read_exact(&mut buf)?;

        let mut parser = Parser::from_integrity(&buf[SKIPPABLE_HEADER_SIZE..])?;
        parser.verify_skippable_header(&buf)?;

        let len = 8192.min(parser.seek_table_size);
        let mut buf = vec![0u8; len];

        let mut offset = 0;
        loop {
            if reader.read(&mut buf[offset..])? == 0 {
                break;
            };
            let n = parser.parse_entries(&buf);
            if n == 0 {
                break;
            }
            buf.copy_within(n.., 0);
            offset = buf.len() - n;
        }
        parser.verify()?;

        Ok(parser.into())
    }

    /// Adds a frame to this seek table.
    ///
    /// # Errors
    ///
    /// Fails if `num_frames()` reaches `SEEKABLE_MAX_FRAMES`.
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

    /// The number of frames in this seek table.
    pub fn num_frames(&self) -> u32 {
        // Can always be casted (max value SEEKABLE_MAX_FRAMES)
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
    pub fn max_frame_size_decomp(&self) -> u64 {
        (0..self.num_frames())
            .map(|i| {
                self.frame_size_decomp(i)
                    .expect("Frame index is never out of range")
            })
            .max()
            .unwrap_or(0)
    }

    /// Convert this seek table in an immutable, serializable form.
    ///
    /// The seek table will be serialized with the seekable integrity field placed as a
    /// header before any frame data. This is useful for creating a stand-alone seek table that
    /// can be parsed in a streaming fashion, i.e. without seeking the input.
    pub fn into_head_serializer(self) -> HeadSerializer {
        HeadSerializer {
            frames: self.entries.into_frames(),
            frame_index: 0,
            write_pos: 0,
        }
    }

    /// Convert this seek table in an immutable, serializable form.
    ///
    /// The seek table will be serialized with the seekable integrity field placed as a
    /// footer after any frame data. This is the typical seek table that can be appended to a
    /// seekable archive, however, parses need to seek the input for deserialization.
    pub fn into_foot_serializer(self) -> FootSerializer {
        FootSerializer {
            frames: self.entries.into_frames(),
            frame_index: 0,
            write_pos: 0,
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

/// A helper for seek table serialization with a header integrity field.
///
/// The seek table will be serialized with the seekable integrity field placed as a
/// header before any frame data. This is useful for creating stand-alone seek tables that
/// can be parsed in a streaming fashion, i.e. without seeking the input.
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
/// let mut ser = seek_table.into_head_serializer();
/// let mut buf = vec![0; ser.encoded_len()];
///
/// ser.write_into(&mut buf);
///
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct HeadSerializer {
    frames: Vec<Frame>,
    frame_index: usize,
    write_pos: usize,
}

impl HeadSerializer {
    /// Wite the seek table into `buf`.
    ///
    /// Returns the number of written. Call this repetitively until `0` is returned to serialize
    /// the entire seek table.
    pub fn write_into(&mut self, buf: &mut [u8]) -> usize {
        let mut buf_pos = 0;

        write_skippable_header!(buf, buf_pos, self);
        // Always fits in u32 (max value SEEKABLE_MAX_FRAMES)
        let num_frames = self.frames.len() as u32;
        // Write the integrity field at the beginning (head)
        write_integrity!(buf, buf_pos, self, num_frames, SKIPPABLE_HEADER_SIZE);

        // Serialize frames
        while self.frame_index < self.frames.len() {
            let offset = SKIPPABLE_HEADER_SIZE
                + SEEK_TABLE_INTEGRITY_SIZE
                + SIZE_PER_FRAME * self.frame_index;
            write_frame!(buf, buf_pos, self, offset);
        }

        buf_pos
    }

    /// Reset the serialization progress.
    ///
    /// Serialization stars from the beginning after calling this function. Can be called at any
    /// time.
    ///
    /// # Examples
    ///
    /// ```
    /// use zeekstd::SeekTable;
    ///
    /// # let mut seek_table = SeekTable::new();
    /// # seek_table.log_frame(123, 456)?;
    /// # seek_table.log_frame(333, 444)?;
    /// let mut ser = seek_table.into_head_serializer();
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

    // The total size of the seek table frame, not including the SKIPPABLE_MAGIC_NUMBER and
    // seek_table_size. Should always fit in u32.
    fn frame_size(&self) -> u32 {
        (self.encoded_len() - SKIPPABLE_HEADER_SIZE) as u32
    }
}

impl std::io::Read for HeadSerializer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.write_into(buf))
    }
}

/// A helper for seek table serialization with a footer integrity field.
///
/// The seek table will be serialized with the seekable integrity field placed as a
/// footer after any frame data. This is the typical seek table that can be appended to a
/// seekable archive, however, parses need to seek the input for deserialization.
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
/// let mut ser = seek_table.into_foot_serializer();
/// let mut buf = vec![0; ser.encoded_len()];
///
/// ser.write_into(&mut buf);
///
/// # Ok::<(), zeekstd::Error>(())
/// ```
pub struct FootSerializer {
    frames: Vec<Frame>,
    frame_index: usize,
    write_pos: usize,
}

impl FootSerializer {
    /// Wite the seek table into `buf`.
    ///
    /// Returns the number of written. Call this repetitively until `0` is returned to serialize
    /// the entire seek table.
    pub fn write_into(&mut self, buf: &mut [u8]) -> usize {
        let mut buf_pos = 0;

        write_skippable_header!(buf, buf_pos, self);
        // Serialize frames
        while self.frame_index < self.frames.len() {
            let offset = SKIPPABLE_HEADER_SIZE + SIZE_PER_FRAME * self.frame_index;
            write_frame!(buf, buf_pos, self, offset);
        }

        let offset = SKIPPABLE_HEADER_SIZE + SIZE_PER_FRAME * self.frames.len();
        // Always fits in u32 (max value SEEKABLE_MAX_FRAMES)
        let num_frames = self.frames.len() as u32;
        // Write the integrity field at the end (foot)
        write_integrity!(buf, buf_pos, self, num_frames, offset);

        buf_pos
    }

    /// Reset the serialization progress.
    ///
    /// Serialization stars from the beginning after calling this function. Can be called at any
    /// time.
    ///
    /// # Examples
    ///
    /// ```
    /// use zeekstd::SeekTable;
    ///
    /// # let mut seek_table = SeekTable::new();
    /// # seek_table.log_frame(123, 456)?;
    /// # seek_table.log_frame(333, 444)?;
    /// let mut ser = seek_table.into_foot_serializer();
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
        SKIPPABLE_HEADER_SIZE + self.frames.len() * SIZE_PER_FRAME + SEEK_TABLE_INTEGRITY_SIZE
    }

    // The total size of the seek table frame, not including the SKIPPABLE_MAGIC_NUMBER and
    // seek_table_size. Should always fit in u32.
    fn frame_size(&self) -> u32 {
        (self.encoded_len() - SKIPPABLE_HEADER_SIZE) as u32
    }
}

impl std::io::Read for FootSerializer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.write_into(buf))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use super::*;

    use rand::Rng;
    use zstd_safe::{OutBuffer, seekable::FrameLog};

    fn seek_table() -> SeekTable {
        let mut rng = rand::rng();
        let mut st = SeekTable::new();
        let num_frames = rng.random_range(4096..65536);

        for _ in 0..num_frames {
            let c_size = rng.random();
            let d_size = rng.random();
            st.log_frame(c_size, d_size).unwrap();
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

    #[test]
    fn serialize_with_head_integrity() {
        let mut ser = seek_table().into_head_serializer();

        // Complete serialization
        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, buf.len());

        // Further calls write zero bytes
        let n = ser.write_into(&mut buf);
        assert_eq!(n, 0);

        ser.reset();

        // Multiple write calls with changing buffer sizes
        let mut rng = rand::rng();
        let mut pos = 0;
        while pos < buf.len() {
            let len = if pos < 20 {
                1
            } else {
                (buf.len() - pos).min(rng.random_range(1..100))
            };
            let n = ser.write_into(&mut buf[pos..pos + len]);
            assert_eq!(n, len);
            pos += len;
        }

        assert_eq!(pos, ser.encoded_len());
    }

    #[test]
    fn serialize_with_foot_integrity() {
        let mut ser = seek_table().into_foot_serializer();

        // Complete serialization
        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, buf.len());

        // Further calls write zero bytes
        let n = ser.write_into(&mut buf);
        assert_eq!(n, 0);

        ser.reset();

        // Multiple write calls with changing buffer sizes
        let mut rng = rand::rng();
        let mut pos = 0;
        while pos < buf.len() {
            let len = if pos < 20 {
                1
            } else {
                (buf.len() - pos).min(rng.random_range(1..100))
            };
            let n = ser.write_into(&mut buf[pos..pos + len]);
            assert_eq!(n, len);
            pos += len;
        }

        assert_eq!(pos, ser.encoded_len());
    }

    #[test]
    fn serde_cycle_with_head_integrity() {
        let st = seek_table();
        let mut ser = st.clone().into_head_serializer();

        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, ser.encoded_len());

        let from_bytes = SeekTable::from_bytes(&buf).unwrap();
        assert_eq!(from_bytes, st);

        ser.reset();
        let mut seek_table = Cursor::new(Vec::with_capacity(ser.encoded_len()));
        let n = io::copy(&mut ser, &mut seek_table).unwrap();
        assert_eq!(n, ser.encoded_len() as u64);

        seek_table.set_position(0);
        let from_reader = SeekTable::from_reader(&mut seek_table).unwrap();
        assert_eq!(from_reader, st);
    }

    #[test]
    fn serde_cycle_with_foot_integrity() {
        let st = seek_table();
        let mut ser = st.clone().into_foot_serializer();

        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, ser.encoded_len());

        let from_bytes = SeekTable::from_bytes(&buf).unwrap();
        assert_eq!(from_bytes, st);

        ser.reset();
        let mut seek_table = Cursor::new(Vec::with_capacity(ser.encoded_len()));
        let n = io::copy(&mut ser, &mut seek_table).unwrap();
        assert_eq!(n, ser.encoded_len() as u64);

        seek_table.set_position(0);
        let from_reader = SeekTable::from_seekable(&mut seek_table).unwrap();
        assert_eq!(from_reader, st);
    }

    #[test]
    fn serialize_compatible_with_zstd_seekable() {
        let st = seek_table();
        let mut ser = st.clone().into_foot_serializer();
        let mut buf = vec![0; ser.encoded_len()];
        let n = ser.write_into(&mut buf);
        assert_eq!(n, ser.encoded_len());

        let mut sa = zstd_safe::seekable::Seekable::create();
        sa.init_buff(&buf).unwrap();

        assert_eq!(st.num_frames(), sa.num_frames());
        for i in 0..st.num_frames() {
            assert_eq!(
                st.frame_start_comp(i).unwrap(),
                sa.frame_compressed_offset(i).unwrap()
            );
            assert_eq!(
                st.frame_start_decomp(i).unwrap(),
                sa.frame_decompressed_offset(i).unwrap()
            );
            assert_eq!(
                st.frame_size_comp(i).unwrap(),
                sa.frame_compressed_size(i).unwrap() as u64
            );
            assert_eq!(
                st.frame_size_decomp(i).unwrap(),
                sa.frame_decompressed_size(i).unwrap() as u64
            );
        }
    }

    #[test]
    fn deserialize_compatible_with_zstd_seekable() {
        const NUM_FRAMES: u32 = 1234;
        let mut fl = FrameLog::create(true);

        for i in 1..=NUM_FRAMES {
            fl.log_frame(i * 7, i * 13, Some(i)).unwrap();
        }

        let cap = SKIPPABLE_HEADER_SIZE + (NUM_FRAMES * 12) as usize + SEEK_TABLE_INTEGRITY_SIZE;
        let mut buf = vec![0; cap];
        let mut out_buf = OutBuffer::around(&mut buf);
        let n = fl.write_seek_table(&mut out_buf).unwrap();
        // Verify that the entire seek table got written
        assert_eq!(n, 0);

        let st = SeekTable::from_bytes(&buf).unwrap();
        assert_eq!(st.num_frames(), NUM_FRAMES);

        for i in 1..=NUM_FRAMES {
            let c_size = i as u64 * 7;
            let d_size = i as u64 * 13;
            assert_eq!(st.frame_size_comp(i - 1).unwrap(), c_size);
            assert_eq!(st.frame_size_decomp(i - 1).unwrap(), d_size);
        }
    }
}
