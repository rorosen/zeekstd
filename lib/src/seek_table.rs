use zstd_safe::zstd_sys::ZSTD_ErrorCode;

use crate::{
    SEEK_TABLE_FOOTER_SIZE, SEEKABLE_MAGIC_NUMBER, SKIPPABLE_HEADER_SIZE, SKIPPABLE_MAGIC_NUMBER,
    error::{Error, Result},
    seekable::Seekable,
};

macro_rules! read_le32 {
    ($buf:expr, $offset:expr) => {
        ($buf[$offset] as u32)
            | (($buf[$offset + 1] as u32) << 8)
            | (($buf[$offset + 2] as u32) << 16)
            | (($buf[$offset + 3] as u32) << 24)
    };
}

#[derive(Debug, Clone)]
struct Entry {
    c_offset: u64,
    d_offset: u64,
    checksum: Option<u32>,
}

#[derive(Debug, Clone)]
struct Entries(Vec<Entry>);

impl core::ops::Index<u32> for Entries {
    type Output = Entry;

    fn index(&self, index: u32) -> &Self::Output {
        let idx = usize::try_from(index).expect("Frame index can be transformed to uisze");
        &self.0[idx]
    }
}

/// A helper struct that parses the bytes of a seek table.
#[derive(Debug)]
struct SeekTableParser {
    with_checksum: bool,
    num_frames: usize,
    size_per_frame: usize,
    seek_table_size: usize,
    entries: Entries,
    c_offset: u64,
    d_offset: u64,
}

impl SeekTableParser {
    /// Create a [`SeekTableParser`] from the footer of a seek table.
    ///
    /// The footer consists of the last 9 bytes of a seek table.
    ///
    /// # Errors
    ///
    /// Fails if `buf` does not contain a valid seek table footer.
    fn from_footer(buf: &[u8]) -> Result<Self> {
        if read_le32!(buf, 5) != SEEKABLE_MAGIC_NUMBER {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }

        // Check reserved bits are not set
        if ((buf[4] >> 2) & 0x1f) > 0 {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
        }

        let with_checksum = (buf[4] & (1 << 7)) > 0;
        let num_frames = read_le32!(buf, 0)
            .try_into()
            .expect("Number of frames never exceeds u32");
        let size_per_frame: usize = if with_checksum { 12 } else { 8 };
        let table_size = num_frames * size_per_frame;
        let seek_table_size = table_size + SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE;

        Ok(Self {
            with_checksum,
            num_frames,
            size_per_frame,
            seek_table_size,
            entries: Entries(vec![]),
            c_offset: 0,
            d_offset: 0,
        })
    }

    /// Verifies the header of the seek table.
    ///
    /// The header consists of the first 8 bytes of a seek table.
    ///
    /// # Errors
    ///
    /// Fails if `buf` does not start with the skippable magic number (`0x184D2A5E`) or does not
    /// specify the correct seek table size.
    fn verify_header(&self, buf: &[u8]) -> Result<()> {
        if read_le32!(buf, 0) != SKIPPABLE_MAGIC_NUMBER {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }
        let size = usize::try_from(read_le32!(buf, 4)).expect("Frame size never exceeds u32");
        if size + SKIPPABLE_HEADER_SIZE != self.seek_table_size {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }

        Ok(())
    }

    /// Call this repetitively to parse the entries of a seek table.
    ///
    /// Returns how many bytes were consumed from `buf`. In case of a `0` return value, all
    /// entries were parsed or the provided buffer is too small.
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

            let checksum = if self.with_checksum {
                Some(read_le32!(buf, pos + 8))
            } else {
                None
            };

            let entry = Entry {
                c_offset: *c_offset,
                d_offset: *d_offset,
                checksum,
            };
            entries.0.push(entry);
            // Casting u32 to u64 is fine
            *c_offset += read_le32!(buf, pos) as u64;
            *d_offset += read_le32!(buf, pos + 4) as u64;
            pos += self.size_per_frame;
        }

        if entries.0.len() == self.num_frames {
            // Add an additional entry that marks the end of the last frame
            let entry = Entry {
                c_offset: *c_offset,
                d_offset: *d_offset,
                checksum: None,
            };
            entries.0.push(entry);
        }

        pos
    }
}

impl From<SeekTableParser> for SeekTable {
    fn from(value: SeekTableParser) -> Self {
        SeekTable {
            entries: value.entries,
            with_checksum: value.with_checksum,
            // Frame number always fits in u32
            num_frames: value.num_frames as u32,
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
#[derive(Debug, Clone)]
pub struct SeekTable {
    entries: Entries,
    with_checksum: bool,
    num_frames: u32,
}

impl SeekTable {
    /// Creates a new `SeekTable` from a seekable archive.
    ///
    /// # Errors
    ///
    /// Returns an error if the seek table cannot be parsed or validation fails.
    pub fn from_seekable<S>(src: &mut S) -> Result<Self>
    where
        S: Seekable,
    {
        let footer = src.seek_table_footer()?;
        let mut parser = SeekTableParser::from_footer(&footer)?;
        src.seek_to_seek_table_start(parser.seek_table_size)?;
        // No need to read the footer again
        let cap = 8192.min(parser.seek_table_size - SEEK_TABLE_FOOTER_SIZE);
        let mut buf = vec![0u8; cap];
        src.read(&mut buf)?;
        parser.verify_header(&buf[..8])?;
        buf.drain(..8);

        loop {
            if parser.parse_entries(&buf) == 0 {
                break;
            }
            if src.read(&mut buf)? == 0 {
                break;
            };
        }

        Ok(parser.into())
    }

    fn frame_index_at(&self, offset: u64, callback: impl Fn(u32) -> u64) -> u32 {
        if offset >= callback(self.num_frames) {
            return self.num_frames;
        }

        let mut low = 0;
        let mut high = self.num_frames;

        while low + 1 < high {
            let mid = low.midpoint(high);
            if callback(mid) <= offset {
                low = mid;
            } else {
                high = mid;
            }
        }

        low
    }

    /// Gets the number of frames in the `SeekTable`.
    pub fn num_frames(&self) -> u32 {
        self.num_frames
    }

    /// Whether the frames contain a checksum.
    pub fn with_checksum(&self) -> bool {
        self.with_checksum
    }

    /// Gets the checksum of the frame at `index`.
    ///
    /// Returns `None` if the frame has no checksum.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_checksum(&self, index: u32) -> Result<Option<u32>> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index].checksum)
    }

    /// Gets the frame index at the given compressed offset.
    pub fn frame_index_comp(&self, offset: u64) -> u32 {
        self.frame_index_at(offset, |i| self.entries[i].c_offset)
    }

    /// Gets the frame index at the given decompressed offset.
    pub fn frame_index_decomp(&self, offset: u64) -> u32 {
        self.frame_index_at(offset, |i| self.entries[i].d_offset)
    }

    /// Gets the start position of frame `index` in the compressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_start_comp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index].c_offset)
    }

    /// Gets the start position of frame `index` in the decompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_start_decomp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index].d_offset)
    }

    /// Gets the end position of frame `index` in the compressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_end_comp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index + 1].c_offset)
    }

    /// Gets the end position of frame `index` in the decompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_end_decomp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index + 1].d_offset)
    }

    /// Gets the compressed size of frame `index`.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_size_comp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        let size = self.entries[index + 1].c_offset - self.entries[index].c_offset;
        Ok(size)
    }

    /// Gets the decompressed size of frame `index`.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_size_decomp(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        let size = self.entries[index + 1].d_offset - self.entries[index].d_offset;
        Ok(size)
    }
}
