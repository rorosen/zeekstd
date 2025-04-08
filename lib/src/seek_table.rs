use std::{
    fmt::Debug,
    io::{BufRead, Seek, SeekFrom},
};

use zstd_safe::zstd_sys::ZSTD_ErrorCode;

use crate::{
    SEEK_TABLE_FOOTER_SIZE, SEEKABLE_MAGIC_NUMBER, SKIPPABLE_HEADER_SIZE, SKIPPABLE_MAGIC_NUMBER,
    error::{Error, Result},
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
    checksum: u32,
}

/// Holds information of the frames of a seekable archive.
///
/// The `SeekTable` allows decompressors to jump directly to the beginning of frames. It is placed
/// in a Zstandard skippable frame at the end of a seekable archive.
#[derive(Debug, Clone)]
pub struct SeekTable {
    entries: Vec<Entry>,
    with_checksum: bool,
    num_frames: u32,
}

impl SeekTable {
    /// Get the number of frames of the `SeekTable`.
    pub fn num_frames(&self) -> u32 {
        self.num_frames
    }

    /// Whether the frames contain a checksum.
    pub fn with_checksum(&self) -> bool {
        self.with_checksum
    }
}

impl SeekTable {
    /// Create a new `SeekTable` from a seekable archive.
    ///
    /// # Errors
    ///
    /// Returns an error if validation of the `SeekTable` fails.
    pub fn from_seekable<S>(src: &mut S) -> Result<Self>
    where
        S: Seek + BufRead,
    {
        src.seek(SeekFrom::End(-(SEEK_TABLE_FOOTER_SIZE as i64)))?;
        let buf = src.fill_buf()?;

        if read_le32!(buf, 5) != SEEKABLE_MAGIC_NUMBER {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }
        // Check reserved bits
        if ((buf[4] >> 2) & 0x1f) > 0 {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_corruption_detected));
        }

        let with_checksum = (buf[4] & (1 << 7)) > 0;
        let num_frames = read_le32!(buf, 0);
        let size_per_frame: usize = if with_checksum { 12 } else { 8 };
        let table_size = num_frames * size_per_frame as u32;
        let seek_table_size = table_size + SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE;

        src.seek(SeekFrom::End(-(seek_table_size as i64)))?;
        let mut buf = src.fill_buf()?;

        if read_le32!(buf, 0) != SKIPPABLE_MAGIC_NUMBER {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }
        if read_le32!(buf, 4) + SKIPPABLE_HEADER_SIZE != seek_table_size {
            return Err(Error::zstd(ZSTD_ErrorCode::ZSTD_error_prefix_unknown));
        }

        let mut entries = vec![];
        let mut pos: usize = 8;
        let mut c_offset = 0;
        let mut d_offset = 0;

        while (entries.len() as u32) < num_frames {
            if pos + size_per_frame > buf.len() {
                src.consume(pos);
                buf = src.fill_buf()?;
                pos = 0;
            }

            let checksum = if with_checksum {
                Some(read_le32!(buf, pos + 8))
            } else {
                None
            };

            let entry = Entry {
                c_offset,
                d_offset,
                checksum: checksum.unwrap_or(0),
            };
            entries.push(entry);
            c_offset += read_le32!(buf, pos) as u64;
            d_offset += read_le32!(buf, pos + 4) as u64;
            pos += size_per_frame;
        }

        // Add a last entry that only has the end of the last frame
        let entry = Entry {
            c_offset,
            d_offset,
            checksum: 0,
        };
        entries.push(entry);

        let seek_table = SeekTable {
            entries,
            with_checksum,
            num_frames,
        };
        Ok(seek_table)
    }

    fn frame_index_at_offset(&self, offset: u64, callback: impl Fn(usize) -> u64) -> u32 {
        if offset >= callback(self.num_frames as usize) {
            return self.num_frames;
        }

        let mut low = 0;
        let mut high = self.num_frames;

        while low + 1 < high {
            let mid = low.midpoint(high);
            if callback(mid as usize) <= offset {
                low = mid;
            } else {
                high = mid;
            }
        }

        low
    }

    /// Get the frame index at the given compressed offset.
    pub fn frame_index_at_compressed_offset(&self, offset: u64) -> u32 {
        self.frame_index_at_offset(offset, |i| self.entries[i].c_offset)
    }

    /// Get the frame index at the given decompressed offset.
    pub fn frame_index_at_decompressed_offset(&self, offset: u64) -> u32 {
        self.frame_index_at_offset(offset, |i| self.entries[i].d_offset)
    }

    /// Get the checksum of the frame at `index`.
    ///
    /// # Returns
    ///
    /// Returns zero if the frame has no checksum.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_checksum(&self, index: u32) -> Result<u32> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index as usize].checksum)
    }

    /// Get the start position of the frame at `index` in the compressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_compressed_start(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index as usize].c_offset)
    }

    /// Get the start position of the frame at `index` in the decompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_decompressed_start(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index as usize].d_offset)
    }

    /// Get the end position of the frame at `index` in the compressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_compressed_end(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index as usize + 1].c_offset)
    }

    /// Get the end position of the frame at `index` in the decompressed data.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_decompressed_end(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        Ok(self.entries[index as usize + 1].d_offset)
    }

    /// Get the compressed size of the frame at `index`.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_compressed_size(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        let size =
            self.entries[index as usize + 1].c_offset - self.entries[index as usize].c_offset;
        Ok(size)
    }

    /// Get the decompressed size of the frame at `index`.
    ///
    /// # Errors
    ///
    /// Fails if the frame index is out of range.
    pub fn frame_decompressed_size(&self, index: u32) -> Result<u64> {
        if index >= self.num_frames {
            return Err(Error::frame_index_too_large());
        }

        let size =
            self.entries[index as usize + 1].d_offset - self.entries[index as usize].d_offset;
        Ok(size)
    }
}
