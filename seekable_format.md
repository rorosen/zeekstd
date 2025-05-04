# Zstandard Seekable Format

### Notices

The initial version of this document, as well as the copyright notice, are copied from version
`0.1.0` of the [seekable format specification] of zstd.

[seekable format specification]: <https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md>

Copyright (c) Meta Platforms, Inc. and affiliates.

Permission is granted to copy and distribute this document for any purpose and without charge,
including translations into other languages and incorporation into compilations, provided that the
copyright notice and this notice are preserved, and that any substantive changes or deletions from
the original are clearly marked. Distribution of this document is unlimited.

### Version

0.1.1 (02/05/25)

## Introduction

This document defines a format for compressed data to be stored so that subranges of the data can be
efficiently decompressed without requiring the entire document to be decompressed. This is done by
splitting up the input data into frames, each of which are compressed independently, and so can be
decompressed independently. Decompression then takes advantage of a provided 'seek table', which
allows the decompressor to immediately jump to the desired data. This is done in a way that is
compatible with the original Zstandard format by placing the seek table in a Zstandard skippable
frame.

### Overall conventions

In this document:

- square brackets i.e. `[` and `]` are used to indicate optional fields or parameters.
- the naming convention for identifiers is `Mixed_Case_With_Underscores`
- All numeric fields are little-endian unless specified otherwise

## Format

The format consists of a number of frames (Zstandard compressed frames and skippable frames), and a
skippable frame containing the seek table. The seek table frame can either be appended to the end of
all other frames, or written to a separate file.

### Seek Table Format

The seek table can be structured in two different formats, i.e. the classic `Foot` format and the
`Head` format, which was added in version `0.1.1` of this document. Seekable decoders start reading
`Foot` seek tables from the end, while `Head` seek tables can be read from the beginning without
needing to seek to the end of the file. The classic `Foot` format is designed to be placed at the
end of seekable archives. The `Head` format, on the other hand, should be placed in stand-alone
files.

In version `0.1.0` of this document, `Seek_Table_Entries` contained an optional checksum. Placing
checksums in the seek table is deprecated in version `0.1.1`, the `Content_Checksum` field of
regular [Zstandard frames] is used instead. However, seek tables that contain checksums can still be
decoded successfully, although any checksum data is ignored.

**`Foot`**

The seek table integrity field is at the end of the skippable frame, after any frame data. This
format is the same as specified in version `0.1.0` of this document.

| `Skippable_Magic_Number` | `Frame_Size` | `[Seek_Table_Entries]` | `Seek_Table_Integrity` |
| ------------------------ | ------------ | ---------------------- | ---------------------- |
| 4 bytes                  | 4 bytes      | 8 bytes each           | 9 bytes                |

**`Head`**

The seek table integrity field is placed directly after the skippable header, before any frame data.
This format was added in version `0.1.1` of this document and is incompatible with prior decoders.

| `Skippable_Magic_Number` | `Frame_Size` | `Seek_Table_Integrity` | `[Seek_Table_Entries]` |
| ------------------------ | ------------ | ---------------------- | ---------------------- |
| 4 bytes                  | 4 bytes      | 9 bytes                | 8 bytes each           |

**`Skippable_Magic_Number`**

Value : 0x184D2A5E. This is for compatibility with [Zstandard skippable frames]. Since it is legal
for other Zstandard skippable frames to use the same magic number, it is not recommended for a
decoder to recognize frames solely on this.

**`Frame_Size`**

The total size of the skippable frame, not including the `Skippable_Magic_Number` or `Frame_Size`.
This is for compatibility with [Zstandard skippable frames].

[Zstandard skippable frames]: https://github.com/facebook/zstd/blob/release/doc/zstd_compression_format.md#skippable-frames

#### `Seek_Table_Integrity`

The seek table integrity format is as follows:

| `Number_Of_Frames` | `Seek_Table_Descriptor` | `Seekable_Magic_Number` |
| ------------------ | ----------------------- | ----------------------- |
| 4 bytes            | 1 byte                  | 4 bytes                 |

`Seek_Table_Integrity` is called `Seek_Table_Footer` in version `0.1.0` of this document.

**`Seekable_Magic_Number`**

Value : 0x8F92EAB1. This value must be the last bytes present in the integrity field so that
decoders can efficiently find it and determine if there is an actual seek table present.

**`Number_Of_Frames`**

The number of stored frames in the data.

**`Seek_Table_Descriptor`**

A bitfield describing the format of the seek table.

| Bit number | Field name      |
| ---------- | --------------- |
| 7          | `Checksum_Flag` |
| 6-2        | `Reserved_Bits` |
| 1-0        | `Unused_Bits`   |

While only `Checksum_Flag` currently exists, there are 7 other bits in this field that can be used
for future changes to the format, for example the addition of inline dictionaries.

**`Checksum_Flag`**

The checksum flag is not actively used in version `0.1.1`. Checksum data will not be placed in the
seek table, instead the `Content_Checksum` field of regular [Zstandard frames] is used. Every seek
table created with version `0.1.1` sets `Checksum_Flag` to zero.

[Zstandard frames]: <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#zstandard-frames>

`Reserved_Bits` are not currently used but may be used in the future for breaking changes, so a
compliant decoder should ensure they are set to 0. `Unused_Bits` may be used in the future for
non-breaking changes, so a compliant decoder should not interpret these bits.

#### **`Seek_Table_Entries`**

`Seek_Table_Entries` consists of `Number_Of_Frames` (one for each frame in the data, not including
the seek table frame) entries of the following form, in sequence:

| `Compressed_Size` | `Decompressed_Size` | `[Checksum]` |
| ----------------- | ------------------- | ------------ |
| 4 bytes           | 4 bytes             | 4 bytes      |

**`Compressed_Size`**

The compressed size of the frame. The cumulative sum of the `Compressed_Size` fields of frames `0`
to `i` gives the offset in the compressed file of frame `i+1`.

**`Decompressed_Size`**

The size of the decompressed data contained in the frame. For skippable or otherwise empty frames,
this value is 0.

**`Checksum`**

Not used in version `0.1.1`, created seek tables will never contain checksums. Legacy seek tables
that have `Checksum_Flag` set and contain checksums can be decoded, but the checksums are ignored.
The `Content_Checksum` field of regular [Zstandard frames] is used instead.

## Version Changes

- 0.1.1: add `Foot` and `Head` seek table formats, deprecate checksum data in seek table
- 0.1.0: initial version
