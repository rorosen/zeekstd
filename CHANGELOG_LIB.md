# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2]

### Fixed

- Fix a seek table decoding bug where it gets populated with wrong data when the read buffer gets
  only partially filled.

## [0.6.1]

### Fixed

- Decoding no longer panics due to wrong slice indexing when the output buffer is partially filled

## [0.6.0]

### Fixed

- The `read()` function of the implementation of the `Seekable` trait for `BytesWrapper` no longer
  panics due to wrong internal range boundaries
- Fixed a problem where frames were not logged in the seek table when the frame epilogue exactly
  filled the output buffer in use

### Added

- New enum `OffsetFrom` with the variants `Start(u64)` and `End(i64)`. Works similar to
  `std::io::SeekFrom`
- New structs `CompressionProgress` and `EpilogueProgress`, which are used to indicate the progress
  of a compression/epilogue writing step
- Added the `std` feature, which is enabled by default. Disabling the `std` feature limits
  higher-level features of zeekstd, but also allows it to run in `no_std` programs

### Changed

The `Seekable` trait has changed in an incompatible way:

- The method `Seekable::seek_table_footer()` was removed
- The method `Seekable::seek_to_seek_table_start()` was removed
- The method `Seekable::set_offset()` now returns `Result<u64>` where the `u64` value is the new
  offset position form the start of the seekable object
- The type of `offset` in `Seekable::set_offset()` changed from `u64` to `OffsetFrom`
- The method `Seekable::seek_table_integrity()` was added

The `RawEncoder` struct has changed in an incompatible way:

- The methods `RawEncoder::compress()` and `RawEncoder::compress_with_prefix` now return
  `Result<CompressionProgress>` instead of `Result<(u64, u64)>`
- The method `RawEncoder::end_frame()` now returns `Result<EpilogueProgress>` instead of
  `Result<(u64, u64)>`

The `EncodeOptions` struct has changed in an incompatible way:

- The method `EncodeOptions::into_raw()` was renamed to `EncodeOptions::into_raw_encoder()`

The `SeekTable` struct has changed in an incompatible way:

- The method `SeekTable::from_seekable_format()` was added
- The method `SeekTable::from_bytes()` was removed. Use `SeekTable::from_seekable()` or
  `SeekTable::from_seekable_format()` together with the `BytesWrapper` struct instead

The `Error` struct changed in an incompatible way:

- The function `Error::other()` was removed
- The method `Error::is_other()` was removed

## [0.5.1]

### Added

- Use property testing

### Fixed

- Parsing a seek table with 1022 frames does not falsely yield a "corruption detected" error anymore

## [0.5.0]

### Added

- Implement decompression from an arbitrary byte offset up to an offset limit
  - `offset` and `offset_limit` can be set on `DecodeOptions` and `Decoder`
  - All values are decompressed offsets
  - If `offset` is not the beginning of a frame, the decoder will decompress everything from the
    last frame start up to `offset` to an internal buffer
  - The decoder will stop decompression when reaching `offset_limit`. The checksum of the last frame
    will not be verified, except `offset_limit` is exactly the end of a frame
  - Only bytes in the requested range are returned from `read` and `decompress` calls
- Implement `std::io::Seek` for `Decoder`

### Changed

- `Decoder::set_lower_frame` and `Decoder::set_upper_frame` return a `Result` now
