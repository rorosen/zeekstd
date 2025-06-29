# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Implement decompression from an arbitrary byte offset up to an offset limit
  - `offset` and `offset_limit` can be set on `DecodeOptions` and `Decoder`
  - All values are decompressed offsets
  - If `offset` is not the beginning of a frame, the decoder will decompress everything from the
    last frame start up to `offset` to an internal buffer
  - The decoder will stop decompression when reaching `offset_limit`. The checksum of the last frame
    will not be verified, except `offset_limit` is exactly the end of a frame
  - Only bytes in the requested range are returned from `read` and `decompress` calls
  - `Decoder::set_lower_frame` and `Decoder::set_upper_frame` return a `Result` now
- Implement `std::io::Seek` for `Decoder`
- CLI: Add options for decompression from an arbitrary byte offset up to an offset limit
  - `--from` now expects a byte offset, not a frame index
  - `--from-frame` takes a frame index
  - `--to` now expects an offset limit, not a frame index
  - `--to-frame` takes a frame index
