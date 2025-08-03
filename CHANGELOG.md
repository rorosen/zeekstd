# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1-lib]

### Added

- Use property testing

### Fixed

- Parsing a seek table with 1022 frames does not falsely yield a "corruption detected" error anymore

## [0.5.0-lib]

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

## [0.4.0-lib]

### Added

- Add options for decompression from an arbitrary byte offset up to an offset limit

### Changed

- Argument `--from` of the `decompress` command now expects a byte offset, not a frame index
- Argument `--to` of the `decompress` command now expects an offset limit, not a frame index
