# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Do not start printing the progress bar before checking whether output file exists
- Only derive the output file name during decompression when the input file has a `zst` extension
- Refuse reading from stdin, if it is a terminal. Use `--force` to disable the check
- Fix the numbers of frames that are printed when `--num-frames` is passed to the `list` subcommand.
  Formerly this listed one frame too much.

## [0.4.4]

### Added

- Add `-s` as shorthand for `--frame-size` in compress subcommand

## [0.4.3]

### Fixed

- Print raw progress bytes if `--raw-bytes` is passed
- Respect offset for progress bar
- Accept `u64` range for `--to` argument

## [0.4.2]

### Changed

- Use lib `v0.6.1`

## [0.4.1]

### Fixed

- The window size that is used when creating/applying binary patches is now always big enough to fit
  the complete prefix
- Parsing a seek table with 1022 frames does not falsely yield a "corruption detected" error anymore

## [0.4.0]

### Added

- Add options for decompression from an arbitrary byte offset up to an offset limit

### Changed

- Argument `--from` of the `decompress` command now expects a byte offset, not a frame index
- Argument `--to` of the `decompress` command now expects an offset limit, not a frame index
