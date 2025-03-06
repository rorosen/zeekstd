# Zeekstd

Compress and decompress data using the
[Zstandard Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format). This
tool uses rust bindings provided by [zstd-rs](https://github.com/gyscos/zstd-rs).

## Compressing

Compress data with the `compress` subcommand. This is the default when no subcommand is specified.

```bash
$ seq 20000 | zeekstd compress -o numbers.txt.zst
Wrote 12.60 KiB to numbers.txt.zst
# or
$ seq 20000 | zeekstd -o numbers.txt.zst
Wrote 12.60 KiB to numbers.txt.zst
```

The created archive can be inspected with the regular `zstd` command.

```bash
$ zstd -l numbers.txt.zst
Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename
    15      1    12.6 KiB                        None  numbers.txt.zst
```

You can control the maximum frame size, and therefore the number of frames in the archive, with the
`--max-frame-size` parameter.

See `zeekstd compress --help` for all available compression options.

## Decompressing

Decompress with the `decompress` subcommand.

```bash
$ zeekstd decompress numbers.txt.zst
Read 12.60 KiB from numbers.txt.zst
Wrote 106.34 KiB to numbers.txt
Decompression ratio: 843.81%
```

If you want to decompress the complete archive, you may also use the regular `zstd` tool as it
produces the same result. However, the advantage of the seekable format shows when you only want to
decompress only a part of the archive.

```bash
$ zeekstd decompress -cf --from 12348 --to 12362 numbers.txt.zst
2692
2693
2694
```

Notice that `zeekstd` needs to decompress the complete frame that contains the data, although only
the requested bytes are shown.

See `zeekstd decompress --help` for all available decompression options.

## License

- The zstd C library is under a dual BSD/GPLv2 license.
- Zeekstd is under a BSD license.
