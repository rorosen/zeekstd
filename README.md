# Zeekstd

Compress and decompress data using the
[Zstandard Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format). This
tool uses rust bindings provided by [zstd-rs](https://github.com/gyscos/zstd-rs).

## Compressing

Compress data with the `compress` subcommand. This is the default when no subcommand is specified.

```bash
$ seq 20000 | zeekstd compress -o numbers.txt.zst
STDIN : 11.85% ( 106.34 KiB => 12.60 KiB, numbers.txt.zst)
# or
$ seq 20000 | zeekstd -o numbers.txt.zst
STDIN : 11.85% ( 106.34 KiB => 12.60 KiB, numbers.txt.zst)
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
numbers.txt.zst : 106.34 KiB
```

Note that you can also use the regular `zstd` command to decompress the complete archive. However,
the advantage of the seekable format shows when you want to decompress only a part of the archive.

Use the `--from` and `--to` arguments to specify the decompressed start and end positions. You may
also use the `--from-frame` and `--to-frame` arguments to specify frame numbers. We also pass `-cf`
in the example to force printing to stdout, since we know that this is only text data.

```bash
$ zeekstd d -cf --from 12348 --to 12362 numbers.txt.zst
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
