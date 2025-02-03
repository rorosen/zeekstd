# Zeekstd

Compress and decompress data using the
[Zstandard Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format). This
tool uses rust bindings provided by [zstd-rs](https://github.com/gyscos/zstd-rs).

## Compressing

Compress data with the `compress` subcommand.

```bash
$ seq 20000 | zeekstd compress -o numbers.txt.zst
Wrote 12.60 KiB to numbers.txt.zst
```

The created archive can be inspected with the regular `zstd` command.

```bash
$ zstd -l numbers.txt.zst
Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename
    15      1    12.6 KiB                        None  numbers.txt.zst
```

You can control the maximal frame size, and therefore the number of frames in the archive, with the
`--max-frame-size` parameter. See `zeekstd compress --help` for all available compression options.

## Decompressing

Decompress with the `decompress` subcommand.

```bash
$ zeekstd decompress numbers.txt.zst
Read 12.60 KiB from numbers.txt.zst
Wrote 106.34 KiB to numbers.txt
Decompression ratio: 843.81%
```

If you decompress the complete archive, you may also use the regular `zstd` tool, it produces the
same result. However, the advantage of the seekable format shows when you only want to decompress a
section of the archive.

```bash
# Decompress only the first 6 bytes (3 characters and 3 newlines)
$ zeekstd -cf decompress --to 6 numbers.txt.zst
1
2
3
```

Keep in mind that `zeekstd` is required to decompress the complete first frame, although only 6
bytes are shown. See `zeekstd decompress --help` for all available decompression options.
