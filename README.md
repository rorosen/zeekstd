# Zeekstd

Compress and decompress data using the
[Zstandard Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format). The
seekable format splits compressed data into a series of independent "frames", each compressed
individually, so that decompression of a section in the middle of an archive only requires zeekstd
to decompress at most a frame's worth of extra data, instead of the entire archive.

Zeekstd uses rust bindings provided by [zstd-rs](https://github.com/gyscos/zstd-rs).

## Compression

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

## Decompression

Decompress seekable archives with the `decompress` subcommand.

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

## Print Information

Print information about a seekable archive with the `list` subcommand. When called with no further
arguments, it will print general information similar to `zstd -l`.

```bash
$ zeekstd list numbers.txt.zst
Frames          Compressed      Decompressed    Max Frame Size  Ratio           Filename
14              12.42 KiB       106.34 KiB      8.00 KiB        8.561           numbers.txt.zst
```

You can also list all frames of an archive.

```bash
$ zeekstd list numbers.txt.zst --from start --to end
Frame Index     Compressed      Decompressed    Compressed Offset    Decompressed Offset
0               2.23 KiB        8.00 KiB        0                    0
1               697 B           8.00 KiB        2287                 8192
2               745 B           8.00 KiB        2984                 16384
3               752 B           8.00 KiB        3729                 24576
4               722 B           8.00 KiB        4481                 32768
5               806 B           8.00 KiB        5203                 40960
6               923 B           8.00 KiB        6009                 49152
7               883 B           8.00 KiB        6932                 57344
8               963 B           8.00 KiB        7815                 65536
9               910 B           8.00 KiB        8778                 73728
10              879 B           8.00 KiB        9688                 81920
11              948 B           8.00 KiB        10567                90112
12              908 B           8.00 KiB        11515                98304
13              297 B           2.34 KiB        12423                106496
```

Or only specific frames.

```bash
$ zeekstd l numbers.txt.zst --from-frame 6 --to-frame 9
Frame Index     Compressed      Decompressed    Compressed Offset    Decompressed Offset
6               923 B           8.00 KiB        6009                 49152
7               883 B           8.00 KiB        6932                 57344
8               963 B           8.00 KiB        7815                 65536
```

See `zeekstd list --help` for all available list options.

## License

- The zstd C library is under a dual BSD/GPLv2 license.
- Zeekstd is under a BSD 2-Clause License.
