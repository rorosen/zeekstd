# Zeekstd CLI

A CLI tool for the Zstandard seekable format.

## Installation

#### From nixpkgs

```bash
nix-shell -p zeekstd
```

> [!NOTE]
> This installation method is temporary

#### From prebuilt binaries

Visit the [release page](https://github.com/rorosen/zeekstd/releases) for prebuilt, statically
linked binaries of zeekstd.

#### From `crates.io`

```bash
cargo install zeekstd_cli
```

#### From local source

```bash
cargo install --path ./cli
```

## Building

#### With cargo

```bash
git clone https://github.com/rorosen/zeekstd.git
cd zeekstd
cargo build -p zeekstd_cli --release
./target/release/zeekstd --version
```

#### With Nix

```bash
nix build github:rorosen/zeekstd#default
./result/bin/zeekstd --version
```

## Compression

Compress data with the `compress` subcommand. This is the default when no subcommand is specified.

```bash
$ seq 20000 | zeekstd compress --frame-size 10K -o numbers.txt.zst
STDIN : 25.03% ( 106.34 KiB => 26.61 KiB, numbers.txt.zst)
# or
$ seq 20000 | zeekstd --frame-size 10K -o numbers.txt.zst
STDIN : 25.03% ( 106.34 KiB => 26.61 KiB, numbers.txt.zst)
```

Run `zeekstd compress --help` for all available compression options.

## Decompression

Decompress seekable files with the `decompress` subcommand. If not specified otherwise, the complete
input is decompressed.

```bash
$ zeekstd decompress numbers.txt.zst
numbers.txt.zst : 106.34 KiB
```

Alternatively, decompress only specific frames. Note that `--to-frame` is inclusive, the command
below will decompress 4 frames: 3, 4, 5 and 6.

```bash
$ zeekstd decompress --from-frame 3 --to-frame 6 numbers.txt.zst
numbers.txt.zst : 40.00 KiB
```

Or decompress between arbitrary byte offsets.

```bash
$ zeekstd decompress --from 114 --to 117 numbers.txt.zst -cfq
42
```

See `zeekstd decompress --help` for all available decompression options.

## Print Information

Print information about a seekable compressed file with the `list` subcommand. When called with no
further arguments, it will print compact information about the compressed file, similar to
`zstd -l`.

```bash
$ zeekstd list numbers.txt.zst
Frames          Compressed      Uncompressed    Max Frame Size  Ratio      Filename
11              26.51 KiB       106.34 KiB      10.00 KiB       4.011      numbers.txt.zst
```

Pass the `--detail` flag to list all frames individually and see more detailed information.

```bash
$ zeekstd list --detail numbers.txt.zst
Frame Index     Compressed      Uncompressed    Compressed Offset    Uncompressed Offset
0               4.21 KiB        10.00 KiB       0 B                  0 B
1               4.17 KiB        10.00 KiB       4.21 KiB             10.00 KiB
2               4.18 KiB        10.00 KiB       8.38 KiB             20.00 KiB
3               4.19 KiB        10.00 KiB       12.56 KiB            30.00 KiB
4               4.07 KiB        10.00 KiB       16.74 KiB            40.00 KiB
5               1.08 KiB        10.00 KiB       20.82 KiB            50.00 KiB
6               977 B           10.00 KiB       21.90 KiB            60.00 KiB
7               1.08 KiB        10.00 KiB       22.85 KiB            70.00 KiB
8               1.07 KiB        10.00 KiB       23.93 KiB            80.00 KiB
9               978 B           10.00 KiB       25.00 KiB            90.00 KiB
10              572 B           6.34 KiB        25.95 KiB            100.00 KiB
```

See `zeekstd list --help` for all available list options.
