# Zeekstd CLI

## Installation

#### From nixpkgs

```bash
nix-shell -p zeekstd
```

> [!NOTE]
> This installation method is temporary

#### From binaries

TODO

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
$ seq 20000 | zeekstd compress -o numbers.txt.zst
STDIN : 11.85% ( 106.34 KiB => 12.60 KiB, numbers.txt.zst)
# or
$ seq 20000 | zeekstd -o numbers.txt.zst
STDIN : 11.85% ( 106.34 KiB => 12.60 KiB, numbers.txt.zst)
```

See `zeekstd compress --help` for all available compression options.

## Decompression

Decompress seekable files with the `decompress` subcommand. Per default the complete input is
decompressed.

```bash
$ zeekstd decompress numbers.txt.zst
numbers.txt.zst : 106.34 KiB
```

Alternatively, decompress between arbitrary byte offsets.

```bash
$ zeekstd decompress --from 113 --to 117 numbers.txt.zst -cfq
42
```

See `zeekstd decompress --help` for all available decompression options.

## Print Information

Print information about a seekable compressed file with the `list` subcommand. When called with no
further arguments, it will print general information similar to `zstd -l`, pass the `--detail` flag
to list all frames individually.

```bash
$ zeekstd list numbers.txt.zst
Frames          Compressed      Decompressed    Max Frame Size  Ratio           Filename
14              12.42 KiB       106.34 KiB      8.00 KiB        8.561           numbers.txt.zst
```

See `zeekstd list --help` for all available list options.
