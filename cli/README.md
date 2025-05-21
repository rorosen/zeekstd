# Zeekstd CLI

## Building

If you have Rust installed, just clone this repo and run `cargo build`.

```bash
git clone https://github.com/rorosen/zeekstd.git
cd zeekstd
cargo build -p zeekstd_cli --release
./target/release/zeekstd --version
```

Alternatively, build with `nix build`.

```bash
nix build github:rorosen/zeekstd#default
./result/bin/zeekstd --version
```

Zeekstd is also available from nixpkgs.

```bash
nix-shell -p zeekstd
zeekstd --version
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

Decompress seekable archives with the `decompress` subcommand.

```bash
$ zeekstd decompress numbers.txt.zst
numbers.txt.zst : 106.34 KiB
```

See `zeekstd decompress --help` for all available decompression options.

## Print Information

Print information about a seekable archive with the `list` subcommand. When called with no further
arguments, it will print general information similar to `zstd -l`, pass the `--detail` flag to list
all frames individually.

```bash
$ zeekstd list numbers.txt.zst
Frames          Compressed      Decompressed    Max Frame Size  Ratio           Filename
14              12.42 KiB       106.34 KiB      8.00 KiB        8.561           numbers.txt.zst
```

See `zeekstd list --help` for all available list options.
