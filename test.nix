{
  zeekstd,
  zstd,
  runCommand,
}:
runCommand "zeekstd-test"
  {
    nativeBuildInputs = [
      zeekstd
      zstd
    ];
  }
  ''
    set -x

    seq 20000 > numbers.txt
    # Compress via input file and stdin
    zeekstd numbers.txt
    cat numbers.txt | zeekstd -o numbers.stdin.zst
    # Verify both compressions yield the same result
    cmp numbers.txt.zst numbers.stdin.zst
    # Decompress with zeekstd and zstd
    zeekstd decompress numbers.txt.zst -o numbers.txt.decompressed
    zstd -d numbers.txt.zst -o numbers.txt.decompressed-zstd
    # Verify both decompressions yield the same result
    cmp numbers.txt numbers.txt.decompressed
    cmp numbers.txt numbers.txt.decompressed-zstd
    # Decompress partially
    zeekstd decompress --stdout --from 12348 --to 12362 numbers.txt.zst > partial-numbers.txt
    echo -en "2692\n2693\n2694" | cmp partial-numbers.txt

    touch $out
  ''
