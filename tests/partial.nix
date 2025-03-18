{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-partial-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 20000 > num
  zeekstd --max-frame-size 1K num -o num.zst

  # Decompress first frame
  zeekstd d -c --from-frame 0 --to-frame 0 num.zst > first
  size_first=$(stat -c %s first)
  [ $size_first -le 1024 ] || exit 1
  head -c "$size_first" num | cmp first

  # Produces the same output independent of frame size
  zeekstd --max-frame-size 8K num -o num.8k.zst
  zeekstd d -c --from 12348 --to 12362 num.zst > partial
  zeekstd d -c --from 12348 --to 12362 num.8k.zst > partial.8k
  cmp partial partial.8k
  echo -en "2692\n2693\n2694" | cmp partial

  touch $out
''
