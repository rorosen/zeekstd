{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-partial-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 20000 > num
  zeekstd --max-frame-size 1K num -o num.zst

  # Decompress only the first frame
  zeekstd d -c --from-frame 0 --to-frame 0 num.zst > first
  size_first=$(stat -c %s first)
  [ $size_first -le 1024 ] || exit 1
  head -c "$size_first" num | cmp first

  touch $out
''
