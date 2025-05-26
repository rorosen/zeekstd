{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-list-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 690000 | zeekstd -o num.zst
  seq 690000 | zeekstd -o /dev/null --seek-table-file st.bin

  # Regular list
  zeekstd l num.zst
  # Seperate seek table list
  zeekstd l --seek-table-format head st.bin
  # Detail and from-to produce same output
  detail_out=$(zeekstd l num.zst -d)
  from_to_out=$(zeekstd l num.zst --from 0 --to end)
  [ "$detail_out" == "$from_to_out" ] || exit 1

  touch $out
''
