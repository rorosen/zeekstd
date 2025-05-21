{
  zeekstd,
  runCommand,
}:
runCommand "zeekstd-list-test" { nativeBuildInputs = [ zeekstd ]; } ''
  set -x

  seq 690000 | zeekstd -o num.zst
  seq 690000 | zeekstd -o /dev/null --seek-table-file st.bin

  # Just check that list works, no proper test yet
  zeekstd l num.zst
  zeekstd l --seek-table-format head st.bin
  zeekstd l num.zst --from start --to end

  touch $out
''
