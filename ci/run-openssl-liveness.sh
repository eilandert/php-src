#!/bin/sh
set -eu

CDPATH=''
export CDPATH
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
php_binary=${TEST_PHP_EXECUTABLE:-${1:-"$repo_root/sapi/cli/php"}}

if [ ! -x "$php_binary" ]; then
  echo "PHP test binary is not executable: $php_binary" >&2
  exit 2
fi

exec "$php_binary" -n "$repo_root/run-tests.php" \
  -q --set-timeout 10 -p "$php_binary" \
  "$repo_root/ext/openssl/tests/gh10495.phpt" \
  "$repo_root/ext/openssl/tests/gh10495_liveness_modes.phpt" \
  "$repo_root/ext/openssl/tests/gh10495_liveness_error.phpt" \
  "$repo_root/ext/openssl/tests/phpt_extract_tls_records.phpt"
