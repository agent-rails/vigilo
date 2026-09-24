#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$TMP_DIR/.config/vigilo" "$TMP_DIR/.local/bin" "$TMP_DIR/.local/share/vigilo"

printf 'VIGILO_UNSUPPORTED=$(touch %s/evaluated)\n' "$TMP_DIR" > "$TMP_DIR/.config/vigilo/env"
cat > "$TMP_DIR/.local/bin/vigilo" <<'EOF'
#!/bin/sh
touch "${VIGILO_TEST_LAUNCHED:?}"
EOF
chmod 0700 "$TMP_DIR/.local/bin/vigilo"

if VIGILO_HOME="$TMP_DIR" VIGILO_TEST_LAUNCHED="$TMP_DIR/launched" sh "$ROOT/deploy/user/run-vigilo.sh" >/dev/null 2>&1; then
	echo "unsupported environment variable unexpectedly accepted" >&2
	exit 1
fi
test ! -e "$TMP_DIR/evaluated"
test ! -e "$TMP_DIR/launched"
echo "PASS: user env parser rejects unsupported keys without evaluating shell content"
