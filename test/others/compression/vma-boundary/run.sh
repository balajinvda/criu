#!/bin/bash

# Verify that block-compressed pre-dumps start a fresh pagemap entry at
# every VMA boundary, even though the output xfer is opened only after page
# collection finishes.

set -euo pipefail

# shellcheck source=test/others/env.sh
source ../../env.sh

CRIU_CMD=("${CRIU}" --no-default-config)
ZDTM_DIR="../../../zdtm/static"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECK_PAGEMAP="${SCRIPT_DIR}/check_pagemap.py"
TEST_NAME="compress_pages_block04"
IMAGE_DIR=""
PID=""

function fail {
	echo "FAIL: $*"
	exit 1
}

function cleanup {
	if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
		kill -TERM "$PID" 2>/dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$PID" 2>/dev/null || break
			sleep 0.1
		done
		if kill -0 "$PID" 2>/dev/null; then
			kill -KILL "$PID" 2>/dev/null || true
		fi
	fi
	if [ -x "$ZDTM_DIR/$TEST_NAME" ]; then
		(
			cd "$ZDTM_DIR"
			make "$TEST_NAME.cleanout"
		) >/dev/null 2>&1 || true
	fi
	if [ -n "$IMAGE_DIR" ]; then
		rm -rf -- "$IMAGE_DIR"
	fi
}

trap cleanup EXIT

IMAGE_DIR=$(mktemp -d dump-vma-boundary.XXXXXX)

(
	cd "$ZDTM_DIR"
	make "$TEST_NAME.cleanout"
	make "$TEST_NAME"
	make "$TEST_NAME.pid"
)

PID=$(cat "$ZDTM_DIR/$TEST_NAME.pid")
kill -0 "$PID" || fail "test did not start"

"${CRIU_CMD[@]}" pre-dump -D "$IMAGE_DIR" -o dump.log -t "$PID" -v4 \
	-R --track-mem --pre-dump-mode splice --compress-block=256K \
	|| fail "block pre-dump failed"

PYTHONPATH="${BASE_DIR}/lib${PYTHONPATH:+:${PYTHONPATH}}" \
	python3 "$CHECK_PAGEMAP" "$IMAGE_DIR" "$PID" \
	"$ZDTM_DIR/$TEST_NAME.test" \
	|| fail "pagemap validation failed"

(
	cd "$ZDTM_DIR"
	make "$TEST_NAME.stop"
	grep PASS "$TEST_NAME.out"
) || fail "memory content verification failed"
PID=""

echo "Test PASSED"
