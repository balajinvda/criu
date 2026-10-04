#!/bin/sh

set -eu

root=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)
page_size=$(getconf PAGESIZE)
if [ "$page_size" -lt 65536 ] && [ $((65536 % page_size)) -eq 0 ]; then
	set -- "$page_size" 65536
else
	set -- "$page_size"
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "compression/benchmark: must run as root" >&2
	exit 1
fi

# main.py reads CRIU's generated statistics protobufs through pycriu.
make -C "$root" lib

timeout --foreground --kill-after=30s 300s \
	python3 "$root/contrib/compression-benchmark/main.py" \
	--criu "$root/criu/criu" \
	--iterations 1 \
	--size 256 \
	--data-pattern zero mixed random text elf \
	--modes uncompressed lz4-block \
	--block-sizes "$@" \
	--decompress-threads 4 \
	--no-drop-caches \
	--no-progress-bar
