#!/usr/bin/env python3

import argparse
import glob
import hashlib
import importlib
import os
import random
import struct
import sys


PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PAGE_COMPRESSION_THRESHOLD = PAGE_SIZE * 7 // 8
PE_PARENT = 1 << 0
PE_PRESENT = 1 << 2
PE_PAYLOAD_ALIGNED = 1 << 3


def pycriu_images():
    return importlib.import_module("pycriu.images")


def lz4_block():
    return importlib.import_module("lz4.block")


def assert_inventory_version(directory, expected):
    images = pycriu_images()
    with open(os.path.join(directory, "inventory.img"), "rb") as image_file:
        inventory = images.load(image_file)

    actual = inventory["entries"][0]["img_version"]
    if actual != expected:
        print(
            "FAIL: inventory version is %d, expected %d" % (actual, expected)
        )
        return 1
    return 0


def make_sparse_pagemap_image(directory, compressed):
    images = pycriu_images()
    with open(os.path.join(directory, "inventory.img"), "wb") as image_file:
        inventory = {"magic": "INVENTORY", "entries": [{"img_version": 2}]}
        if compressed:
            inventory["entries"][0]["img_version"] = 3
            inventory["entries"][0]["compress"] = 1
        images.dump(inventory, image_file)

    if compressed:
        # One raw present page, one non-present hole, one legacy parent entry
        # without flags, and one zero present page with no payload.
        pages = bytes([0x41]) * PAGE_SIZE
        entries = [
            {"pages_id": 1},
            {
                "vaddr": 0x100000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": PE_PRESENT,
                "blocks": {
                    "block_sizes": [PAGE_SIZE],
                    "total_payload_size": PAGE_SIZE,
                    "pages_per_block": 1,
                },
            },
            {
                "vaddr": 0x101000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": 0,
            },
            {
                "vaddr": 0x102000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "in_parent": True,
            },
            {
                "vaddr": 0x103000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": PE_PRESENT,
                "blocks": {
                    "block_sizes": [0],
                    "total_payload_size": 0,
                    "pages_per_block": 1,
                },
            },
        ]
    else:
        # Two present pages are adjacent in pages.img, while the pagemap has a
        # non-present hole and a legacy parent reference between them.
        pages = bytes([0x41]) * PAGE_SIZE + bytes([0x42]) * PAGE_SIZE
        entries = [
            {"pages_id": 1},
            {
                "vaddr": 0x100000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": PE_PRESENT,
            },
            {
                "vaddr": 0x101000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": 0,
            },
            {
                "vaddr": 0x102000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "in_parent": True,
            },
            {
                "vaddr": 0x103000,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": PE_PRESENT,
            },
        ]

    with open(os.path.join(directory, "pages-1.img"), "wb") as image_file:
        image_file.write(pages)

    with open(os.path.join(directory, "pagemap-1.img"), "wb") as image_file:
        images.dump({"magic": "PAGEMAP", "entries": entries}, image_file)
    return 0


def make_threshold_pagemap_image(directory):
    images = pycriu_images()
    block = lz4_block()
    rng = random.Random(0)
    random_page = bytes(rng.randrange(256) for _ in range(PAGE_SIZE))
    page = None

    # Find a deterministic page on the raw side of CRIU's 7/8 threshold. A
    # fixed-size compressible island is brittle across LZ4 releases because an
    # incompressible block may legitimately grow by a few different bytes.
    for zero_bytes in range(1, PAGE_SIZE + 1):
        trial_page = random_page[:-zero_bytes] + b"\0" * zero_bytes
        compressed_size = len(
            block.compress(trial_page, store_size=False, acceleration=1)
        )
        if PAGE_COMPRESSION_THRESHOLD <= compressed_size < PAGE_SIZE:
            page = trial_page
            break

    if page is None:
        print("FAIL: unable to construct a page at the raw fallback threshold")
        return 1

    with open(os.path.join(directory, "inventory.img"), "wb") as image_file:
        images.dump(
            {"magic": "INVENTORY", "entries": [{"img_version": 2}]},
            image_file,
        )

    with open(os.path.join(directory, "pages-1.img"), "wb") as image_file:
        image_file.write(page)

    with open(os.path.join(directory, "pagemap-1.img"), "wb") as image_file:
        images.dump(
            {
                "magic": "PAGEMAP",
                "entries": [
                    {"pages_id": 1},
                    {
                        "vaddr": 0x100000,
                        "compat_nr_pages": 1,
                        "nr_pages": 1,
                        "flags": PE_PRESENT,
                    },
                ],
            },
            image_file,
        )
    return 0


def make_truncated_uncompressed_entry_image(directory):
    images = pycriu_images()
    with open(os.path.join(directory, "inventory.img"), "wb") as image_file:
        images.dump(
            {
                "magic": "INVENTORY",
                "entries": [{"img_version": 3, "compress": 1}],
            },
            image_file,
        )

    with open(os.path.join(directory, "pages-1.img"), "wb") as image_file:
        image_file.write(bytes([0x41]) * PAGE_SIZE)

    with open(os.path.join(directory, "pagemap-1.img"), "wb") as image_file:
        images.dump(
            {
                "magic": "PAGEMAP",
                "entries": [
                    {"pages_id": 1},
                    {
                        "vaddr": 0x100000,
                        "compat_nr_pages": 2,
                        "nr_pages": 2,
                        "flags": PE_PRESENT,
                    },
                ],
            },
            image_file,
        )
    return 0


def assert_pagemap_entry_uncompressed(directory):
    images = pycriu_images()
    with open(os.path.join(directory, "pagemap-1.img"), "rb") as image_file:
        pagemap = images.load(image_file)

    entry = pagemap["entries"][1]
    if "blocks" in entry:
        print("FAIL: raw-only entry retained blocks")
        return 1
    if not int(entry.get("flags", 0)) & PE_PAYLOAD_ALIGNED:
        print("FAIL: raw-only entry lacks PE_PAYLOAD_ALIGNED")
        return 1
    return 0


def assert_block_pagemap(directory):
    images = pycriu_images()
    found_block = False
    found_short_block = False
    for path in glob.glob(os.path.join(directory, "pagemap-*.img")):
        with open(path, "rb") as image_file:
            pagemap = images.load(image_file)
        for entry in pagemap["entries"][1:]:
            blocks = entry.get("blocks", {})
            block_pages = blocks.get("pages_per_block", 0)
            if block_pages > 1:
                found_block = True
                if entry.get("nr_pages", entry["compat_nr_pages"]) % block_pages:
                    found_short_block = True
        if found_block and found_short_block:
            break
    if not found_block:
        print("FAIL: no block-compressed pagemap entry found")
        return 1
    if not found_short_block:
        print("FAIL: no short final compression block found")
        return 1
    return 0


def write_pair(directory, images, pages_id, entry, payload):
    with open(
        os.path.join(directory, "pages-%d.img" % pages_id), "wb"
    ) as image_file:
        image_file.write(payload)
    with open(
        os.path.join(directory, "pagemap-%d.img" % pages_id), "wb"
    ) as image_file:
        images.dump(
            {
                "magic": "PAGEMAP",
                "entries": [{"pages_id": pages_id}, entry],
            },
            image_file,
        )


def write_partial_pair(directory, images, pages_id, kind):
    with open(
        os.path.join(directory, "pages-%d.img" % pages_id), "wb"
    ) as image_file:
        image_file.write(b"A" * PAGE_SIZE)

    entry = images.pagemap_entry()
    entry.vaddr = 0x100000
    entry.compat_nr_pages = 1
    entry.nr_pages = 1
    entry.flags = PE_PRESENT

    blocks = entry.blocks
    if kind == "empty-blocks":
        blocks.SetInParent()
    else:
        blocks.block_sizes.append(PAGE_SIZE)
        if kind != "missing-pages-per-block":
            blocks.pages_per_block = 1
        if kind != "missing-total-payload-size":
            blocks.total_payload_size = PAGE_SIZE

    with open(
        os.path.join(directory, "pagemap-%d.img" % pages_id), "wb"
    ) as image_file:
        images.dump(
            {"magic": "PAGEMAP", "entries": [{"pages_id": pages_id}]},
            image_file,
        )
        entry_data = entry.SerializePartialToString()
        image_file.write(struct.pack("i", len(entry_data)))
        image_file.write(entry_data)


def make_malformed_compressed_image(directory, kind):
    images = pycriu_images()
    with open(os.path.join(directory, "inventory.img"), "wb") as image_file:
        images.dump(
            {
                "magic": "INVENTORY",
                "entries": [{"img_version": 3, "compress": 1}],
            },
            image_file,
        )

    base = {
        "vaddr": 0x100000,
        "compat_nr_pages": 1,
        "nr_pages": 1,
        "flags": PE_PRESENT,
    }

    if kind == "oversize":
        base["blocks"] = {
            "block_sizes": [PAGE_SIZE + 1],
            "total_payload_size": PAGE_SIZE + 1,
            "pages_per_block": 1
        }
        write_pair(directory, images, 1, base, b"A" * (PAGE_SIZE + 1))
    elif kind == "total":
        base["blocks"] = {
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE - 1,
            "pages_per_block": 1
        }
        write_pair(directory, images, 1, base, b"A" * PAGE_SIZE)
    elif kind == "count":
        base["compat_nr_pages"] = 2
        base["nr_pages"] = 2
        base["blocks"] = {
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE,
            "pages_per_block": 1
        }
        write_pair(directory, images, 1, base, b"A" * PAGE_SIZE)
    elif kind == "flags":
        base["flags"] = PE_PRESENT | PE_PARENT
        base["blocks"] = {
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE,
            "pages_per_block": 1
        }
        write_pair(directory, images, 1, base, b"A" * PAGE_SIZE)
    elif kind == "aligned-nonpresent":
        base["flags"] = PE_PAYLOAD_ALIGNED
        write_pair(directory, images, 1, base, b"")
    elif kind == "block-limit":
        base["blocks"] = {
            "pages_per_block": 4 * 1024 * 1024 // PAGE_SIZE + 1,
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE
        }
        write_pair(directory, images, 1, base, b"A" * PAGE_SIZE)
    elif kind == "block-zero":
        base["blocks"] = {
            "pages_per_block": 0,
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE
        }
        write_pair(directory, images, 1, base, b"A" * PAGE_SIZE)
    elif kind == "block-count":
        base["compat_nr_pages"] = 17
        base["nr_pages"] = 17
        base["blocks"] = {
            "pages_per_block": 16,
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE
        }
        write_pair(directory, images, 1, base, b"A" * PAGE_SIZE)
    elif kind == "block-final-oversize":
        base["compat_nr_pages"] = 17
        base["nr_pages"] = 17
        base["blocks"] = {
            "pages_per_block": 16,
            "block_sizes": [0, PAGE_SIZE + 1],
            "total_payload_size": PAGE_SIZE + 1
        }
        write_pair(directory, images, 1, base, b"A" * (PAGE_SIZE + 1))
    elif kind in ("missing-pages-per-block", "missing-total-payload-size",
                  "empty-blocks"):
        write_partial_pair(directory, images, 1, kind)
    elif kind == "transaction":
        first = dict(base)
        first["blocks"] = {
            "block_sizes": [PAGE_SIZE],
            "total_payload_size": PAGE_SIZE,
            "pages_per_block": 1
        }
        write_pair(directory, images, 1, first, b"A" * PAGE_SIZE)

        second = dict(base)
        second["vaddr"] = 0x200000
        second["blocks"] = {
            "block_sizes": [8],
            "total_payload_size": 8,
            "pages_per_block": 1
        }
        write_pair(directory, images, 2, second, b"not-lz4!")
    else:
        raise ValueError("unknown malformed-image kind %s" % kind)
    return 0


def make_transactional_compress_image(directory):
    images = pycriu_images()
    with open(os.path.join(directory, "inventory.img"), "wb") as image_file:
        images.dump(
            {"magic": "INVENTORY", "entries": [{"img_version": 2}]},
            image_file,
        )

    for pages_id, size in ((1, PAGE_SIZE), (2, PAGE_SIZE - 1)):
        with open(
            os.path.join(directory, "pages-%d.img" % pages_id), "wb"
        ) as image_file:
            image_file.write(bytes([0x40 + pages_id]) * size)
        with open(
            os.path.join(directory, "pagemap-%d.img" % pages_id), "wb"
        ) as image_file:
            images.dump(
                {
                    "magic": "PAGEMAP",
                    "entries": [
                        {"pages_id": pages_id},
                        {
                            "vaddr": pages_id * 0x100000,
                            "compat_nr_pages": 1,
                            "nr_pages": 1,
                            "flags": PE_PRESENT,
                        },
                    ],
                },
                image_file,
            )
    return 0


def expected_sparse_checksum(kind):
    if kind == "raw-zero":
        contents = bytes([0x41]) * PAGE_SIZE + bytes(PAGE_SIZE)
    elif kind == "two-raw":
        contents = bytes([0x41]) * PAGE_SIZE + bytes([0x42]) * PAGE_SIZE
    else:
        raise ValueError("unknown checksum kind %s" % kind)
    print(hashlib.md5(contents).hexdigest())
    return 0


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser("assert-inventory-version")
    inventory_parser.add_argument("directory")
    inventory_parser.add_argument("expected", type=int)

    sparse_parser = subparsers.add_parser("make-sparse-pagemap")
    sparse_parser.add_argument("directory")
    sparse_parser.add_argument("compressed", type=int, choices=(0, 1))

    threshold_parser = subparsers.add_parser("make-threshold-pagemap")
    threshold_parser.add_argument("directory")

    truncated_parser = subparsers.add_parser("make-truncated-uncompressed")
    truncated_parser.add_argument("directory")

    raw_parser = subparsers.add_parser("assert-entry-uncompressed")
    raw_parser.add_argument("directory")

    block_parser = subparsers.add_parser("assert-block-pagemap")
    block_parser.add_argument("directory")

    malformed_parser = subparsers.add_parser("make-malformed-compressed")
    malformed_parser.add_argument("directory")
    malformed_parser.add_argument("kind")

    transaction_parser = subparsers.add_parser("make-transactional-compress")
    transaction_parser.add_argument("directory")

    checksum_parser = subparsers.add_parser("expected-sparse-checksum")
    checksum_parser.add_argument("kind", choices=("raw-zero", "two-raw"))

    subparsers.add_parser("has-lz4")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "assert-inventory-version":
        return assert_inventory_version(args.directory, args.expected)
    if args.command == "make-sparse-pagemap":
        return make_sparse_pagemap_image(args.directory, bool(args.compressed))
    if args.command == "make-threshold-pagemap":
        return make_threshold_pagemap_image(args.directory)
    if args.command == "make-truncated-uncompressed":
        return make_truncated_uncompressed_entry_image(args.directory)
    if args.command == "assert-entry-uncompressed":
        return assert_pagemap_entry_uncompressed(args.directory)
    if args.command == "assert-block-pagemap":
        return assert_block_pagemap(args.directory)
    if args.command == "make-malformed-compressed":
        return make_malformed_compressed_image(args.directory, args.kind)
    if args.command == "make-transactional-compress":
        return make_transactional_compress_image(args.directory)
    if args.command == "expected-sparse-checksum":
        return expected_sparse_checksum(args.kind)
    if args.command == "has-lz4":
        lz4_block()
        return 0
    raise AssertionError("unhandled command %s" % args.command)


if __name__ == "__main__":
    sys.exit(main())
