#!/usr/bin/env python3

import argparse
import math
import os
import sys

import pycriu.images


PE_PRESENT = 4
EXPECTED_BOUNDARY_COUNT = 3


def load_layout(path, page_size):
    mapping = None
    vma_boundaries = []

    with open(path) as layout_file:
        for line_number, line in enumerate(layout_file, 1):
            fields = line.split()
            if not fields:
                continue

            try:
                if fields[0] == "mapping" and len(fields) == 3 and mapping is None:
                    mapping = (int(fields[1], 16), int(fields[2], 16))
                elif fields[0] == "boundary" and len(fields) == 2:
                    vma_boundaries.append(int(fields[1], 16))
                else:
                    raise ValueError(
                        f"invalid VMA layout line: {line.strip()}"
                    )
            except ValueError as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error

    if mapping is None:
        raise ValueError("VMA layout has no mapping range")

    mapping_start, mapping_end = mapping
    if (
        mapping_start >= mapping_end
        or mapping_start % page_size
        or mapping_end % page_size
    ):
        raise ValueError("VMA mapping range is empty or unaligned")

    if len(vma_boundaries) != EXPECTED_BOUNDARY_COUNT:
        raise ValueError(
            f"VMA layout has {len(vma_boundaries)} boundaries, "
            f"expected {EXPECTED_BOUNDARY_COUNT}"
        )
    if vma_boundaries != sorted(set(vma_boundaries)):
        raise ValueError("VMA boundaries are duplicated or unsorted")
    if any(
        boundary <= mapping_start or boundary >= mapping_end
        for boundary in vma_boundaries
    ):
        raise ValueError("VMA boundary lies outside the mapping")
    if any(boundary % page_size for boundary in vma_boundaries):
        raise ValueError("VMA boundary is not page-aligned")

    # A common page period could let pipe rollover, rather than VMA handling,
    # create every expected split. Co-prime offsets rule out that false pass.
    second_boundary_offset = (
        vma_boundaries[1] - vma_boundaries[0]
    ) // page_size
    third_boundary_offset = (
        vma_boundaries[2] - vma_boundaries[0]
    ) // page_size
    if math.gcd(second_boundary_offset, third_boundary_offset) != 1:
        raise ValueError("VMA boundary spacing can match a periodic pipe rollover")

    return mapping, vma_boundaries


def load_pagemap_entries(path):
    with open(path, "rb") as image:
        image_entries = pycriu.images.load(image)["entries"]

    if not image_entries:
        raise ValueError("pagemap image has no header")

    # The first decoded record is pagemap_head, not a page range.
    return image_entries[1:]


def collect_present_ranges(entries, mapping, page_size):
    mapping_start, mapping_end = mapping
    present_ranges = []
    found_block_entry = False

    for entry in entries:
        flags = int(entry.get("flags", 0))
        if not (flags & PE_PRESENT):
            continue

        entry_start = int(entry["vaddr"])
        nr_pages = int(entry["nr_pages"])
        if nr_pages <= 0:
            raise ValueError(
                f"present pagemap entry at {entry_start:#x} has no pages"
            )
        if entry_start % page_size:
            raise ValueError(
                f"present pagemap entry starts at unaligned address "
                f"{entry_start:#x}"
            )

        entry_end = entry_start + nr_pages * page_size
        if entry_end <= mapping_start or entry_start >= mapping_end:
            continue
        present_ranges.append(
            (max(entry_start, mapping_start), min(entry_end, mapping_end))
        )

        if int(entry.get("blocks", {}).get("pages_per_block", 0)):
            found_block_entry = True

    return sorted(present_ranges), found_block_entry


def check_contiguous_coverage(present_ranges, mapping, page_size):
    mapping_start, mapping_end = mapping

    if not present_ranges:
        print("FAIL: pagemap contains no present ranges for the test mapping")
        return 1

    covered_until = mapping_start
    for range_start, range_end in present_ranges:
        if range_start != covered_until:
            print(
                f"FAIL: pagemap coverage is discontinuous at {covered_until:#x} "
                f"(next range {range_start:#x}-{range_end:#x})"
            )
            return 1
        covered_until = range_end

    if covered_until != mapping_end:
        print(
            f"FAIL: pagemap coverage ends at {covered_until:#x}, "
            f"expected {mapping_end:#x}"
        )
        return 1

    if all(
        range_end - range_start == page_size
        for range_start, range_end in present_ranges
    ):
        print("FAIL: only single-page ranges found; VMA split check is inconclusive")
        return 1

    return 0


def check_boundary_splits(present_ranges, vma_boundaries):
    for boundary in vma_boundaries:
        for range_start, range_end in present_ranges:
            if range_start < boundary < range_end:
                print(
                    f"FAIL: pagemap range {range_start:#x}-{range_end:#x} "
                    f"crosses VMA boundary {boundary:#x}"
                )
                return 1

        has_left_range = any(
            range_start < boundary and range_end == boundary
            for range_start, range_end in present_ranges
        )
        has_right_range = any(
            range_start == boundary and range_end > boundary
            for range_start, range_end in present_ranges
        )

        if not has_left_range:
            print(
                f"FAIL: no present pagemap range ends at VMA boundary "
                f"{boundary:#x}"
            )
            return 1
        if not has_right_range:
            print(
                f"FAIL: no present pagemap range starts at VMA boundary "
                f"{boundary:#x}"
            )
            return 1

    return 0


def check_pagemap(entries, mapping, vma_boundaries, page_size):
    present_ranges, found_block_entry = collect_present_ranges(
        entries, mapping, page_size
    )

    # Boundary checks are meaningful only after proving exact mapping coverage.
    if check_contiguous_coverage(present_ranges, mapping, page_size):
        return 1
    if check_boundary_splits(present_ranges, vma_boundaries):
        return 1

    if not found_block_entry:
        print("FAIL: test mapping contains no block-compressed entry")
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Check that block-compressed pagemap entries stay within VMAs"
    )
    parser.add_argument("directory")
    parser.add_argument("pid")
    parser.add_argument("layout")
    args = parser.parse_args()

    page_size = os.sysconf("SC_PAGE_SIZE")
    try:
        mapping, vma_boundaries = load_layout(args.layout, page_size)
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}")
        return 1

    pagemap_path = os.path.join(args.directory, f"pagemap-{args.pid}.img")
    try:
        entries = load_pagemap_entries(pagemap_path)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"FAIL: cannot read {pagemap_path}: {error}")
        return 1

    try:
        return check_pagemap(entries, mapping, vma_boundaries, page_size)
    except (KeyError, TypeError, ValueError) as error:
        print(f"FAIL: invalid pagemap entry: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
