#ifndef __CR_PAGEMAP_BLOCK_H__
#define __CR_PAGEMAP_BLOCK_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Internal representation of a pages-image range queued for PIE restore.
 *
 * PACKED_RAW and ZERO originate from entries which still carry compression
 * metadata.  They are separate from UNCOMPRESSED so that the restorer can
 * bypass LZ4 without treating their packed image offsets as ordinary pages
 * image offsets (in particular, --auto-dedup must not punch PACKED_RAW).
 */
enum restore_vma_io_storage {
	VMA_IO_UNCOMPRESSED,
	VMA_IO_ENCODED,
	VMA_IO_PACKED_RAW,
	VMA_IO_ZERO,
};

/*
 * Memory block payload layout describing how pagemap entries or I/O vectors
 * are chunked and stored in pages-*.img.
 */
struct page_block_layout {
	uint32_t *sizes;          /* Payload byte size per block in the image */
	size_t nr_blocks;         /* Total number of compressed blocks */
	uint64_t total_bytes;     /* Sum of all block payload sizes */
	uint32_t pages_per_block; /* Granularity: virtual pages per block (1 for page-sized blocks) */
};

/*
 * Helper to round a page count down to the nearest multiple of the block granularity.
 * Used when reading bounded memory batches without splitting a block across chunks.
 */
static inline unsigned long block_align_down(unsigned long nr_pages, uint32_t pages_per_block)
{
	if (pages_per_block <= 1)
		return nr_pages;
	return nr_pages - (nr_pages % pages_per_block);
}

/*
 * Helper to calculate the number of blocks required to cover @nr_pages
 * given a specific block granularity (@pages_per_block).
 */
static inline unsigned long block_nr_blocks(unsigned long nr_pages, uint32_t pages_per_block)
{
	if (pages_per_block <= 1)
		return nr_pages;
	return (nr_pages + pages_per_block - 1) / pages_per_block;
}

#endif /* __CR_PAGEMAP_BLOCK_H__ */
