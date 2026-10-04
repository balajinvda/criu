#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check block-compressed pages across adjacent VMAs";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

/*
 * Split one mapping at several irregular offsets. Without explicit page-pipe
 * boundaries, the random and compressible pages can remain in one pagemap
 * entry spanning every VMA. The boundary offsets have no common period larger
 * than one page, so fixed-capacity pipe rollover cannot create every split.
 */
#define FIRST_BOUNDARY_PAGES	13
#define SECOND_BOUNDARY_PAGES	47
#define THIRD_BOUNDARY_PAGES	94
#define RANDOM_PAGES		64
#define TOTAL_PAGES		128
#define COMPRESSIBLE_BYTE	0x5a
#define INIT_CRC		(~(uint32_t)0)

static const size_t boundary_pages[] = {
	FIRST_BOUNDARY_PAGES,
	SECOND_BOUNDARY_PAGES,
	THIRD_BOUNDARY_PAGES,
};

static int verify_compressible(const uint8_t *mapping)
{
	size_t start = RANDOM_PAGES * PAGE_SIZE;
	size_t end = TOTAL_PAGES * PAGE_SIZE;
	size_t i;

	for (i = start; i < end; i++) {
		if (mapping[i] != COMPRESSIBLE_BYTE) {
			fail("compressible byte %zu is %#x, expected %#x", i, mapping[i], COMPRESSIBLE_BYTE);
			return -1;
		}
	}

	return 0;
}

static int write_layout(const char *path, const uint8_t *mapping,
			size_t mapping_size)
{
	size_t i;
	int fd;
	int ret = 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		pr_perror("open(%s)", path);
		return -1;
	}

	if (dprintf(fd, "mapping %lx %lx\n", (unsigned long)mapping, (unsigned long)(mapping + mapping_size)) < 0) {
		pr_perror("write VMA mapping range");
		ret = -1;
	}

	for (i = 0; !ret && i < ARRAY_SIZE(boundary_pages); i++) {
		const uint8_t *boundary = mapping + boundary_pages[i] * PAGE_SIZE;

		if (dprintf(fd, "boundary %lx\n", (unsigned long)boundary) < 0) {
			pr_perror("write VMA boundaries");
			ret = -1;
		}
	}
	if (close(fd)) {
		pr_perror("close VMA boundary file");
		ret = -1;
	}

	return ret;
}

int main(int argc, char **argv)
{
	size_t mapping_size = TOTAL_PAGES * PAGE_SIZE;
	uint32_t crc = INIT_CRC;
	uint8_t *mapping;
	int ret = 1;

	test_init(argc, argv);

	mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	datagen(mapping, RANDOM_PAGES * PAGE_SIZE, &crc);
	memset(mapping + RANDOM_PAGES * PAGE_SIZE, COMPRESSIBLE_BYTE, (TOTAL_PAGES - RANDOM_PAGES) * PAGE_SIZE);

	/*
	 * Alternating protections create four readable, adjacent VMAs:
	 *
	 *   page 0       13          47           94          128
	 *        |   R   |    RW     |     R      |     RW     |
	 */
	if (mprotect(mapping, FIRST_BOUNDARY_PAGES * PAGE_SIZE, PROT_READ)) {
		pr_perror("mprotect first VMA");
		return 1;
	}
	if (mprotect(mapping + SECOND_BOUNDARY_PAGES * PAGE_SIZE,
		     (THIRD_BOUNDARY_PAGES - SECOND_BOUNDARY_PAGES) * PAGE_SIZE,
		     PROT_READ)) {
		pr_perror("mprotect third VMA");
		return 1;
	}
	if (write_layout(filename, mapping, mapping_size))
		goto out;

	test_daemon();
	test_waitsig();

	crc = INIT_CRC;
	if (datachk(mapping, RANDOM_PAGES * PAGE_SIZE, &crc)) {
		fail("random pages changed");
		goto out;
	}
	if (verify_compressible(mapping))
		goto out;

	pass();
	ret = 0;
out:
	unlink(filename);
	return ret;
}
