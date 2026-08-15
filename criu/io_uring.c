#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/io_uring.h>

/* Added in kernel 6.6; may be absent from the build's uapi headers. */
#ifndef IORING_SETUP_NO_SQARRAY
#define IORING_SETUP_NO_SQARRAY (1U << 16)
#endif

#include "protobuf.h"
#include "images/io_uring.pb-c.h"

#include "fdinfo.h"
#include "files.h"
#include "imgset.h"
#include "io_uring.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "pstree.h"
#include "log.h"

#undef LOG_PREFIX
#define LOG_PREFIX "io_uring: "

int is_io_uring_link(char *link)
{
	return is_anon_link_type(link, "[io_uring]");
}

static int dump_one_io_uring(int lfd, u32 id, const struct fd_parms *p)
{
	IoUringFileEntry iour = IO_URING_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;

	/* Parses SqMask/CqMask -> sq/cq_entries and rejects registered files/buffers/SQPOLL. */
	if (parse_fdinfo(lfd, FD_TYPES__IO_URING, &iour))
		return -1;

	iour.id = id;
	iour.flags = p->flags;
	iour.fown = (FownEntry *)&p->fown;
	iour.ino = p->stat.st_ino; /* matches the ring VMAs' shmid, for per-ring restore mapping */
	/* setup_flags filled by parse_fdinfo (e.g. IORING_SETUP_SQPOLL); ring is quiesced at dump. */

	pr_info("Dumping id %#x sq_entries %u cq_entries %u flags %#x\n", iour.id, iour.sq_entries, iour.cq_entries,
		iour.flags);

	fe.type = FD_TYPES__IO_URING;
	fe.id = iour.id;
	fe.iour = &iour;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops io_uring_dump_ops = {
	.type = FD_TYPES__IO_URING,
	.dump = dump_one_io_uring,
};

struct io_uring_info {
	IoUringFileEntry *ioure;
	struct file_desc d;
	int uring_fd;
	struct list_head rlist;
};

static LIST_HEAD(rst_io_urings);

static int io_uring_open(struct file_desc *d, int *new_fd)
{
	struct io_uring_info *info;
	IoUringFileEntry *ioure;
	struct io_uring_params p;
	int tmp;

	info = container_of(d, struct io_uring_info, d);
	ioure = info->ioure;

	memset(&p, 0, sizeof(p));
	p.flags = ioure->setup_flags;

	pr_info("Creating io_uring id %#x sq_entries %u flags %#x\n", ioure->id, ioure->sq_entries, ioure->setup_flags);

	tmp = syscall(__NR_io_uring_setup, ioure->sq_entries, &p);
	if (tmp < 0) {
		pr_perror("Can't io_uring_setup for %#x", ioure->id);
		return -1;
	}

	/*
	 * Reconstruct the SQ array (slot -> SQE index map). The kernel zeroes a
	 * fresh ring's SQ array; liburing/libuv write the identity map
	 * (array[i] = i) once at setup and never change it, so the dump never
	 * captured it and the VMA remap onto this fresh ring leaves it zeroed.
	 * Without this, every submission resolves to SQE 0: the SQPOLL poller
	 * processes the wrong/duplicate SQE, the expected completions never
	 * arrive, and libuv aborts in uv__epoll_ctl_flush (assert want == 0).
	 * We map the same ring fd the restored task will remap, so the identity
	 * map we write here is exactly what it sees. NO_SQARRAY rings have no
	 * array to init (and we never request that flag).
	 */
	if (!(p.flags & IORING_SETUP_NO_SQARRAY)) {
		size_t sqr_len = (size_t)p.sq_off.array + (size_t)p.sq_entries * sizeof(__u32);
		__u32 *array;
		void *sqr;
		__u32 i;

		sqr = mmap(NULL, sqr_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, tmp,
			   IORING_OFF_SQ_RING);
		if (sqr == MAP_FAILED) {
			pr_perror("io_uring: can't map SQ ring to init sq_array for %#x", ioure->id);
			close(tmp);
			return -1;
		}
		array = (__u32 *)((char *)sqr + p.sq_off.array);
		for (i = 0; i < p.sq_entries; i++)
			array[i] = i;
		munmap(sqr, sqr_len);

		pr_info("Initialized sq_array identity for id %#x (%u entries)\n", ioure->id, p.sq_entries);
	}

	if (rst_file_params(tmp, ioure->fown, ioure->flags)) {
		pr_perror("Can't restore params for %#x", ioure->id);
		close(tmp);
		return -1;
	}

	info->uring_fd = file_master(d)->fe->fd;
	list_add_tail(&info->rlist, &rst_io_urings);

	*new_fd = tmp;
	return 0;
}

static struct file_desc_ops io_uring_desc_ops = {
	.type = FD_TYPES__IO_URING,
	.open = io_uring_open,
};

static int collect_one_io_uring(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct io_uring_info *info = o;

	info->ioure = pb_msg(msg, IoUringFileEntry);
	info->uring_fd = -1;

	return file_desc_add(&info->d, info->ioure->id, &io_uring_desc_ops);
}

struct collect_image_info io_uring_cinfo = {
	.fd_type = CR_FD_FILES,
	.pb_type = PB_FILE,
	.priv_size = sizeof(struct io_uring_info),
	.collect = collect_one_io_uring,
};

/*
 * The io_uring SQ/CQ ring and SQEs mappings (VMA_AREA_IO_URING) are re-mmap'd in
 * the PIE restorer (see __export_restore_task) from the ring whose inode matches
 * the vma's shmid. Pass the (inode, fd) of every restored ring via task_restore_args.
 */
int prepare_io_urings(struct task_restore_args *ta)
{
	struct io_uring_info *info;

	ta->iour_rings = (struct rst_iour *)rst_mem_align_cpos(RM_PRIVATE);
	ta->iour_rings_n = 0;

	list_for_each_entry(info, &rst_io_urings, rlist) {
		struct rst_iour *r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);

		if (!r)
			return -1;
		r->ino = info->ioure->ino;
		r->fd = info->uring_fd;
		ta->iour_rings_n++;
	}

	return 0;
}
