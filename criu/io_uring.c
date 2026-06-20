#include <unistd.h>

#include "protobuf.h"
#include "images/io_uring.pb-c.h"

#include "fdinfo.h"
#include "files.h"
#include "imgset.h"
#include "io_uring.h"
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
	/* Default-setup ring (no SQPOLL/CQSIZE); guaranteed quiesced at dump time. */
	iour.setup_flags = 0;

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
