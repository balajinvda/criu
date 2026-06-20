#ifndef __CR_IO_URING_H__
#define __CR_IO_URING_H__

struct fdtype_ops;

extern int is_io_uring_link(char *link);
extern const struct fdtype_ops io_uring_dump_ops;

#endif /* __CR_IO_URING_H__ */
