#ifndef __CR_IO_URING_H__
#define __CR_IO_URING_H__

struct fdtype_ops;
struct collect_image_info;
struct task_restore_args;

extern int is_io_uring_link(char *link);
extern const struct fdtype_ops io_uring_dump_ops;
extern struct collect_image_info io_uring_cinfo;
extern int prepare_io_urings(struct task_restore_args *ta);

#endif /* __CR_IO_URING_H__ */
