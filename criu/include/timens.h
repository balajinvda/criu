#ifndef __CR_TIME_NS_H__
#define __CR_TIME_NS_H__

extern int dump_time_ns(int ns_id);
extern void timens_note_seized(void);
extern int timens_wait_dumped_clocks(pid_t root, int ns_id);
extern int prepare_timens(int pid);

extern struct ns_desc time_ns_desc;
extern struct ns_desc time_for_children_ns_desc;

#endif /* __CR_TIME_NS_H__ */
