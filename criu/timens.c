#include <time.h>
#include <sched.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>

#include "types.h"
#include "proc_parse.h"
#include "namespaces.h"
#include "timens.h"
#include "cr_options.h"

#include "protobuf.h"
#include "images/timens.pb-c.h"

static void normalize_timespec(struct timespec *ts);

/*
 * The clocks when the dump stopped the tasks. A restore continues the
 * tasks' clocks from the dumped values, so the values must be read when
 * the tasks stopped: the latest moment any of them could read a clock.
 * Read at the end of the dump instead, they would count the dump itself
 * (minutes for a large memory) as time the tasks ran, and a restored task
 * would find every timeout it was waiting on expired.
 */
static struct {
	bool set;
	struct timespec mono, boot; /* in criu's own time namespace */
	struct timespec moff, boff; /* that namespace's offsets */
	bool offsets;
} seized;

void timens_note_seized(void)
{
	clock_gettime(CLOCK_MONOTONIC, &seized.mono);
	clock_gettime(CLOCK_BOOTTIME, &seized.boot);
	seized.offsets = parse_timens_offsets(&seized.boff, &seized.moff) == 0;
	seized.set = true;
}

/*
 * The clocks of the current time namespace at the moment the tasks were
 * seized. dump_time_ns runs in criu's own time namespace for the root one
 * and in a dumped namespace (switch_ns) for a nested one; a namespace's
 * clocks differ from criu's by the difference of their offsets.
 */
static int seized_clocks(int ns_id, struct timespec *mono, struct timespec *boot)
{
	struct timespec moff = {}, boff = {};

	if (!seized.set)
		return -1;
	*mono = seized.mono;
	*boot = seized.boot;
	if (ns_id == 0)
		return 0;
	if (!seized.offsets || parse_timens_offsets(&boff, &moff))
		return -1;
	mono->tv_sec += moff.tv_sec - seized.moff.tv_sec;
	mono->tv_nsec += moff.tv_nsec - seized.moff.tv_nsec;
	boot->tv_sec += boff.tv_sec - seized.boff.tv_sec;
	boot->tv_nsec += boff.tv_nsec - seized.boff.tv_nsec;
	normalize_timespec(mono);
	normalize_timespec(boot);
	return 0;
}

int dump_time_ns(int ns_id)
{
	struct cr_img *img;
	TimensEntry te = TIMENS_ENTRY__INIT;
	Timespec b = TIMESPEC__INIT, m = TIMESPEC__INIT;
	struct timespec mono, boot;
	int ret;

	img = open_image(CR_FD_TIMENS, O_DUMP, ns_id);
	if (!img)
		return -1;

	if (seized_clocks(ns_id, &mono, &boot)) {
		pr_warn("timens: no clocks from the seize; dumping the current ones\n");
		clock_gettime(CLOCK_MONOTONIC, &mono);
		clock_gettime(CLOCK_BOOTTIME, &boot);
	}
	pr_debug("timens: dumped monotonic %" PRId64 ".%09ld boottime %" PRId64 ".%09ld\n",
		 (int64_t)mono.tv_sec, mono.tv_nsec, (int64_t)boot.tv_sec, boot.tv_nsec);
	te.monotonic = &m;
	te.monotonic->tv_sec = mono.tv_sec;
	te.monotonic->tv_nsec = mono.tv_nsec;
	te.boottime = &b;
	te.boottime->tv_sec = boot.tv_sec;
	te.boottime->tv_nsec = boot.tv_nsec;

	ret = pb_write_one(img, &te, PB_TIMENS);
	close_image(img);

	return ret < 0 ? -1 : 0;
}

static void normalize_timespec(struct timespec *ts)
{
	while (ts->tv_nsec >= NSEC_PER_SEC) {
		ts->tv_nsec -= NSEC_PER_SEC;
		++ts->tv_sec;
	}
	while (ts->tv_nsec < 0) {
		ts->tv_nsec += NSEC_PER_SEC;
		--ts->tv_sec;
	}
}

int prepare_timens(int id)
{
	int exit_code = -1;
	int ret, fd = -1;
	struct cr_img *img;
	TimensEntry *te;
	struct timespec ts;
	struct timespec prev_moff = {}, prev_boff = {};

	if (opts.unprivileged)
		return 0;

	img = open_image(CR_FD_TIMENS, O_RSTR, id);
	if (!img)
		return -1;

	if (id == 0 && empty_image(img)) {
		pr_warn("Clocks values have not been dumped\n");
		close_image(img);
		return 0;
	}

	ret = pb_read_one(img, &te, PB_TIMENS);
	close_image(img);
	if (ret < 0)
		goto err;

	if (opts.timens_budget_ms) {
		/* timens_wait_dumped_clocks() resumes the tasks when they reach the dumped values. */
		int64_t sec = opts.timens_budget_ms / 1000;
		long nsec = (opts.timens_budget_ms % 1000) * 1000000L;
		struct timespec m = { te->monotonic->tv_sec - sec, te->monotonic->tv_nsec - nsec };
		struct timespec b = { te->boottime->tv_sec - sec, te->boottime->tv_nsec - nsec };

		normalize_timespec(&m);
		normalize_timespec(&b);
		te->monotonic->tv_sec = m.tv_sec;
		te->monotonic->tv_nsec = m.tv_nsec;
		te->boottime->tv_sec = b.tv_sec;
		te->boottime->tv_nsec = b.tv_nsec;
		pr_info("timens: clocks start %u ms behind the dumped values\n", opts.timens_budget_ms);
	}

	if (unshare(CLONE_NEWTIME)) {
		pr_perror("Unable to create a new time namespace");
		return -1;
	}

	if (parse_timens_offsets(&prev_boff, &prev_moff))
		goto err;

	fd = open_proc_rw(PROC_SELF, "timens_offsets");
	if (fd < 0)
		goto err;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec = ts.tv_sec - prev_moff.tv_sec;
	ts.tv_nsec = ts.tv_nsec - prev_moff.tv_nsec;

	ts.tv_sec = te->monotonic->tv_sec - ts.tv_sec;
	ts.tv_nsec = te->monotonic->tv_nsec - ts.tv_nsec;
	normalize_timespec(&ts);

	pr_debug("timens: monotonic %" PRId64 " %ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);
	if (dprintf(fd, "%d %" PRId64 " %ld\n", CLOCK_MONOTONIC, (int64_t)ts.tv_sec, ts.tv_nsec) < 0) {
		pr_perror("Unable to set a monotonic clock offset");
		goto err;
	}

	clock_gettime(CLOCK_BOOTTIME, &ts);

	ts.tv_sec = ts.tv_sec - prev_boff.tv_sec;
	ts.tv_nsec = ts.tv_nsec - prev_boff.tv_nsec;

	ts.tv_sec = te->boottime->tv_sec - ts.tv_sec;
	ts.tv_nsec = te->boottime->tv_nsec - ts.tv_nsec;
	normalize_timespec(&ts);

	pr_debug("timens: boottime %" PRId64 " %ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);
	if (dprintf(fd, "%d %" PRId64 " %ld\n", CLOCK_BOOTTIME, (int64_t)ts.tv_sec, ts.tv_nsec) < 0) {
		pr_perror("Unable to set a boottime clock offset");
		goto err;
	}

	timens_entry__free_unpacked(te, NULL);
	close_safe(&fd);

	fd = open_proc(PROC_SELF, "ns/time_for_children");
	if (fd < 0) {
		pr_perror("Unable to open ns/time_for_children");
		goto err;
	}
	if (switch_ns_by_fd(fd, &time_ns_desc, NULL))
		goto err;
	exit_code = 0;
err:
	close_safe(&fd);
	return exit_code;
}
static int64_t ts_ns(const struct timespec *ts)
{
	return (int64_t)ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

/*
 * With --timens-budget the restored clocks started behind the dumped values
 * (prepare_timens). Keep the tasks stopped until their monotonic clock has
 * reached the dumped value, so it continues from there and never reads
 * earlier than it did before the dump. A restore longer than the budget
 * resumes them at once; only the overrun counts as time they ran.
 */
int timens_wait_dumped_clocks(pid_t root, int ns_id)
{
	struct timespec moff_self = {}, boff_self = {}, moff_root = {}, boff_root = {}, now;
	struct cr_img *img;
	TimensEntry *te = NULL;
	int64_t target, restored, wait;

	if (!opts.timens_budget_ms || opts.unprivileged)
		return 0;

	img = open_image(CR_FD_TIMENS, O_RSTR, ns_id);
	if (!img)
		goto blind;
	if (empty_image(img) || pb_read_one(img, &te, PB_TIMENS) < 0) {
		close_image(img);
		goto blind;
	}
	close_image(img);
	target = (int64_t)te->monotonic->tv_sec * NSEC_PER_SEC + te->monotonic->tv_nsec;
	timens_entry__free_unpacked(te, NULL);

	if (parse_timens_offsets(&boff_self, &moff_self) ||
	    parse_pid_timens_offsets(root, &boff_root, &moff_root))
		goto blind;

	clock_gettime(CLOCK_MONOTONIC, &now);
	restored = ts_ns(&now) - ts_ns(&moff_self) + ts_ns(&moff_root);
	wait = target - restored;
	if (wait <= 0) {
		pr_warn("timens: the restore took %" PRId64 " ms longer than its budget; the tasks see it\n",
			-wait / 1000000);
		return 0;
	}
	pr_info("timens: resuming the tasks in %" PRId64 " ms, when their clocks reach the dumped values\n",
		wait / 1000000);
	now.tv_sec = wait / NSEC_PER_SEC;
	now.tv_nsec = wait % NSEC_PER_SEC;
	while (nanosleep(&now, &now) && errno == EINTR)
		;
	return 0;

blind:
	/*
	 * Without the values, wait out the whole budget: the clocks then read
	 * at least the dumped values, never earlier ones.
	 */
	pr_warn("timens: cannot read the restored clocks; waiting out the whole budget\n");
	now.tv_sec = opts.timens_budget_ms / 1000;
	now.tv_nsec = (opts.timens_budget_ms % 1000) * 1000000L;
	while (nanosleep(&now, &now) && errno == EINTR)
		;
	return 0;
}

struct ns_desc time_ns_desc = NS_DESC_ENTRY(CLONE_NEWTIME, "time");
struct ns_desc time_for_children_ns_desc = NS_DESC_ENTRY(CLONE_NEWTIME, "time_for_children");
