/*
 * NVIDIA character-device fds and device VMAs.
 *
 * cuda-checkpoint closes the /dev/nvidia* fds of a task while it releases the
 * GPU, so CRIU's later fd collection never sees them, and the kernel refuses
 * to dump a device mapping it does not understand. This file records those
 * fds before the checkpoint action runs, lets CRIU dump them as external
 * files, claims the device VMAs during dump, and reopens the devices by their
 * original path at restore so the task finds the same fd numbers again.
 */
#include "criu-plugin.h"
#include "criu-log.h"
#include "plugin.h"
#include "util.h"
#include "cuda_plugin.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

static int scan_and_save_nvidia_fds(int pid);
static bool is_nvidia_device_major(unsigned int maj);

/* Forward declaration - checks if a device major number is an NVIDIA device */
static bool is_nvidia_device_major(unsigned int maj);

/**
 * Handle NVIDIA device VMAs during dump.
 * This hook is called when CRIU encounters a device file mmap.
 * Returning 0 tells CRIU that this plugin will handle the VMA.
 */
int cuda_plugin_handle_device_vma(int fd, const struct stat *st_buf)
{
	unsigned int major_num = major(st_buf->st_rdev);

	if (is_nvidia_device_major(major_num)) {
		pr_info("CUDA plugin handling NVIDIA device VMA (major %d, minor %d)\n",
			major_num, minor(st_buf->st_rdev));

		if (cuda_plugin_add_inventory())
			return -1;

		return 0; /* Plugin will handle this VMA */
	}

	return -ENOTSUP; /* Not our device, let other plugins try */
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, cuda_plugin_handle_device_vma)

/**
 * Update VMA mapping during restore.
 * For NVIDIA device VMAs, we return a /dev/zero mapping instead of the real device.
 * cuda-checkpoint will restore the actual GPU state after CRIU restore completes.
 */
int cuda_plugin_update_vma_map(const char *path, const uint64_t addr,
			       const uint64_t old_pgoff, uint64_t *new_pgoff, int *plugin_fd)
{
	static int devzero_fd = -1;
	int dup_fd;

	/* Check if this is an NVIDIA device by major number.
	 * The path comes from CRIU's VMA info - stat it to verify. */
	{
		struct stat vma_st;
		if (stat(path, &vma_st) < 0 || !S_ISCHR(vma_st.st_mode) ||
		    !is_nvidia_device_major(major(vma_st.st_rdev))) {
			return -ENOTSUP; /* Not our device */
		}
	}

	pr_debug("CUDA plugin: mapping NVIDIA VMA at 0x%lx (%s) to /dev/zero\n",
		(unsigned long)addr, path);

	/* Open /dev/zero once and keep it */
	if (devzero_fd < 0) {
		devzero_fd = open("/dev/zero", O_RDWR);
		if (devzero_fd < 0) {
			pr_perror("CUDA plugin: failed to open /dev/zero");
			return -1;
		}
	}

	/*
	 * CRIU will dup and close the returned fd, so we must return a dup'd copy.
	 * We keep devzero_fd for ourselves, and return a fresh dup each time.
	 */
	dup_fd = dup(devzero_fd);
	if (dup_fd < 0) {
		pr_perror("CUDA plugin: failed to dup /dev/zero fd");
		return -1;
	}

	*plugin_fd = dup_fd;
	*new_pgoff = 0;

	return 1; /* Tell CRIU to use our fd */
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, cuda_plugin_update_vma_map)

/**
 * Handle NVIDIA device file descriptors during dump.
 * NVIDIA device FDs cannot be dumped normally - they are kernel resources
 * tied to GPU context. We tell CRIU to skip them.
 * cuda-checkpoint will restore the GPU context on restore.
 */
/*
 * NVIDIA device major numbers are dynamically allocated and can change
 * between systems, kernel versions, and driver versions.
 * We detect them at runtime by reading /proc/devices.
 *
 * Known NVIDIA device types:
 * - nvidia, nvidiactl, nvidia-modeset (usually 195)
 * - nvidia-uvm (dynamic, e.g., 507)
 * - nvidia-nvswitch (dynamic, e.g., 508)
 * - nvidia-nvlink (dynamic, e.g., 509)
 * - nvidia-caps (dynamic, e.g., 510)
 * - nvidia-caps-imex-channels (dynamic, e.g., 511)
 */
#define MAX_NVIDIA_MAJORS 16
static int nvidia_majors[MAX_NVIDIA_MAJORS];
static int nvidia_major_count = 0;
static bool majors_initialized = false;

static void add_nvidia_major(int major)
{
	/* Check if already added */
	for (int i = 0; i < nvidia_major_count; i++) {
		if (nvidia_majors[i] == major)
			return;
	}
	if (nvidia_major_count < MAX_NVIDIA_MAJORS) {
		nvidia_majors[nvidia_major_count++] = major;
	}
}

static void init_nvidia_majors(void)
{
	FILE *f;
	char line[256];

	if (majors_initialized)
		return;

	majors_initialized = true;

	f = fopen("/proc/devices", "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		int major;
		char name[64];

		if (sscanf(line, "%d %63s", &major, name) != 2)
			continue;

		/* Match any device name containing "nvidia" */
		if (strstr(name, "nvidia") != NULL) {
			add_nvidia_major(major);
			pr_debug("CUDA plugin: detected NVIDIA device '%s' at major %d\n", name, major);
		}
	}

	fclose(f);

	pr_info("CUDA plugin: detected %d NVIDIA device majors\n", nvidia_major_count);
}

static bool is_nvidia_device_major(unsigned int maj)
{
	init_nvidia_majors();

	for (int i = 0; i < nvidia_major_count; i++) {
		if ((int)maj == nvidia_majors[i])
			return true;
	}

	/* Fallback to common known values if detection failed */
	if (maj == 195)  /* nvidia - usually static */
		return true;

	return false;
}

/*
 * Save NVIDIA device file mappings to a file during dump.
 * Format: one line per file "id path\n"
 */
#define NVIDIA_FILES_IMG "nvidia-files.img"
static FILE *nvidia_files_fp = NULL;

static void save_nvidia_file_mapping(int id, unsigned int maj, unsigned int min, const char *path)
{
	if (!nvidia_files_fp) {
		int img_dir_fd = criu_get_image_dir();
		int fd = openat(img_dir_fd, NVIDIA_FILES_IMG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			pr_perror("Failed to create %s via openat(img_dir_fd=%d)", NVIDIA_FILES_IMG, img_dir_fd);
			return;
		}
		nvidia_files_fp = fdopen(fd, "w");
		if (!nvidia_files_fp) {
			pr_perror("Failed to fdopen %s", NVIDIA_FILES_IMG);
			close(fd);
			return;
		}
		pr_info("CUDA plugin: saving NVIDIA mappings via openat(img_dir_fd=%d, %s)\n",
			img_dir_fd, NVIDIA_FILES_IMG);
	}
	fprintf(nvidia_files_fp, "%d %u %u %s\n", id, maj, min, path);
	fflush(nvidia_files_fp);
	pr_debug("CUDA plugin: saved mapping id=0x%x -> %s (dev %u:%u)\n", id, path, maj, min);
}

/*
 * Scan a process's file descriptors for NVIDIA devices and save mappings.
 * This MUST be called BEFORE cuda-checkpoint closes the device FDs.
 *
 * The id format uses FD number + device info to create a unique identifier
 * that can be matched during restore.
 */
static int scan_and_save_nvidia_fds(int pid)
{
	char fd_dir[64];
	DIR *dir;
	struct dirent *entry;
	int count = 0;

	snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
	dir = opendir(fd_dir);
	if (!dir) {
		pr_perror("CUDA plugin: failed to open %s", fd_dir);
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		char fd_path[PATH_MAX];
		char link_target[256];
		struct stat st;
		ssize_t len;
		int fd_num;

		if (entry->d_name[0] == '.')
			continue;

		fd_num = atoi(entry->d_name);
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd_num);

		/* Stat the FD directly to get device type and major/minor.
		 * Uses fstatat on the /proc/pid/fd/N symlink - no need to
		 * resolve the link target first. This catches ALL nvidia
		 * devices regardless of path or naming. */
		if (stat(fd_path, &st) < 0)
			continue;

		if (!S_ISCHR(st.st_mode))
			continue;

		if (!is_nvidia_device_major(major(st.st_rdev)))
			continue;

		/* Read the symlink for the device path (for mapping file) */
		len = readlink(fd_path, link_target, sizeof(link_target) - 1);
		if (len <= 0)
			continue;
		link_target[len] = '\0';

		/* Create a unique ID from major:minor:fd */
		unsigned int maj = major(st.st_rdev);
		unsigned int min = minor(st.st_rdev);
		int id = (maj << 20) | (min << 8) | (fd_num & 0xFF);

		save_nvidia_file_mapping(id, maj, min, link_target);
		count++;

		pr_debug("CUDA plugin: found NVIDIA fd %d -> %s (id=0x%x)\n",
			fd_num, link_target, id);
	}

	closedir(dir);

	if (count > 0) {
		pr_info("CUDA plugin: saved %d NVIDIA device mappings for pid %d\n", count, pid);
	}

	return count;
}

int cuda_plugin_dump_file(int fd, int id)
{
	struct stat st;
	char path[PATH_MAX];
	char fd_link[64];
	ssize_t len;

	if (fstat(fd, &st) == -1) {
		return -ENOTSUP; /* Can't stat, not our file */
	}

	/* Handle any character device - not just NVIDIA.
	 * CRIU calls DUMP_EXT_FILE for devices it can't dump natively.
	 * We save the path + major:minor so we can reopen/mknod on restore.
	 * This covers nvidia, gdrdrv, and any future GPU-related drivers. */
	if (!S_ISCHR(st.st_mode)) {
		return -ENOTSUP; /* Not a character device */
	}

	/*
	 * Register this plugin in the inventory so CRIU knows to load it
	 * during restore. This is critical - without it, the plugin will
	 * be disabled during restore and external files won't be restored.
	 */
	if (cuda_plugin_add_inventory())
		return -1;

	/* Get the actual device path */
	unsigned int dmaj = major(st.st_rdev);
	unsigned int dmin = minor(st.st_rdev);
	snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", fd);
	len = readlink(fd_link, path, sizeof(path) - 1);
	if (len > 0) {
		path[len] = '\0';
		save_nvidia_file_mapping(id, dmaj, dmin, path);
	} else {
		/* Readlink failed - scan /dev for matching major:minor */
		DIR *devdir = opendir("/dev");
		bool found = false;
		if (devdir) {
			struct dirent *de;
			while ((de = readdir(devdir)) != NULL) {
				struct stat devst;
				snprintf(path, sizeof(path), "/dev/%s", de->d_name);
				if (stat(path, &devst) == 0 && S_ISCHR(devst.st_mode) &&
				    major(devst.st_rdev) == dmaj && minor(devst.st_rdev) == dmin) {
					save_nvidia_file_mapping(id, dmaj, dmin, path);
					found = true;
					break;
				}
			}
			closedir(devdir);
		}
		if (!found) {
			snprintf(path, sizeof(path), "/dev/nvidia-unknown-%u-%u", dmaj, dmin);
			save_nvidia_file_mapping(id, dmaj, dmin, path);
			pr_warn("CUDA plugin: couldn't find device for major %u minor %u, "
				"using placeholder path\n", dmaj, dmin);
		}
	}

	pr_info("CUDA plugin: marking NVIDIA device fd %d id 0x%x (%s) as external\n",
		fd, id, path);

	/* Return 0 to tell CRIU we handled this file (skip dumping it) */
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, cuda_plugin_dump_file)

/**
 * Restore an external NVIDIA device file.
 * CRIU calls this during restore for each ext file we claimed during dump.
 */
/*
 * Load NVIDIA device file mappings saved during dump.
 */
#define MAX_NVIDIA_FILES 512
static struct {
	int id;
	unsigned int maj;
	unsigned int min;
	char path[PATH_MAX];
} nvidia_file_map[MAX_NVIDIA_FILES];
static int nvidia_file_map_count = 0;
static bool nvidia_file_map_loaded = false;

static void load_nvidia_file_mappings(void)
{
	FILE *fp;
	int id, fd;
	char path[PATH_MAX];
	int img_dir_fd;

	if (nvidia_file_map_loaded)
		return;
	nvidia_file_map_loaded = true;

	img_dir_fd = criu_get_image_dir();
	fd = openat(img_dir_fd, NVIDIA_FILES_IMG, O_RDONLY);
	if (fd < 0) {
		pr_warn("CUDA plugin: no %s found via openat(img_dir_fd=%d) (errno=%d: %s), using fallback\n",
			NVIDIA_FILES_IMG, img_dir_fd, errno, strerror(errno));
		return;
	}
	fp = fdopen(fd, "r");
	if (!fp) {
		pr_warn("CUDA plugin: fdopen failed for %s (errno=%d: %s)\n",
			NVIDIA_FILES_IMG, errno, strerror(errno));
		close(fd);
		return;
	}
	pr_info("CUDA plugin: loading NVIDIA mappings via openat(img_dir_fd=%d, %s)\n",
		img_dir_fd, NVIDIA_FILES_IMG);

	{
		unsigned int fmaj, fmin;
		while (fscanf(fp, "%d %u %u %255s", &id, &fmaj, &fmin, path) == 4) {
			if (nvidia_file_map_count >= MAX_NVIDIA_FILES) {
				pr_warn("CUDA plugin: too many NVIDIA files, truncating\n");
				break;
			}
			nvidia_file_map[nvidia_file_map_count].id = id;
			nvidia_file_map[nvidia_file_map_count].maj = fmaj;
			nvidia_file_map[nvidia_file_map_count].min = fmin;
			strncpy(nvidia_file_map[nvidia_file_map_count].path, path, sizeof(nvidia_file_map[0].path) - 1);
			nvidia_file_map[nvidia_file_map_count].path[sizeof(nvidia_file_map[0].path) - 1] = '\0';
			nvidia_file_map_count++;
		}
	}
	fclose(fp);
	pr_info("CUDA plugin: loaded %d NVIDIA file mappings\n", nvidia_file_map_count);
}

static int find_nvidia_entry_for_id(int id, const char **out_path,
				    unsigned int *out_maj, unsigned int *out_min)
{
	load_nvidia_file_mappings();
	for (int i = 0; i < nvidia_file_map_count; i++) {
		if (nvidia_file_map[i].id == id) {
			*out_path = nvidia_file_map[i].path;
			*out_maj = nvidia_file_map[i].maj;
			*out_min = nvidia_file_map[i].min;
			return 0;
		}
	}
	return -1;
}

int cuda_plugin_restore_file(int id, bool *retry_needed)
{
	int fd;
	const char *path;

	*retry_needed = false;

	if (!cuda_plugin_active())
		return -ENOTSUP;

	/* Look up the original path and device major:minor for this file ID */
	{
		unsigned int dmaj, dmin;
		if (find_nvidia_entry_for_id(id, &path, &dmaj, &dmin) == 0) {
			fd = open(path, O_RDWR);
			if (fd >= 0) {
				pr_debug("CUDA plugin: restored id 0x%x as %s (fd=%d)\n", id, path, fd);
				return fd;
			}
			/* Device doesn't exist in container - create it via mknod */
			if (errno == ENOENT && dmaj > 0) {
				char parent[PATH_MAX];
				strncpy(parent, path, sizeof(parent) - 1);
				parent[sizeof(parent) - 1] = '\0';
				char *slash = strrchr(parent, '/');
				if (slash && slash != parent) {
					*slash = '\0';
					mkdir(parent, 0755);
				}
				if (mknod(path, S_IFCHR | 0666, makedev(dmaj, dmin)) == 0 ||
				    errno == EEXIST) {
					fd = open(path, O_RDWR);
					if (fd >= 0) {
						pr_info("CUDA plugin: restored id 0x%x as %s "
							"(created via mknod %u:%u, fd=%d)\n",
							id, path, dmaj, dmin, fd);
						return fd;
					}
				}
				pr_warn("CUDA plugin: mknod %s (%u:%u) failed: %s\n",
					path, dmaj, dmin, strerror(errno));
			} else {
				pr_warn("CUDA plugin: can't open %s for id 0x%x: %s\n",
					path, id, strerror(errno));
			}
		}
	}

	/* Fallback: try to reconstruct device path from the ID.
	 * ID format: (major << 20) | (minor << 8) | (fd_num & 0xFF)
	 * We can extract major/minor and scan /dev for a matching device. */
	{
		unsigned int id_major = (id >> 20) & 0xFFF;
		unsigned int id_minor = (id >> 8) & 0xFFF;
		DIR *devdir = opendir("/dev");
		if (devdir) {
			struct dirent *de;
			while ((de = readdir(devdir)) != NULL) {
				char devpath[PATH_MAX];
				struct stat devst;
				snprintf(devpath, sizeof(devpath), "/dev/%s", de->d_name);
				if (stat(devpath, &devst) < 0)
					continue;
				if (!S_ISCHR(devst.st_mode))
					continue;
				if (major(devst.st_rdev) == id_major &&
				    minor(devst.st_rdev) == id_minor) {
					fd = open(devpath, O_RDWR);
					if (fd >= 0) {
						pr_info("CUDA plugin: restored id 0x%x as %s "
							"(fallback by major:minor %u:%u, fd=%d)\n",
							id, devpath, id_major, id_minor, fd);
						closedir(devdir);
						return fd;
					}
				}
			}
			closedir(devdir);
		}
	}

	/* Return -ENOTSUP (not -ENOENT) so CRIU knows this plugin can't handle
	 * this file and tries other restore methods. -ENOENT means "file doesn't
	 * exist" which causes CRIU to abort. -ENOTSUP means "not my file." */
	pr_debug("CUDA plugin: id 0x%x (major=%u minor=%u) not an NVIDIA device, returning ENOTSUP\n",
		id, (id >> 20) & 0xFFF, (id >> 8) & 0xFFF);
	return -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, cuda_plugin_restore_file)

/* Record the task's NVIDIA device fds before the checkpoint action closes them. */
int cuda_device_files_record(int pid)
{
	if (!cuda_plugin_active())
		return 0;
	return scan_and_save_nvidia_fds(pid);
}

/* Flush and close the device-file image at the end of a dump. */
void cuda_device_files_dump_finish(void)
{
	if (nvidia_files_fp) {
		fclose(nvidia_files_fp);
		nvidia_files_fp = NULL;
	}
}
