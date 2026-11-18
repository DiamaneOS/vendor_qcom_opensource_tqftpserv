// SPDX-License-Identifier: BSD-3-Clause
/*
 * Path translation: sanitize_path(), translate_open() and translate_unlink()
 * on a tree with symbolic links leading out, subfolders, an empty firmware
 * name and odd file names.
 *
 * Input: u8 op, then the path (up to the first NUL or the end).
 *   op % 4: 0 open for reading, 1 open for writing, 2 unlink, 3 check only
 *   op & 4: prefix the path with one of the served folders, picked by op >> 3
 */
#include "fuzz_common.h"

static const char *const prefixes[] = {
	"/readwrite/", "/readonly/firmware/image/", "/readonly/firmware/modem_pr",
	"/readonly/vendor/firmware/", "/readonly/vendor/firmware_mnt/image/",
	"/readonly/firmware/", "/", "",
};

/* sanitize_path() as its comment states it */
static bool path_is_safe(const char *path)
{
	const char *p = path;
	const char *end;
	size_t len;

	if (*p == '/')
		p++;
	while (*p) {
		end = strchr(p, '/');
		len = end ? (size_t)(end - p) : strlen(p);
		if (len == 0)
			return false;
		if (len == 2 && p[0] == '.' && p[1] == '.')
			return false;
		if (!end)
			break;
		p = end + 1;
	}
	return true;
}

/* @rel without "." components, as the kernel resolves it */
static void normalize(const char *rel, char *out, size_t size)
{
	const char *p = rel;
	size_t n = 0;

	out[0] = '\0';
	while (*p) {
		const char *end = strchr(p, '/');
		size_t len = end ? (size_t)(end - p) : strlen(p);

		if (!(len == 1 && p[0] == '.') && len) {
			if (n + len + 2 >= size)
				return;
			if (n)
				out[n++] = '/';
			memcpy(out + n, p, len);
			n += len;
			out[n] = '\0';
		}
		if (!end)
			break;
		p = end + 1;
	}
}

static bool lexists(const char *path)
{
	struct stat st;

	return lstat(path, &st) == 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char path[8192];
	char expect[PATH_MAX * 2];
	char where[PATH_MAX];
	char rel[PATH_MAX * 2];
	struct fz_usage usage;
	static bool dirty = true;
	uint64_t fw_hash, out_hash;
	size_t base_alloc;
	int base_fds;
	uint8_t op;
	size_t len;
	int fd;

	fz_init_once();
	if (!size)
		return 0;
	op = data[0];
	len = 0;
	if (op & 4)
		len = stpcpy(path, prefixes[(op >> 3) % 8]) - path;
	size--;
	data++;
	if (size > 4095)
		size = 4095;
	memcpy(path + len, data, size);
	path[len + size] = '\0';

	FZ_CHECK((sanitize_path(path) == 0) == path_is_safe(path),
		 "sanitize_path() said %d for \"%s\"", sanitize_path(path), path);
	if (op % 4 == 3)
		return 0;

	if (dirty)
		fz_reset_rw(FZ_TREE_PLAIN);
	dirty = false;
	fw_hash = fz_tree_hash(fz_fw_base);
	out_hash = fz_tree_hash(fz_outside);
	fz_rw_usage(&usage.entries, &usage.bytes, &usage.largest);
	base_fds = fz_count_fds();
	base_alloc = fz_allocated();

	rel[0] = '\0';
	if (!strncmp(path, "/readwrite/", 11))
		normalize(path + 11, rel, sizeof(rel));
	snprintf(expect, sizeof(expect), "%s%s%s", fz_rw_dir, rel[0] ? "/" : "", rel);

	switch (op % 4) {
	case 0:
	case 1:
		fd = translate_open(path, op % 4 ? O_WRONLY | O_CREAT : O_RDONLY);
		if (fd < 0)
			break;
		dirty |= op % 4 == 1;
		FZ_CHECK(path_is_safe(path), "\"%s\" opened", path);
		/* A firmware file opened for writing comes back read-only */
		FZ_CHECK(fz_fd_inside(fd, fz_fd_writable(fd), where, sizeof(where)),
			 "\"%s\" opened %s", path, where);
		/* No symbolic link is followed under the readwrite folder */
		if (fz_under(where, fz_rw_dir))
			FZ_CHECK(!strcmp(where, expect), "\"%s\" opened %s, not %s",
				 path, where, expect);
		fz_close(fd);
		break;
	case 2: {
		bool existed = lexists(expect);
		struct stat st;

		if (existed && lstat(expect, &st) == 0 && S_ISDIR(st.st_mode))
			existed = false;
		if (translate_unlink(path) < 0)
			break;
		dirty = true;
		FZ_CHECK(path_is_safe(path) && rel[0], "\"%s\" unlinked", path);
		FZ_CHECK(existed && !lexists(expect), "\"%s\" unlinked, but not %s", path, expect);
		break;
	}
	}

	FZ_CHECK(fz_count_fds() == base_fds, "%d descriptors open, %d at start",
		 fz_count_fds(), base_fds);
	FZ_CHECK(!fz_alloc_exact() || fz_allocated() == base_alloc, "%lld bytes held",
		 (long long)fz_allocated() - (long long)base_alloc);
	FZ_CHECK(fz_tree_hash(fz_fw_base) == fw_hash, "the firmware folder changed");
	FZ_CHECK(fz_tree_hash(fz_outside) == out_hash, "a folder outside changed");
	fz_check_budgets(&usage);
	return 0;
}
