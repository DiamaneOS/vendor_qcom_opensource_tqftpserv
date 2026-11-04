#ifndef __TRANSLATE_H__
#define __TRANSLATE_H__

#include <stdbool.h>
#include <stddef.h>

/*
 * Budgets of the readwrite directory, which only a factory reset can clear for
 * the user. The modem keeps two files of a few bytes there.
 */
#define TQFTPSERV_MAX_FILE_BYTES (16 * 1024 * 1024)
#define TQFTPSERV_MAX_RW_BYTES (64 * 1024 * 1024)
#define TQFTPSERV_MAX_RW_FILES 256

int sanitize_path(const char *path);
int translate_open(const char *path, int flags);
int translate_unlink(const char *path);
bool translate_write_allowed(int fd, size_t len);

#endif
