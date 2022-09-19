#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>

int movefd(int oldfd, int newfd);

ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);

int get_rand_bytes(void *buf, int len);

int get_one_line(void *buf, int maxlen);

void cat_file(const char *filename);

#endif
