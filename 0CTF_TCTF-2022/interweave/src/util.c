#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>

int movefd(int oldfd, int newfd) {
	int r = dup2(oldfd, newfd);
	if (oldfd != newfd) {
		close(oldfd);
	}
	return r;
}

ssize_t readn(int fd, void *buf, size_t count) {
	size_t alreadycount = 0;
	while (alreadycount < count) {
		ssize_t r = read(fd, ((char *)buf)+alreadycount, count-alreadycount);
		if (r <= 0) {
			if (alreadycount == 0) {
				return r;
			}
			break;
		}
		alreadycount += r;
	}
	return alreadycount;
}

ssize_t writen(int fd, const void *buf, size_t count) {
	size_t alreadycount = 0;
	while (alreadycount < count) {
		ssize_t r = write(fd, ((char *)buf)+alreadycount, count-alreadycount);
		if (r <= 0) {
			if (alreadycount == 0) {
				return r;
			}
			break;
		}
		alreadycount += r;
	}
	return alreadycount;
}



int get_rand_bytes(void *buf, int len) {
	int already = 0;
	while (already < len) {
		int r = getrandom(((char*)buf)+already, len-already, 0);
		if (r <= 0) {
			return already ? already : r;
		}
		already += r;
	}
	return already;
}


int get_one_line(void *buf, int maxlen) {
	int index = 0;
	while (index < maxlen) {
		int c = getchar();
		if (c == EOF || c == '\n') {
			break;
		}
		/*
		char c = -1;
		int r = read(STDIN_FILENO, &c, 1);
		if (r != 1 || c == '\n') {
			break;
		}
		*/
		((unsigned char *)buf)[index++] = c;
	}
	return index;
}

void cat_file(const char *filename) {
	int fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		char buf[256];
		int r = read(fd, buf, sizeof(buf));
		if (r > 0) {
			r = write(STDOUT_FILENO, buf, r);
			(void)r;
		}
	}
}
