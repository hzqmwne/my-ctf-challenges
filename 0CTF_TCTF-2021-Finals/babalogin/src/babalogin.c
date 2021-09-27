#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "babalogin.h"
#include "data.h"


//#define DEBUG 1


char mylogin_binary[MAX_BINARY_LEN];
int mylogin_binary_len = 0;

struct fullcompiler global_maliciouscompiler = { .compiler_binary_len = 0, .linker_binary_len = 0 };
struct fullcompiler global_finalcompiler = { .compiler_binary_len = 0, .linker_binary_len = 0 };


int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {
	return syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
}

int close_range(unsigned int first, unsigned int last, unsigned int flags) {
	// https://man7.org/linux/man-pages/man2/close_range.2.html, since linux 5.9
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
	return syscall(SYS_close_range, first, last, flags);
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

int movefd(int oldfd, int newfd) {
	int r = dup2(oldfd, newfd);
	if (oldfd != newfd) {
		close(oldfd);
	}
	return r;
}


int run_binary(const char *binary, int binary_len, const char *input, int input_len, char *output, int *p_output_len) {    // return 0 for success, -1 for error
	// fork + memfd_create + pipe + dup2 + close + seccomp + execveat + waitpid
	
	int r;
	int stdinpipe[2];
	int stdoutpipe[2];
	
	r = pipe(stdinpipe);
	if (r < 0) {
		return r;
	}
	r = pipe(stdoutpipe);
	if (r < 0) {
		return r;
	}

	pid_t pid = fork();

	if (pid == 0) {
		// child
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		close(stdinpipe[1]);
		close(stdoutpipe[0]);
		movefd(stdinpipe[0], 0);
		movefd(stdoutpipe[1], 1);
		
		int mfd = memfd_create("", MFD_CLOEXEC);
		writen(mfd, binary, binary_len);

		if (mfd > 2) {
			if (close_range(2, mfd-1, 0) != 0) {
				exit(0);
			}
		}
		if (close_range(mfd+1, 0x7ffffffe, 0) != 0) {
			exit(0);
		}

		struct rlimit rl = { .rlim_cur = 1, .rlim_max = 1 };
		setrlimit(RLIMIT_CPU, &rl);
		install_seccomp();

		execveat(mfd, "", NULL, NULL, AT_EMPTY_PATH);

		exit(0);
	}

	if (pid < 0) {
		return pid;
	}

	// parent
	close(stdinpipe[0]);
	close(stdoutpipe[1]);

	writen(stdinpipe[1], input, input_len);
	close(stdinpipe[1]);
	int output_len = readn(stdoutpipe[0], output, MAX_OUTPUT_LEN);

	waitpid(-1, NULL, 0);

	close(stdoutpipe[0]);

	if (output_len < 0) {
		return output_len;
	}
	else if (output_len == 0) {
		return -1;
	}
	
	*p_output_len = output_len;
	return 0;
}

int do_fullcompile(const struct fullcompiler *fc, const char *source, int source_len, char *binary, int *p_binary_len) {    // return 0 for success, -1 for error
	int r;
	int middle_len = 0;
	char middle[MAX_OUTPUT_LEN];

	r = run_binary(fc->compiler_binary, fc->compiler_binary_len, source, source_len, middle, &middle_len);
	if (r != 0) {
		return r;
	}

	r = run_binary(fc->linker_binary, fc->linker_binary_len, middle, middle_len, binary, p_binary_len);
	if (r != 0) {
		return r;
	}

	return 0;
}

int do_fullcompiler_bootstrap(const struct fullcompiler *raw, const char *compiler_source, int compiler_source_len, const char *linker_source, int linker_source_len, struct fullcompiler *final) {
	struct fullcompiler stage1 = { .compiler_binary_len = 0, .linker_binary_len = 0 };
	struct fullcompiler stage2 = { .compiler_binary_len = 0, .linker_binary_len = 0 };

	int r;

	// first, use a third party fullcompiler raw to build stage1, version1 has the correct logic but may not the correct binary bytes
#ifdef DEBUG
	printf("do_fullcompiler_bootstrap: before stage1\n");
#endif
	r = do_fullcompile(raw, compiler_source, compiler_source_len, stage1.compiler_binary, &stage1.compiler_binary_len);
	if (r != 0) {
		return r;
	}
	r = do_fullcompile(raw, linker_source, linker_source_len, stage1.linker_binary, &stage1.linker_binary_len);
	if (r != 0) {
		return r;
	}

	// second, use version1 fullcompiler to build stage2, stage2 should have the correct binary bytes
#ifdef DEBUG
	printf("do_fullcompiler_bootstrap: before stage2\n");
#endif
	r = do_fullcompile(&stage1, compiler_source, compiler_source_len, stage2.compiler_binary, &stage2.compiler_binary_len);
	if (r != 0) {
		return r;
	}
	r = do_fullcompile(&stage1, linker_source, linker_source_len, stage2.linker_binary, &stage2.linker_binary_len);
	if (r != 0) {
		return r;
	}
	
	// third, use version2 to build final version, final version should have the same binary bytes compared with stage2
#ifdef DEBUG
	printf("do_fullcompiler_bootstrap: before stage3\n");
#endif
	r = do_fullcompile(&stage2, compiler_source, compiler_source_len, final->compiler_binary, &final->compiler_binary_len);
	if (r != 0) {
		return r;
	}
	r = do_fullcompile(&stage2, linker_source, linker_source_len, final->linker_binary, &final->linker_binary_len);
	if (r != 0) {
		return r;
	}

	// finally, check stage2 binary bytes are the same with final binay bytes
#ifdef DEBUG
	printf("do_fullcompiler_bootstrap: before compare %d %d %d %d\n", raw->compiler_binary_len, stage1.compiler_binary_len, stage2.compiler_binary_len, final->compiler_binary_len);
#endif
	if (final->compiler_binary_len != stage2.compiler_binary_len || memcmp(final->compiler_binary, stage2.compiler_binary, final->compiler_binary_len) != 0) {
		return -1;
	}
	if (final->linker_binary_len != stage2.linker_binary_len || memcmp(final->linker_binary, stage2.linker_binary, final->linker_binary_len) != 0) {
		return -1;
	}

	return 0;
}


void do_login(const char *binary, int binary_len, char **argv, char **envp) {    // noreturn
	int mfd = memfd_create("", MFD_CLOEXEC);
	write(mfd, binary, binary_len);
	execveat(mfd, "", argv, envp, AT_EMPTY_PATH);
	exit(0);
}

int main(void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int r;

	printf("0CTF-2021-Finals login: ");
	scanf("%4095s", &login_environ[login_environ_header_len]);    // XXX vuln: overflow

#ifdef DEBUG
	printf("main: before do_fullcompiler_bootstrap malicious\n");
#endif
	r = do_fullcompiler_bootstrap(&global_rawcompiler, maliciouscompiler_source, maliciouscompiler_source_len, maliciouslinker_source, maliciouslinker_source_len, &global_maliciouscompiler);
	if (r != 0) {
#ifdef DEBUG
		printf("bootstrap error\n");
#endif
		exit(0);
	}

#ifdef DEBUG
	printf("main: before do_fullcompiler_bootstrap\n");
#endif
	r = do_fullcompiler_bootstrap(&global_maliciouscompiler, mycompiler_source, mycompiler_source_len, mylinker_source, mylinker_source_len, &global_finalcompiler);
	if (r != 0) {
#ifdef DEBUG
		printf("bootstrap error\n");
#endif
		exit(0);
	}

	// TODO: do_test_fullcompiler(&global_finalcompiler);
	// testcases: source, input list, intended_output list
	// testcases: 1. echo  2. + - * /, check input be two integers  3. sort  4. hexstring  5. isprime
	// each testcase comes with 5 inputs

#ifdef DEBUG
	printf("main: before do_fullcompile\n");
#endif
	r = do_fullcompile(&global_finalcompiler, mylogin_source, mylogin_source_len, mylogin_binary, &mylogin_binary_len);
	if (r != 0) {
#ifdef DEBUG
		printf("compile mylogin error\n");
#endif
		exit(0);
	}

#ifdef DEBUG
	printf("main: before do_login\n");
#endif
	char *env[2] = {login_environ, NULL};
	do_login(mylogin_binary, mylogin_binary_len, NULL, (char **)&env);

	return 0;
}

