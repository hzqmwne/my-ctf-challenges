#include <stddef.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>


static int install_seccomp(void) {
	/*
		line  CODE  JT   JF      K
		=================================
		0000: 0x20 0x00 0x00 0x00000004  A = arch
		0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
		0002: 0x20 0x00 0x00 0x00000000  A = sys_number
		0003: 0x35 0x04 0x00 0x40000000  if (A >= 0x40000000) goto 0008
		0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
		0005: 0x15 0x03 0x00 0x0000003c  if (A == exit) goto 0009
		0006: 0x15 0x02 0x00 0x000000e7  if (A == exit_group) goto 0009
		0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
		0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
		0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
	*/
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 6),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		return -1;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		return -1;
	}
	return 0;
}

int init_sandbox(void) {    // return 0 for success, < 0 for error
	int r;
	struct rlimit rl = { .rlim_cur = 1, .rlim_max = 1 };
	r = setrlimit(RLIMIT_CPU, &rl);
	if (r < 0) {
		return r;
	}
	rl.rlim_cur = 128*1024*1024;
	rl.rlim_max = 128*1024*1024;
	r = setrlimit(RLIMIT_AS, &rl);
	if (r < 0) {
		return r;
	}
	r = install_seccomp();
	return r;
}
