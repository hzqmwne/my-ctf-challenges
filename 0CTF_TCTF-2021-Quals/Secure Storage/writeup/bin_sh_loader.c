#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(void) {
	uid_t euid = geteuid();
	gid_t egid = getegid();
	setresgid(egid, egid, egid);
	setresuid(euid, euid, euid);
	execl("/bin/sh", "/bin/sh", NULL);
	return 0;
}
