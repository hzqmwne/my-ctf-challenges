#ifndef TINYLIB_H_
#define TINYLIB_H_

// https://git.musl-libc.org/cgit/musl/tree/arch/x86_64/syscall_arch.h

typedef unsigned long size_t;
typedef signed long ssize_t;
typedef signed long off_t;


static __inline long __syscall0(long n)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall1(long n, long a1)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall2(long n, long a1, long a2)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
						  : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10): "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return ret;
}

// =============================================================================

static inline ssize_t read(int fd, void *buf, size_t count) {
	return (ssize_t)__syscall3(0, (long)fd, (long)buf, (long)count);
}

static inline ssize_t write(int fd, const void *buf, size_t count) {
	return (ssize_t)__syscall3(1, (long)fd, (long)buf, (long)count);
}

// https://git.musl-libc.org/cgit/musl/tree/include/fcntl.h
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2

static inline int open(const char *pathname, int flags) {
	return (int)__syscall2(2, (long)pathname, flags);
}

static inline int close(int fd) {
	return (int)__syscall1(3, (long)fd);
}

// https://git.musl-libc.org/cgit/musl/tree/include/sys/mman.h
#define MAP_SHARED     0x01
#define MAP_PRIVATE    0x02
#define MAP_ANONYMOUS  0x20
#define MAP_NORESERVE  0x4000
#define PROT_NONE      0
#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_EXEC      4

static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	return (void *)__syscall6(9, (long)addr, (long)length, (long)prot, (long)flags, (long)fd, (long)offset);
}

static inline int munmap(void *addr, size_t length) {
	return (int)__syscall2(11, (long)addr, (long)length);
}

static inline int execve(const char *pathname, char *const argv[], char *const envp[]) {
	return (int)__syscall3(59, (long)pathname, (long)argv, (long)envp);
}

static inline void exit(int status) {
	__syscall1(60, (long)status);
}

#endif

