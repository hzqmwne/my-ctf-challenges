#include "tinylib.h"

// copied from /usr/include/elf.h

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;
typedef Elf64_Half Elf64_Versym;

#define EI_NIDENT (16)

typedef struct
{
  unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
  Elf64_Half    e_type;                 /* Object file type */
  Elf64_Half    e_machine;              /* Architecture */
  Elf64_Word    e_version;              /* Object file version */
  Elf64_Addr    e_entry;                /* Entry point virtual address */
  Elf64_Off     e_phoff;                /* Program header table file offset */
  Elf64_Off     e_shoff;                /* Section header table file offset */
  Elf64_Word    e_flags;                /* Processor-specific flags */
  Elf64_Half    e_ehsize;               /* ELF header size in bytes */
  Elf64_Half    e_phentsize;            /* Program header table entry size */
  Elf64_Half    e_phnum;                /* Program header table entry count */
  Elf64_Half    e_shentsize;            /* Section header table entry size */
  Elf64_Half    e_shnum;                /* Section header table entry count */
  Elf64_Half    e_shstrndx;             /* Section header string table index */
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word    p_type;                 /* Segment type */
  Elf64_Word    p_flags;                /* Segment flags */
  Elf64_Off     p_offset;               /* Segment file offset */
  Elf64_Addr    p_vaddr;                /* Segment virtual address */
  Elf64_Addr    p_paddr;                /* Segment physical address */
  Elf64_Xword   p_filesz;               /* Segment size in file */
  Elf64_Xword   p_memsz;                /* Segment size in memory */
  Elf64_Xword   p_align;                /* Segment alignment */
} Elf64_Phdr;

/* Fields in the e_ident array.  The EI_* macros are indices into the
   array.  The macros under each EI_* macro are the values the byte
   may have.  */

#define EI_MAG0         0               /* File identification byte 0 index */
#define ELFMAG0         0x7f            /* Magic number byte 0 */

#define EI_MAG1         1               /* File identification byte 1 index */
#define ELFMAG1         'E'             /* Magic number byte 1 */

#define EI_MAG2         2               /* File identification byte 2 index */
#define ELFMAG2         'L'             /* Magic number byte 2 */

#define EI_MAG3         3               /* File identification byte 3 index */
#define ELFMAG3         'F'             /* Magic number byte 3 */

#define EI_CLASS        4               /* File class byte index */
#define ELFCLASSNONE    0               /* Invalid class */
#define ELFCLASS32      1               /* 32-bit objects */
#define ELFCLASS64      2               /* 64-bit objects */
#define ELFCLASSNUM     3

#define EI_DATA         5               /* Data encoding byte index */
#define ELFDATANONE     0               /* Invalid data encoding */
#define ELFDATA2LSB     1               /* 2's complement, little endian */
#define ELFDATA2MSB     2               /* 2's complement, big endian */
#define ELFDATANUM      3

#define EI_VERSION      6               /* File version byte index */
                                        /* Value must be EV_CURRENT */

#define EI_OSABI        7               /* OS ABI identification */
#define ELFOSABI_NONE           0       /* UNIX System V ABI */
#define ELFOSABI_SYSV           0       /* Alias.  */
#define ELFOSABI_HPUX           1       /* HP-UX */
#define ELFOSABI_NETBSD         2       /* NetBSD.  */
#define ELFOSABI_GNU            3       /* Object uses GNU ELF extensions.  */
#define ELFOSABI_LINUX          ELFOSABI_GNU /* Compatibility alias.  */
#define ELFOSABI_SOLARIS        6       /* Sun Solaris.  */
#define ELFOSABI_AIX            7       /* IBM AIX.  */
#define ELFOSABI_IRIX           8       /* SGI Irix.  */
#define ELFOSABI_FREEBSD        9       /* FreeBSD.  */
#define ELFOSABI_TRU64          10      /* Compaq TRU64 UNIX.  */
#define ELFOSABI_MODESTO        11      /* Novell Modesto.  */
#define ELFOSABI_OPENBSD        12      /* OpenBSD.  */
#define ELFOSABI_ARM_AEABI      64      /* ARM EABI */
#define ELFOSABI_ARM            97      /* ARM */
#define ELFOSABI_STANDALONE     255     /* Standalone (embedded) application */

#define EI_ABIVERSION   8               /* ABI version */

#define EI_PAD          9               /* Byte index of padding bytes */


/* Legal values for e_type (object file type).  */

#define ET_EXEC         2               /* Executable file */
#define ET_DYN          3               /* Shared object file */

/* Legal values for e_machine (architecture).  */

#define EM_X86_64       62      /* AMD x86-64 architecture */

/* Legal values for e_version (version).  */

#define EV_CURRENT      1               /* Current version */

/* Legal values for p_type (segment type).  */

#define PT_LOAD         1               /* Loadable program segment */
#define PT_PHDR         6               /* Entry for header table itself */
#define PT_GNU_STACK    0x6474e551      /* Indicates stack executability */

/* Legal values for p_flags (segment flags).  */

#define PF_X            (1 << 0)        /* Segment is executable */
#define PF_W            (1 << 1)        /* Segment is writable */
#define PF_R            (1 << 2)        /* Segment is readable */

static int do_input(char *buf) {
	int len = 0;
	int maxsize = 4096;
	while (1) {
		int r = read(0, buf+len, maxsize-len);
		if (r <= 0) {
			break;
		}
		len += r;
	}
	return len;
}

static void do_output(char *buf, int len) {
	int count = 0;
	while (count < len) {
		int r = write(1, buf, len-count);
		if (r <= 0) {
			break;
		}
		count += r;
	}
}

static void *memset(void *s, int c, size_t n) {
	for (size_t i = 0; i < n; i++) {
		((char *)s)[i] = c;
	}
	return s;
}

static void *memcpy(void *dest, const void *src, size_t n) {
	for (size_t i = 0; i < n; i++) {
		((char *)dest)[i] = ((char *)src)[i];
	}
	return dest;
}

static void do_linker(char *middle, int middle_len, char *binary, int *p_binary_len) {
	if (middle_len == 0) {
		*p_binary_len = 0;
		return;
	}

	int ph_num = 4;
	int header_size = sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)*ph_num;

	Elf64_Ehdr *eh = (Elf64_Ehdr *)binary;
	memset(eh, 0, sizeof(Elf64_Ehdr));
	eh->e_ident[EI_MAG0] = ELFMAG0; eh->e_ident[EI_MAG1] = ELFMAG1; eh->e_ident[EI_MAG2] = ELFMAG2; eh->e_ident[EI_MAG3] = ELFMAG3;
	eh->e_ident[EI_CLASS] = ELFCLASS64;
	eh->e_ident[EI_DATA] = ELFDATA2LSB;
	eh->e_ident[EI_VERSION] = EV_CURRENT;
	eh->e_type = ET_DYN;                 /* Object file type */
	eh->e_machine = EM_X86_64;              /* Architecture */
	eh->e_version = EV_CURRENT;              /* Object file version */
	eh->e_entry = 0x1000;                /* Entry point virtual address */
	eh->e_phoff = sizeof(Elf64_Ehdr);                /* Program header table file offset */
	eh->e_shoff = 0;                /* Section header table file offset */
	eh->e_flags = 0;                /* Processor-specific flags */
	eh->e_ehsize = sizeof(Elf64_Ehdr);               /* ELF header size in bytes */
	eh->e_phentsize = sizeof(Elf64_Phdr);            /* Program header table entry size */
	eh->e_phnum = ph_num;                /* Program header table entry count */
	eh->e_shentsize = 0;            /* Section header table entry size */
	eh->e_shnum = 0;                /* Section header table entry count */
	eh->e_shstrndx = 0;             /* Section header string table index */

	Elf64_Phdr *ph1 = (Elf64_Phdr *)&binary[sizeof(Elf64_Ehdr)];
	memset(ph1, 0, sizeof(Elf64_Phdr));
	ph1->p_type = PT_PHDR;                 /* Segment type */
	ph1->p_flags = PF_R;                /* Segment flags */
	ph1->p_offset = sizeof(Elf64_Ehdr);               /* Segment file offset */
	ph1->p_vaddr = sizeof(Elf64_Ehdr);                /* Segment virtual address */
	ph1->p_paddr = sizeof(Elf64_Ehdr);                /* Segment physical address */
	ph1->p_filesz = sizeof(Elf64_Phdr)*ph_num;               /* Segment size in file */
	ph1->p_memsz = sizeof(Elf64_Phdr)*ph_num;                /* Segment size in memory */
	ph1->p_align = 8;                /* Segment alignment */

	Elf64_Phdr *ph2 = (Elf64_Phdr *)&binary[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
	memset(ph2, 0, sizeof(Elf64_Phdr));
	ph2->p_type = PT_LOAD;                 /* Segment type */
	ph2->p_flags = PF_R;                /* Segment flags */
	ph2->p_offset = 0;               /* Segment file offset */
	ph2->p_vaddr = 0;                /* Segment virtual address */
	ph2->p_paddr = 0;                /* Segment physical address */
	ph2->p_filesz = header_size;               /* Segment size in file */
	ph2->p_memsz = header_size;                /* Segment size in memory */
	ph2->p_align = 0x1000;                /* Segment alignment */

	Elf64_Phdr *ph3 = (Elf64_Phdr *)&binary[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)*2];
	memset(ph3, 0, sizeof(Elf64_Phdr));
	ph3->p_type = PT_LOAD;                 /* Segment type */
	ph3->p_flags = PF_R|PF_X;                /* Segment flags */
	ph3->p_offset = 0x1000;               /* Segment file offset */
	ph3->p_vaddr = 0x1000;                /* Segment virtual address */
	ph3->p_paddr = 0x1000;                /* Segment physical address */
	ph3->p_filesz = middle_len;               /* Segment size in file */
	ph3->p_memsz = middle_len;                /* Segment size in memory */
	ph3->p_align = 0x1000;                /* Segment alignment */

	Elf64_Phdr *ph4 = (Elf64_Phdr *)&binary[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)*3];
	memset(ph4, 0, sizeof(Elf64_Phdr));
	ph4->p_type = PT_GNU_STACK;                 /* Segment type */
	ph4->p_flags = PF_R|PF_W;                /* Segment flags */
	ph4->p_offset = 0;               /* Segment file offset */
	ph4->p_vaddr = 0;                /* Segment virtual address */
	ph4->p_paddr = 0;                /* Segment physical address */
	ph4->p_filesz = 0;               /* Segment size in file */
	ph4->p_memsz = 0;                /* Segment size in memory */
	ph4->p_align = 0x10;                /* Segment alignment */

	memset(&binary[header_size], 0, 4096-header_size);
	memcpy(&binary[4096], middle, middle_len);
	*p_binary_len = 4096 + middle_len;
}

int main(int argc, char **argv, char **envp) {
	char middle[4096];
	char binary[8192];
	int binary_len = 0;
	int middle_len = do_input(middle);
	do_linker(middle, middle_len, binary, &binary_len);
	do_output(binary, binary_len);
	return 0;
}

