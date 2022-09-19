#define _GNU_SOURCE 
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <elf.h>
#include "util.h"
#include "sandbox.h"

#define ENABLE_SANDBOX 1

int run_binary(const void *binary, int binary_len, char **argv, char **envp, const void *input, int input_len, void *output, int max_output_len, int *p_output_len) {
	// fork + memfd_create + pipe + dup2 + close + seccomp + execveat + waitpid
	
	int r;
	int stdinpipe[2];
	int stdoutpipe[2];
	
	r = pipe(stdinpipe);
	if (r < 0) {
		exit(1);
	}
	r = pipe(stdoutpipe);
	if (r < 0) {
		exit(1);
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
				exit(1);
			}
		}
		if (close_range(mfd+1, 0x7ffffffe, 0) != 0) {
			exit(1);
		}
		if (input == NULL || input_len == 0) {
			if (close(0) != 0) {
				exit(1);
			}
		}

#if ENABLE_SANDBOX
		r = init_sandbox();
		if (r < 0) {
			exit(-1);
		}
#endif

		execveat(mfd, "", argv, envp, AT_EMPTY_PATH);

		exit(1);
	}

	if (pid < 0) {
		exit(1);
	}

	// parent
	close(stdinpipe[0]);
	close(stdoutpipe[1]);

	if (input != NULL && input_len != 0) {
		writen(stdinpipe[1], input, input_len);
	}
	close(stdinpipe[1]);
	int output_len = readn(stdoutpipe[0], output, max_output_len);

	int status;
	waitpid(-1, &status, 0);

	close(stdoutpipe[0]);

	*p_output_len = output_len;
	return status;
}


int is_valid_elf(const void *file, unsigned int file_size) {
	// return 1 for valid, 0 for invalids

	const Elf64_Ehdr *elf_header = file;
	if (file_size < sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)) {
		return 0;
	}

	// check elf header

	if ( !(elf_header->e_ident[EI_MAG0] == ELFMAG0 \
		 && elf_header->e_ident[EI_MAG1] == ELFMAG1 \
		 && elf_header->e_ident[EI_MAG2] == ELFMAG2 \
		 && elf_header->e_ident[EI_MAG3] == ELFMAG3) ) {
		return 0;
	}
	if ( !(elf_header->e_ident[EI_CLASS] == ELFCLASS64 \
		 && elf_header->e_ident[EI_DATA] == ELFDATA2LSB \
		 && elf_header->e_ident[EI_VERSION] == EV_CURRENT \
		 && elf_header->e_ident[EI_OSABI] == ELFOSABI_SYSV \
		 && elf_header->e_ident[EI_ABIVERSION] == 0) ) {
		return 0;
	}
	if ( !(memcmp(&elf_header->e_ident[EI_PAD], "\x00\x00\x00\x00\x00\x00", EI_NIDENT-EI_PAD) == 0) ) {
		return 0;
	}

	if ( !(elf_header->e_type == ET_EXEC || elf_header->e_type == ET_DYN) ) {
		return 0;
	}
	if ( !(elf_header->e_machine == EM_X86_64 \
		 && elf_header->e_version == 1 \
		 && elf_header->e_phoff == sizeof(Elf64_Ehdr) ) ) {
		return 0;
	}
	if ( !(elf_header->e_shoff <= file_size) ) {
		return 0;
	}
	if ( !(elf_header->e_flags == 0 \
		 && elf_header->e_ehsize == sizeof(Elf64_Ehdr) \
		 && elf_header->e_phentsize == sizeof(Elf64_Phdr) \
		 && elf_header->e_phnum <= 127) ) {
		return 0;
	}
	if ( !((elf_header->e_shentsize == 0 || elf_header->e_shentsize == sizeof(Elf64_Ehdr)) \
		 && elf_header->e_shnum <= 127 \
		 && elf_header->e_shstrndx <= file_size) ) {
		return 0;
	}

	return 1;
}
