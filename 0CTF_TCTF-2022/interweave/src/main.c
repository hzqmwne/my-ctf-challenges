#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"
#include "base64.h"
#include "sha256.h"
#include "filelessrun.h"

#define N_PROGRAMS 16
#define MESSAGE_SIZE 0xc00
#define FILE_GOAL_SIZE 0x1000
#define MAX_FILE_SIZE 0x2000

#define MAX_OUTPUT_LEN 0x1000


#define CHECK(x) do { if (!(x)) { exit(1); } } while(0)


struct program {
	unsigned char message[MESSAGE_SIZE];
	unsigned char file[MAX_FILE_SIZE];
	int file_size;
	unsigned char file_sha256[SHA256_BLOCK_SIZE];
};

struct task {
	int id;
	int exit_status;
	unsigned char output[MAX_OUTPUT_LEN];
	int output_len;
};

struct program all_programs[N_PROGRAMS];
struct task all_tasks[N_PROGRAMS];


int main(void) {
	setvbuf(stdin, NULL, _IOLBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int total_file_size_less_or_equal_than_goal = 0;
	int total_exit_normally = 0;
	int total_output_correct_message = 0;
	int total_output_correct_hash = 0;

	int r;
	int i;

	// init program messages
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		p->file_size = 0;
		r = get_rand_bytes(p->message, MESSAGE_SIZE);
		CHECK(r == MESSAGE_SIZE);
	}

	// output program messages
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		BYTE out[(MESSAGE_SIZE+2)/3*4+1];
		r = base64_encode(p->message, out, MESSAGE_SIZE);
		out[r] = '\0';
		printf("%s\n", out);
	}

	// get user input programs
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		BYTE buf[MAX_FILE_SIZE/3*4];
		r = get_one_line(buf, sizeof(buf));
		CHECK(r > 0);
		r = base64_decode(buf, p->file, r);
		CHECK((r > 0) && (r <= (int)sizeof(buf)));
		p->file_size = r;
		if (r <= FILE_GOAL_SIZE) {
			total_file_size_less_or_equal_than_goal++;
		}
	}

	// check all program are valid ELF strictly
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		r = is_valid_elf(p->file, p->file_size);
		if (!r) {
			exit(0);
		}
	}

	// calculate program sha256s
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		sha256_sum(p->file, p->file_size, p->file_sha256);
	}

	// check all sha256s are different
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		int j;
		for (j = i + 1; j < N_PROGRAMS; j++) {
			struct program *q = &all_programs[j];
			r = memcmp(p->file_sha256, q->file_sha256, SHA256_BLOCK_SIZE);
			if (r == 0) {
				exit(0);
			}
		}
	}

	// init run tasks
	for (i = 0; i < N_PROGRAMS; i++) {
		struct task *t = &all_tasks[i];
		t->id = i;
		t->exit_status = -1;
		t->output_len = 0;
	}

	// run each tasks
	for (i = 0; i < N_PROGRAMS; i++) {
		struct program *p = &all_programs[i];
		struct task *t = &all_tasks[i];
		t->exit_status = run_binary(p->file, p->file_size, NULL, NULL, NULL, 0, t->output, MAX_OUTPUT_LEN, &t->output_len);
	}

	// check run results
	for (i = 0; i < N_PROGRAMS; i++) {
		struct task *t = &all_tasks[i];
		int status = t->exit_status;
		if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
			total_exit_normally++;
			// check first 0xc00 bytes should be equal to message, and later 0x200 bytes should be equal to the 16 sha256s
			if (t->output_len == MESSAGE_SIZE + N_PROGRAMS * SHA256_BLOCK_SIZE) {
				if (memcmp(t->output, all_programs[i].message, MESSAGE_SIZE) == 0) {
					total_output_correct_message++;
				}
				for (int j = 0; j < N_PROGRAMS; j++) {
					if (memcmp((unsigned char *)t->output + MESSAGE_SIZE + j * SHA256_BLOCK_SIZE, all_programs[j].file_sha256, SHA256_BLOCK_SIZE) == 0) {
						total_output_correct_hash++;
					}
				}
			}
		}
	}

	// judge, then output flag
	if (total_exit_normally == N_PROGRAMS) {
		if (total_output_correct_message == N_PROGRAMS) {
			cat_file("flag1.txt");

			if (total_output_correct_hash >= (N_PROGRAMS)*(N_PROGRAMS+1)/2) {
				cat_file("flag2.txt");

				if (total_output_correct_hash == N_PROGRAMS * N_PROGRAMS) {
					cat_file("flag3.txt");

					if (total_file_size_less_or_equal_than_goal == N_PROGRAMS) {
						cat_file("flag4.txt");
					}
				}
			}
		}
	}

	return 0;
}
