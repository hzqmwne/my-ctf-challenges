#ifndef FILELESSRUN_H
#define FILELESSRUN_H

int run_binary(const void *binary, int binary_len, char **argv, char **envp, const void *input, int input_len, void *output, int max_output_len, int *p_output_len);
int is_valid_elf(const void *file, int file_size);

#endif
