CC=musl-gcc
targets = exp_stage1_leak exp_stage3_kernel exp_stage4_qemu sh

all: $(targets)

% : %.c
	$(CC) -static -s -o $@ $^

sh : bin_sh_loader.c
	$(CC) -static -s -o $@ $^

.PHONY clean:
	rm -f $(targets)

