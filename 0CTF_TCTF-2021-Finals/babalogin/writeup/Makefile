# https://stackoverflow.com/questions/15189704/makefile-removes-object-files-for-no-reason
# https://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
# https://unix.stackexchange.com/questions/517190/what-causes-make-to-delete-intermediate-files


all: malicious_compiler.source

.PRECIOUS: %.elf %.textbin

#malicious_compiler.elf : startup.c malicious_compiler.c
%.elf : %.c startup.c
	gcc -masm=intel -nostdlib -nostartfiles -nostdinc -static-pie -T linker.lds -Os -g -fno-reorder-functions -o $@ $^

%.textbin: %.elf
	objcopy -O binary -j .text $^ $@

%.source: %.textbin
	base64 -w 0 $^ > $@

.PHONY: clean
clean:
	rm -f *.source *.textbin *.elf

