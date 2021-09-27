# https://stackoverflow.com/questions/15189704/makefile-removes-object-files-for-no-reason
# https://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
# https://unix.stackexchange.com/questions/517190/what-causes-make-to-delete-intermediate-files
# https://www.gnu.org/software/make/manual/html_node/Multiple-Targets.html

targets = mycompiler.binary mylinker.binary mylogin.binary babalogin_with_debuginfo babalogin

all: $(targets)

.PRECIOUS: %.elf %.textbin %.source

# bootstarp of compiler and linker

mycompiler.binary mylinker.binary &:: mycompiler.source mylinker.source mycompiler.elf mylinker.elf
	cat mycompiler.source | ./mycompiler.elf | ./mylinker.elf > mycompiler_tmp.binary && chmod +x mycompiler_tmp.binary
	cat mylinker.source | ./mycompiler.elf | ./mylinker.elf > mylinker_tmp.binary && chmod +x mylinker_tmp.binary
	cat mycompiler.source | ./mycompiler_tmp.binary | ./mylinker_tmp.binary > mycompiler.binary && chmod +x mycompiler.binary
	cat mylinker.source | ./mycompiler_tmp.binary | ./mylinker_tmp.binary > mylinker.binary && chmod +x mylinker.binary
	diff mycompiler.binary mycompiler_tmp.binary && diff mylinker.binary mylinker_tmp.binary && rm mycompiler_tmp.binary mylinker_tmp.binary

#

%.elf: %.c startup.c 
	gcc -masm=intel -nostdlib -nostartfiles -nostdinc -static-pie -T linker.lds -Os -g -fno-reorder-functions -o $@ $^

%.textbin: %.elf
	objcopy -O binary -j .text $^ $@

%.source: %.textbin
	base64 -w 0 < $^ > $@

%.binary: %.source
	cat $^ | ./mycompiler.binary | ./mylinker.binary > $@ && chmod +x $@

#

data.c data.h &:: data.c.template data.h.template mycompiler.source mylinker.source mylogin.source mycompiler.binary mylinker.binary
	python3 generate_data.py $^

sandbox.c: sandbox.txt
	seccomp-tools asm $^ -f c_source | sed 's/static void/void/g ; s/perror[^;]*; //g' > $@


babalogin_with_debuginfo: babalogin.c data.c sandbox.c
	gcc -static-pie -g -o $@ $^

babalogin: babalogin_with_debuginfo
	strip -o $@ $^  

#

.PHONY: clean
clean:
	rm -f $(targets) *.elf *.textbin *.source *.middle *.binary data.c data.h sandbox.c

