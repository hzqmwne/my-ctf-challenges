#KDIR:=/lib/modules/$(shell uname -r)/build/
KDIR:=../develop/usr/src/linux-headers-5.4.0-77-generic/
PWD:=$(shell pwd)

export RCS_FIND_IGNORE:= \( -name SCCS -o -name BitKeeper -o -name .svn -o -name CVS -o -name .pc -o -name .hg -o -name .git -o -name libc.a \) -prune -o 


obj-m := ss.o
ss-objs := ss_driver.o

all: ss.ko ss_stripped.ko ss_agent ss_agent_stripped

ss.ko: ss_driver.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS+=-g

ss_stripped.ko: ss.ko
	strip --strip-unneeded $^ -o $@

ss_agent: ss_agent.c
	$(CC) -g -static-pie -o $@ $^ ./libc.a

ss_agent_stripped: ss_agent
	strip $^ -o $@

clean:
	@mv libc.a libc.a_ || true
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@mv libc.a_ libc.a || true
	rm ss_stripped.ko ss_agent ss_agent_stripped 2>/dev/null || true

