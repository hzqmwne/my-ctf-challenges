FROM ubuntu:18.04 as builder

ARG PREFIXDIR=/root
ARG ROOTDIR=$PREFIXDIR/rootdir

RUN cd $PREFIXDIR && \
	apt-get update && \
	apt-get install -y xinetd && \
	 \
	 \
	mkdir $ROOTDIR && \
	cd $ROOTDIR && \
	 \
	 \
	umask 0022 && \
	 \
	mkdir bin etc lib64 lib lib/x86_64-linux-gnu usr usr/sbin && \
	 \
	cp /lib/x86_64-linux-gnu/ld-2.27.so \
		/lib/x86_64-linux-gnu/libc-2.27.so \
		/lib/x86_64-linux-gnu/libdl-2.27.so \
		/lib/x86_64-linux-gnu/libnsl-2.27.so \
		/lib/x86_64-linux-gnu/libtinfo.so.5.9 \
		/lib/x86_64-linux-gnu/libselinux.so.1 \
		/lib/x86_64-linux-gnu/libwrap.so.0.7.6 \
		/lib/x86_64-linux-gnu/libpcre.so.3.13.3 \
		/lib/x86_64-linux-gnu/libpthread-2.27.so \
		/lib/x86_64-linux-gnu/libnss_nis-2.27.so \
		/lib/x86_64-linux-gnu/libnss_files-2.27.so \
		lib/x86_64-linux-gnu/ && \
	 \
	ln -s /lib/x86_64-linux-gnu/ld-2.27.so lib64/ld-linux-x86-64.so.2 && \
	ln -s libc-2.27.so lib/x86_64-linux-gnu/libc.so.6 && \
	ln -s libdl-2.27.so lib/x86_64-linux-gnu/libdl.so.2 && \
	ln -s libnsl-2.27.so lib/x86_64-linux-gnu/libnsl.so.1 && \
	ln -s libtinfo.so.5.9 lib/x86_64-linux-gnu/libtinfo.so.5 && \
	ln -s libwrap.so.0.7.6 lib/x86_64-linux-gnu/libwrap.so.0 && \
	ln -s libpcre.so.3.13.3 lib/x86_64-linux-gnu/libpcre.so.3 && \
	ln -s libpthread-2.27.so lib/x86_64-linux-gnu/libpthread.so.0 && \
	ln -s libnss_nis-2.27.so lib/x86_64-linux-gnu/libnss_nis.so.2 && \
	ln -s libnss_files-2.27.so lib/x86_64-linux-gnu/libnss_files.so.2 && \
	 \
	cp /bin/bash bin/ && \
	ln -s bash bin/sh && \
	cp /bin/cat bin/ && \
	cp /bin/ls bin/ls && \
	cp /usr/sbin/xinetd usr/sbin && \
	mkdir etc/xinetd.d && \
	cp /etc/xinetd.conf etc/ && \
	cp /etc/protocols etc/



FROM scratch
ARG PREFIXDIR=/root
ARG ROOTDIR=$PREFIXDIR/rootdir
COPY --from=builder $ROOTDIR /
CMD ["/usr/sbin/xinetd", "-dontfork"]

