FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
	apt-get upgrade -y && \
	apt-get install -y xinetd socat busybox

RUN apt-get install -y libpixman-1-0 libglib2.0-0

CMD ["/usr/sbin/xinetd", "-dontfork"]
#CMD ["/usr/bin/socat", "tcp-l:8888,fork,reuseaddr", "exec:/home/pwn/start.sh,stderr,setsid,su=nobody"]

