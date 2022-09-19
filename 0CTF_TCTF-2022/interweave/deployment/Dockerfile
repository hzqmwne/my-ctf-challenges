FROM ubuntu:22.04

RUN apt-get update && apt-get install -y xinetd

COPY challenge /challenge
COPY ctf.xinetd /etc/xinetd.d/ctf

CMD ["/usr/sbin/xinetd", "-dontfork"]
