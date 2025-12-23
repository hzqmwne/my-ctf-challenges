FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

RUN apt-get update && apt-get install -y xinetd

COPY pwn /pwn
COPY flag.txt /flag
COPY ctf.xinetd /etc/xinetd.d/ctf

CMD ["/usr/sbin/xinetd", "-dontfork"]
