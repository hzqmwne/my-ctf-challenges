#!/bin/sh


# download

wget https://download.qemu.org/qemu-4.2.1.tar.xz

wget http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-5.4.0-77-generic_5.4.0-77.86_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-5.4.0-77-generic_5.4.0-77.86_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-headers-5.4.0-77_5.4.0-77.86_all.deb
wget http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-headers-5.4.0-77-generic_5.4.0-77.86_amd64.deb

wget http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6-dev_2.27-3ubuntu1.2_amd64.deb

wget https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64

# wget https://raw.githubusercontent.com/hugsy/gdb-static/master/gdbserver-7.10.1-x64

# extract

tar Jxvf qemu-4.2.1.tar.xz

dpkg -x linux-image*.deb ./
dpkg -x linux-headers*all.deb ./
dpkg -x linux-headers*amd64.deb ./
dpkg -x libc6-dev*.deb ./

# create symbol links

ln -s ../src/ss_device.c qemu-4.2.1/hw/misc/
echo 'common-obj-y += ss_device.o' >> qemu-4.2.1/hw/misc/Makefile.objs

ln -s ../prepare/usr/lib/x86_64-linux-gnu/libc.a ../src/

ln -s ../prepare/busybox-x86_64 ../src/


# build qemu with new device

(cd qemu-4.2.1; ./configure --target-list=x86_64-softmmu; make)


