#!/bin/sh

if [ $(id -u) -ne 0 ];then
    echo "the user is not root"
    exit 1
fi


cd $(dirname $0)


rm -rf rootfs share

mkdir -m 0755 rootfs
(cd rootfs && mkdir -m 0755 bin challenge dev etc proc sbin sys usr etc/init.d usr/bin usr/sbin)
(cd rootfs && mkdir -m 1777 tmp)


cp ../../develop/busybox-x86_64 rootfs/bin/busybox
chmod 0755 rootfs/bin/busybox

(cd rootfs && bin/busybox --list-full | sed 's/^usr\/s\?bin\/.*\?$/..\/..\/bin\/busybox \0/g  ;  s/^sbin\/.*\?$/..\/bin\/busybox \0/g  ;  s/^bin\/.*\?$/busybox \0/g  ;  s/^linuxrc$/bin\/busybox \0/g' | xargs -L 1 ln -s)


cp inittab rootfs/etc/
chmod 0644 rootfs/etc/inittab
cp rcS rootfs/etc/init.d/
chmod 0755 rootfs/etc/init.d/rcS

cp ../../src/ss_stripped.ko rootfs/challenge/ss.ko
chmod 0644 rootfs/challenge/ss.ko

cp ../../src/ss_agent_stripped rootfs/challenge/ss_agent
chgrp 900 rootfs/challenge/ss_agent
chmod 2755 rootfs/challenge/ss_agent

cp secrets/admin_key.txt rootfs/challenge/
chgrp 900 rootfs/challenge/admin_key.txt
chmod 0640 rootfs/challenge/admin_key.txt

cp secrets/secret2.txt rootfs/challenge/
chgrp 900 rootfs/challenge/secret2.txt
chmod 0640 rootfs/challenge/secret2.txt

cp secrets/secret3.txt rootfs/challenge/
chmod 0600 rootfs/challenge/secret3.txt


mkdir -m 755 share
(cd ./rootfs ; find . | cpio -o -H newc --quiet > ../share/initramfs.cpio)
cp ../../develop/boot/vmlinuz-5.4.0-77-generic ./share/vmlinuz && chmod 0644 ./share/vmlinuz
strip ../../develop/qemu-4.2.1/x86_64-softmmu/qemu-system-x86_64 -o ./share/qemu-system-x86_64
mkdir -m 755 share/pc-bios
cp ../../develop/qemu-4.2.1/pc-bios/bios-256k.bin ./share/pc-bios/
cp ../../develop/qemu-4.2.1/pc-bios/kvmvapic.bin ./share/pc-bios/
cp ../../develop/qemu-4.2.1/pc-bios/linuxboot_dma.bin ./share/pc-bios/
cp ../../develop/qemu-4.2.1/pc-bios/vgabios-stdvga.bin ./share/pc-bios/
cp ../../develop/qemu-4.2.1/pc-bios/efi-e1000.rom ./share/pc-bios/

cp start.sh share/
cp secrets/flag.txt share/



tar zcf secure_storage_attachments_to_player.tar.gz share Dockerfile docker-compose.yml pwn-xinetd tmp

