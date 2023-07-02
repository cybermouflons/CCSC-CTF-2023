#!/bin/sh
#musl-gcc -o exploit/x_final exploit/x_final.c -static
#cp exploit/x_final ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
