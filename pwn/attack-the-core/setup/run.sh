#!/bin/bash

timeout --foreground 300 /usr/bin/qemu-system-x86_64 \
	-cpu kvm64,+smep,+smap \
	-m 128M \
	-kernel /bzImage \
	-initrd /initramfs.cpio.gz \
	-monitor none \
	-nographic \
	-no-reboot \
	-append "console=ttyS0 kpti loglevel=0"
	#-fsdev local,security_model=passthrough,id=fsdev0,path=./ \
	#-device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare \
	

# DEBUG
# Uncomment above for shared folder with host for easier
# exploit development