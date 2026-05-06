# Out-of-tree build for IS31FL319X LED driver
# Cross-compile for ARM64: make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

obj-m := leds-is31fl319x.o

# Default kernel source location
KDIR ?= /lib/modules/$(shell uname -r)/build

# For cross-compilation
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

# Deploy to target
deploy:
	scp leds-is31fl319x.ko root@192.168.1.200:/lib/modules/`ssh root@192.168.1.200 uname -r`/kernel/drivers/leds/
	ssh root@192.168.1.200 "depmod -a && modprobe leds-is31fl319x"
