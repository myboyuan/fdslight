ifneq ($(KERNELRELEASE),)
obj-m := fdslight_dgram.o
ccflags-y := -std=gnu99 -g -Wall -D FDSL_LINUX_KERNEL
else
		PWD  := $(shell pwd)
		KVER := $(shell uname -r)
		KDIR := /lib/modules/$(KVER)/build
all:
		$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
		rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions modules.*  Module.*
endif