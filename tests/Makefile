# Makefile for f3_target.ko (A-1 stage-2 trap validation stimulus)
#
# Build against the Realm kernel tree (6.12.0-opencca-wip), cross-compiled
# for arm64 with the same toolchain you used for a1_test_arm.

obj-m := f3_target.o

# Point this at the built Realm kernel source tree.
KDIR ?= $(HOME)/opencca-workspace/source/opencca/linux

ARCH          ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
