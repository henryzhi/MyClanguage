#
# Makefile for the ipvs modules.
#

obj-m += hello.o

#KDIR := ~/linux-3.10.0-514.26.2.el7
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

EXTRA_CFLAGS += -I$(shell pwd)/udis86/
EXTRA_CFLAGS += -O -g 

udis86_extra-objs-y := udis86/decode.o \
	udis86/syn-intel.o \
	udis86/itab.o \
	udis86/syn-att.o \
	udis86/syn.o \
	udis86/udis86.o

inl_hook-objs-y := util.o inl_hook.o rh_trr.o drv.o

hello-objs := drv.o $(inl_hook-objs-y) $(udis86_extra-objs-y)

modules:
	make -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
	@find $(PWD) \
		\( -name '*.[oas]' -o -name '*.ko' -o -name '.*.cmd' \
		-o -name '*.ko.*' \
		-o -name '.*.d' -o -name '.*.tmp' -o -name '*.mod.c' \
		-o -name '*.symtypes' -o -name 'modules.order' \
		-o -name 'Module.markers' -o -name '.tmp_*.o.*' \
		-o -name '*.gcno' \) -type f -print | xargs rm -f

.PHONY: modules clean

