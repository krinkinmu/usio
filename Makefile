ifneq ($(KERNELRELEASE),)

obj-m := usio.o
usio-y := main.o
CFLAGS_main.o += -DDEBUG

else

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	rm -rf *.o *.ko *.order *.symvers *.mod.c

endif
