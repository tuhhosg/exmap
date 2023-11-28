all: modules

KDIR ?= /lib/modules/`uname -r`/build

obj-m = exmap.o
exmap-m = driver.o memory.o ksyms.o
ccflags-y += -g 

kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild)

clean:
	$(Q)$(MAKE) $(kbuild)
