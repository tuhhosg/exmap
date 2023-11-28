all: modules

KDIR ?= /lib/modules/`uname -r`/build

obj-m = memory_pool.o
memory_pool-m = driver.o ksyms.o
ccflags-y += -g 

kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild)

clean:
	$(Q)$(MAKE) $(kbuild)
