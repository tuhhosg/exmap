all: modules eval

KDIR ?= /lib/modules/`uname -r`/build

obj-y := module/ memory_pool/
kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild)

clean:
	$(Q)$(MAKE) $(kbuild)
	$(RM) modules.order
	make -C module/ clean
	make -C memory_pool/ clean

eval:
	make -C eval/

.PHONY: eval
