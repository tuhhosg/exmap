all: modules eval #module memory_pool

KDIR ?= /lib/modules/`uname -r`/build

obj-y := module/ memory_pool/
kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild)

clean:
	$(Q)$(MAKE) $(kbuild)
	$(RM) modules.order

# module:
# 	make -C module/

# memory_pool:
# 	make -C memory_pool/

eval:
	make -C eval/

.PHONY: eval #module memory_pool
