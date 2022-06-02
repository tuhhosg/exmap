TESTS = \
	test-bench-alloc \
	test-bench-steal \
	test-exmap


all: modules ${TESTS}

# out-of-tree build for our kernel-module, firmware and inmates
KDIR ?= /lib/modules/`uname -r`/build

obj-m = exmap.o
exmap-m = driver.o memory.o ksyms.o
ccflags-y += -g 

kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild)

clean:
	$(Q)$(MAKE) $(kbuild)
	rm -f ${TESTS} *.o


test-%: test-%.cc
	g++ -o $@  $< -O3 -lpthread -ggdb


################################################################
# QEMU

SYSTEM = ~/proj/eBPF/iouring-and-ebpf/qemu/system.qcow2

QEMU_FLAGS=-m 4g -enable-kvm  -hda ${SYSTEM} \
	-device e1000,netdev=net0 \
	-netdev user,id=net0,hostfwd=tcp::2222-:22 \
	-virtfs local,path=..,security_model=none,mount_tag=share0

qemu:
	qemu-system-x86_64 ${QEMU_FLAGS} -smp 12

ssh:
	ssh -p 2222 root@localhost
