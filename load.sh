#!/bin/bash

rmmod exmap;
make && insmod exmap.ko
cp -v linux/exmap.h /usr/include/linux

if ! lsmod | grep -q null_blk; then 
	#modprobe --first-time null_blk no_sched=1 irqmode=2 completion_nsec=1 submit_queues=16 hw_queue_depth=128 bs=4096
	#modprobe --first-time null_blk no_sched=1 irqmode=1 completion_nsec=1 submit_queues=16 hw_queue_depth=128 bs=4096
	modprobe --first-time null_blk no_sched=1 irqmode=0 queue_mode=0 completion_nsec=0 hw_queue_depth=128 bs=4096

fi
