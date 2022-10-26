## Repository file structure
### Module

- driver.c/h: main implementation
- memory.c: C-c C-v from linux kernel memory.c, adapted
- ksyms.c/h: get non-exported functions
- exmap.h: includes for the kernel module
- linux/exmap.h: includes for applications using exmap
- config.h: configuration options, mostly for testing purposes

### Evaluation

- test-exmap.cc: test the basic functionality of exmap (create/alloc/free)
- test-bench-alloc.cc/test-bench-steal.cc: allocation/free benchmark with one or two interfaces per thread, or a pool of threads allocating and freeing from and to shared lists
- test-bench-read.cc: test different usages of exmap with pread
- bench_common.h: functions/classes/... used by multiple benchmark programs
