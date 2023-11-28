# ExMap - Fully explicit virtual memory
The ExMap kernel module creates a virtual memory area (VMA) that is not managed by the Linux kernel.
This area is shared with a user space application, giving it fast and directly controlled file-mapped I/O or anonymous memory.

Memory operations, such as allocation and freeing, as well as reads and writes, can only be done explicitly by the application using ExMap.
With ExMap, there is no OS implicity (like page faults or automatic write-back).

See [vmcache](https://github.com/viktorleis/vmcache) for a database buffer manager that uses ExMap.

## How to build and run
[`./load.sh`](./load.sh) will
1) copy the ExMap header for applications to `/usr/include`,
2) build and (re-)insert the `exmap` and `memory_pool` kernel modules, and
3) insert the `null_blk` test block device.

Once everything is built and loaded, run `./test-exmap` in the [`eval`](./eval) folder for a basic functionality test.

## Repository structure

[`module`](./module) contains the main ExMap driver and an adapted version of Linux's `mm/memory.c`.

[`memory_pool`](./memory_pool) is a separate general module, used by ExMap, that provides its lock-free memory pool.

For both, a workaround through `kallsyms` is used in order to get non-exported functions.

Finally, the [`eval`](./eval) folder contains some basic tests and benchmarks.
