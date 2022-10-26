## Usage
- loading module provides /dev/exmap
- interact with it from an application via `ioctl`
- include `linux/exmap.h`
- Config:
  - backing fd (e.g. SSD)
  - amount of memory to reserve
- then mmap to make exmap visible
- create interface
- `ioctl` with different opcodes

## Implementation structure (possibly outdated)
On module load: `exmap_init_module`.

- `exmap_acquire_ksyms`: get function pointers that are not exported by the kernel via kallsyms
  - in this case: tlb flush and vfs read
- create character device `/dev/exmap`
- set device permissions to a+rw to allow exmap use for non-root users
- set supported file operations `fops` (mmap/open/ioctl/..)

Now, an application can `open("/dev/exmap")` to create an exmap area.

- allocates memory for an `exmap_ctx` (management data structure) and zeroes it

Next (TODO order of these two steps) the user sets the exmap size (TODO suggested value based on thread count?) and `mmap`s it to make it visible in memory.

- this `mmap` call leads the linux kernel to create a VMA (TODO elaborate?)
- `exmap_mmap` is used both for the exmap itself, and for the interfaces used to control it
- the two variants are distinguished by their offset/position in memory

For configuration, a `struct exmap_ioctl_setup` is used:

- `fd`: (optional) backing file descriptor (e.g. SSD to read from, or -1 to disable)
- `max_interfaces`: maximum number of interfaces
- `buffer_size`: amount of memory reserved for the exmap

The `exmap_ioctl` function handles all `ioctl` calls depending on their opcode, in this case `EXMAP_IOCTL_SETUP`.

- copies the `exmap_ioctl_setup` from user memory
- sets (optional) backing fd, memory size, interface count and allocates memory for the interfaces
- allocates memory from the system for one bundle of free pages per interface. This bundle is a single page, whose memory can be filled with up to 512 addresses of free pages. These are allocated on demand, and not pre-allocated, as the latter method leads to a large performance drop.
- NOTE: currently the system `rlimit` for locked memory/pages is ignored

Now the user has to create at least one `exmap_user_interface` via `mmap`.

- `len = 4096, fd = dev_exmap_fd, offset = (interfaces_base + id<<12)` NOTE maybe there should be a wrapper for this

Via this interface and `ioctl`, the user can perform actions like:

- `exmap_alloc`
  - allocate pages from the system on demand, if possible
  - iterate over the list of iovecs and insert pages from the given interface into their respective PTEs
  - TODO elaborate: `walk_to_pmd` also creates the multi-layered paging structure
- `exmap_free`
  - unmap pages, which returns them to the interface's free bundle
  - perform a TLB shootdown with `flush_tlb_mm`

On module unload: `exmap_cleanup_module` deletes the chardev `/dev/exmap`.
