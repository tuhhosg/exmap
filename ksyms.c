#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/compiler_types.h>
#include <linux/rmap.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

/* Auxiliary function pointers here */

void (*flush_tlb_mm_range_ksym)(struct mm_struct *mm, unsigned long start,
								unsigned long end, unsigned int stride_shift,
								bool freed_tables);

ssize_t (*vfs_read_ksym)(struct file *file, char __user *buf, 
						 size_t count, loff_t *pos);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

int exmap_acquire_ksyms(void)
{
	kallsyms_lookup_name_t kallsyms_lookup_name;

	/*
	 * From kernel 5.7.0 onwards, kallsyms_lookup_name
	 * is no longer exported by default. This workaround
	 * uses kprobes to find the address of the function.
	 */
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	/* 
	 * Try to find all necessary symbols,
	 * return -1 if any lookup fails
	 */
	flush_tlb_mm_range_ksym = (void *)kallsyms_lookup_name("flush_tlb_mm_range");
	if(!flush_tlb_mm_range_ksym)
		return -1;


	vfs_read_ksym = (void *)kallsyms_lookup_name("vfs_read");
	if(!vfs_read_ksym)
		return -1;


	return 0;
}

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
						unsigned long end, unsigned int stride_shift,
						bool freed_tables)
{
	flush_tlb_mm_range_ksym(mm, start, end, stride_shift, freed_tables);
}

ssize_t vfs_read(struct file *file, char __user *buf, 
				 size_t count, loff_t *pos)
{
	return vfs_read_ksym(file, buf, count, pos);
}
