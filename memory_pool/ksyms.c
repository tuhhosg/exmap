#include <linux/kallsyms.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

/* Auxiliary function pointers here */
struct page* (*alloc_contig_pages_ksym)(unsigned long nr_pages, gfp_t gfp_mask,
										int nid, nodemask_t *nodemask);


typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

int acquire_ksyms(void)
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

	alloc_contig_pages_ksym = (void *)kallsyms_lookup_name("alloc_contig_pages");
	if(!alloc_contig_pages_ksym)
		return -1;

	return 0;
}
struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
								int nid, nodemask_t *nodemask) {
	return alloc_contig_pages_ksym(nr_pages, gfp_mask, nid, nodemask);
}
