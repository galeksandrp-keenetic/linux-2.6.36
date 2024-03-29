/*
 * highmem.h: virtual kernel memory mappings for high memory
 *
 * Used in CONFIG_HIGHMEM systems for memory pages which
 * are not addressable by direct kernel virtual addresses.
 *
 * Copyright (C) 1999 Gerhard Wichert, Siemens AG
 *		      Gerhard.Wichert@pdb.siemens.de
 *
 *
 * Redesigned the x86 32-bit VM architecture to deal with
 * up to 16 Terabyte physical memory. With current x86 CPUs
 * we now support up to 64 Gigabytes physical RAM.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */
#ifndef _ASM_HIGHMEM_H
#define _ASM_HIGHMEM_H

#ifdef __KERNEL__

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/uaccess.h>
#include <asm/kmap_types.h>

/* undef for production */
#define HIGHMEM_DEBUG 1

/* declarations for highmem.c */
extern unsigned long highstart_pfn, highend_pfn;

extern pte_t *pkmap_page_table;

/*
 * Right now we initialize only a single pte table. It can be extended
 * easily, subsequent pte tables have to be allocated in one physical
 * chunk of RAM.
 */
#define LAST_PKMAP 1024
#define LAST_PKMAP_MASK (LAST_PKMAP-1)
#define PKMAP_NR(virt)  ((virt-PKMAP_BASE) >> PAGE_SHIFT)
#define PKMAP_ADDR(nr)  (PKMAP_BASE + ((nr) << PAGE_SHIFT))

#ifdef CONFIG_RALINK_SOC
#define ARCH_PKMAP_COLORING             1
#define     set_pkmap_color(pg,cl)      { cl = ((unsigned long)lowmem_page_address(pg) >> \
					    PAGE_SHIFT) & (FIX_N_COLOURS - 1); }
#define     get_last_pkmap_nr(p,cl)     (last_pkmap_nr_arr[cl])
#define     get_next_pkmap_nr(p,cl)     (last_pkmap_nr_arr[cl] = \
					    ((p + FIX_N_COLOURS) & LAST_PKMAP_MASK))
#define     is_no_more_pkmaps(p,cl)     (p < FIX_N_COLOURS)
#define     get_next_pkmap_counter(c,cl)    (c - FIX_N_COLOURS)
extern unsigned int     last_pkmap_nr_arr[];
#endif

extern void * kmap_high(struct page *page);
extern void kunmap_high(struct page *page);

extern void *__kmap(struct page *page);
extern void __kunmap(struct page *page);
extern void *__kmap_atomic(struct page *page, enum km_type type);
extern void __kunmap_atomic_notypecheck(void *kvaddr, enum km_type type);
extern void *kmap_atomic_pfn(unsigned long pfn, enum km_type type);
extern struct page *__kmap_atomic_to_page(void *ptr);

#define kmap			__kmap
#define kunmap			__kunmap
#define kmap_atomic		__kmap_atomic
#define kunmap_atomic_notypecheck		__kunmap_atomic_notypecheck
#define kmap_atomic_to_page	__kmap_atomic_to_page

#define flush_cache_kmaps()	flush_cache_all()

extern void kmap_init(void);

#define kmap_prot PAGE_KERNEL

#endif /* __KERNEL__ */

#endif /* _ASM_HIGHMEM_H */
