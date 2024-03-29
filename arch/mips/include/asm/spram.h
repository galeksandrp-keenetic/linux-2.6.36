#ifndef _MIPS_SPRAM_H
#define _MIPS_SPRAM_H

#ifdef CONFIG_CPU_MIPSR2
extern __init void spram_config(void);
#else
static inline void spram_config(void) { };
#endif /* CONFIG_CPU_MIPSR2 */

#if defined(CONFIG_MIPS_TC3262) || defined(CONFIG_MIPS_TC3162)
extern int is_sram_addr(void *p);
extern void *alloc_sram(int n);
extern void free_sram(void *p, int n);
#endif

#endif /* _MIPS_SPRAM_H */
