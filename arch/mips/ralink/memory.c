#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/bootmem.h>

#include <asm/bootinfo.h>
#include <asm/addrspace.h>

#define MIN_SDRAM_SIZE  (16*1024*1024)				/* Minimum SDRAM size */
#if defined (CONFIG_RALINK_RT2880) || \
    defined (CONFIG_RALINK_RT3352) || \
    defined (CONFIG_RALINK_RT3052) || \
    defined (CONFIG_RALINK_RT5350)
#define MAX_SDRAM_SIZE  (64*1024*1024)
#define TEST_OFFSET	63
#elif 	defined (CONFIG_RALINK_RT2883) || \
		defined (CONFIG_RALINK_RT3883)
#define MAX_SDRAM_SIZE  (128*1024*1024)	
#define TEST_OFFSET	127
#elif 	defined (CONFIG_RALINK_MT7620) || \
		defined (CONFIG_RALINK_MT7621)
#define MAX_SDRAM_SIZE  (256*1024*1024)
#define TEST_OFFSET	255
#else
#define MAX_SDRAM_SIZE  (64*1024*1024)
#define TEST_OFFSET	63
#endif

static spinlock_t rtlmem_lock = SPIN_LOCK_UNLOCKED;

void __init prom_meminit(void)
{
	unsigned long mem, memsize, reg_mem, mempos, memmeg;
	unsigned long before, offset;
	unsigned long flags;
	unsigned short save_dword;

	spin_lock_irqsave(&rtlmem_lock, flags);

	//Maximum RAM for autodetect
	reg_mem = MAX_SDRAM_SIZE >> 20;

	//First PASS RAM capacity
	for(memmeg=8;memmeg<reg_mem;memmeg+=8){
		mempos = 0xa0000000L + memmeg * 0x100000;
		save_dword = *(volatile unsigned short *)mempos;

		*(volatile unsigned short *)mempos = (unsigned short)0xABCD;
		if (*(volatile unsigned short *)mempos != (unsigned short)0xABCD){
			*(volatile unsigned short *)mempos = save_dword;
			break;
		}

		*(volatile unsigned short *)mempos = (unsigned short)0xDCBA;
		if (*(volatile unsigned short *)mempos != (unsigned short)0xDCBA){
			*(volatile unsigned short *)mempos = save_dword;
			break;
		}
		*(volatile unsigned short *)mempos = save_dword;
	}

		//Second PASS Test to be sure in RAM capacity
		before = ((unsigned long) &prom_init) & (TEST_OFFSET << 20);
		offset = ((unsigned long) &prom_init) - before;

		for (mem = before + (1 << 20); mem < (reg_mem << 20); mem += (1 << 20))
			if (*(unsigned long *)(offset + mem) == *(unsigned long *)(prom_init))
			{
				mem -= before;
				break;
			}

	//Calculate ram size	
	memsize = memmeg << 20;

	//Select smallest size from passes...
	if(mem < memsize){
		memsize = mem;
	}

	//This correct detect ram for some boards..
	if(memsize > MAX_SDRAM_SIZE){
		memsize = MAX_SDRAM_SIZE;
	}

	if(memsize < MIN_SDRAM_SIZE){
		memsize = MIN_SDRAM_SIZE;
	}

	spin_unlock_irqrestore(&rtlmem_lock,flags);
	
	printk(KERN_INFO "%ldM RAM Detected!\n",(memsize/1024)/1024);
	/* Set ram size */
	add_memory_region(0x00000000, memsize, BOOT_MEM_RAM);
}

void __init prom_free_prom_memory(void)
{
}
