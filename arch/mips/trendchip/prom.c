#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/bootmem.h>
#include <linux/blkdev.h>

#include <asm/mipsmtregs.h>
#include <asm/addrspace.h>
#include <asm/bootinfo.h>
#include <asm/cpu.h>
#include <asm/time.h>
#include <asm/tc3162/tc3162.h>
#include <asm/traps.h>


extern int __imem, __dmem;

/* frankliao added 20101215 */
unsigned long flash_base;
EXPORT_SYMBOL(flash_base);
unsigned int (*ranand_read_byte)(unsigned long long) = NULL;
EXPORT_SYMBOL(ranand_read_byte);
unsigned int (*ranand_read_dword)(unsigned long long) = NULL;
EXPORT_SYMBOL(ranand_read_dword);

#ifdef CONFIG_MIPS_TC3262
unsigned char io_swap_noneed=0;
EXPORT_SYMBOL(io_swap_noneed);
#endif

static void tc3162_component_setup(void)
{
#if defined(CONFIG_CPU_TC3162) && (defined(CONFIG_TC3162_IMEM) || defined(CONFIG_TC3162_DMEM))
	unsigned int controlReg;
	unsigned long flags;
#endif
	/* setup bus timeout value */
	VPint(CR_AHB_AACS) = 0xffff;

	/* reset hwnat */
	if (isRT65168) {
		/* table reset */
		VPint(0xbfbe0024) = 0x0;
		VPint(0xbfbe0024) = 0xffff;
		
		/* hwnat swreset */
		VPint(0xbfbe0000) = (1<<1);
	}

#ifdef CONFIG_CPU_TC3162
#ifdef CONFIG_TC3162_IMEM
	/* setup imem start address */
	VPint(CR_IMEM) = CPHYSADDR(&__imem);

	/* clear internal imem */
	local_irq_save(flags);
	controlReg = read_c0_cctl();
	write_c0_cctl(controlReg & ~CCTL_IMEMOFF);
	write_c0_cctl(controlReg | CCTL_IMEMOFF);
	write_c0_cctl(controlReg);
	local_irq_restore(flags);

	/* refill internal imem */
	local_irq_save(flags);
	controlReg = read_c0_cctl();
	write_c0_cctl(controlReg & ~CCTL_IMEMFILL4);
	write_c0_cctl(controlReg | CCTL_IMEMFILL4);
	write_c0_cctl(controlReg);
	local_irq_restore(flags);
	
	printk("Enable IMEM addr=%x\n", CPHYSADDR(&__imem));
#endif

#ifdef CONFIG_TC3162_DMEM
	/* setup dmem start address */
	VPint(CR_DMEM) = CPHYSADDR(&__dmem);

	memcpy((void *) 0xa0001000, (void *) KSEG1ADDR(&__dmem), 0x800);

	/* clear internal dmem */
	local_irq_save(flags);
	controlReg = read_c0_cctl();
	write_c0_cctl(controlReg & ~CCTL_DMEMOFF);
	write_c0_cctl(controlReg | CCTL_DMEMOFF);
	write_c0_cctl(controlReg);
	local_irq_restore(flags);

	/* internal dmem on */
	local_irq_save(flags);
	controlReg = read_c0_cctl();
	write_c0_cctl(controlReg & ~CCTL_DMEMON);
	write_c0_cctl(controlReg | CCTL_DMEMON);
	write_c0_cctl(controlReg);
	local_irq_restore(flags);

	printk("Enable DMEM addr=%x\n", CPHYSADDR(&__dmem));

	memcpy((void *) KSEG1ADDR(&__dmem), (void *) 0xa0001000, 0x800);
#endif
#endif
}

/* frankliao added 20101215 */
void flash_init(void)
{

	if ((IS_NANDFLASH) && (isRT63165 || isRT63365 || isMT751020)) {
		flash_base = 0x0;
	} else {
#ifdef CONFIG_TCSUPPORT_ADDR_MAPPING
		if(isMT751020){
			flash_base = 0xbc000000;
			printk(KERN_INFO "%s: flash_base: 0x%08lx \n",__func__, flash_base);
		}
		else if (isTC3162U || isRT63260 || isRT65168 || isTC3182 || isRT63165 || isRT63365)
#else
		if (isTC3162U || isRT63260 || isRT65168 || isTC3182 || isRT63165 || isRT63365 || isMT751020)
#endif		
			flash_base = 0xb0000000;
		else
			flash_base = 0xbfc00000;
		printk(KERN_INFO "%s: flash_base: 0x%08lx \n",__func__, flash_base);
	}
}

const char *get_system_type(void)
{
#ifdef CONFIG_MIPS_TC3262
	if (isTC3182)
		return "TrendChip TC3182 SOC";
	else if (isRT65168)
		return "Ralink RT65168 SOC";
	else if (isRT63165){
		io_swap_noneed = 1;
		return "Ralink RT63165 SOC";
	} else if (isRT63368) {
		io_swap_noneed = 1;
#ifdef __BIG_ENDIAN
		return "Ralink RT63368 SOC";
#else
		return "Ralink RT6856 SOC";
#endif
	} else if (isRT63365) {
		io_swap_noneed = 1;
#ifdef CONFIG_TCSUPPORT_DYING_GASP
		//if(!isRT63368){
			//gpio 4 is share pin for rt63365.
			VPint(0xbfb00860) &= ~(1<<13);//disable port 4 led when use rt63365.
		//}
#endif		
		return "Ralink RT63365 SOC";
	}else if (isMT751020){
		io_swap_noneed = 1;
		return "Ralink MT751020 SOC";
	}else
		return "TrendChip TC3169 SOC";
#else
	if (isRT63260)
		return "Ralink RT63260 SOC";
	else if (isTC3162U)
		return "TrendChip TC3162U SOC";
	else if (isTC3162L5P5)
		return "TrendChip TC3162L5/P5 SOC";
	else if (isTC3162L4P4)
		return "TrendChip TC3162L4/P4 SOC";
	else if (isTC3162L3P3)
		return "TrendChip TC3162L2F/P2F";
	else if (isTC3162L2P2)
		return "TrendChip TC3162L2/P2";
	else 
		return "TrendChip TC3162";
#endif
}

extern struct plat_smp_ops msmtc_smp_ops;
#define VECTORSPACING 0x100	/* for EI/VI mode */


void __init mips_nmi_setup (void)
{
	void *base;
	extern char except_vec_nmi;
	#if 0
	base = cpu_has_veic ?
		(void *)(CAC_BASE + 0xa80) :
		(void *)(CAC_BASE + 0x380);
	#endif

	base = cpu_has_veic ?
		(void *)(ebase + 0x200 + VECTORSPACING*64) :
		(void *)(ebase + 0x380);
		
	printk("nmi base is 0x%08lx\n", (unsigned long)base);

	//Fill the NMI_Handler address in a register, which is a R/W register
	//start.S will read it, then jump to NMI_Handler address
	VPint(0xbfb00244) = (unsigned long)base;
	
	memcpy(base, &except_vec_nmi, 0x80);
	flush_icache_range((unsigned long)base, (unsigned long)base + 0x80);
}
#ifdef CONFIG_IMAGE_CMDLINE_HACK
extern char __image_cmdline[];
static void  __init prom_init_cmdline(void)
{
	char *p = __image_cmdline;
	int replace = 0;

	if (*p == '-') {
		replace = 1;
		p++;
	}

	if (*p == '\0')
		return;

	if (replace) {
		strlcpy(arcs_cmdline, p, sizeof(arcs_cmdline));
	} else {
		strlcat(arcs_cmdline, " ", sizeof(arcs_cmdline));
		strlcat(arcs_cmdline, p, sizeof(arcs_cmdline));
	}
}
#else
static void  __init prom_init_cmdline(void)
{
    return;
}
#endif
void __init prom_init(void)
{
	unsigned long memsize;
#ifndef CONFIG_MIPS_TC3262
	unsigned char samt;
#endif
	unsigned long col;
	unsigned long row;

	/* frankliao added 20101222 */
	flash_init();

    prom_init_cmdline();
#ifdef CONFIG_MIPS_TC3262
	if (isRT63165 || isRT63365 || isMT751020) {
		/* enable external sync */
		strcat(arcs_cmdline, " es=1");

#ifndef CONFIG_SMP
	{
		/* when kernel is UP, set ES=1. Otherwise, set in mips_mt_set_cpuoptions */
		unsigned int oconfig7 = read_c0_config7();
		unsigned int nconfig7 = oconfig7;

		nconfig7 |= (1 << 8);

		__asm__ __volatile("sync");
		write_c0_config7(nconfig7);
		ehb();
		printk("Config7: 0x%08x\n", read_c0_config7());
	}
#endif
	}

	if(isMT751020){
		memsize = 0x800000 * (1 << (((VPint(0xbfb0008c) >> 13) & 0x7) - 1));
		printk("memsize: %luMB\n", (memsize>>20));
	}
	else if (isRT63165 || isRT63365) {
		/* DDR */
		if (VPint(CR_AHB_HWCONF) & (1<<25)) {
			memsize = 0x800000 * (1 << (((VPint(CR_DMC_DDR_CFG1) >> 18) & 0x7) - 1));

		/* SDRAM */
		} else {
			unsigned long sdram_cfg1;
			
			/* calculate SDRAM size */
			sdram_cfg1 = VPint(0xbfb20004);
			row = 11 + ((sdram_cfg1>>16) & 0x3);
			col = 8 + ((sdram_cfg1>>20) & 0x3);
			/* 4 bands and 16 bit width */
			memsize = (1 << row) * (1 << col) * 4 * 2;
		}
	} else {
		memsize = 0x800000 * (1 << (((VPint(CR_DMC_CTL1) >> 18) & 0x7) - 1));
	}
#else
	/* calculate SDRAM size */
	samt = VPchar(CR_DMC_SAMT);
	row = 8 + (samt & 0x3);
	col = 11 + ((samt>>2) & 0x3);
	/* 4 bands and 16 bit width */
	memsize = (1 << row) * (1 << col) * 4 * 2;
#endif

	printk(KERN_INFO "%s prom init\n", get_system_type());

	tc3162_component_setup();

	add_memory_region(0 + 0x20000, memsize - 0x20000, BOOT_MEM_RAM);
	if (isMT751020) {
		board_nmi_handler_setup = mips_nmi_setup;
	}

	//mips_machgroup = MACH_GROUP_TRENDCHIP;
	//mips_machtype = MACH_TRENDCHIP_TC3162;

#ifdef CONFIG_MIPS_MT_SMP
	register_smp_ops(&vsmp_smp_ops);
#endif
#ifdef CONFIG_MIPS_MT_SMTC
	register_smp_ops(&msmtc_smp_ops);
#endif
}

void __init prom_free_prom_memory(void)
{
	/* We do not have any memory to free */
}

int prom_putchar(char data)
{
	while (!(LSR_INDICATOR & LSR_THRE))
		;
	VPchar(CR_UART_THR) = data; 
	return 1;
}
EXPORT_SYMBOL(prom_putchar);

char prom_getchar(void)
{
	while (!(LSR_INDICATOR & LSR_RECEIVED_DATA_READY))
		;
	return VPchar(CR_UART_RBR);
}

static char ppbuf[1024];

void
prom_write(const char *buf, unsigned int n)
{
	char ch;

	while (n != 0) {
		--n;
		if ((ch = *buf++) == '\n')
			prom_putchar('\r');
		prom_putchar(ch);
	}
}
EXPORT_SYMBOL(prom_write);

void
prom_printf(const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(ppbuf, sizeof(ppbuf), fmt, args);
	va_end(args);

	prom_write(ppbuf, i);
}
EXPORT_SYMBOL(prom_printf);

#ifdef CONFIG_KGDB
static unsigned long  uclk_65000[13]={
	357500, 	// uclk 5.5     Baud Rate 115200
	175500, 	// uclk 2.7     Baud Rate 57600
	119808, 	// uclk 1.8432  Baud Rate 38400
	89856,	// uclk	1.3824	Baud Rate 28800
	59904,	// uclk 0.9216	Baud Rate 19200
	44928,	// uclk 0.6912	Baud Rate 14400
	29952,	// uclk 0.4608	Baud Rate 9600
	14976,	// uclk 0.2304	Baud Rate 4800
	7488,	// uclk 0.1152	Baud Rate 2400 
	3744,	// uclk 0.0576	Baud Rate 1200
	1872,	// uclk 0.0288	Baud Rate 600
	936,		// uclk 0.0144	Baud Rate 300
	343		// uclk 0.00528	Baud Rate 110
};

static void hsuartInit(void)
{
	unsigned long	div_x,div_y;
	unsigned long	word;
	unsigned long   tmp;

	tmp = VPint(CR_GPIO_CTRL);
	tmp &= ~0x0fa30000;
	tmp |= 0x0fa30000;
	VPint(CR_GPIO_CTRL) = tmp; // set GPIO pin 13 & pin 12 are alternative outputs, GPIO pin 11 & pin 10 are alternative inputs
	tmp = VPint(CR_GPIO_ODRAIN);
	tmp &= ~0x00003000;
	tmp |= 0x00003000;
	VPint (CR_GPIO_ODRAIN) = tmp; // set GPIO output enable

// Set FIFO controo enable, reset RFIFO, TFIFO, 16550 mode, watermark=0x00 (1 byte)
	VPchar(CR_HSUART_FCR) = UART_FCR|UART_WATERMARK;

// Set modem control to 0
	VPchar(CR_HSUART_MCR) = UART_MCR;

// Disable IRDA, Disable Power Saving Mode, RTS , CTS flow control
	VPchar(CR_HSUART_MISCC) = UART_MISCC;

	/* access the bardrate divider */
	VPchar(CR_HSUART_LCR) = UART_BRD_ACCESS;

	div_y = UART_XYD_Y;
	div_x = (unsigned int)(uclk_65000[0]/SYS_HCLK)*2;
	word = (div_x<<16)|div_y;
	VPint(CR_HSUART_XYD) = word;

/* Set Baud Rate Divisor to 3*16		*/
	VPchar(CR_HSUART_BRDL) = UART_BRDL;
	VPchar(CR_HSUART_BRDH) = UART_BRDH;

/* Set DLAB = 0, clength = 8, stop =1, no parity check 	*/
	VPchar(CR_HSUART_LCR) = UART_LCR;

// Set interrupt Enable to, enable Tx, Rx and Line status
	VPchar(CR_HSUART_IER) = UART_IER;	
}

static int hsuartInitialized = 0;

int putDebugChar(char c)
{
	if (!hsuartInitialized) {
		hsuartInit();
		hsuartInitialized = 1;
	}

	while (!(VPchar(CR_HSUART_LSR) & LSR_THRE))
		;
	VPchar(CR_HSUART_THR) = c; 

	return 1;
}

char getDebugChar(void)
{
	if (!hsuartInitialized) {
		hsuartInit();
		hsuartInitialized = 1;
	}

	while (!(VPchar(CR_HSUART_LSR) & LSR_RECEIVED_DATA_READY))
		;
	return VPchar(CR_HSUART_RBR);
}
#endif
#if defined(CONFIG_TCSUPPORT_DYING_GASP) && (defined(CONFIG_MIPS_RT65168) || defined(CONFIG_MIPS_RT63365))
__IMEM
void dying_gasp_setup_mem_cpu(void){
#ifdef CONFIG_MIPS_RT65168	
		VPint(0xbfb20000) |= (1<<12); //set ddr to self refresh mode. 
		VPint(0xbfb000c0) &= ~((1<<5)|(1<<6)|(1<<7));//CPU divide to 32 and ram divide to 3
		VPint(0xbfb000c0) |= (1<<3)|(1<<4)|(1<<5)|(1<<7);
#endif
#ifdef CONFIG_MIPS_RT63365		
		VPint(0xbfb00040) |= (1<<0); // reset ddr device
		//do not kill CPU because we need do watchdog interrupt
		//kill CPU
		//VPint(0xbfb001c8) |= (1<<24); // bypass pll 2 700M 	
		//VPint(0xbfb001cc) |= (1<<24); // bypass pll 2 665M	
		//VPint(0xbfb001d0) |= (1<<24); // bypass pll 2 500
#endif
	if (cpu_wait)
		(*cpu_wait)();
}
EXPORT_SYMBOL(dying_gasp_setup_mem_cpu);
#endif
