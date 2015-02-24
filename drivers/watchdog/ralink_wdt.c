#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <asm/uaccess.h>
#include <asm/mach-ralink/rt_mmap.h>
#include <asm/mach-ralink/surfboardint.h>

#if defined (CONFIG_MIPS_RT63365)
#define TMR1CTL		(RALINK_TIMER_BASE + 0x0)  /* WDG Timer Control */
#define TMR1LOAD	(RALINK_TIMER_BASE + 0x2C) /* WDG Timer Load Value Register */
#define TMR1VAL		(RALINK_TIMER_BASE + 0x30) /* WDG Timer Current Value Register */
#define RLDWDOG		(RALINK_TIMER_BASE + 0x38) /* Reload Watchdog */
#elif defined (CONFIG_RALINK_MT7621) || defined (CONFIG_RALINK_MT7628)
#define TMRSTAT     (RALINK_TIMER_BASE)  /* Timer Status Register */
#define TMR0LOAD	(RALINK_TIMER_BASE + 0x14)  /* Timer0 Load Value */
#define TMR0VAL		(RALINK_TIMER_BASE + 0x18)  /* Timer0 Counter Value */
#define TMR0CTL		(RALINK_TIMER_BASE + 0x10)  /* Timer0 Control */
#define TMR1LOAD	(RALINK_TIMER_BASE + 0x24)  /* Timer1 Load Value */
#define TMR1VAL		(RALINK_TIMER_BASE + 0x28)  /* Timer1 Counter Value */
#define TMR1CTL		(RALINK_TIMER_BASE + 0x20)  /* Timer1 Control */
#define TMR2LOAD	(RALINK_TIMER_BASE + 0x34)  /* Timer2 Load Value */
#define TMR2VAL		(RALINK_TIMER_BASE + 0x38)  /* Timer2 Counter Value */
#define TMR2CTL		(RALINK_TIMER_BASE + 0x30)  /* Timer2 Control */
#else
#define TMR0LOAD	(RALINK_TIMER_BASE + 0x10)  /* Timer0 Load Value */
#define TMR0VAL		(RALINK_TIMER_BASE + 0x14)  /* Timer0 Counter Value */
#define TMR0CTL		(RALINK_TIMER_BASE + 0x18)  /* Timer0 Control */
#define TMR1LOAD	(RALINK_TIMER_BASE + 0x20)  /* Timer1 Load Value */
#define TMR1VAL		(RALINK_TIMER_BASE + 0x24)  /* Timer1 Counter Value */
#define TMR1CTL		(RALINK_TIMER_BASE + 0x28)  /* Timer1 Control */
#endif

#define PHYS_TO_K1(physaddr) KSEG1ADDR(physaddr)
#define sysRegRead(phys) (*(volatile unsigned int *)PHYS_TO_K1(phys))
#define sysRegWrite(phys, val)  ((*(volatile unsigned int *)PHYS_TO_K1(phys)) = (val))

#define RALINK_WDG_TIMER 10


static struct timer_list wdg_timer;
static int wdg_load_value;

static void ralink_wdt_enable(unsigned int enable)
{
	unsigned int result;
	
	result = sysRegRead(TMR1CTL);
	
	if (enable){
#if defined (CONFIG_MIPS_RT63365)
	     result |= (1<<25) | (1<<5);
#else
             result |= (1<<7);
#endif
	}
	else{
#if defined (CONFIG_MIPS_RT63365)
	     result &= ~((1<<25)|(1<<5));
#else
	     result &= ~(1<<7);
#endif

	}

	sysRegWrite(TMR1CTL, result);
}
void ralink_wdt_refresh(unsigned long unused)
{
#if defined (CONFIG_MIPS_RT63365)
	sysRegWrite(RLDWDOG, 1);
#elif defined (CONFIG_RALINK_MT7621) || defined (CONFIG_RALINK_MT7628)
	sysRegWrite(TMRSTAT, (1 << 9)); //WDTRST
#else
	sysRegWrite(TMR1LOAD, wdg_load_value);
#endif

	wdg_timer.expires = jiffies + HZ * 4;
	add_timer(&wdg_timer);
}
#if defined (CONFIG_RALINK_MT7621) || defined (CONFIG_RALINK_MT7628)
void set_wdg_timer_clock_prescale(int prescale)
{
	 unsigned int result;

	 result =sysRegRead(TMR1CTL);
	 result &= 0x0000FFFF;
	 result |= (prescale << 16); //unit = 1u
	 sysRegWrite(TMR1CTL, result);
}

void set_wdg_timer_mode(unsigned int mode)
{
}
#else
void set_wdg_timer_clock_prescale(unsigned int timer, unsigned int prescale)
{
	unsigned int result;

	result=sysRegRead(timer);
	result &= ~0xF;
	result=result | (prescale&0xF);
	sysRegWrite(timer,result);

}

void set_wdg_timer_mode(unsigned int mode)
{
	unsigned int result;

	result=sysRegRead(TMR1CTL);
	result &= ~(0x3<<4);
	result=result | (mode << 4);
	sysRegWrite(TMR1CTL,result);

}
#endif

int __init ralink_wdt_init(void)
{
	wdg_timer.function = ralink_wdt_refresh;
	wdg_timer.data = 0;
	init_timer(&wdg_timer);

	set_wdg_timer_mode(3); // Watchdog mode

#if defined (CONFIG_RALINK_RT2880) || defined (CONFIG_RALINK_RT2883) || \
	defined (CONFIG_RALINK_RT3052) || defined (CONFIG_RALINK_RT3883)
	/* 
	 * System Clock = CPU Clock/2
	 * For user easy configuration, We assume the unit of watch dog timer is 1s, 
	 * so we need to calculate the TMR1LOAD value.
	 * Unit= 1/(SysClk/65536), 1 Sec = (SysClk)/65536 
	 */
	set_wdg_timer_clock_prescale(TMR1CTL,15);
	wdg_load_value =  RALINK_WDG_TIMER * (get_surfboard_sysclk()/65536);
#elif defined (CONFIG_MIPS_RT63365)
	int hwconf = sysRegRead(RALINK_SYSCTL_BASE + 0x8c);
	if ((hwconf >> 24) & 0x3 == 0) { //SDR
		wdg_load_value =  RALINK_WDG_TIMER * (140 * 1000 * 1000 / 2);
	} else {
		if (hwconf >> 26 & 0x1 == 0) {
			wdg_load_value =  RALINK_WDG_TIMER * (233 * 1000 * 1000 / 2);
		} else {
			wdg_load_value =  RALINK_WDG_TIMER * (175 * 1000 * 1000 / 2);
		}
	}
	sysRegWrite(TMR1LOAD, wdg_load_value);
#elif defined (CONFIG_RALINK_MT7621) || defined (CONFIG_RALINK_MT7628)
	set_wdg_timer_clock_prescale(1000); //1ms
	wdg_load_value = RALINK_WDG_TIMER * 1000;
	sysRegWrite(TMR1LOAD, wdg_load_value);
#else
	set_wdg_timer_clock_prescale(TMR1CTL,15);
	wdg_load_value =  RALINK_WDG_TIMER * (40000000/65536); //fixed at 40Mhz
#endif

	ralink_wdt_refresh(wdg_load_value);
	ralink_wdt_enable(1);
	printk(KERN_INFO "Ralink WDG timer loaded\n");
	return 0;
}

void __exit ralink_wdt_exit(void)
{
	printk(KERN_INFO "Ralink WDG timer unloaded\n");

	ralink_wdt_enable(0);
	del_timer_sync(&wdg_timer);
}
module_init(ralink_wdt_init);
module_exit(ralink_wdt_exit);
