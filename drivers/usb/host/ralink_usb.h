

#ifndef __RALINK_USB_H__

#include <asm/mach-ralink/rt_mmap.h>

#define SYSCFG1			(RALINK_SYSCTL_BASE + 0x14)
#define USB0_HOST_MODE		(1UL<<10)

#define RT2880_CLKCFG1_REG      (RALINK_SYSCTL_BASE + 0x30)

#define RT2880_RSTCTRL_REG      (RALINK_SYSCTL_BASE + 0x34)
#define RALINK_UHST_RST         (1<<22)
#define RALINK_UDEV_RST         (1<<25)

inline static void try_wake_up(void)
{
	u32 val;

	val = le32_to_cpu(*(volatile u_long *)(RT2880_CLKCFG1_REG));
#if defined (CONFIG_RALINK_RT3883) || defined (CONFIG_RALINK_RT3352) || defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7628)
	val = val | (RALINK_UPHY0_CLK_EN | RALINK_UPHY1_CLK_EN) ;
#elif defined (CONFIG_RALINK_RT5350)
	/* one port only */
	val = val | (RALINK_UPHY0_CLK_EN) ;
#else
#error	"no define platform"
#endif
	*(volatile u_long *)(RT2880_CLKCFG1_REG) = cpu_to_le32(val);
	udelay(10000);	// enable port0 & port1 Phy clock

	val = le32_to_cpu(*(volatile u_long *)(RT2880_RSTCTRL_REG));
	val = val & ~(RALINK_UHST_RST | RALINK_UDEV_RST);
	*(volatile u_long *)(RT2880_RSTCTRL_REG) = cpu_to_le32(val);
	udelay(10000);	// toggle reset bit 25 & 22 to 0
}

#if defined (CONFIG_RALINK_MT7620)
inline static void try_wake_up_20(void)
{
	u32 val;

	val = le32_to_cpu(*(volatile u_long *)(RT2880_CLKCFG1_REG));
	val = val | (RALINK_UPHY1_CLK_EN); // For MT7620 this bit sign is a RALINK_UPHY48M_CLK_EN
	*(volatile u_long *)(RT2880_CLKCFG1_REG) = cpu_to_le32(val);
	udelay(10000);	// enable port0 48M Phy clock

	val = le32_to_cpu(*(volatile u_long *)(RT2880_RSTCTRL_REG));
	val = val & ~(RALINK_UHST_RST | RALINK_UDEV_RST);
	*(volatile u_long *)(RT2880_RSTCTRL_REG) = cpu_to_le32(val);
	udelay(10000);	// toggle reset bit 25 & 22 to 0
}

inline static void try_wake_up_11(void)
{
	u32 val;

	val = le32_to_cpu(*(volatile u_long *)(RT2880_CLKCFG1_REG));
	val = val | (RALINK_UPHY0_CLK_EN) ;// For MT7620 this bit sign is a RALINK_UPHY12M_CLK_EN
	*(volatile u_long *)(RT2880_CLKCFG1_REG) = cpu_to_le32(val);
	udelay(10000);	// enable port0 12M Phy clock

	val = le32_to_cpu(*(volatile u_long *)(RT2880_RSTCTRL_REG));
	val = val & ~(RALINK_UHST_RST | RALINK_UDEV_RST);
	*(volatile u_long *)(RT2880_RSTCTRL_REG) = cpu_to_le32(val);
	udelay(10000);	// toggle reset bit 25 & 22 to 0
}
#endif

inline static void try_sleep(void)
{
	u32 val;

	val = le32_to_cpu(*(volatile u_long *)(RT2880_CLKCFG1_REG));
#if defined (CONFIG_RALINK_RT3883) || defined (CONFIG_RALINK_RT3352) || defined (CONFIG_RALINK_MT7620) || defined (CONFIG_RALINK_MT7628)
	val = val & ~(RALINK_UPHY0_CLK_EN | RALINK_UPHY1_CLK_EN);
#elif defined (CONFIG_RALINK_RT5350)
	val = val & ~(RALINK_UPHY0_CLK_EN);
#else
#error	"no define platform"
#endif
	*(volatile u_long *)(RT2880_CLKCFG1_REG) = cpu_to_le32(val);
	udelay(10000);  // disable port0 & port1 Phy clock

	val = le32_to_cpu(*(volatile u_long *)(RT2880_RSTCTRL_REG));
	val = val | (RALINK_UHST_RST | RALINK_UDEV_RST);
	*(volatile u_long *)(RT2880_RSTCTRL_REG) = cpu_to_le32(val);
	udelay(10000);  // toggle reset bit 25 & 22 to 1
}

#endif /* __RALINK_USB_H__ */
