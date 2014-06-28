/**************************************************************************
 *
 *  BRIEF MODULE DESCRIPTION
 *     PCI init for Ralink and Trendchip RT6336x/RT685x solution
 *
 *  Copyright 2007 Ralink Inc. (bruce_chang@ralinktech.com.tw)
 *  Copyright 2012 NDM Systems. (mcmcc@mail.ru)
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 *
 **************************************************************************
 */

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <asm/pci.h>
#include <asm/io.h>
#include <asm/mach-ralink/eureka_ep430.h>
#include <linux/init.h>
#include <linux/mod_devicetable.h>
#include <linux/delay.h>
#include <asm/mach-ralink/surfboardint.h>

#ifdef CONFIG_PCI

#undef DEBUG
#undef DBG

/* #define DEBUG */

#ifdef DEBUG
#define DBG(f, a...)	printk(f, ## a )
#else
#define DBG(f, a...)	do {} while (0)
#endif

#ifdef __BIG_ENDIAN
#define OP_WRITE(ofs, data)	\
		*(volatile u32 *)(RALINK_PCI_BASE+(ofs)) = cpu_to_be32(data)
#define OP_READ(ofs, data)	\
		*(data) = be32_to_cpu(*(volatile u32 *)(RALINK_PCI_BASE+(ofs)))
#else
#define OP_WRITE(ofs, data)	\
		*(volatile u32 *)(RALINK_PCI_BASE+(ofs)) = cpu_to_le32(data)
#define OP_READ(ofs, data)	\
		*(data) = le32_to_cpu(*(volatile u32 *)(RALINK_PCI_BASE+(ofs)))
#endif

/*
 * These functions and structures provide the BIOS scan and mapping of the PCI
 * devices.
 */

#define RALINK_PCI_MM_MAP_BASE					0x20000000
#define RALINK_PCI_IO_MAP_BASE					0x1f600000
#define MEMORY_BASE							0
#define PCI_ACCESS_READ							0
#define PCI_ACCESS_WRITE						1

/*
 * pcie_disable = 0 mean there is a card on this slot
 * pcie_disable = 1 mean there is no card on this slot
 */

int pcie0_disable = 0;
int pcie1_disable = 0;

void __inline__ read_config(unsigned long bus, unsigned long dev, unsigned long func,
                            unsigned long reg, unsigned long *val);
void __inline__ write_config(unsigned long bus, unsigned long dev, unsigned long func,
                             unsigned long reg, unsigned long val);

static int config_access(unsigned char access_type, struct pci_bus *bus,
                         unsigned int devfn, unsigned char where,
                         u32 * data)
{
	unsigned int slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);
	uint32_t address_reg, data_reg;
	unsigned int address;

	address_reg = RALINK_PCI_CONFIG_ADDR;
	data_reg = RALINK_PCI_CONFIG_DATA_VIRTUAL_REG;

	/* Setup address */
	address = (bus->number << 24) | (slot << 19) | (func << 16) | (where & 0xfc);
	/* start the configuration cycle */
	OP_WRITE(address_reg, address);

	if (access_type == PCI_ACCESS_WRITE) {
		OP_WRITE(data_reg, *data);
	} else {
		OP_READ(data_reg, data);
	}

	return 0;
}

static int read_config_byte(struct pci_bus *bus, unsigned int devfn,
                            int where, u32 * val)
{
	u32 data;
	int ret;

	ret = config_access(PCI_ACCESS_READ, bus, devfn, (unsigned char)where, &data);
	*val = (data >> ((where & 3) << 3)) & 0xff;
	return ret;
}

static int read_config_word(struct pci_bus *bus, unsigned int devfn,
                            int where, u32 * val)
{
	u32 data;
	int ret;

	ret = config_access(PCI_ACCESS_READ, bus, devfn, (unsigned char)where, &data);
	*val = (data >> ((where & 3) << 3)) & 0xffff;
	return ret;
}

static int read_config_dword(struct pci_bus *bus, unsigned int devfn,
                             int where, u32 * val)
{
	return config_access(PCI_ACCESS_READ, bus, devfn, (unsigned char)where, val);
}

static int write_config_byte(struct pci_bus *bus, unsigned int devfn, int where,
                             u32 val)
{
	u32 data = 0;

	if (config_access(PCI_ACCESS_READ, bus, devfn, where, &data))
		return -1;

	data = (data & ~(0xff << ((where & 3) << 3))) | (val << ((where & 3) << 3));

	if (config_access(PCI_ACCESS_WRITE, bus, devfn, (unsigned char)where, &data))
		return -1;

	return PCIBIOS_SUCCESSFUL;
}

static int write_config_word(struct pci_bus *bus, unsigned int devfn, int where,
                             u32 val)
{
	u32 data = 0;

	if (config_access(PCI_ACCESS_READ, bus, devfn, where, &data))
		return -1;

	data = (data & ~(0xffff << ((where & 3) << 3))) | (val << ((where & 3) << 3));

	if (config_access(PCI_ACCESS_WRITE, bus, devfn, where, &data))
		return -1;

	return PCIBIOS_SUCCESSFUL;
}

static int write_config_dword(struct pci_bus *bus, unsigned int devfn, int where,
                              u32 val)
{
	if (config_access(PCI_ACCESS_WRITE, bus, devfn, where, &val))
		return -1;

	return PCIBIOS_SUCCESSFUL;
}

static int pci_config_read(struct pci_bus *bus, unsigned int devfn,
                           int where, int size, u32 * val)
{
	switch (size) {
		case 1:
			return read_config_byte(bus, devfn, where, val);
		case 2:
			return read_config_word(bus, devfn, where, val);
		default:
			return read_config_dword(bus, devfn, where, val);
	}
}

static int pci_config_write(struct pci_bus *bus, unsigned int devfn,
                            int where, int size, u32 val)
{
	switch (size) {
		case 1:
			return write_config_byte(bus, devfn, where, val);
		case 2:
			return write_config_word(bus, devfn, where, val);
		default:
			return write_config_dword(bus, devfn, where, val);
	}
}

/*
 *  General-purpose PCI functions.
 */

struct pci_ops rt2880_pci_ops = {
	.read =  pci_config_read,
	.write = pci_config_write,
};

static struct resource rt2880_res_pci_mem = {
	.name = "PCIe Memory space",
	.start = RALINK_PCI_MM_MAP_BASE,
	.end = (u32)((RALINK_PCI_MM_MAP_BASE + (unsigned char *)0x0fffffff)),
	.flags = IORESOURCE_MEM,
};

static struct resource rt2880_res_pci_io = {
	.name = "PCIe I/O space",
	.start = RALINK_PCI_IO_MAP_BASE,
	.end = (u32)((RALINK_PCI_IO_MAP_BASE + (unsigned char *)0x0ffff)),
	.flags = IORESOURCE_IO,
};

struct pci_controller rt2880_controller = {
	.pci_ops = &rt2880_pci_ops,
	.mem_resource = &rt2880_res_pci_mem,
	.io_resource = &rt2880_res_pci_io,
};

void __inline__ read_config(unsigned long bus, unsigned long dev, unsigned long func,
                            unsigned long reg, unsigned long *val)
{
	unsigned long address_reg, data_reg, address;

	address_reg = RALINK_PCI_CONFIG_ADDR;
	data_reg = RALINK_PCI_CONFIG_DATA_VIRTUAL_REG;

	/* set addr */
	address = (bus << 24) | (dev << 19) | (func << 16) | (reg & 0xfc);

	/* start the configuration cycle */
	OP_WRITE(address_reg, address);
	/* read the data */
	OP_READ(data_reg, val);
	return;
}

void __inline__ write_config(unsigned long bus, unsigned long dev, unsigned long func,
                             unsigned long reg, unsigned long val)
{
	unsigned long address_reg, data_reg, address;

	address_reg = RALINK_PCI_CONFIG_ADDR;
	data_reg = RALINK_PCI_CONFIG_DATA_VIRTUAL_REG;

	/* set addr */
	address = (bus << 24) | (dev << 19) | (func << 16) | (reg & 0xfc);

	/* start the configuration cycle */
	OP_WRITE(address_reg, address);
	/* read the data */
	OP_WRITE(data_reg, val);
	return;
}

#if 0
int __init pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	if(slot == 0)
		return RALINK_INT_PCIE0;

	if(slot == 1)
		return RALINK_INT_PCIE1;

	return (dev->irq);
}

#else

int __init pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	u16 cmd;
	u32 val;
	const struct resource *res;
	int i;
	int irq = -1;

	DBG("** bus = %x, slot = 0x%x\n", dev->bus->number, slot);

	if((dev->bus->number == 0) && (slot == 0)) {
		RALINK_PCI0_BAR0SETUP_ADDR = 0xFFFF0001;
		write_config(0, 0, 0, PCI_BASE_ADDRESS_0, MEMORY_BASE);
		read_config(0, 0, 0, PCI_BASE_ADDRESS_0, (unsigned long *)&val);
		DBG("BAR0 at slot 0 = %x\n", val);
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
	} else if((dev->bus->number == 0) && (slot == 0x1)) {
		RALINK_PCI1_BAR0SETUP_ADDR = 0xFFFF0001;
		write_config(0, 1, 0, PCI_BASE_ADDRESS_0, MEMORY_BASE);
		read_config(0, 1, 0, PCI_BASE_ADDRESS_0, (unsigned long *)&val);
		DBG("BAR0 at slot 1 = %x\n", val);
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
	} else if((dev->bus->number == 1) && (slot == 0x0)) {
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
		if(pcie0_disable ==1 && pcie1_disable ==0) {
			irq = RALINK_INT_PCIE1;
		} else {
			irq = RALINK_INT_PCIE0;
		}
	} else if((dev->bus->number == 1) && (slot == 0x1)) {
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
		irq = RALINK_INT_PCIE1;
	} else if((dev->bus->number == 2) && (slot == 0x0)) {
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
		irq = RALINK_INT_PCIE1;
	} else if((dev->bus->number == 2) && (slot == 0x1)) {
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
		irq = RALINK_INT_PCIE1;
	} else {
		DBG("bus = 0x%x, slot = 0x%x\n", dev->bus->number, slot);
		return 0;
	}

	for(i = 0; i < 6; i++) {
		res = &dev->resource[i];
		DBG("res[%d]->start = 0x%08x\n", i, res->start);
		DBG("res[%d]->end = 0x%08x\n", i, res->end);
	}

	pci_write_config_byte((struct pci_dev*)dev, PCI_CACHE_LINE_SIZE, 0x14); /* configure cache line size 0x14 */
	pci_write_config_byte((struct pci_dev*)dev, PCI_LATENCY_TIMER, 0xFF);   /* configure latency timer 0x10 */
	pci_read_config_word((struct pci_dev*)dev, PCI_COMMAND, &cmd);

	/* FIXME */
	cmd = cmd | PCI_COMMAND_MASTER | PCI_COMMAND_IO | PCI_COMMAND_MEMORY;

	pci_write_config_word((struct pci_dev*)dev, PCI_COMMAND, cmd);
	pci_write_config_byte((struct pci_dev*)dev, PCI_INTERRUPT_LINE, irq);

	return irq;
}
#endif

static __init int rt6xxxx_pci_init(void)
{
	unsigned long val = 0;

	printk(KERN_INFO "Start PCIe register access for RT685x/RT6336x\n");
#ifndef CONFIG_PCIE_CONCURENNCY
	/* PCI Control Register: Port1(bit22) disable */
	*((unsigned long *)(0xbfb00088)) &= ~(1<<22);
	mdelay(1);
	/* assert PCIe RC1 reset signal */
	*((unsigned long *)(0xbfb00834)) |= (1<<27);
	/* disable reference clock of dev1 */
	*((unsigned long *)(0xbfb00090)) &= ~(1<<3);
#endif

	/* PCIe Configuration and Status Register:PCIeRST */
	RALINK_PCI_PCICFG_ADDR &= ~(1<<1);

	mdelay(500);

	DBG("RT6xxxx PCIe RC mode\n");
	if((RALINK_PCI0_STATUS & 0x1) == 0)
	{
		/* assert PCIe RC0 reset signal */
		*((unsigned long *)(0xbfb00088)) &= ~(1<<23);
		DBG("PCIE0 no card, disable it\n");
		pcie0_disable = 1;
	}
	if((RALINK_PCI1_STATUS & 0x1) == 0)
	{
		/* PCI Control Register: Port1(bit22) disable */
		*((unsigned long *)(0xbfb00088)) &= ~(1<<22);
		mdelay(1);
		/* assert PCIe RC1 reset signal */
		*((unsigned long *)(0xbfb00834)) |= (1<<27);
		mdelay(1);
		/* disable reference clock of dev1 */
		*((unsigned long *)(0xbfb00090)) &= ~(1<<3);
		DBG("PCIE1 no card, disable it(RST&CLK)\n");
		pcie1_disable = 1;
	} else {
		if(pcie0_disable == 1) {
			/* pcie0 no card, pcie1 has card */
			RALINK_PCI_PCICFG_ADDR &= ~(0xff<<16);
			RALINK_PCI_PCICFG_ADDR |= 1<<16;
			DBG("*** RALINK_PCI_PCICFG_ADDR = 0x%08x\n", RALINK_PCI_PCICFG_ADDR);
		}
	}

	RALINK_PCI_MEMBASE = 0xffffffff;
	RALINK_PCI_IOBASE = RALINK_PCI_IO_MAP_BASE;

	/* PCIe0 */
	RALINK_PCI0_BAR0SETUP_ADDR = 0xFFFF0001;
	RALINK_PCI0_IMBASEBAR0_ADDR = MEMORY_BASE;
	RALINK_PCI0_ID = 0x08021814;
	RALINK_PCI0_CLASS = 0x06040001;
	RALINK_PCI0_SUBID = 0x28801814;
	/* PCIe1 */
	RALINK_PCI1_BAR0SETUP_ADDR = 0xFFFF0001;
	RALINK_PCI1_IMBASEBAR0_ADDR = MEMORY_BASE;
	RALINK_PCI1_ID = 0x08021814;
	RALINK_PCI1_CLASS = 0x06040001;
	RALINK_PCI1_SUBID = 0x28801814;

	RALINK_PCI_PCIMSK_ADDR |= (1<<20); /* enable pcie0 interrupt */
	RALINK_PCI_PCIMSK_ADDR |= (1<<21); /* enable pcie1 interrupt */

	/* PCIe0 */
	if(pcie0_disable == 0 || pcie1_disable == 0) {
		read_config(0, 0, 0, 0x4, &val);
		write_config(0, 0, 0, 0x4, val|0x7);
	}
	/* PCIe1 */
	if(pcie0_disable == 0 && pcie1_disable == 0) {
		read_config(0, 1, 0, 0x4, &val);
		write_config(0, 1, 0, 0x4, val|0x7);
	}

	ioport_resource.end = 0x1fffffff;
	iomem_resource.end = 0xffffffff;

	register_pci_controller(&rt2880_controller);
	return 0;

}
arch_initcall(rt6xxxx_pci_init);

void ahbErrChk(void)
{
	return;
}
EXPORT_SYMBOL(ahbErrChk);

int pcieRegInitConfig(void)
{
	return 0;
}
EXPORT_SYMBOL(pcieRegInitConfig);

void pcieReset(void)
{
	return;
}
EXPORT_SYMBOL(pcieReset);

void setahbstat(int val)
{
	return;
}
EXPORT_SYMBOL(setahbstat);

/* Do platform specific device initialization at pci_enable_device() time */
int pcibios_plat_dev_init(struct pci_dev *dev)
{
	return 0;
}

struct pci_fixup pcibios_fixups[] = {
	{ 0 }
};

#endif /* CONFIG_PCI */
