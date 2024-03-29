#ifndef __SPIC_H__
#define __SPIC_H__

#include <rt_mmap.h>
#define RT2880_RSTCTRL_REG		(RALINK_SYSCTL_BASE+0x34)

#define RSTCTRL_SPI_RESET		RALINK_SPI_RST

#define RT2880_SPISTAT_REG		(RALINK_SPI_BASE+0x00)
#define RT2880_SPICFG_REG		(RALINK_SPI_BASE+0x10)
#define RT2880_SPICTL_REG		(RALINK_SPI_BASE+0x14)
#define RT2880_SPIDATA_REG		(RALINK_SPI_BASE+0x20)

#define RT2880_SPIUSER_REG		(RALINK_SPI_BASE+0x2C)
#define RT2880_SPIADDR_REG		(RALINK_SPI_BASE+0x24)
#define RT2880_SPIMODE_REG		(RALINK_SPI_BASE+0x3c)
#define RT2880_SPIBS_REG		(RALINK_SPI_BASE+0x28)
#define RT2880_SPITXFIFO_REG	(RALINK_SPI_BASE+0x30)
#define RT2880_SPIRXFIFO_REG	(RALINK_SPI_BASE+0x34)
#define RT2880_SPIFIFOSTAT_REG	(RALINK_SPI_BASE+0x38)


#define RT2880_SPI0_CTL_REG		RT2880_SPICTL_REG
#define RT2880_SPI1_CTL_REG		(RALINK_SPI_BASE+0x54)
#define RT2880_SPI_DMA			(RALINK_SPI_BASE+ 0x80)
#define RT2880_SPI_ARB_REG		(RALINK_SPI_BASE+0xf0)

/* SPICFG register bit field */
#define SPICFG_LSBFIRST				(0<<8)
#define SPICFG_MSBFIRST				(1<<8)

#define SPICFG_RXCLKEDGE_FALLING	(1<<5)		/* rx on the falling edge of the SPICLK signal */
#define SPICFG_TXCLKEDGE_FALLING	(1<<4)		/* tx on the falling edge of the SPICLK signal */

#define SPICFG_SPICLK_DIV2			(0<<0)		/* system clock rat / 2  */
#define SPICFG_SPICLK_DIV4			(1<<0)		/* system clock rat / 4  */
#define SPICFG_SPICLK_DIV8			(2<<0)		/* system clock rat / 8  */
#define SPICFG_SPICLK_DIV16			(3<<0)		/* system clock rat / 16  */
#define SPICFG_SPICLK_DIV32			(4<<0)		/* system clock rat / 32  */
#define SPICFG_SPICLK_DIV64			(5<<0)		/* system clock rat / 64  */
#define SPICFG_SPICLK_DIV128		(6<<0)		/* system clock rat / 128 */

#define SPICFG_SPICLKPOL		(1<<6)		/* spi clk*/

#define SPICFG_ADDRMODE			(1 << 12)
#define SPICFG_RXENVDIS			(1<<11)
#define SPICFG_RXCAP			(1<<10)
#define SPICFG_SPIENMODE		(1<<9)

/* SPICTL register bit field */
#define SPICTL_HIZSDO				(1<<3)
#define SPICTL_STARTWR				(1<<2)
#define SPICTL_STARTRD				(1<<1)
#define SPICTL_SPIENA_LOW			(0<<0)		/* #cs low active */
#define SPICTL_SPIENA_HIGH			(1<<0)

/* SPI COMMAND MODE */
#define SPICTL_START				(1<<4)
#define SPIFIFO_TX_FULL				(1 << 17)
#define SPIFIFO_RX_EMPTY			(1 << 18)
#define SPIINT_SPIDONE				(1<<0)
#define SPIINT_ILLSPI				(1<<1)
#define SPIINT_RX_EMPTY_RD			(1<<2)
#define SPIINT_TX_FULL_WR			(1<<3)
#define SPIINT_DMA_EMPTY_RD			(1<<4)
#define SPIINT_DMA_FULL_WR			(1<<5)
/* SPI USER MODE */
#define SPIUSR_SINGLE				0x1
#define SPIUSR_DUAL					0x2
#define SPIUSR_QUAD					0x4
#define SPIUSR_NO_DATA				0x0
#define SPIUSR_READ_DATA			0x1
#define SPIUSR_WRITE_DATA			0x2
#define SPIUSR_NO_DUMMY				0x0
#define SPIUSR_ONE_DUMMY			0x1
#define SPIUSR_TWO_DUMMY			0x2
#define SPIUSR_THREE_DUMMY			0x3
#define SPIUSR_NO_MODE				0x0
#define SPIUSR_ONE_MODE				0x1
#define SPIUSR_NO_ADDR				0x0
#define SPIUSR_ONE_BYTE_ADDR		0x1
#define SPIUSR_TWO_BYTE_ADDR		0x2
#define SPIUSR_THREE_BYTE_ADDR		0x3
#define SPIUSR_FOUR_BYTE_ADDR		0x4
#define SPIUSR_NO_INSTRU			0x0
#define SPIUSR_ONE_INSTRU			0x1

/* SPIARB register bit field */
#define SPIARB_ARB_EN			(1<<31)

#if defined(CONFIG_RALINK_SPI_CS0_HIGH_ACTIVE)
#define SPIARB_SPI0_ACTIVE_MODE		1
#else
#define SPIARB_SPI0_ACTIVE_MODE		0
#endif

#if defined(CONFIG_RALINK_SPI_CS1_HIGH_ACTIVE)
#define SPIARB_SPI1_ACTIVE_MODE		1
#else
#define SPIARB_SPI1_ACTIVE_MODE		0
#endif

#define spi_busy_loop 3000
#define max_ee_busy_loop 500


/*
 * ATMEL AT25XXXX Serial EEPROM 
 * access type
 */

/* Instruction codes */
#define WREN_CMD	0x06
#define WRDI_CMD	0x04
#define RDSR_CMD	0x05
#define WRSR_CMD	0x01
#define READ_CMD	0x03
#define WRITE_CMD	0x02

/* STATUS REGISTER BIT */
#define RDY 0	/*  Busy Indicator Bit */
#define WEN 1	/*  Write Enable Bit   */
#define BP0 2	/* Block Write Protect Bit */
#define BP1 3	/* Block Write Protect Bit */
#define WPEN 7	/* Software Write Protect Enable Bit */


#define ENABLE	1
#define DISABLE	0

#define CFG_CLK_DIV SPICFG_SPICLK_DIV8

#define RALINK_SYSCTL_ADDR		RALINK_SYSCTL_BASE	// system control
#define RALINK_REG_GPIOMODE		(RALINK_SYSCTL_ADDR + 0x60)


static inline u32 raspi_read(u32 reg)
{
	return __raw_readl((void __iomem *)(reg));
}

static inline void raspi_write(u32 reg, u32 val)
{
	__raw_writel(val,(void __iomem *)(reg));
}
#endif	//__SPIC_H__
