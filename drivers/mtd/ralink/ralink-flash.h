#ifndef __RALINK_FLASH_H__
#define __RALINK_FLASH_H__

#ifdef CONFIG_RALINK_RT3052
	#define	RALINK_MTD_PHYSMAP_START		0xBF000000
	#define	RALINK_MTD_PHYSMAP_LEN			0x1000000
	#define	RALINK_MTD_PHYSMAP_BUSWIDTH		2 
#endif

#define BOOT_FROM_NOR	0
#define BOOT_FROM_NAND	2
#define BOOT_FROM_SPI	3

int ra_check_flash_type(void);

#endif //__RALINK_FLASH_H__
