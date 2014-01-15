/*
 * Copyright © 2007 Eugene Konev <ejka@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * TI AR7 flash partition table.
 * Based on ar7 map by Felix Fietkau <nbd@openwrt.org>
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/bootmem.h>
#include <linux/magic.h>

#ifndef SQUASHFS_MAGIC
#define SQUASHFS_MAGIC	0x73717368
#endif

#define KERNEL_MAGIC	be32_to_cpu(0x27051956)
#define ROOTFS_MAGIC	SQUASHFS_MAGIC

struct mtd_partition ndm_parts[] = {
	{
		name:			"U-Boot",  		/* mtdblock0 */
		size:			0,  		/* 3 blocks */
		offset:			0
	}, {
		name:			"U-Config", 	/* mtdblock1 */
		size:			0x10000,  		/* 1 block */
		offset:			0
	}, {
		name:			"RF-EEPROM", 	/* mtdblock2 */
		size:			0,
		offset:			0
	}, {
		name:			"Kernel", 		/* mtdblock3 */
		size:			0,
		offset:			0
	}, {
		name:			"RootFS", 		/* mtdblock4 */
		size:			0,
		offset:			0
	}, {
		name:			"Firmware", 	/* mtdblock5 */
		size:			0,
		offset:			0
	},{
		name:			"Config", 		/* mtdblock6 */
		size:			0,
		offset:			0
	}, {
		name:			"Storage", 		/* mtdblock7 */
		size:			0x100000,
		offset:			0
	}, {
		name:			"Backup", 		/* mtdblock8 */
		size:			0,
		offset:			0
	},{
		name:			"Full", 		/* mtdblock9 */
		size:			MTDPART_SIZ_FULL,
		offset:			0
	}
};


static int create_mtd_partitions(struct mtd_info *master,
				 struct mtd_partition **pparts,
				 unsigned long origin)
{
	unsigned int offset,flash_size;
	size_t len;
	size_t i,delete=0;
	__le32 magic;

	flash_size = master->size;
	
	printk("Current flash size = 0x%x\n",flash_size);
	
	/* U-Boot */	
	ndm_parts[0].offset = 0;
	ndm_parts[0].size = (3*master->erasesize);

	/* U-Config */
	ndm_parts[1].offset = (3*master->erasesize);
	ndm_parts[1].size = master->erasesize;

	/* RF-EEPROM */
	ndm_parts[2].offset = (4*master->erasesize);
	
	for (offset = ndm_parts[1].offset; offset < flash_size;
		offset += master->erasesize) {
		
		master->read(master, offset, sizeof(magic), 
						&len, (uint8_t *)&magic);
		if (magic == KERNEL_MAGIC){
			printk("Found kernel at offset 0x%x\n",offset);
			ndm_parts[2].size = offset - ndm_parts[2].offset;
			ndm_parts[3].offset = offset;	//Kernel offset
			ndm_parts[5].offset = offset;	//Firmware offset
			ndm_parts[8].offset = offset;	//Backup offset
		}
		if (magic == ROOTFS_MAGIC) {
			printk("Found rootfs at offset 0x%x\n",offset);
			ndm_parts[3].size = offset - ndm_parts[3].offset;
			ndm_parts[4].offset = offset;
			break;
		}
	}
	
	/* Backup */
	ndm_parts[8].size = flash_size - ndm_parts[8].offset;
	
	/* Delete Storage if flash size less then 8M */
	if (flash_size < 0x800000) {
		delete = 1;
		for (i = 7; i < ARRAY_SIZE(ndm_parts); i++){
			ndm_parts[i]=ndm_parts[i+1];
		}
		ndm_parts[6].offset = flash_size - master->erasesize;
	} else {
		ndm_parts[7].offset = flash_size - ndm_parts[7].size;
		ndm_parts[6].offset = ndm_parts[7].offset - master->erasesize;
	}
	
	/* Config */
	ndm_parts[6].size = master->erasesize;
	
	/* Firmware */
	ndm_parts[5].size = ndm_parts[6].offset - ndm_parts[5].offset;
	
	/* RootFS */
	ndm_parts[4].size = ndm_parts[6].offset - ndm_parts[4].offset;
	
	
	
	*pparts = ndm_parts;
	return (ARRAY_SIZE(ndm_parts) - delete);
}

static struct mtd_part_parser ndm_parser = {
	.owner = THIS_MODULE,
	.parse_fn = create_mtd_partitions,
	.name = "ndmpart",
};

static int __init ndm_parser_init(void)
{
	printk("Registering NDM partiotions parser\n");
	return register_mtd_parser(&ndm_parser);
}

module_init(ndm_parser_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NDM Systems Inc. <info@ndmsystems.com>");
MODULE_DESCRIPTION("MTD partitioning for NDM devices");
