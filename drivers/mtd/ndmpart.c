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
#define NDMS_MAGIC	0x736D646E
#define CONFIG_MAGIC	cpu_to_be32(0x2e6e646d)
#define CONFIG_MAGIC_V1	cpu_to_be32(0x1f8b0801)

#define KERNEL_MAGIC	be32_to_cpu(0x27051956)
#define ROOTFS_MAGIC	SQUASHFS_MAGIC

enum {
	PART_U_BOOT,
	PART_U_CONFIG,
	PART_RF_EEPROM,
	PART_KERNEL,
	PART_ROOTFS,
	PART_FIRMWARE,
	PART_CONFIG,
	PART_STORAGE,
	PART_BACKUP,
	PART_FULL,
	PART_MAX
};

struct mtd_partition ndm_parts[PART_MAX] = {
	[PART_U_BOOT] = {
		name:			"U-Boot",  	/* mtdblock0 */
		size:			0,  		/* 3 blocks */
		offset:			0
	},
	[PART_U_CONFIG] = {
		name:			"U-Config", 	/* mtdblock1 */
		size:			0x10000,  	/* 1 block */
		offset:			0
	},
	[PART_RF_EEPROM] = {
		name:			"RF-EEPROM", 	/* mtdblock2 */
		size:			0,
		offset:			0
	},
	[PART_KERNEL] = {
		name:			"Kernel", 	/* mtdblock3 */
		size:			0,
		offset:			0
	},
	[PART_ROOTFS] = {
		name:			"RootFS", 	/* mtdblock4 */
		size:			0,
		offset:			0
	},
	[PART_FIRMWARE] = {
		/* kernel and rootfs */
		name:			"Firmware", 	/* mtdblock5 */
		size:			0,
		offset:			0
	},
	[PART_CONFIG] = {
		name:			"Config", 	/* mtdblock6 */
		size:			0,
		offset:			0
	},
	[PART_STORAGE] = {
		name:			"Storage", 	/* mtdblock7 */
#ifdef CONFIG_MTD_NDM_SHRINK_STORAGE
		size:			0x80000,
#else
		size:			CONFIG_MTD_NDM_STORAGE_SIZE,
#endif
		offset:			0
	},
	[PART_BACKUP] = {
		/* kernel, rootfs, config and storage */
		name:			"Backup", 	/* mtdblock8 */
		size:			0,
		offset:			0
	},
	[PART_FULL] = {
		/* full flash */
		name:			"Full", 	/* mtdblock9 */
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
	size_t i, delete = 0;
	__le32 magic;

	flash_size = master->size;

	printk(KERN_INFO "Current flash size = 0x%x\n", flash_size);

	/* U-Boot */
	ndm_parts[PART_U_BOOT].offset = 0;
	if (master->type == MTD_NANDFLASH)
#if defined(CONFIG_RALINK_MT7621)
		ndm_parts[PART_U_BOOT].size = (master->erasesize << 2);
#else
		ndm_parts[PART_U_BOOT].size = (master->erasesize);
#endif
	else
		ndm_parts[PART_U_BOOT].size = (3 * master->erasesize);

	/* U-Config */
	ndm_parts[PART_U_CONFIG].offset = ndm_parts[PART_U_BOOT].size;
#if defined(CONFIG_RALINK_MT7621)
	if (master->type == MTD_NANDFLASH)
		ndm_parts[PART_U_CONFIG].size = (master->erasesize << 2);
	else
#endif
	ndm_parts[PART_U_CONFIG].size = master->erasesize;

	/* RF-EEPROM */
	ndm_parts[PART_RF_EEPROM].offset = ndm_parts[PART_U_CONFIG].offset +
					   ndm_parts[PART_U_CONFIG].size;

	/* XXX: Why PART_U_CONFIG? */
	for (offset = ndm_parts[PART_U_CONFIG].offset; offset < flash_size;
	     offset += master->erasesize) {
		
		master->read(master, offset, sizeof(magic), &len,
		             (uint8_t *) &magic);
		if (magic == KERNEL_MAGIC){
			printk(KERN_INFO "Found kernel at offset 0x%x\n",
			       offset);

			ndm_parts[PART_RF_EEPROM].size = offset -
				ndm_parts[PART_RF_EEPROM].offset;
			ndm_parts[PART_KERNEL].offset = offset;
			ndm_parts[PART_FIRMWARE].offset = offset;
			ndm_parts[PART_BACKUP].offset = offset;
		}
		if ((le32_to_cpu(magic) == ROOTFS_MAGIC) ||
		    (le32_to_cpu(magic) == NDMS_MAGIC)) {
			printk(KERN_INFO "Found rootfs at offset 0x%x\n", offset);

			ndm_parts[PART_KERNEL].size = offset -
				ndm_parts[PART_KERNEL].offset;
			ndm_parts[PART_ROOTFS].offset = offset;
			break;
		}
	}
	
	/* Backup */
	ndm_parts[PART_BACKUP].size = flash_size - ndm_parts[PART_BACKUP].offset;

	/* Delete Storage if flash size less then 8M, or 
	 * NDM_STORAGE_SIZE set to zero
	 */
	if ((flash_size < 0x800000) || (ndm_parts[PART_STORAGE].size == 0)) {
		delete = 1;
		for (i = PART_STORAGE; i < PART_MAX - 1; i++) {
			ndm_parts[i] = ndm_parts[i + 1];
		}
#if defined(CONFIG_RALINK_MT7621)
		if (master->type == MTD_NANDFLASH)
			ndm_parts[PART_CONFIG].offset = flash_size -
				(master->erasesize << 1);
		else
#endif
		ndm_parts[PART_CONFIG].offset = flash_size - master->erasesize;
	} else {
		ndm_parts[PART_STORAGE].offset = flash_size -
			ndm_parts[PART_STORAGE].size;
#if defined(CONFIG_RALINK_MT7621)
		if (master->type == MTD_NANDFLASH)
			ndm_parts[PART_CONFIG].offset = ndm_parts[PART_STORAGE].offset -
				(master->erasesize << 1);
		else
#endif
		ndm_parts[PART_CONFIG].offset = ndm_parts[PART_STORAGE].offset -
						master->erasesize;

#ifdef CONFIG_MTD_NDM_SHRINK_STORAGE

		offset = ndm_parts[PART_CONFIG].offset - 0x80000;
		master->read(master, offset, sizeof(magic), &len,
			     (uint8_t *) &magic);

		if ((magic == CONFIG_MAGIC) || (magic == CONFIG_MAGIC_V1)) {
			unsigned char *iobuf;
			struct erase_info ei;
			int err;

			printk(KERN_INFO "found config in old partition at 0x%012llx, move it\n",
			       (unsigned long long) offset);
			iobuf = kmalloc(master->erasesize, GFP_KERNEL);
			master->read(master, offset, master->erasesize,
							&len, iobuf);

			if (len != master->erasesize) {
				printk(KERN_ERR "read failed at 0x%012llx\n",
				       (unsigned long long) offset);
			} else {

				memset(&ei, 0, sizeof(struct erase_info));
				ei.mtd  = master;
				ei.addr = ndm_parts[PART_CONFIG].offset;
				ei.len  = master->erasesize;
				err = master->erase(master, &ei);

				err = master->write(master, ndm_parts[PART_CONFIG].offset,
						    master->erasesize, &len, iobuf);

				if (!err && len != master->erasesize) {
					printk(KERN_ERR "write failed at 0x%012llx\n",
					       (unsigned long long) ndm_parts[PART_CONFIG].offset);
				} else {
					memset(&ei, 0, sizeof(struct erase_info));
					ei.mtd  = master;
					ei.addr = offset;
					ei.len  = master->erasesize;

					err = master->erase(master, &ei);

					if ((err) || (ei.state == MTD_ERASE_FAILED)) {
						printk(KERN_ERR "erase failed at 0x%012llx\n",
						       (unsigned long long) offset);
					}
				}
			}
		}
#endif
	}

	/* Config */
#if defined(CONFIG_RALINK_MT7621)
	if (master->type == MTD_NANDFLASH)
		ndm_parts[PART_CONFIG].size = (master->erasesize << 1);
	else
#endif
	ndm_parts[PART_CONFIG].size = master->erasesize;

	/* Firmware */
	ndm_parts[PART_FIRMWARE].size = ndm_parts[PART_CONFIG].offset -
					ndm_parts[PART_FIRMWARE].offset;

	/* RootFS */
	ndm_parts[PART_ROOTFS].size = ndm_parts[PART_CONFIG].offset -
				      ndm_parts[PART_ROOTFS].offset;

	*pparts = ndm_parts;
	return (PART_MAX - delete);
}

static struct mtd_part_parser ndm_parser = {
	.owner = THIS_MODULE,
	.parse_fn = create_mtd_partitions,
	.name = "ndmpart",
};

static int __init ndm_parser_init(void)
{
	printk(KERN_INFO "Registering NDM partitions parser\n");
	return register_mtd_parser(&ndm_parser);
}

module_init(ndm_parser_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NDM Systems Inc. <info@ndmsystems.com>");
MODULE_DESCRIPTION("MTD partitioning for NDM devices");
