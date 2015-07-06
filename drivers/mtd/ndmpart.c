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
#define SQUASHFS_MAGIC			0x73717368
#endif

#define NDMS_MAGIC			0x736D646E
#define CONFIG_MAGIC			cpu_to_be32(0x2e6e646d)
#define CONFIG_MAGIC_V1			cpu_to_be32(0x1f8b0801)

#define KERNEL_MAGIC			be32_to_cpu(0x27051956)
#define ROOTFS_MAGIC			SQUASHFS_MAGIC
#define PART_OPTIONAL_NUM		2		/* storage and dump */

#define MIN_FLASH_SIZE_FOR_STORAGE	0x800000	/* 8 MB */

enum {
	PART_U_BOOT,
	PART_U_CONFIG,
	PART_RF_EEPROM,
	PART_KERNEL,
	PART_ROOTFS,
	PART_FIRMWARE,
	PART_CONFIG,
	PART_STORAGE,	/* optional */
	PART_DUMP,	/* optional */
	PART_BACKUP,
	PART_FULL,
	PART_MAX
};

struct mtd_partition ndm_parts[PART_MAX] = {
	[PART_U_BOOT] = {
		name:			"U-Boot",  	/* mtdblock0 */
		size:			0,
		offset:			0
	},
	[PART_U_CONFIG] = {
		name:			"U-Config", 	/* mtdblock1 */
		size:			0,
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
	}
#if 0
	[PART_STORAGE]
	[PART_DUMP]
	[PART_BACKUP]	/* kernel, rootfs, config and storage */
	[PART_FULL]	/* full flash */
#endif
};

#ifdef CONFIG_MTD_NDM_CONFIG_TRANSITION
/*
 * TODO:
 * - erase full partition (?);
 * - smart detecting size of config.
 */
static void config_move(struct mtd_info *master, unsigned int offset)
{
	__le32 magic;
	int ret;
	size_t len;
	struct erase_info ei;
	unsigned char *iobuf;

	ret = master->read(master, offset, sizeof magic, &len,
			   (uint8_t *) &magic);
	if (ret || len != sizeof magic)
		goto out;

	if (magic != CONFIG_MAGIC && magic != CONFIG_MAGIC_V1)
		goto out;

	printk(KERN_INFO "Found config in old partition at 0x%012llx, move it\n",
	       (unsigned long long) offset);

	iobuf = kmalloc(master->erasesize, GFP_KERNEL);
	if (iobuf == NULL) {
		printk(KERN_ERR "no memory\n");
		goto out;
	}

	// Read old config.
	ret = master->read(master, offset, master->erasesize,
			   &len, iobuf);
	if (ret || len != master->erasesize) {
		printk(KERN_ERR "read failed at 0x%012llx\n",
		       (unsigned long long) offset);
		goto out_kfree;
	}

	// Erase new place.
	memset(&ei, 0, sizeof(struct erase_info));
	ei.mtd  = master;
	ei.addr = ndm_parts[PART_CONFIG].offset;
	ei.len  = master->erasesize;

	ret = master->erase(master, &ei);
	if (ret || ei.state == MTD_ERASE_FAILED) {
		printk(KERN_ERR "erase failed at 0x%012llx\n",
		       (unsigned long long) ei.addr);
		goto out_kfree;
	}

	// Write config to new place.
	ret = master->write(master, ndm_parts[PART_CONFIG].offset,
			    master->erasesize, &len, iobuf);
	if (ret || len != master->erasesize) {
		printk(KERN_ERR "write failed at 0x%012llx\n",
		       (unsigned long long) ndm_parts[PART_CONFIG].offset);
		goto out_kfree;
	}

	// Erase old place.
	memset(&ei, 0, sizeof(struct erase_info));
	ei.mtd  = master;
	ei.addr = offset;
	ei.len  = master->erasesize;

	ret = master->erase(master, &ei);
	if (ret || ei.state == MTD_ERASE_FAILED) {
		printk(KERN_ERR "erase failed at 0x%012llx\n",
		       (unsigned long long) ei.addr);
	}

out_kfree:
	kfree(iobuf);
out:
	return;
}
#endif

static inline unsigned part_u_boot_size(struct mtd_info *master)
{
	unsigned size;

	if (master->type == MTD_NANDFLASH)
#ifdef CONFIG_RALINK_MT7621
		size = master->erasesize << 2;
#else
		size = master->erasesize;
#endif
	else
		size = 3 * master->erasesize;

	return size;
}

static inline unsigned part_u_config_size(struct mtd_info *master)
{
	unsigned size;

#ifdef CONFIG_RALINK_MT7621
	if (master->type == MTD_NANDFLASH)
		size = master->erasesize << 2;
	else
#endif
	size = master->erasesize;

	return size;
}

static inline unsigned part_config_size(struct mtd_info *master)
{
	unsigned size;

#ifdef CONFIG_RALINK_MT7621
	if (master->type == MTD_NANDFLASH)
		size = master->erasesize << 2;
	else
#endif
	size = master->erasesize;

	return size;
}

static int create_mtd_partitions(struct mtd_info *master,
				 struct mtd_partition **pparts,
				 unsigned long origin)
{
	bool use_dump, use_storage;
	int index, dump_index, part_num, storage_index;
	size_t len;
	uint32_t config_offset, offset, flash_size, flash_size_lim;
	__le32 magic;

	flash_size = master->size;

	flash_size_lim = CONFIG_MTD_NDM_FLASH_SIZE_LIMIT;
	if (!flash_size_lim)
		flash_size_lim = flash_size;

	printk(KERN_INFO "Current flash size = 0x%x\n", flash_size);

	/* U-Boot */
	ndm_parts[PART_U_BOOT].size = part_u_boot_size(master);

	/* U-Config */
	ndm_parts[PART_U_CONFIG].offset = ndm_parts[PART_U_BOOT].size;
	ndm_parts[PART_U_CONFIG].size = part_u_config_size(master);

	/* RF-EEPROM */
	ndm_parts[PART_RF_EEPROM].offset = ndm_parts[PART_U_CONFIG].offset +
					   ndm_parts[PART_U_CONFIG].size;

	/*
	 * TODO: Move to separate function.
	 */
	for (offset = ndm_parts[PART_RF_EEPROM].offset;
	     offset < flash_size_lim; offset += master->erasesize) {
		
		master->read(master, offset, sizeof(magic), &len,
		             (uint8_t *) &magic);
		if (magic == KERNEL_MAGIC){
			printk(KERN_INFO "Found kernel at offset 0x%x\n",
			       offset);

			ndm_parts[PART_RF_EEPROM].size = offset -
				ndm_parts[PART_RF_EEPROM].offset;
			ndm_parts[PART_KERNEL].offset = offset;
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
	
	index = PART_CONFIG + 1;

	/* Dump & Storage */
	use_dump = use_storage = false;
	dump_index = storage_index = 0;

	part_num = PART_MAX - PART_OPTIONAL_NUM;

	if (CONFIG_MTD_NDM_DUMP_SIZE)
		use_dump = true;

	if (CONFIG_MTD_NDM_STORAGE_SIZE &&
	    flash_size_lim >= MIN_FLASH_SIZE_FOR_STORAGE)
		use_storage = true;

	if (use_storage) {
		ndm_parts[index].name = "Storage";
		ndm_parts[index].size = CONFIG_MTD_NDM_STORAGE_SIZE;

		part_num++;
		storage_index = index;
		index++;
	}

	if (use_dump) {
		ndm_parts[index].name = "Dump";
		ndm_parts[index].size = CONFIG_MTD_NDM_DUMP_SIZE;
		ndm_parts[index].offset = flash_size_lim - CONFIG_MTD_NDM_DUMP_SIZE;

		part_num++;
		dump_index = index;
		index++;
	}

	ndm_parts[PART_CONFIG].size = part_config_size(master);

	if (use_dump && !use_storage) {
		config_offset = ndm_parts[dump_index].offset -
				ndm_parts[PART_CONFIG].size;
	} else if (!use_dump && use_storage) {
		ndm_parts[storage_index].offset = flash_size_lim -
						  CONFIG_MTD_NDM_STORAGE_SIZE;
		config_offset = ndm_parts[storage_index].offset -
				ndm_parts[PART_CONFIG].size;
	} else if (use_dump && use_storage) {
		ndm_parts[storage_index].offset = ndm_parts[dump_index].offset -
						  CONFIG_MTD_NDM_STORAGE_SIZE;
		config_offset = ndm_parts[storage_index].offset -
				ndm_parts[PART_CONFIG].size;
	} else {
		config_offset = flash_size_lim - ndm_parts[PART_CONFIG].size;
	}

	/* Config */
	ndm_parts[PART_CONFIG].offset = config_offset;
#ifdef CONFIG_MTD_NDM_CONFIG_TRANSITION
	config_move(master, CONFIG_MTD_NDM_CONFIG_TRANSITION_OFFSET);
#endif

	/* Backup */
	ndm_parts[index].name = "Backup";
	ndm_parts[index].offset = ndm_parts[PART_KERNEL].offset;
	ndm_parts[index].size = flash_size_lim - ndm_parts[index].offset;

	if (use_dump)
		ndm_parts[index].size -= ndm_parts[dump_index].size;

	index++;

	/* Full */
	ndm_parts[index].name = "Full";
	ndm_parts[index].size = MTDPART_SIZ_FULL;
	ndm_parts[index].offset = 0;

	/* Firmware */
	ndm_parts[PART_FIRMWARE].offset = ndm_parts[PART_KERNEL].offset;
	ndm_parts[PART_FIRMWARE].size = ndm_parts[PART_CONFIG].offset -
					ndm_parts[PART_FIRMWARE].offset;

	/* Rootfs */
	ndm_parts[PART_ROOTFS].size = ndm_parts[PART_CONFIG].offset -
				      ndm_parts[PART_ROOTFS].offset;

	*pparts = ndm_parts;
	return part_num;
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
