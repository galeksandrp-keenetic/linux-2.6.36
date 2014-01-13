#include <linux/init.h>
#include <linux/types.h>
#include <linux/root_dev.h>
#include <linux/kernel.h>
#include <linux/mtd/map.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/tc3162/tc3162.h>

#define WINDOW_ADDR 0x1fc00000
#define WINDOW_SIZE 0x400000
#define BUSWIDTH 	2


static struct mtd_info *tc3162_mtd_info;

static struct map_info tc3162_map = {
       .name = "tc3162",
       .size = WINDOW_SIZE,
       .bankwidth = BUSWIDTH,
       .phys = WINDOW_ADDR,
};

static int __init tc3162_mtd_init(void)
{
#ifdef CONFIG_TCSUPPORT_ADDR_MAPPING
	/*add address mapping on 7510. Pork*/
	if(isMT751020){
		uint32 tmpVal;
		tmpVal = regRead32(0xbfb00038);
		tmpVal &= 0xffe0e0e0;
		tmpVal |= 0x80070f00;
		regWrite32(0xbfb00038,tmpVal);
		//VPint(0xbfb00038) |= 0x80070F00;
		printk("tc3162: flash device 0x%08x at 0x%08x\n", 0x1000000, 0x1c000000);
		tc3162_map.virt = ioremap_nocache(0x1c000000, 0x1000000);
		tc3162_map.phys = 0x1c000000;
		tc3162_map.size = 0x1000000;
		ioremap_nocache(WINDOW_ADDR, WINDOW_SIZE);
	}
	/*add 8M 16M flash support. shnwind*/
	else if (isTC3162U || isTC3182 || isRT65168 || isRT63165 || isRT63365 || isRT63260){
#else
	if (isTC3162U || isTC3182 || isRT65168 || isRT63165 || isRT63365 || isRT63260 || isMT751020){
#endif //CONFIG_TCSUPPORT_ADDR_MAPPING
		/*enable addr bigger than 4M support.*/
		VPint(0xbfb00038) |= 0x80000000;
		printk("tc3162: flash device 0x%08x at 0x%08x\n", 0x1000000, 0x10000000);
		tc3162_map.virt = ioremap_nocache(0x10000000, 0x1000000);
		tc3162_map.phys = 0x10000000;
		tc3162_map.size = 0x1000000;
		ioremap_nocache(WINDOW_ADDR, WINDOW_SIZE);
	}else{
		printk("tc3162: flash device 0x%08x at 0x%08x\n", WINDOW_SIZE, WINDOW_ADDR);
		tc3162_map.virt = ioremap_nocache(WINDOW_ADDR, WINDOW_SIZE);
	}
	if (!tc3162_map.virt) {
   		printk("tc3162: Failed to ioremap\n");
		return -EIO;
	}

	simple_map_init(&tc3162_map);

	tc3162_mtd_info = do_map_probe("spiflash_probe", &tc3162_map);

	if (!tc3162_mtd_info) {
		iounmap((void *)tc3162_map.virt);
		return -ENXIO;
	}

	tc3162_mtd_info->owner = THIS_MODULE;
	if (add_mtd_device(tc3162_mtd_info)) {
		printk("Failed to add tc3262 flash device\n");
		map_destroy(tc3162_mtd_info);
		tc3162_mtd_info = 0;
		iounmap((void *)tc3162_map.virt);
		return -ENOMEM;
	}

	return 0;
}

static void __exit tc3162_mtd_cleanup(void)
{
	if (tc3162_mtd_info) {
		del_mtd_device(tc3162_mtd_info);
		map_destroy(tc3162_mtd_info);
		iounmap((void *)tc3162_map.virt);
	}
}

int ra_mtd_read_nm(char *name, loff_t from, size_t len, u_char *buf)
{
	int ret;
	size_t rdlen;
	struct mtd_info *mtd;

	mtd = get_mtd_device_nm(name);
	if (IS_ERR(mtd))
		return (int)mtd;

	ret = mtd->read(mtd, from, len, &rdlen, buf);
	if (rdlen != len)
		printk("warning: ra_mtd_read_nm: rdlen is not equal to len\n");

	put_mtd_device(mtd);
	return ret;
}

int ra_mtd_write_nm(char *name, loff_t to, size_t len, const u_char *buf)
{
	int ret = -1;
	size_t rdlen, wrlen;
	struct mtd_info *mtd;
	struct erase_info ei;
	u_char *bak = NULL;

	mtd = get_mtd_device_nm(name);
	if (IS_ERR(mtd))
		return (int)mtd;
	if (len > mtd->erasesize) {
		put_mtd_device(mtd);
		return -E2BIG;
	}

	bak = kmalloc(mtd->erasesize, GFP_KERNEL);
	if (bak == NULL) {
		put_mtd_device(mtd);
		return -ENOMEM;
	}

	ret = mtd->read(mtd, 0, mtd->erasesize, &rdlen, bak);
	if (ret != 0) {
		put_mtd_device(mtd);
		kfree(bak);
		return ret;
	}
	if (rdlen != mtd->erasesize)
		printk("warning: ra_mtd_write: rdlen is not equal to erasesize\n");

	memcpy(bak + to, buf, len);

	ei.mtd = mtd;
	ei.callback = NULL;
	ei.addr = 0;
	ei.len = mtd->erasesize;
	ei.priv = 0;
	ret = mtd->erase(mtd, &ei);
	if (ret != 0) {
		put_mtd_device(mtd);
		kfree(bak);
		return ret;
	}

	ret = mtd->write(mtd, 0, mtd->erasesize, &wrlen, bak);

	put_mtd_device(mtd);
	kfree(bak);
	return ret;
}
EXPORT_SYMBOL(ra_mtd_write_nm);
EXPORT_SYMBOL(ra_mtd_read_nm);
module_init(tc3162_mtd_init);
module_exit(tc3162_mtd_cleanup);

