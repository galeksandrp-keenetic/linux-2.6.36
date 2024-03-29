#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#include <asm/mach-ralink/rt_mmap.h>
#include <asm/mach-ralink/surfboardint.h>

static struct resource mtk_nand_resources[] = {
	{
		.start	= RALINK_NAND_CTRL_BASE,
		.end	= RALINK_NAND_CTRL_BASE + 0x1A0,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= RALINK_NANDECC_CTRL_BASE,
		.end	= RALINK_NANDECC_CTRL_BASE + 0x150,
		.flags	= IORESOURCE_MEM,
	},
#if 0
/* TODO */
	{
		.start	= SURFBOARDINT_NAND,
		.flags	= IORESOURCE_IRQ,
	},
	{
		.start	= SURFBOARDINT_NAND_ECC,
		.flags	= IORESOURCE_IRQ,
	},
#endif
};


static struct platform_device mtk_nand_device = {
	.name			= "mtk-nand",
	.id				= 0,
	.num_resources  = ARRAY_SIZE(mtk_nand_resources),
	.resource		= mtk_nand_resources,
};

int __init mtk_nand_register(void)
{

	int retval = 0;

	retval = platform_device_register(&mtk_nand_device);
	if (retval != 0) {
		printk(KERN_ERR "register nand device fail\n");
		return retval;
	}


	return retval;
}
static int __init raeth_device_init(void)
{
	struct platform_device *pdev;
	int retval = 0;

	pdev = platform_device_alloc("raeth", -1);
	if (!pdev)
		return -ENOMEM;

	retval = platform_device_add(pdev);
	if (retval)
		goto err_free_device;

	return 0;

err_free_device:
	platform_device_put(pdev);

	return retval;

}
device_initcall(raeth_device_init);

arch_initcall(mtk_nand_register);

