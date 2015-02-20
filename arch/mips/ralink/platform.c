#include <linux/init.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/platform_device.h>

static int __init raeth_device_init(void)
{
	struct platform_device *pdev;
	int retval = 0;

	pdev = platform_device_alloc("raeth", -1);
	if (!pdev)
		return -ENOMEM;

//	pdev->id = PLAT8250_DEV_PLATFORM;
//	pdev->dev.platform_data = lasat_serial8250_port;

//	retval = platform_device_add_resources(pdev, lasat_serial_res, ARRAY_SIZE(lasat_serial_res));
//	if (retval)
//		goto err_free_device;

	retval = platform_device_add(pdev);
	if (retval)
		goto err_free_device;

	return 0;

err_free_device:
	platform_device_put(pdev);

	return retval;

}
device_initcall(raeth_device_init);
