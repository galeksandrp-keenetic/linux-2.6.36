/*
 * USB CDC Device Management subdriver
 *
 * Copyright (c) 2012  Bjørn Mork <bjorn@mork.no>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#ifndef __LINUX_USB_CDC_WDM_H
#define __LINUX_USB_CDC_WDM_H

//#include <uapi/linux/usb/cdc-wdm.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
/* "Telephone Control Model Functional Descriptor" from CDC WMC spec 6.3..3 */
struct usb_cdc_dmm_desc {
	__u8	bFunctionLength;
	__u8	bDescriptorType;
	__u8	bDescriptorSubtype;
	__u16	bcdVersion;
	__le16	wMaxCommand;
} __attribute__ ((packed));
#endif


extern struct usb_driver *usb_cdc_wdm_register(struct usb_interface *intf,
					struct usb_endpoint_descriptor *ep,
					int bufsize,
					int (*manage_power)(struct usb_interface *, int));

/* ----------------------------------------------------------------------- */

/* translate USB error codes to codes user space understands */
static inline int usb_translate_errors(int error_code)
{
	switch (error_code) {
	case 0:
	case -ENOMEM:
	case -ENODEV:
	case -EOPNOTSUPP:
		return error_code;
	default:
		return -EIO;
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline const char *dev_name(const struct device *dev)
{
#if 0
	/* Use the init name until the kobject becomes available */
	if (dev->init_name)
		return dev->init_name;
#endif
	return kobject_name(&dev->kobj);
}
#endif

/*
 * Prevent the compiler from merging or refetching accesses.  The compiler
 * is also forbidden from reordering successive instances of ACCESS_ONCE(),
 * but only when the compiler is aware of some particular ordering.  One way
 * to make the compiler aware of ordering is to put the two invocations of
 * ACCESS_ONCE() in different C statements.
 *
 * This macro does absolutely -nothing- to prevent the CPU from reordering,
 * merging, or refetching absolutely anything at any time.  Its main intended
 * use is to mediate communication between process-level code and irq/NMI
 * handlers, all running on the same CPU.
 */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#endif /* __LINUX_USB_CDC_WDM_H */
