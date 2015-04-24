obj-$(CONFIG_MTD_NAND_MTK)	+= rt_nand.o

rt_nand-objs = ralink_nand.o nand_verify.o gdma.o

ifeq ($(CONFIG_MIPS_RT63365),y)
EXTRA_CFLAGS += -DTCSUPPORT_NAND_RT63368
rt_nand-objs += bmt.o
endif
