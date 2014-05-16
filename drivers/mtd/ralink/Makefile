#obj-$(CONFIG_RALINK_SOC)	+= ralink-flash.o
obj-$(CONFIG_MTD_NAND_RALINK)	+= ralink_nand.o
obj-$(CONFIG_MTD_SPI_RALINK)	+= ralink_spi.o 

ifeq ($(CONFIG_RALINK_RT3052),y)
rt_nand-objs = ralink_nand_rt3052.o gdma.o
else
rt_nand-objs = ralink_nand.o gdma.o
endif

ifeq ($(CONFIG_RALINK_RT3883),y)
rt_nand-objs = ralink_nand_rt3052.o gdma.o
else
rt_nand-objs = ralink_nand.o gdma.o
endif

ifeq ($(CONFIG_RALINK_MT7621),y)
rt_nand-objs = 
rt_spi-objs = ralink_bbu_spi.o
else

ifeq ($(CONFIG_RALINK_MT7628),y)
rt_nand-objs = 
rt_spi-objs = ralink_bbu_spi.o
else
rt_spi-objs = ralink_spi.o
endif

endif


