obj-y := \
	prom.o \
	setup.o \
	irq.o \
	tcwdog.o \
	ex_mdio_api.o \
	platform.o
#	tcadsl.o 
#	ledcetrl.o

obj-$(CONFIG_MIPS_TC3162) += time.o
obj-$(CONFIG_MIPS_TC3162U) += time.o
obj-$(CONFIG_MIPS_TC3262) += time2.o

obj-$(CONFIG_MIPS_MT_SMP)	+= malta-smp.o
obj-$(CONFIG_MIPS_MT_SMTC)	+= malta-smtc.o
