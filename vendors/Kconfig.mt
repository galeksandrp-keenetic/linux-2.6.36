menu "MediaTek modules"

menuconfig MT76X2
	bool "MT7602E && MT7612E Wi-Fi driver"

if MT76X2

choice
	prompt "Choose first Wi-Fi interface"

	config FIRST_IF_RT2860
	bool "RT2860 (MT7602E)"
	select RTMP_MAC
	select RALINK_RT2860
endchoice

choice
	prompt "EEPROM type of 1st card"
	depends on ! FIRST_IF_NONE

	config FIRST_IF_EEPROM_PROM
	bool "EEPROM"

	config FIRST_IF_EEPROM_EFUSE
	bool "EFUSE"

	config FIRST_IF_EEPROM_FLASH
	bool "FLASH"
endchoice

choice
	prompt "Choose second Wi-Fi interface"

	config SECOND_IF_MT7612E
	bool "MT7612E"
	select RLT_MAC
	select RALINK_MT7612E
endchoice

choice
	prompt "EEPROM type of 2nd card"
	depends on ! SECOND_IF_NONE

	config SECOND_IF_EEPROM_PROM
	bool "EEPROM"

	config SECOND_IF_EEPROM_EFUSE
	bool "EFUSE"

	config SECOND_IF_EEPROM_FLASH
	bool "FLASH"
endchoice

config RT_FIRST_CARD
	int
	depends on ! FIRST_IF_NONE
	default 2860 if FIRST_IF_RT2860

config RT_SECOND_CARD
	int
	depends on ! SECOND_IF_NONE
	default 7612 if SECOND_IF_MT7612E

config RT_FIRST_IF_RF_OFFSET
	hex
	depends on ! FIRST_IF_NONE
	default 0x40000

config RT_SECOND_IF_RF_OFFSET
	hex
	depends on ! SECOND_IF_NONE
	default 0x48000

config RT_FIRST_CARD_EEPROM
	string
	depends on ! FIRST_IF_NONE
	default "prom" if FIRST_IF_EEPROM_PROM
	default "efuse" if FIRST_IF_EEPROM_EFUSE
	default "flash" if FIRST_IF_EEPROM_FLASH

config RT_SECOND_CARD_EEPROM
	string
	depends on ! SECOND_IF_NONE
	default "prom" if SECOND_IF_EEPROM_PROM
	default "efuse" if SECOND_IF_EEPROM_EFUSE
	default "flash" if SECOND_IF_EEPROM_FLASH

config MULTI_INF_SUPPORT
	bool
	default y if !FIRST_IF_NONE && !SECOND_IF_NONE

config PCI_SUPPORT
	bool

choice
	prompt "Configuration method selection"
	default CONFIG_METHOD_NEW

	config CONFIG_METHOD_NEW
	bool "New"
	select WIFI_BASIC_FUNC
endchoice

if CONFIG_METHOD_NEW
	menu "Wi-Fi generic feature options"
		source "drivers/net/wireless/mt76x2/Kconfig"
	endmenu

	menu "Wi-Fi operation modes"
		choice
			prompt "Main mode"
			default WIFI_MODE_AP

			config WIFI_MODE_AP
			bool "AP"
		endchoice

		if WIFI_MODE_AP
		source "drivers/net/wireless/mt76x2_ap/Kconfig"
		endif
	endmenu

	config RALINK_RT28XX
		bool
		default n
		select RTMP_PCI_SUPPORT

	config RALINK_MT7612E
		bool
		default n
		select RTMP_PCI_SUPPORT
endif # CONFIG_METHOD_NEW

endif # MT76X2

config RTDEV
	bool
	default y if MT76X2 && !SECOND_IF_NONE || RTDEV_MII
	default y if RTDEV_PLC

menuconfig MT7628
	bool "MT7628 SoC Wi-Fi driver"

if MT7628
source "drivers/net/wireless/mt7628_ap/Kconfig"
endif # MT7628

endmenu

