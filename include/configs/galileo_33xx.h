/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Config file for Galileo-33x board
 *
 * Copyright (C) 2021, Leuze Electronic -https://www.leuze.com
 *
 * Author: Berrux Nguimeya Kana <bkana@leuze.de>
 */

#ifndef __CONFIG_GALILEO_33XX
#define __CONFIG_GALILEO_33XX

//#define CONFIG_GALILEO_33XX

#include <configs/ti_am335x_common.h>

#undef CONFIG_MAX_RAM_BANK_SIZE
#define CONFIG_MAX_RAM_BANK_SIZE	(512 << 20)	/* 512MB */

#define CONFIG_MACH_TYPE		MACH_TYPE_CM_T335

/* Clock Defines */
#define V_OSCK				25000000  /* Clock output from T2 */
#define V_SCLK				(V_OSCK)

#define CONFIG_ENV_SIZE			(16 << 10)	/* 16 KiB */

#ifndef CONFIG_SPL_BUILD

#define NETWORK_ARGS \
	"ethaddr=00:15:7b:00:00:03\0" \
	"serverip=192.168.60.1\0" \
	"ipaddr=192.168.60.101\0" \
	"netmask=255.255.255.0\0"

#define MTD_ARGS \
	"mtdids=" CONFIG_MTDIDS_DEFAULT "\0" \
	"mtdparts=" CONFIG_MTDPARTS_DEFAULT "\0"

#define ADDR_ARGS \
	"kernel_loadaddr=82000000\0" \
	"fdt_loadaddr=88000000\0"

#define KERNEL_ARGS \
	"console=ttyO0,115200n8\0" \
	"rootargs_ubi=rw ubi.mtd=ubi,2048\0" \
	"rootfstype_ubi=ubifs rootwait=1\0"

#define BOOT_ARGS \
	"BOOT_ORDER=A B\0" \
	"BOOT_A_LEFT=3\0" \
	"BOOT_B_LEFT=3\0" \

#define BOOTCHOOSE_CMD \
	"bootchoose_cmd=" \
	"test -n \"${BOOT_ORDER}\" || setenv BOOT_ORDER \"A B\"; " \
	"test -n \"${BOOT_A_LEFT}\" || setenv BOOT_A_LEFT 3; " \
	"test -n \"${BOOT_B_LEFT}\" || setenv BOOT_B_LEFT 3; " \
	"setenv default_bootargs \"console=${console} rootfstype=${rootfstype_ubi}\"; " \
	"setenv bootargs; " \
	"for BOOT_SLOT in \"${BOOT_ORDER}\"; do " \
		"if test \"x${bootargs}\" != \"x\"; then ; " \
		"elif test \"x${BOOT_SLOT}\" = \"xA\"; then " \
			"if test ${BOOT_A_LEFT} -gt 0; then " \
				"echo \"Found valid slot A, ${BOOT_A_LEFT} attempts remaining\"; " \
				"setexpr BOOT_A_LEFT ${BOOT_A_LEFT} - 1; " \
				"setenv load_cmd \"nand read ${kernel_loadaddr} kernelA; nand read ${fdt_loadaddr} dtbA;\"; " \
				"setenv bootargs \"${default_bootargs} root=ubi0:rootfsA ${rootargs_ubi} rauc.slot=A\"; " \
			"fi; " \
		"elif test \"x${BOOT_SLOT}\" = \"xB\"; then " \
			"if test ${BOOT_B_LEFT} -gt 0; then " \
				"echo \"Found valid slot B, ${BOOT_B_LEFT} attempts remaining\"; " \
				"setexpr BOOT_B_LEFT ${BOOT_B_LEFT} - 1; " \
				"setenv load_cmd \"nand read ${kernel_loadaddr} kernelB; nand read ${fdt_loadaddr} dtbB;\"; " \
				"setenv bootargs \"${default_bootargs} root=ubi0:rootfsB ${rootargs_ubi} rauc.slot=B\"; " \
			"fi; " \
		"fi; " \
	"done; " \
	"if test -n \"${bootargs}\"; then " \
		"saveenv; " \
	"else " \
		"echo \"No valid slot found, resetting tries to 3\"; " \
		"setenv BOOT_A_LEFT 3; " \
		"setenv BOOT_B_LEFT 3; " \
		"saveenv; " \
		"reset; " \
	"fi; " \
	"\0"

#define BOOT_CMD \
	"boot_cmd=" \
	"echo Determining boot slot... TEST; " \
	"run bootchoose_cmd; " \
	"echo Loading kernel and device-tree...; "  \
	"run load_cmd; " \
	"echo Starting kernel...; " \
	"bootz ${kernel_loadaddr} - ${fdt_loadaddr}; " \
	"\0"

#define FIT_IMG_BOOT \
	"fit_img_boot=" \
	"echo Activating verification...; " \
	"setenv verify yes; " \
	"echo Load FIT Image in RAM...; " \
	"nand read 84000000 kernelB; " \
	"echo Boot FIT Image...; " \
	"bootm 84000000; " \
	"\0"

#define CONFIG_EXTRA_ENV_SETTINGS \
	ADDR_ARGS \
	NETWORK_ARGS \
	KERNEL_ARGS \
	MTD_ARGS \
	BOOT_ARGS \
	BOOTCHOOSE_CMD \
	BOOT_CMD \
	FIT_IMG_BOOT

#define CONFIG_BOOTCOMMAND \
	"run boot_cmd;"

#endif /* CONFIG_SPL_BUILD */

#define CONFIG_TIMESTAMP
#define CONFIG_SYS_AUTOLOAD		"no"

/* Serial console configuration */

/* NS16550 Configuration */
#define CONFIG_SYS_NS16550_COM1		0x44e09000	/* UART0 */
#define CONFIG_SYS_NS16550_COM2		0x48022000	/* UART1 */

/* I2C Configuration */
#define CONFIG_SYS_I2C_EEPROM_ADDR	0x50	/* Main EEPROM */
#define CONFIG_SYS_I2C_EEPROM_ADDR_LEN	1
#define CONFIG_SYS_I2C_EEPROM_BUS	0

/* SPL */

/* Network. */
#define CONFIG_PHY_ATHEROS

/* NAND support */
#define CONFIG_SYS_NAND_5_ADDR_CYCLE
#define CONFIG_SYS_NAND_PAGE_COUNT	(CONFIG_SYS_NAND_BLOCK_SIZE / \
					 CONFIG_SYS_NAND_PAGE_SIZE)
#define CONFIG_SYS_NAND_PAGE_SIZE	2048
#define CONFIG_SYS_NAND_OOBSIZE		128
#define CONFIG_SYS_NAND_BLOCK_SIZE	(128 * 1024)
#define CONFIG_SYS_NAND_BAD_BLOCK_POS	NAND_LARGE_BADBLOCK_POS
#define CONFIG_SYS_NAND_ECCPOS		{ 0, }

#define CONFIG_SYS_NAND_ECCSIZE		0
#define CONFIG_SYS_NAND_ECCBYTES	0

/* ??PATCH bkana@leuze.com 2021-02-16 */
#define CONFIG_SYS_NAND_USE_FLASH_BBT

#define CONFIG_SYS_NAND_U_BOOT_START	CONFIG_SYS_TEXT_BASE

#undef CONFIG_SYS_NAND_U_BOOT_OFFS
/* ??PATCH bkana@leuze.com 2021-02-16 */
#define CONFIG_SYS_NAND_U_BOOT_OFFS	0x180000

#define CONFIG_ENV_OFFSET		0x380000 /* environment starts here */

#define CONFIG_SYS_ENV_SECT_SIZE	(128 << 10)	/* 128 KiB */
#define CONFIG_SYS_NAND_ONFI_DETECTION
#ifdef CONFIG_SPL_OS_BOOT
#define CONFIG_SYS_NAND_SPL_KERNEL_OFFS	0x500000
#endif

/* GPIO pin + bank to pin ID mapping */
#define GPIO_PIN(_bank, _pin)		((_bank << 5) + _pin)

/* Status LED */
/* Status LED polarity is inversed, so init it in the "off" state */

/* EEPROM */
#define CONFIG_ENV_EEPROM_IS_ON_I2C
#define CONFIG_SYS_I2C_EEPROM_ADDR_LEN		1
#define CONFIG_SYS_EEPROM_PAGE_WRITE_BITS	4
#define CONFIG_SYS_EEPROM_PAGE_WRITE_DELAY_MS	5
#define CONFIG_SYS_EEPROM_SIZE			256

#ifndef CONFIG_SPL_BUILD
/*
 * Enable PCA9555 at I2C0-0x26.
 * First select the I2C0 bus with "i2c dev 0", then use "pca953x" command.
 */
#define CONFIG_PCA953X
#define CONFIG_SYS_I2C_PCA953X_ADDR	0x26
#define CONFIG_SYS_I2C_PCA953X_WIDTH	{ {0x26, 16} }
#endif /* CONFIG_SPL_BUILD */

#endif	/* __CONFIG_GALILEO_33XX */

