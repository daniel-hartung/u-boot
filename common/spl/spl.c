// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2010
 * Texas Instruments, <www.ti.com>
 *
 * Aneesh V <aneesh@ti.com>
 */
#define LOG_DEBUG

#include <common.h>
#include <bloblist.h>
#include <binman_sym.h>
#include <dm.h>
#include <handoff.h>
#include <spl.h>
#include <asm/u-boot.h>
#include <nand.h>
#include <fat.h>
#include <version.h>
#include <image.h>
#include <malloc.h>
#include <dm/root.h>
#include <linux/compiler.h>
#include <fdt_support.h>
#include <bootcount.h>

#include <i2c.h>

#include "../lib/cryptoauthlib/lib/hal/atca_hal.h"
#include "../lib/cryptoauthlib/lib/atca_basic.h"
#include <../lib/cryptoauthlib.h>
#include "../lib/cryptoauthlib/lib/atca_cfgs.h"

#include <../include/u-boot/sha256.h>

DECLARE_GLOBAL_DATA_PTR;

#ifndef CONFIG_SYS_UBOOT_START
#define CONFIG_SYS_UBOOT_START	CONFIG_SYS_TEXT_BASE
#endif
#ifndef CONFIG_SYS_MONITOR_LEN
/* Unknown U-Boot size, let's assume it will not be more than 200 KB */
#define CONFIG_SYS_MONITOR_LEN	(200 * 1024)
#endif

u32 *boot_params_ptr = NULL;

/* See spl.h for information about this */
binman_sym_declare(ulong, u_boot_any, image_pos);

/* Define board data structure */
static bd_t bdata __attribute__ ((section(".data")));

/*
 * Board-specific Platform code can reimplement show_boot_progress () if needed
 */
__weak void show_boot_progress(int val) {}

#if defined(CONFIG_SPL_OS_BOOT) || CONFIG_IS_ENABLED(HANDOFF)
/* weak, default platform-specific function to initialize dram banks */
__weak int dram_init_banksize(void)
{
	return 0;
}
#endif

/*
 * Default function to determine if u-boot or the OS should
 * be started. This implementation always returns 1.
 *
 * Please implement your own board specific funcion to do this.
 *
 * RETURN
 * 0 to not start u-boot
 * positive if u-boot should start
 */
#ifdef CONFIG_SPL_OS_BOOT
__weak int spl_start_uboot(void)
{
	puts(SPL_TPL_PROMPT
	     "Please implement spl_start_uboot() for your board\n");
	puts(SPL_TPL_PROMPT "Direct Linux boot not active!\n");
	return 1;
}

/*
 * Weak default function for arch specific zImage check. Return zero
 * and fill start and end address if image is recognized.
 */
int __weak bootz_setup(ulong image, ulong *start, ulong *end)
{
	 return 1;
}
#endif

/* Weak default function for arch/board-specific fixups to the spl_image_info */
void __weak spl_perform_fixups(struct spl_image_info *spl_image)
{
}

void spl_fixup_fdt(void)
{
#if defined(CONFIG_SPL_OF_LIBFDT) && defined(CONFIG_SYS_SPL_ARGS_ADDR)
	void *fdt_blob = (void *)CONFIG_SYS_SPL_ARGS_ADDR;
	int err;

	err = fdt_check_header(fdt_blob);
	if (err < 0) {
		printf("fdt_root: %s\n", fdt_strerror(err));
		return;
	}

	/* fixup the memory dt node */
	err = fdt_shrink_to_minimum(fdt_blob, 0);
	if (err == 0) {
		printf(SPL_TPL_PROMPT "fdt_shrink_to_minimum err - %d\n", err);
		return;
	}

	err = arch_fixup_fdt(fdt_blob);
	if (err) {
		printf(SPL_TPL_PROMPT "arch_fixup_fdt err - %d\n", err);
		return;
	}
#endif
}

/*
 * Weak default function for board specific cleanup/preparation before
 * Linux boot. Some boards/platforms might not need it, so just provide
 * an empty stub here.
 */
__weak void spl_board_prepare_for_linux(void)
{
	/* Nothing to do! */
}

__weak void spl_board_prepare_for_boot(void)
{
	/* Nothing to do! */
}

__weak struct image_header *spl_get_load_buffer(ssize_t offset, size_t size)
{
	return (struct image_header *)(CONFIG_SYS_TEXT_BASE + offset);
}

void spl_set_header_raw_uboot(struct spl_image_info *spl_image)
{
	ulong u_boot_pos = binman_sym(ulong, u_boot_any, image_pos);

	spl_image->size = CONFIG_SYS_MONITOR_LEN;

	/*
	 * Binman error cases: address of the end of the previous region or the
	 * start of the image's entry area (usually 0) if there is no previous
	 * region.
	 */
	if (u_boot_pos && u_boot_pos != BINMAN_SYM_MISSING) {
		/* Binman does not support separated entry addresses */
		spl_image->entry_point = u_boot_pos;
		spl_image->load_addr = u_boot_pos;
	} else {
		spl_image->entry_point = CONFIG_SYS_UBOOT_START;
		spl_image->load_addr = CONFIG_SYS_TEXT_BASE;
	}
	spl_image->os = IH_OS_U_BOOT;
	spl_image->name = "U-Boot";
}

#ifdef CONFIG_SPL_LOAD_FIT_FULL
/* Parse and load full fitImage in SPL */
static int spl_load_fit_image(struct spl_image_info *spl_image,
			      const struct image_header *header)
{
	bootm_headers_t images;
	const char *fit_uname_config = NULL;
	const char *fit_uname_fdt = FIT_FDT_PROP;
	const char *uname;
	ulong fw_data = 0, dt_data = 0, img_data = 0;
	ulong fw_len = 0, dt_len = 0, img_len = 0;
	int idx, conf_noffset;
	int ret;

#ifdef CONFIG_SPL_FIT_SIGNATURE
	images.verify = 1;
#endif
	ret = fit_image_load(&images, (ulong)header,
			     NULL, &fit_uname_config,
			     IH_ARCH_DEFAULT, IH_TYPE_STANDALONE, -1,
			     FIT_LOAD_REQUIRED, &fw_data, &fw_len);
	if (ret < 0)
		return ret;

	spl_image->size = fw_len;
	spl_image->entry_point = fw_data;
	spl_image->load_addr = fw_data;
	spl_image->os = IH_OS_U_BOOT;
	spl_image->name = "U-Boot";

	debug(SPL_TPL_PROMPT "payload image: %32s load addr: 0x%lx size: %d\n",
	      spl_image->name, spl_image->load_addr, spl_image->size);

#ifdef CONFIG_SPL_FIT_SIGNATURE
	images.verify = 1;
#endif
	fit_image_load(&images, (ulong)header,
		       &fit_uname_fdt, &fit_uname_config,
		       IH_ARCH_DEFAULT, IH_TYPE_FLATDT, -1,
		       FIT_LOAD_OPTIONAL, &dt_data, &dt_len);

	conf_noffset = fit_conf_get_node((const void *)header,
					 fit_uname_config);
	if (conf_noffset <= 0)
		return 0;

	for (idx = 0;
	     uname = fdt_stringlist_get((const void *)header, conf_noffset,
					FIT_LOADABLE_PROP, idx,
				NULL), uname;
	     idx++)
	{
#ifdef CONFIG_SPL_FIT_SIGNATURE
		images.verify = 1;
#endif
		ret = fit_image_load(&images, (ulong)header,
				     &uname, &fit_uname_config,
				     IH_ARCH_DEFAULT, IH_TYPE_LOADABLE, -1,
				     FIT_LOAD_OPTIONAL_NON_ZERO,
				     &img_data, &img_len);
		if (ret < 0)
			return ret;
	}

	return 0;
}
#endif

int spl_parse_image_header(struct spl_image_info *spl_image,
			   const struct image_header *header)
{
#ifdef CONFIG_SPL_LOAD_FIT_FULL
	int ret = spl_load_fit_image(spl_image, header);

	if (!ret)
		return ret;
#endif
	if (image_get_magic(header) == IH_MAGIC) {
#ifdef CONFIG_SPL_LEGACY_IMAGE_SUPPORT
		u32 header_size = sizeof(struct image_header);

		if (spl_image->flags & SPL_COPY_PAYLOAD_ONLY) {
			/*
			 * On some system (e.g. powerpc), the load-address and
			 * entry-point is located at address 0. We can't load
			 * to 0-0x40. So skip header in this case.
			 */
			spl_image->load_addr = image_get_load(header);
			spl_image->entry_point = image_get_ep(header);
			spl_image->size = image_get_data_size(header);
		} else {
			spl_image->entry_point = image_get_load(header);
			/* Load including the header */
			spl_image->load_addr = spl_image->entry_point -
				header_size;
			spl_image->size = image_get_data_size(header) +
				header_size;
		}
		spl_image->os = image_get_os(header);
		spl_image->name = image_get_name(header);
		debug(SPL_TPL_PROMPT
		      "payload image: %32s load addr: 0x%lx size: %d\n",
		      spl_image->name, spl_image->load_addr, spl_image->size);
#else
		/* LEGACY image not supported */
		debug("Legacy boot image support not enabled, proceeding to other boot methods\n");
		return -EINVAL;
#endif
	} else {
#ifdef CONFIG_SPL_PANIC_ON_RAW_IMAGE
		/*
		 * CONFIG_SPL_PANIC_ON_RAW_IMAGE is defined when the
		 * code which loads images in SPL cannot guarantee that
		 * absolutely all read errors will be reported.
		 * An example is the LPC32XX MLC NAND driver, which
		 * will consider that a completely unreadable NAND block
		 * is bad, and thus should be skipped silently.
		 */
		panic("** no mkimage signature but raw image not supported");
#endif

#ifdef CONFIG_SPL_OS_BOOT
		ulong start, end;

		if (!bootz_setup((ulong)header, &start, &end)) {
			spl_image->name = "Linux";
			spl_image->os = IH_OS_LINUX;
			spl_image->load_addr = CONFIG_SYS_LOAD_ADDR;
			spl_image->entry_point = CONFIG_SYS_LOAD_ADDR;
			spl_image->size = end - start;
			debug(SPL_TPL_PROMPT
			      "payload zImage, load addr: 0x%lx size: %d\n",
			      spl_image->load_addr, spl_image->size);
			return 0;
		}
#endif

#ifdef CONFIG_SPL_RAW_IMAGE_SUPPORT
		/* Signature not found - assume u-boot.bin */
		debug("mkimage signature not found - ih_magic = %x\n",
			header->ih_magic);
		spl_set_header_raw_uboot(spl_image);
#else
		/* RAW image not supported, proceed to other boot methods. */
		debug("Raw boot image support not enabled, proceeding to other boot methods\n");
		return -EINVAL;
#endif
	}

	return 0;
}

__weak void __noreturn jump_to_image_no_args(struct spl_image_info *spl_image)
{
	typedef void __noreturn (*image_entry_noargs_t)(void);

	image_entry_noargs_t image_entry =
		(image_entry_noargs_t)spl_image->entry_point;

	debug("image entry point: 0x%lx\n", spl_image->entry_point);
	image_entry();
}

#if CONFIG_IS_ENABLED(HANDOFF)
/**
 * Set up the SPL hand-off information
 *
 * This is initially empty (zero) but can be written by
 */
static int setup_spl_handoff(void)
{
	struct spl_handoff *ho;

	ho = bloblist_ensure(BLOBLISTT_SPL_HANDOFF, sizeof(struct spl_handoff));
	if (!ho)
		return -ENOENT;

	return 0;
}

static int write_spl_handoff(void)
{
	struct spl_handoff *ho;

	ho = bloblist_find(BLOBLISTT_SPL_HANDOFF, sizeof(struct spl_handoff));
	if (!ho)
		return -ENOENT;
	handoff_save_dram(ho);
#ifdef CONFIG_SANDBOX
	ho->arch.magic = TEST_HANDOFF_MAGIC;
#endif
	debug(SPL_TPL_PROMPT "Wrote SPL handoff\n");

	return 0;
}
#else
static inline int setup_spl_handoff(void) { return 0; }
static inline int write_spl_handoff(void) { return 0; }

#endif /* HANDOFF */

static int spl_common_init(bool setup_malloc)
{
	int ret;

#if CONFIG_VAL(SYS_MALLOC_F_LEN)
	if (setup_malloc) {
#ifdef CONFIG_MALLOC_F_ADDR
		gd->malloc_base = CONFIG_MALLOC_F_ADDR;
#endif
		gd->malloc_limit = CONFIG_VAL(SYS_MALLOC_F_LEN);
		gd->malloc_ptr = 0;
	}
#endif
	ret = bootstage_init(true);
	if (ret) {
		debug("%s: Failed to set up bootstage: ret=%d\n", __func__,
		      ret);
		return ret;
	}
	bootstage_mark_name(BOOTSTAGE_ID_START_SPL, "spl");
#if CONFIG_IS_ENABLED(LOG)
	ret = log_init();
	if (ret) {
		debug("%s: Failed to set up logging\n", __func__);
		return ret;
	}
#endif
	if (CONFIG_IS_ENABLED(BLOBLIST)) {
		ret = bloblist_init();
		if (ret) {
			debug("%s: Failed to set up bloblist: ret=%d\n",
			      __func__, ret);
			return ret;
		}
	}
	if (CONFIG_IS_ENABLED(HANDOFF)) {
		int ret;

		ret = setup_spl_handoff();
		if (ret) {
			puts(SPL_TPL_PROMPT "Cannot set up SPL handoff\n");
			hang();
		}
	}
	if (CONFIG_IS_ENABLED(OF_CONTROL) && !CONFIG_IS_ENABLED(OF_PLATDATA)) {
		ret = fdtdec_setup();
		if (ret) {
			debug("fdtdec_setup() returned error %d\n", ret);
			return ret;
		}
	}
	if (CONFIG_IS_ENABLED(DM)) {
		bootstage_start(BOOTSTATE_ID_ACCUM_DM_SPL, "dm_spl");
		/* With CONFIG_SPL_OF_PLATDATA, bring in all devices */
		ret = dm_init_and_scan(!CONFIG_IS_ENABLED(OF_PLATDATA));
		bootstage_accum(BOOTSTATE_ID_ACCUM_DM_SPL);
		if (ret) {
			debug("dm_init_and_scan() returned error %d\n", ret);
			return ret;
		}
	}

	return 0;
}

void spl_set_bd(void)
{
	/*
	 * NOTE: On some platforms (e.g. x86) bdata may be in flash and not
	 * writeable.
	 */
	if (!gd->bd)
		gd->bd = &bdata;
}

int spl_early_init(void)
{
	int ret;

	debug("%s\n", __func__);

	ret = spl_common_init(true);
	if (ret)
		return ret;
	gd->flags |= GD_FLG_SPL_EARLY_INIT;

	return 0;
}

int spl_init(void)
{
	int ret;
	bool setup_malloc = !(IS_ENABLED(CONFIG_SPL_STACK_R) &&
			IS_ENABLED(CONFIG_SPL_SYS_MALLOC_SIMPLE));

	debug("%s\n", __func__);

	if (!(gd->flags & GD_FLG_SPL_EARLY_INIT)) {
		ret = spl_common_init(setup_malloc);
		if (ret)
			return ret;
	}
	gd->flags |= GD_FLG_SPL_INIT;

	return 0;
}

#ifndef BOOT_DEVICE_NONE
#define BOOT_DEVICE_NONE 0xdeadbeef
#endif

__weak void board_boot_order(u32 *spl_boot_list)
{
	spl_boot_list[0] = spl_boot_device();
}

static struct spl_image_loader *spl_ll_find_loader(uint boot_device)
{
	struct spl_image_loader *drv =
		ll_entry_start(struct spl_image_loader, spl_image_loader);
	const int n_ents =
		ll_entry_count(struct spl_image_loader, spl_image_loader);
	struct spl_image_loader *entry;

	for (entry = drv; entry != drv + n_ents; entry++) {
		if (boot_device == entry->boot_device)
			return entry;
	}

	/* Not found */
	return NULL;
}

static int spl_load_image(struct spl_image_info *spl_image,
			  struct spl_image_loader *loader)
{
	struct spl_boot_device bootdev;

	bootdev.boot_device = loader->boot_device;
	bootdev.boot_device_name = NULL;

	return loader->load_image(spl_image, &bootdev);
}

/**
 * boot_from_devices() - Try loading an booting U-Boot from a list of devices
 *
 * @spl_image: Place to put the image details if successful
 * @spl_boot_list: List of boot devices to try
 * @count: Number of elements in spl_boot_list
 * @return 0 if OK, -ve on error
 */
static int boot_from_devices(struct spl_image_info *spl_image,
			     u32 spl_boot_list[], int count)
{
	int i;

	for (i = 0; i < count && spl_boot_list[i] != BOOT_DEVICE_NONE; i++) {
		struct spl_image_loader *loader;

		loader = spl_ll_find_loader(spl_boot_list[i]);
#if defined(CONFIG_SPL_SERIAL_SUPPORT) && defined(CONFIG_SPL_LIBCOMMON_SUPPORT)
		if (loader)
			printf("Trying to boot from %s\n", loader->name);
		else
			puts(SPL_TPL_PROMPT "Unsupported Boot Device!\n");
#endif
		if (loader && !spl_load_image(spl_image, loader)) {
			spl_image->boot_device = spl_boot_list[i];
			return 0;
		}
	}

	return -ENODEV;
}

void board_init_r(gd_t *dummy1, ulong dummy2)
{
	u32 spl_boot_list[] = {
		BOOT_DEVICE_NONE,
		BOOT_DEVICE_NONE,
		BOOT_DEVICE_NONE,
		BOOT_DEVICE_NONE,
		BOOT_DEVICE_NONE,
	};
	struct spl_image_info spl_image;
	int ret;

	preloader_console_init();
	debug(">>" SPL_TPL_PROMPT "board_init_r()\n");

	spl_set_bd();

#if defined(CONFIG_SYS_SPL_MALLOC_START)
	mem_malloc_init(CONFIG_SYS_SPL_MALLOC_START,
			CONFIG_SYS_SPL_MALLOC_SIZE);
	gd->flags |= GD_FLG_FULL_MALLOC_INIT;
#endif
	if (!(gd->flags & GD_FLG_SPL_INIT)) {
		if (spl_init())
			hang();
	}
#if !defined(CONFIG_PPC) && !defined(CONFIG_ARCH_MX6)
	/*
	 * timer_init() does not exist on PPC systems. The timer is initialized
	 * and enabled (decrementer) in interrupt_init() here.
	 */
	timer_init();
#endif

#if CONFIG_IS_ENABLED(BOARD_INIT)
	spl_board_init();
#endif

	if (IS_ENABLED(CONFIG_SPL_OS_BOOT) || CONFIG_IS_ENABLED(HANDOFF))
		dram_init_banksize();

	bootcount_inc();

	memset(&spl_image, '\0', sizeof(spl_image));
#ifdef CONFIG_SYS_SPL_ARGS_ADDR
	spl_image.arg = (void *)CONFIG_SYS_SPL_ARGS_ADDR;
#endif
	spl_image.boot_device = BOOT_DEVICE_NONE;
	board_boot_order(spl_boot_list);

	if (boot_from_devices(&spl_image, spl_boot_list,
			      ARRAY_SIZE(spl_boot_list))) {
		puts(SPL_TPL_PROMPT "failed to boot from all boot devices\n");
		hang();
	}

	spl_perform_fixups(&spl_image);
	if (CONFIG_IS_ENABLED(HANDOFF)) {
		ret = write_spl_handoff();
		if (ret)
			printf(SPL_TPL_PROMPT
			       "SPL hand-off write failed (err=%d)\n", ret);
	}
	if (CONFIG_IS_ENABLED(BLOBLIST)) {
		ret = bloblist_finish();
		if (ret)
			printf("Warning: Failed to finish bloblist (ret=%d)\n",
			       ret);
	}

#ifdef CONFIG_CPU_V7M
	spl_image.entry_point |= 0x1;
#endif
	switch (spl_image.os) {
	case IH_OS_U_BOOT:
		debug("Jumping to U-Boot\n");
		break;
#if CONFIG_IS_ENABLED(ATF)
	case IH_OS_ARM_TRUSTED_FIRMWARE:
		debug("Jumping to U-Boot via ARM Trusted Firmware\n");
		spl_invoke_atf(&spl_image);
		break;
#endif
#if CONFIG_IS_ENABLED(OPTEE)
	case IH_OS_TEE:
		debug("Jumping to U-Boot via OP-TEE\n");
		spl_optee_entry(NULL, NULL, spl_image.fdt_addr,
				(void *)spl_image.entry_point);
		break;
#endif
#ifdef CONFIG_SPL_OS_BOOT
	case IH_OS_LINUX:
		debug("Jumping to Linux\n");
		spl_fixup_fdt();
		spl_board_prepare_for_linux();
		jump_to_image_linux(&spl_image);
#endif
	default:
		debug("Unsupported OS image.. Jumping nevertheless..\n");
	}
#if CONFIG_VAL(SYS_MALLOC_F_LEN) && !defined(CONFIG_SYS_SPL_MALLOC_SIZE)
	debug("SPL malloc() used 0x%lx bytes (%ld KB)\n", gd->malloc_ptr,
	      gd->malloc_ptr / 1024);
#endif
#ifdef CONFIG_BOOTSTAGE_STASH
	bootstage_mark_name(BOOTSTAGE_ID_END_SPL, "end_spl");
	ret = bootstage_stash((void *)CONFIG_BOOTSTAGE_STASH_ADDR,
			      CONFIG_BOOTSTAGE_STASH_SIZE);
	if (ret)
		debug("Failed to stash bootstage: err=%d\n", ret);
#endif

	////////////////////////
	// Verifying U-Boot Code

	i2c_set_bus_num(1);
	hal_i2c_random();

	u32 uboot_size = spl_image.size - 64;  // 64 Byte U-Boot header not needed
	char *code_entry = (char*)spl_image.entry_point;
	uint8_t uboot_code[uboot_size];
	memset(uboot_code, 0, uboot_size*sizeof(char));
	int n;

	for (n = 0; n < uboot_size; n++)
	{
		uboot_code[n] = code_entry[n];   
	}    
	char lastchar = uboot_code[uboot_size];
	char *lastestchar = code_entry + uboot_size; 
	
	n = uboot_size*2;
	char converted[(uboot_size * 2) + 1];
	memset(converted, 0, uboot_size*sizeof(char)*2);	
	const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) converted[n] = xx[(uboot_code[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
	converted[uboot_size*2] = '\0'; 
	char *lastconvertedchar = &converted[uboot_size*2]; 

	uint8_t hash[32] = {0};
	sha256_context ctx;
	memset(ctx.buffer, 0, 64*sizeof(uint8_t));
	sha256_starts(&ctx);
	sha256_update(&ctx, converted, uboot_size*2);
	sha256_finish(&ctx, hash);

	const uint8_t realhash[] = {0x9a,0xf9,0x7f,0x45,0xb7,0x5e,0x67,0xb2,0x35,0xfc,0xd4,0xd9,0xf0,0x99,0x11,0x09,0x7a,0x7b,0x2b,0x35,0x77,0xce,0x2d,0xaf,0xef,0x33,0xa7,0x0c,0x11,0x2f,0x64,0x44};
	const uint8_t realsignature[] = {0x80,0x80,0x70,0x15,0xE7,0x02,0xEB,0x53,0xF6,0x41,0xA0,0xC8,0x86,0x16,0x84,0xFB,0x0C,0x1F,0x62,0x06,0x75,0x59,0x5D,0xCB,0x1A,0x7C,0xD8,0xC7,0x1B,0x01,0x8C,0xD0,0x9A,0xFD,0x56,0xE1,0x00,0xD1,0xD5,0x6C,0x4A,0x9D,0x06,0x63,0xDC,0xB5,0x55,0x8F,0x3B,0xCB,0xA4,0x31,0xB2,0x3D,0x41,0x69,0x1C,0x45,0x05,0xC2,0x6B,0x5C,0x00,0x44};  
	const uint8_t publicKey[] = {0xe7,0xa7,0x79,0xfc,0xfc,0xd5,0xe0,0xec,0xdf,0x6d,0x4d,0xd8,0x88,0xb7,0xe4,0x62,0x01,0xd2,0x67,0xc0,0xb1,0x49,0xdb,0x75,0xc4,0x29,0x4b,0x8c,0x34,0x8c,0xad,0x2d,0xb0,0xdb,0x0b,0x9a,0xe8,0x7d,0x21,0xa5,0x54,0x43,0x01,0xd7,0x76,0xfc,0x3f,0xf9,0x03,0x4c,0x8b,0x80,0xc0,0x2a,0xfb,0xf4,0xb7,0x4e,0x0a,0x0e,0x49,0x84,0x6f,0xf8}; 	
	volatile ATCA_STATUS status = ATCA_SUCCESS;
	
	status = atcab_init(&cfg_atecc608b_i2c_default);
	if (status == ATCA_SUCCESS)
	{
		uint8_t randomNumber[32] = {0};
		atcab_random(&randomNumber);

		volatile ATCA_STATUS stat = ATCA_SUCCESS;
		uint16_t keySlot = 10;
		uint16_t testSlot = 11;
		uint8_t checkKey[64] = {0};
		uint8_t testSlotDataWrite[64] = {0xDE};
		uint8_t testSlotDataRead[64] = {0};
		bool is_locked = false;
		bool isverified = false;
		
		uint8_t publicKey_se[72] = {0xe7,0xa7,0x79,0xfc,0xfc,0xd5,0xe0,0xec,0xdf,0x6d,0x4d,0xd8,0x88,0xb7,0xe4,0x62,0x01,0xd2,0x67,0xc0,0xb1,0x49,0xdb,0x75,0xc4,0x29,0x4b,0x8c,0x34,0x8c,0xad,0x2d,0xb0,0xdb,0x0b,0x9a,0xe8,0x7d,0x21,0xa5,0x54,0x43,0x01,0xd7,0x76,0xfc,0x3f,0xf9,0x03,0x4c,0x8b,0x80,0xc0,0x2a,0xfb,0xf4,0xb7,0x4e,0x0a,0x0e,0x49,0x84,0x6f,0xf8}; 
		// Reformat public key into padded format
		memmove(&publicKey_se[40], &publicKey_se[32], 32); // Move Y to padded position
		memset(&publicKey_se[36], 0, 4);                 // Add Y padding bytes
		memmove(&publicKey_se[4], &publicKey_se[0], 32);   // Move X to padded position
		memset(&publicKey_se[0], 0, 4);                  // Add X padding bytes

		// Es muss die (gesamte?) Data Zone und OTP Zone gelocked sein, damit
		// man was auslesen kann.. ich denke mal so kann man es checken?
		stat = atcab_is_config_locked(&is_locked);
		stat = atcab_is_data_locked(&is_locked);
		stat = atcab_is_slot_locked(keySlot, &is_locked);
		//ATCA_STATUS atcab_write_pubkey(uint16_t slot, const uint8_t* public_key)
		//stat = atcab_write_pubkey(keySlot, publicKey_se);
		//stat = atcab_write_bytes_zone(ATCA_ZONE_DATA, testSlot, 0, publicKey_se, 72);
		//stat = atcab_lock_data_slot(testSlot);
		if (!is_locked)
		{
			stat = atcab_write_bytes_zone(ATCA_ZONE_DATA, keySlot, 0, publicKey, 64);
			stat = atcab_lock_data_slot(keySlot);
			
			// Hiermit könnte man die gesamte Data Zone locken, nur
			// wollen wir das so? Dann kann man nichts mehr überschreiben
			// Okay, anscheinend locked es nicht alles?
			//stat = atcab_lock_data_zone();
		} 
		stat = atcab_is_slot_locked(testSlot, &is_locked);
		stat = atcab_read_bytes_zone(ATCA_ZONE_DATA, keySlot, 0, &checkKey, 64);
		//stat = atcab_read_bytes_zone(ATCA_ZONE_DATA, testSlot, 0, &testSlotDataRead, 64);

		stat = atcab_nonce_base(NONCE_MODE_TARGET_MSGDIGBUF, 0, realhash, NULL);
		stat = atcab_read_bytes_zone(ATCA_ZONE_DATA, testSlot, 0, &testSlotDataRead, 64);

		stat = atcab_verify_extern(realhash, realsignature, publicKey, &isverified);
		stat = atcab_verify(VERIFY_MODE_STORED, testSlot, realsignature, NULL, NULL, NULL);
		
		//atcab_verify_stored(const uint8_t* message, const uint8_t* signature, uint16_t key_id, bool* is_verified)
		stat = atcab_verify_stored(realhash, realsignature, testSlot, &isverified);

		stat = atcab_verify_extern(realhash, realsignature, publicKey, &isverified);
		int i = 0;
		i += 1;
	}	
	debug("loaded - jumping to U-Boot...\n");

	spl_board_prepare_for_boot(); 
	jump_to_image_no_args(&spl_image);
}

#ifdef CONFIG_SPL_SERIAL_SUPPORT
/*
 * This requires UART clocks to be enabled.  In order for this to work the
 * caller must ensure that the gd pointer is valid.
 */
void preloader_console_init(void)
{
	gd->baudrate = CONFIG_BAUDRATE;

	serial_init();		/* serial communications setup */

	gd->have_console = 1;

#if CONFIG_IS_ENABLED(BANNER_PRINT)
	puts("\nU-Boot " SPL_TPL_NAME " " PLAIN_VERSION " (" U_BOOT_DATE " - "
	     U_BOOT_TIME " " U_BOOT_TZ ")\n");
#endif
#ifdef CONFIG_SPL_DISPLAY_PRINT
	spl_display_print();
#endif
}
#endif

/**
 * spl_relocate_stack_gd() - Relocate stack ready for board_init_r() execution
 *
 * Sometimes board_init_f() runs with a stack in SRAM but we want to use SDRAM
 * for the main board_init_r() execution. This is typically because we need
 * more stack space for things like the MMC sub-system.
 *
 * This function calculates the stack position, copies the global_data into
 * place, sets the new gd (except for ARM, for which setting GD within a C
 * function may not always work) and returns the new stack position. The
 * caller is responsible for setting up the sp register and, in the case
 * of ARM, setting up gd.
 *
 * All of this is done using the same layout and alignments as done in
 * board_init_f_init_reserve() / board_init_f_alloc_reserve().
 *
 * @return new stack location, or 0 to use the same stack
 */
ulong spl_relocate_stack_gd(void)
{
#ifdef CONFIG_SPL_STACK_R
	gd_t *new_gd;
	ulong ptr = CONFIG_SPL_STACK_R_ADDR;

#if defined(CONFIG_SPL_SYS_MALLOC_SIMPLE) && CONFIG_VAL(SYS_MALLOC_F_LEN)
	if (CONFIG_SPL_STACK_R_MALLOC_SIMPLE_LEN) {
		ptr -= CONFIG_SPL_STACK_R_MALLOC_SIMPLE_LEN;
		gd->malloc_base = ptr;
		gd->malloc_limit = CONFIG_SPL_STACK_R_MALLOC_SIMPLE_LEN;
		gd->malloc_ptr = 0;
	}
#endif
	/* Get stack position: use 8-byte alignment for ABI compliance */
	ptr = CONFIG_SPL_STACK_R_ADDR - roundup(sizeof(gd_t),16);
	new_gd = (gd_t *)ptr;
	memcpy(new_gd, (void *)gd, sizeof(gd_t));
#if CONFIG_IS_ENABLED(DM)
	dm_fixup_for_gd_move(new_gd);
#endif
#if !defined(CONFIG_ARM)
	gd = new_gd;
#endif
	return ptr;
#else
	return 0;
#endif
}
