// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/mmc/host.h>
#include <linux/mmc/sdio.h>

#include "rs_priv.h"

#include "rs_irq.h"
#include "rs_irq_rx.h"
#include "rs_irq_tx_kb.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define READ_WRITE_SIZE		 4

// Base address for SDIO read/write
#define SDIO_BASE_ADDRESS	 0x44

#define SDIO_CPU_RESET_REG_COUNT 5

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

/**
 * sdio_blk_size - Calculate block size
 *
 * @length: length of data
 *
 * Return: block size
 */
static inline u32 sdio_blk_size(u32 length)
{
	u32 n;

	if (length <= SDIO_BLOCK_SIZE)
		return length;

	n = (length - 1) / SDIO_BLOCK_SIZE;

	return (n + 1) * SDIO_BLOCK_SIZE;
}

static s32 sdio_io_ready(struct rs_core *rs_core, u32 addr)
{
	s32 err = 0;
	struct sdio_func *func = rs_core->bus.sdio;

	func->num = 0;
	sdio_writel(func, addr, SDIO_BASE_ADDRESS, &err);

	if (err) {
		pr_err("failed to set sdio base addr to read/write err: 0x%x", err);
	}

	func->num = 1;
	return err;
}

static s32 sdio_bus_read(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 err = 0;
	struct sdio_func *func = core->bus.sdio;
	int cnt = 0;

CLAIM:
	sdio_claim_host(func);

	if (++cnt > 100) {
		pr_err("failed sdio claim host 100 times!!!\n");
		return -1;
	}

	if (!func->card->host->claimed) {
		goto CLAIM;
	}

	if (!!(err = sdio_io_ready(core, addr))) {
		sdio_release_host(func);
		return err;
	}

	length += ALIGN_4BYTE(length); // 4 byte align
	err = sdio_memcpy_fromio(func, data, 0, length); // auto incre
	if (err) {
		pr_err("sdio_memcpy_fromio err %d !!!\n", err);
	}
	sdio_release_host(func);

	return err;
}

static s32 sdio_bus_write(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 err = 0;
	struct sdio_func *func = core->bus.sdio;
	int cnt = 0;

CLAIM:
	sdio_claim_host(func);

	if (++cnt > 100) {
		pr_err("failed sdio claim host 100 times!!!\n");
		return -1;
	}

	if (!func->card->host->claimed) {
		goto CLAIM;
	}

	if (!!(err = sdio_io_ready(core, addr))) {
		sdio_release_host(func);
		return err;
	}

	err = sdio_memcpy_toio(func, 0, data, sdio_blk_size(length));
	if (err) {
		pr_err("sdio_memcpy_toio err %d !!!\n", err);
	}
	sdio_release_host(func);

	return err;
}

static void sdio_irq_handler(struct sdio_func *func)
{
	struct rs_core *core = sdio_get_drvdata(func);

	if (!(core && core->priv && core->enabled)) {
		return;
	}

	(void)rs_irq_handler(-1, core);
}

static void sdio_irq_disable(struct rs_core *rs_core)
{
	s32 ret;

	sdio_claim_host(rs_core->bus.sdio);

	ret = sdio_release_irq(rs_core->bus.sdio);
	if (ret) {
		pr_err("Failed to release sdio irq: %d\n", ret);
	}

	sdio_release_host(rs_core->bus.sdio);
}

static s32 sdio_init(struct sdio_func *func, s32 irq_en)
{
	s32 err;
	struct mmc_host *host;
	struct mmc_card *card;
	u8 reg;
	s32 ret = 0;

	card = func->card;
	host = card->host;

	sdio_claim_host(func);

	sdio_enable_func(func);
	sdio_set_block_size(func, SDIO_BLOCK_SIZE);

	// check sdio config
	// cccr_card_cap
	reg = sdio_f0_readb(func, SDIO_CCCR_CAPS, &err);
	if (reg == 0xff && err) {
		pr_err("failed to read SDIO_CCCR_CAPS: reg=0x%x, err=%x\n", reg, err);
		goto out;
	}

	// Check SDIO_CCCR_IF
	reg = sdio_f0_readb(func, SDIO_CCCR_IF, &err);
	if (reg == 0xff && err) {
		pr_err("failed to read SDIO_CCCR_IF: reg=0x%x, err=%x\n", reg, err);
		goto out;
	}

	if (irq_en) {
		// enable interrupt
		reg = sdio_f0_readb(func, SDIO_CCCR_IENx, &err);
		if (err)
			goto out;

		reg |= BIT(0);
		reg |= BIT(func->num);
		sdio_writeb(func, reg, SDIO_CCCR_IENx, &err);
		if (err)
			goto out;

		// set callback
		/*	Claim and activate the IRQ for the given SDIO function. The provided
         *	handler will be called when that IRQ is asserted.  The host is always
         *	claimed already when the handler is called so the handler must not
         *	call sdio_claim_host() nor sdio_release_host().
         */

		ret = sdio_claim_irq(func, sdio_irq_handler);
		if (ret) {
			pr_err("failed set sdio_claim_irq: ret=%d\n", ret);
			goto out;
		}
	}
	sdio_release_host(func);

	// pr_info("DA16200 sdio init done\n");
	return 0;

out:
	sdio_release_host(func);

	return ret;
}

/**
 * @brief: This function is used to download firmware to card
 *
 * @rs_core: rnss platform pointer
 * @file: firmware file name
 *
 * @return: 0 on success, -1 on error
 */
static s32 da16k_sdio_fw_download(struct rs_core *rs_core, char *file)
{
	u32 *wtemp;
	char *filename = RS_MAC_FW_NAME_SDIO;
	u8 *fw_buffer;
	struct device *dev = core_to_dev(rs_core);
	const struct firmware *lmac_fw;
	s32 ret, i, iteration, remain_length;
	u32 gpioa_pe_ps = 0;
	struct reg_n_addr reg_addr[SDIO_CPU_RESET_REG_COUNT] = { { BOOT_MODE_ADDR, BOOT_MODE_SRAM },
								 // cpu reset
								 { 0x5000502c, 0x50002014 },
								 { 0x50005028, 0x50080278 },
								 { 0x50080278, 0x01 },
								 { 0x50005008, 0x01 } };

	pr_info("DA16200 FW downloading...\n");

	fw_buffer = devm_kmalloc(dev, BURST_LENGTH, GFP_KERNEL);
	wtemp = devm_kmalloc(dev, READ_WRITE_SIZE, GFP_KERNEL);

	/* PORTA pull-down setting to 0 */
	*wtemp = gpioa_pe_ps;
	sdio_bus_write(rs_core, GPIOA_PE_PS, (u8 *)wtemp, READ_WRITE_SIZE);

	// file read
	if ((ret = request_firmware(&lmac_fw, filename, dev))) {
		pr_err("%s: Failed to get %s (%d)\n", __func__, filename, ret);
		return ret;
	}

	iteration = lmac_fw->size / BURST_LENGTH;
	remain_length = lmac_fw->size % BURST_LENGTH;

	for (i = 0; i < iteration; i++) {
		memcpy(fw_buffer, &lmac_fw->data[i * BURST_LENGTH], BURST_LENGTH);
		sdio_bus_write(rs_core, SRAM_BASE_ADDR + (i * BURST_LENGTH), fw_buffer, BURST_LENGTH);
	}

	memcpy(fw_buffer, &lmac_fw->data[i * BURST_LENGTH], remain_length);
	sdio_bus_write(rs_core, SRAM_BASE_ADDR + (i * BURST_LENGTH), fw_buffer, remain_length);
	pr_info("FW downloading Done.\n");

	// set CPU
	for (i = 0; i < SDIO_CPU_RESET_REG_COUNT; i++) {
		*wtemp = reg_addr[i].value;
		sdio_bus_write(rs_core, reg_addr[i].addr, (u8 *)(wtemp), READ_WRITE_SIZE);
	}

	release_firmware(lmac_fw);

	devm_kfree(dev, wtemp);
	devm_kfree(dev, fw_buffer);
	return 0;
}

/**
 * @brief This function is used to send reset command to the device.
 *
 * @param[in] rs_core: platform data
 *
 * @return void
 */
static void host_reset(struct rs_core *rs_core)
{
	RS_DBG(RS_FN_ENTRY_STR);

	*((u32 *)&(rs_core->bus.host_req)) = 0;
	rs_core->bus.host_req.cmd = HOST_RESET_ASK;

	if (sdio_bus_write(rs_core, RS_A2E_CMD_ADDR, (u8 *)&(rs_core->bus.host_req),
			   sizeof(struct st_mgmt_req))) {
		return;
	}

	msleep(20);

	pr_info("host_reset\n");
}

static void sdio_bus_ops_deinit(struct rs_core *rs_core)
{
	struct sdio_func *func = rs_core->bus.sdio;

	rs_kill_mgmt_tx_thread(rs_core);
	sdio_irq_disable(rs_core);

	/* send reset */
	host_reset(rs_core);

	sdio_claim_host(func);
	sdio_disable_func(func);
	sdio_release_host(func);
	rs_core->bus.sdio = NULL;

#if defined(CONFIG_HOST_TX_MERGE)
	rs_tx_merge_buf_deinit();
#endif

	if (!!rs_core)
		kfree(rs_core);
}

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 sdio_probe_init_core(struct sdio_func *sdio, struct rs_core **core)
{
	s32 ret = 0;

	*core = kzalloc(sizeof(struct rs_core), GFP_KERNEL);
	if (!*core) {
		pr_err("failed to alloc platform memory\n");
		return -ENOMEM;
	}

	mutex_init(&((*core)->bus.lock));
	mutex_init(&((*core)->bus.mgmt_lock));

	(*core)->bus.sdio = sdio;
	sdio_set_drvdata(sdio, *core);

	/* da16k sdio device setting */
	if (sdio_init(sdio, 1)) {
		pr_err("failed to init sdio");
		ret = -ENOPROTOOPT;
		goto fail;
	}

	skb_queue_head_init(&(*core)->mgmt_tx_queue);

	rs_init_event(&(*core)->mgmt_thread.event);
	if (rs_create_kthread(*core, &(*core)->mgmt_thread, rs_mgmt_tx_thread, "Tx-Thread")) {
		ret = -ENOMEM;
		goto fail;
	}
	(*core)->init_done = true;

#if defined(CONFIG_HOST_TX_MERGE)
	rs_tx_merge_buf_init();
#endif

	(*core)->bus.ops.read = sdio_bus_read;
	(*core)->bus.ops.write = sdio_bus_write;
	(*core)->bus.ops.deinit = sdio_bus_ops_deinit;
	(*core)->bus.ops.init_mac_addr = core_bus_ops_init_mac_addr;
	(*core)->bus.ops.init_bus_addr = core_bus_ops_init_bus_addr;
	(*core)->bus.ops.mgmt_pkt_write = sdio_bus_write;
	(*core)->bus.ops.tx_kick = tx_bus_ops_kick;
	(*core)->bus.ops.tx_rec = tx_bus_ops_recovery;
#if defined(CONFIG_HOST_TX_MERGE)
	(*core)->bus.ops.tx_merge_kick = tx_bus_ops_merge_kick;
	(*core)->bus.ops.tx_merge_data = tx_bus_ops_merge_data;
#endif
	(*core)->bus.ops.tx_trig = tx_bus_ops_trig;
	(*core)->bus.ops.q_update = tx_bus_ops_q_update;
	(*core)->bus.ops.irq_status = rs_irq_bus_ops_status;
	(*core)->bus.ops.irq_work = NULL;
	(*core)->bus.ops.irq_kickback = NULL;

fail:
	if (ret) {
		kfree((*core));
	}

	return ret;
}

s32 sdio_probe_fw_download(struct sdio_func *func)
{
	struct rs_core *rs_core = NULL;
	s32 ret = 0;

	rs_core = kzalloc(sizeof(struct rs_core), GFP_KERNEL);
	if (!rs_core)
		return -ENOMEM;

	// pr_info("devname %s\n", dev_name(&func->dev));

	(rs_core)->bus.sdio = func;
	sdio_set_drvdata(func, rs_core);

	/* da16k sdio init */
	sdio_init(func, 0);

	/* download fw */
	da16k_sdio_fw_download(rs_core, NULL);
	kfree((rs_core));

	return ret;
}
