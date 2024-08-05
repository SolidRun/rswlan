// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#endif
#include "rs_irq.h"
#include "rs_irq_rx.h"
#include "rs_irq_tx_kb.h"
#include "rs_priv.h"
#include "rs_rx.h"
#include "rs_tx.h"

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

static u32 gpio_reset;
u32 spi_clk;

////////////////////////////////////////////////////////////////////////////////
/// FUNCTIONS

static void spi_bus_ops_irq_work(struct work_struct *work)
{
	struct rs_hw_priv *hw_priv = NULL;
	struct rs_core *core = NULL;

	if (work != NULL) {
		hw_priv = container_of(work, struct rs_hw_priv, irq.wk);

		if ((hw_priv != NULL) && (hw_priv->core != NULL)) {
			core = hw_priv->core;

			(void)rs_isr_main(core);

			enable_irq(core->bus.gpio.irq0_nb);
		}
	}
}

/**
 * @brief Check if SPI is ready
 *
 * @param [rs_core]
 *
 * @return s32
 */
s32 spi_check_ready(struct rs_core *rs_core)
{
	u32 *wtemp = kmalloc(4, GFP_KERNEL);
	u32 *rtemp = kmalloc(4, GFP_KERNEL);
	s32 ret = -1;
	s32 i;

	*wtemp = SPI_CHECK_DATA;

	for (i = 0; i < 200; i++) {
		rs_spi_bus_write(rs_core, SPI_CHECK_ADDR, (u8 *)wtemp, SPI_CHECK_BIT);
		rs_spi_bus_read(rs_core, SPI_CHECK_ADDR, (u8 *)rtemp, SPI_CHECK_BIT);
		if (*rtemp != *wtemp) {
			udelay(1000);
			continue;
		} else {
			ret = 0;
			break;
		}
	}

	kfree(wtemp);
	kfree(rtemp);

	return ret;
}

void hw_reset_fw(void);

s32 spi_probe_fw_download(struct rs_core *core, char *file)
{
	char *filename = RS_MAC_FW_NAME_SPI;
	u8 fw_buffer[BURST_LENGTH];
	struct device *dev = core_to_dev(core);
	const struct firmware *lmac_fw;
	s32 ret, i, iteration, remain_length;
	u32 gpioa_pe_ps = 0;
	/* setting boot mode as SRAM write 0x01 to 0x50000000 */
	struct reg_n_addr reg_addr[6] = { { BOOT_MODE_ADDR, BOOT_MODE_SRAM },
					  // cpu reset
					  { 0x5000502c, 0x50002014 },
					  { 0x50005028, 0x50080278 },
					  { 0x50080278, 0x01 },
					  { 0x50005020, 0xaa000007 },
					  { 0x50005008, 0x01 } };

	pr_info("FW downloading...\n");

	ret = -1;
	for (i = 0; i < 10; i++) {
		if_spi_change_header_mode_8B(core);
		if (spi_check_ready(core)) {
			hw_reset_fw();
			udelay(1000);
		} else {
			ret = 0;
			break;
		}
	}
	if (!!ret) {
		pr_crit("SPI is not ready!\n");
		return ret;
	}

	/* PORTA pull-down setting to 0 */
	rs_spi_bus_write(core, GPIOA_PE_PS, (u8 *)&gpioa_pe_ps, 4);

	// file read
	if ((ret = request_firmware(&lmac_fw, filename, dev))) {
		pr_err("Failed to get %s, err %d\n", filename, ret);
		return ret;
	}
	pr_info("FW name %s, size %ld, First 4 bytes : %02x, %02x, %02x, %02x\n", filename, lmac_fw->size,
		lmac_fw->data[0], lmac_fw->data[1], lmac_fw->data[2], lmac_fw->data[3]);

	iteration = lmac_fw->size / BURST_LENGTH;
	remain_length = lmac_fw->size % BURST_LENGTH;

	for (i = 0; i < iteration; i++) {
		memcpy(fw_buffer, &lmac_fw->data[i * BURST_LENGTH], BURST_LENGTH);
		rs_spi_bus_write(core, SRAM_BASE_ADDR + (i * BURST_LENGTH), fw_buffer, BURST_LENGTH);
	}

	memcpy(fw_buffer, &lmac_fw->data[i * BURST_LENGTH], remain_length);
	rs_spi_bus_write(core, SRAM_BASE_ADDR + (i * BURST_LENGTH), fw_buffer, remain_length);

	pr_info("FW downloading Done.\n");

	// set CPU
	for (i = 0; i < 6; i++) {
		rs_spi_bus_write(core, reg_addr[i].addr, (u8 *)(&reg_addr[i].value),
				 sizeof(reg_addr[i].value));
	}

	release_firmware(lmac_fw);

	return 0;
}

void spi_host_reset(struct rs_core *core)
{
	RS_DBG(RS_FN_ENTRY_STR);

	*((u32 *)&(core->bus.host_req)) = 0;
	core->bus.host_req.cmd = HOST_RESET_ASK;

	if (rs_spi_bus_write(core, RS_A2E_CMD_ADDR, (u8 *)&(core->bus.host_req),
			     sizeof(struct st_mgmt_req))) {
		return;
	}

	msleep(20);

	pr_info("host_reset\n");
}

static void spi_bus_ops_deinit(struct rs_core *core)
{
	RS_DBG(RS_FN_ENTRY_STR);

	rs_kill_mgmt_tx_thread(core);

	disable_irq(core->bus.gpio.irq0_nb);
	free_irq(core->bus.gpio.irq0_nb, core);
	gpio_free(core->bus.gpio.irq0);

	/* send reset */
	spi_host_reset(core);

	if (!!core)
		kfree(core);
}

/**
 * rs_spi_platform_init - Initialize the rz series platform using SPI interface
 *
 * @spi_device SPI device
 * @rs_core Pointer on struct rs_stat * to be populated
 *
 * @return 0 on success, < 0 otherwise
 *
 * Allocate and initialize a rs_core structure for the SPI platform.
 */
s32 spi_probe_init_core(struct spi_device *spi, struct rs_core **core)
{
	s32 err = 0;
	struct device_node *np = spi->dev.of_node;

	*core = kzalloc(sizeof(struct rs_core), GFP_KERNEL);
	if (!*core) {
		return -ENOMEM;
	}

	(*core)->priv = NULL;

	mutex_init(&((*core)->bus.lock));
	mutex_init(&((*core)->bus.mgmt_lock));

	if (np) {
		s32 gpio = of_get_named_gpio(np, "irq0-gpios", 0);
		if (gpio_is_valid(gpio)) {
			(*core)->bus.gpio.irq0 = gpio;
		} else {
			dev_err(&spi->dev, "GPIO%d(irq0-gpios): Valid check failure\n", gpio);
			goto err_wq;
		}

		gpio = of_get_named_gpio(np, "reset-gpios", 0);
		if (gpio_is_valid(gpio)) {
			(*core)->bus.gpio.reset = gpio;
			gpio_reset = gpio;
		} else {
			dev_err(&spi->dev, "GPIO%d(reset-gpios): Valid check failure\n", gpio);
			goto err_wq;
		}

		spi_clk = spi->max_speed_hz;
	} else {
		dev_err(&spi->dev, "Error: No DeviceNode\n");
		goto err_wq;
	}
	/* HW reset DA16xx module */
	hw_reset_fw();
	udelay(1000);

	dev_info(&spi->dev, "CS %d Mode %d %dMhz, %dbit \n", spi->chip_select, spi->mode,
		 spi->max_speed_hz / 1000000, spi->bits_per_word);

	err = spi_setup(spi);
	if (err < 0) {
		goto err_wq;
	}

	skb_queue_head_init(&(*core)->mgmt_tx_queue);

	rs_init_event(&(*core)->mgmt_thread.event);
	if (rs_create_kthread(*core, &(*core)->mgmt_thread, rs_mgmt_tx_thread, "Tx-Thread")) {
		err = -ENOMEM;
		goto err_wq;
	}
	(*core)->init_done = true;

	(*core)->bus.spi = spi;
	(*core)->bus.ops.read = rs_spi_bus_read;
	(*core)->bus.ops.write = rs_spi_tx_write;
	(*core)->bus.ops.deinit = spi_bus_ops_deinit;
	(*core)->bus.ops.init_mac_addr = core_bus_ops_init_mac_addr;
	(*core)->bus.ops.init_bus_addr = core_bus_ops_init_bus_addr;
	(*core)->bus.ops.mgmt_pkt_write = rs_spi_mgmt_write;
	(*core)->bus.ops.tx_kick = tx_bus_ops_kick;
	(*core)->bus.ops.tx_rec = tx_bus_ops_recovery;
	/// SPI shouldn't be sent bulk data sending way.
	(*core)->bus.ops.tx_trig = NULL;
	(*core)->bus.ops.q_update = tx_bus_ops_q_update;
	(*core)->bus.ops.irq_status = rs_irq_bus_ops_status;
	(*core)->bus.ops.irq_work = spi_bus_ops_irq_work;
	(*core)->bus.ops.irq_kickback = NULL;

	if (!rs_get_fw_sflash()) { /* DA16600 FLASH model */
		err = spi_probe_fw_download(*core, NULL);
		if (err != 0) {
			pr_err("fw download err %d\n", err);
			goto err_wq;
		}
		msleep(100);
	} else {
		dev_info(&spi->dev, "FW SFLAH mode. No download FW image.\n");
	}

	err = gpio_request((*core)->bus.gpio.irq0, "rswlan_irq0");
	if (err != 0) {
		dev_err(&spi->dev, "gpio_request err %d\n", err);
		goto err_wq;
	}
	err = gpio_direction_input((*core)->bus.gpio.irq0);
	if (err != 0) {
		dev_err(&spi->dev, "gpio_direction_input err %d\n", err);
		goto err_wq;
	}
	(*core)->bus.gpio.irq0_nb = gpio_to_irq((*core)->bus.gpio.irq0);
	err = request_irq((*core)->bus.gpio.irq0_nb, rs_irq_handler, IRQF_TRIGGER_RISING, "rswlan_irq0",
			  *core);
	if (err != 0) {
		dev_err(&spi->dev, "request_irq err %d\n", err);
		goto err_wq;
	}

	return err;

err_wq:
	kfree((*core));

	return err;
}

void hw_reset_fw(void)
{
	u32 pin = gpio_reset;

	gpio_request(pin, "rswlan_reset");
	gpio_direction_output(pin, 0);

	gpio_set_value(pin, 0);
	msleep(100);
	gpio_set_value(pin, 1);

	gpio_free(pin);
}
EXPORT_SYMBOL(hw_reset_fw);
