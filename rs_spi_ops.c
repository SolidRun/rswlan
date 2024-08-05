// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>
#include <linux/of.h>

#include "rs_priv.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define SPI_READ	      0x40
#define SPI_WRITE	      0x00
#define SPI_AINC	      0x80

#define SPI_CMD_WRITE	      0x0
#define SPI_CMD_READ	      0x1
#define SPI_CMD_BURST_WRITE   0x2
#define SPI_CMD_BURST_READ    0x3

#define MAX_DATA_LENGTH	      0xFFFFFF
#define SET_SPI_TX_DATA(v, s) ((v) >> (8 * (s))) & 0xff
#define SPI_HEADER_SIZE	      8
#define SPI_HEADER_HALF_SIZE  SPI_HEADER_SIZE / 2
#define WIFI_BUF_SIZE	      1024 * 4

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

enum rs_dev_type
{
	da16200,
	da16400,
};

static u8 *tx_buffer = NULL;
static u8 *rx_buffer = NULL;
static unsigned long prev_xfer_time; // = jiffies;
static DEFINE_MUTEX(lock);

static const struct spi_device_id da16xxx_id[] = { { "da16200", da16200 }, { "da16400", da16400 }, {} };
MODULE_DEVICE_TABLE(spi, da16xxx_id);

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

static inline void if_spi_transaction_init(struct rs_core *core)
{
	if (!time_after(jiffies, prev_xfer_time + 1)) {
		/* Unfortunately, the spi requires a delay between successive
         * transactions. If our last transaction was more than a jiffy
         * ago, we have obviously already delayed enough.
         * If not, we have to busy-wait to be on the safe side. */
		ndelay(1);
	}
}

static inline void if_spi_transaction_finish(struct rs_core *core)
{
	prev_xfer_time = jiffies;
}

/*
 * Write out a buffer to an SPI register,
 * using a series of 16-bit transfers.
 */
static inline s32 bus_write(struct rs_core *rs_core, const u8 *buf, s32 len)
{
	s32 err = 0;
	struct spi_message m;
	struct spi_transfer d;
	u8 *tx_buf = kmalloc(len, GFP_KERNEL);

	spi_message_init(&m);
	memset(&d, 0, sizeof(d));

	/*
     * You must take an even number of bytes from the SPU, even if you
     * don't care about the last one.
     */
	BUG_ON(len & 0x1);

	if_spi_transaction_init(rs_core);

	memcpy(tx_buf, buf, len);

	d.tx_buf = tx_buf;
	d.len = len;
	spi_message_add_tail(&d, &m);

	err = spi_sync(rs_core->bus.spi, &m);

	if_spi_transaction_finish(rs_core);

	kfree(tx_buf);
	return err;
}

static inline s32 bus_read(struct rs_core *core, u8 *buf, s32 len)
{
	s32 err = 0;
	struct spi_message m;
	struct spi_transfer d;

	spi_message_init(&m);
	memset(&d, 0, sizeof(d));

	/*
     * You must take an even number of bytes from the SPU, even if you
     * don't care about the last one.
     */
	BUG_ON(len & 0x1);

	if_spi_transaction_init(core);

	memcpy(rx_buffer, tx_buffer, SPI_HEADER_SIZE);

	d.tx_buf = rx_buffer;
	d.rx_buf = rx_buffer;
	d.len = len + SPI_HEADER_SIZE;

	spi_message_add_tail(&d, &m);

	err = spi_sync(core->bus.spi, &m);

	if (!err && buf) {
		memcpy(buf, d.rx_buf + SPI_HEADER_SIZE, len);
	}

	if_spi_transaction_finish(core);

	return err;
}

extern u32 spi_clk;
static inline void make_header(u32 addr, u8 command, u32 length, u8 mode)
{
	s32 i;
	if (mode == 0) { // normal case
		addr = be32_to_cpu(addr);
		for (i = 0; i < SPI_HEADER_SIZE; i++) {
			if (i < SPI_HEADER_HALF_SIZE)
				tx_buffer[i] = SET_SPI_TX_DATA(addr, i);
			else if (i > SPI_HEADER_HALF_SIZE)
				tx_buffer[i] = SET_SPI_TX_DATA(length, 7 - i);
			else
				tx_buffer[SPI_HEADER_HALF_SIZE] = command;
		}
	} else { // for fw download
		if (spi_clk == 50000000) {
			*((u32 *)(&tx_buffer[4])) = 0x9D0B;
		} else {
			*((u32 *)(&tx_buffer[4])) = 0x1D0B;
		}

		tx_buffer[0] = 0x02;
		tx_buffer[1] = 0x40;
		tx_buffer[2] = command | 0x20;
		tx_buffer[3] = length;
	}
}

static s32 if_spi_bulkread(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 ret;
	u8 command = SPI_READ | SPI_AINC;

	if (length > MAX_DATA_LENGTH)
		return -1;

	length += ALIGN_4BYTE(length);

	make_header(addr, command, length, 0);

	ret = bus_read(core, data, length);

	if (ret) {
		pr_err("rs_spi_read fail : %d\n", ret);
		return -1;
	}
	return 0;
}

static s32 if_spi_bulkwrite(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 ret;
	u8 command = SPI_WRITE | SPI_AINC;

	if (length > MAX_DATA_LENGTH) {
		pr_err("rs_spi_write fail \n");
		return -1;
	}

	length += ALIGN_4BYTE(length);

	make_header(addr, command, length, 0);

	ret = bus_write(core, data, length + SPI_HEADER_SIZE);

	if (ret) {
		pr_err("rs_spi_write fail : %d\n", ret);
		return -1;
	}
	return 0;
}

s32 if_spi_change_header_mode_8B(struct rs_core *core)
{
	s32 ret;
	u32 addr = 0x50080240;
	u8 command = SPI_WRITE | SPI_AINC;
	u32 length = 4;

	make_header(addr, command, length, 1);

	ret = bus_write(core, tx_buffer, SPI_HEADER_SIZE);

	if (ret) {
		pr_err("rs_spi_write fail : %d\n", ret);
		return -1;
	}

	return 0;
}

s32 spi_probe_init_core(struct spi_device *spi, struct rs_core **core);

s32 fb_delay;
static s32 spi_drv_cb_probe(struct spi_device *spi)
{
	s32 err = -ENODEV;
	struct rs_core *core = NULL;
	void *drvdata;

	dev_dbg(&spi->dev, "probe\n");

	err = spi_probe_init_core(spi, &core);

	spi_set_drvdata(spi, core);

	if (!err) {
		err = core->bus.ops.init_bus_addr(core);
	}

	if (!err) {
		err = core_init(core, &drvdata);
	}

	if (err) {
		core->bus.ops.deinit(core);
	}

	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
static s32 spi_drv_cb_remove(struct spi_device *spi)
#else
static void spi_drv_cb_remove(struct spi_device *spi)
#endif
{
	struct rs_core *core = spi_get_drvdata(spi);

	dev_dbg(&spi->dev, "remove\n");

	core_deinit(core->priv);
	core->bus.ops.deinit(core);

	mutex_lock(&lock);
	if (tx_buffer) {
		kfree(tx_buffer);
		tx_buffer = NULL;
	}

	if (rx_buffer) {
		kfree(rx_buffer);
		rx_buffer = NULL;
	}
	mutex_unlock(&lock);

	mutex_destroy(&lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	return 0;
#else
	return;
#endif
}

#define DRIVER_NAME "da16xxx_spi" //da16xxx //KBUILD_NONAME //"spi-bcm2835aux"
static const struct spi_device_id da16xx_ids[] = {
	{ "da16xxx_spi" },
	{},
};
MODULE_DEVICE_TABLE(spi, da16xx_ids);

static const struct of_device_id da16k_of_match[] = { { .compatible = "renesas,da16xxx" },
						      { /* sentinel */ } };
MODULE_DEVICE_TABLE(of, da16k_of_match);

static struct spi_driver da16xxx_spi_driver = {
    .driver = {
        .name	    = DRIVER_NAME,
        .bus = &spi_bus_type,
        .of_match_table = of_match_ptr(da16k_of_match),
    },
    .id_table = da16xx_ids,
    .probe    = spi_drv_cb_probe,
    .remove   = spi_drv_cb_remove,
};

s32 rs_spi_bus_read(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 res = 0;

	mutex_lock(&lock);
	if ((rx_buffer != NULL) && (tx_buffer != NULL)) {
		res = if_spi_bulkread(core, addr, data, length);
	}
	mutex_unlock(&lock);

	return res;
}

s32 rs_spi_bus_write(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 res = 0;

	mutex_lock(&lock);
	if ((rx_buffer != NULL) && (tx_buffer != NULL)) {
		memcpy((void *)(tx_buffer + SPI_HEADER_SIZE), (void *)data, length);
		res = if_spi_bulkwrite(core, addr, tx_buffer, length);
	}
	mutex_unlock(&lock);

	return res;
}

s32 rs_spi_tx_write(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 err = -1;

	mutex_lock(&lock);
	if ((rx_buffer != NULL) && (tx_buffer != NULL)) {
		memcpy((void *)(tx_buffer + SPI_HEADER_SIZE), (void *)data, length);
		err = if_spi_bulkwrite(core, addr, tx_buffer, length);

		if (err == 0) {
			core->bus.host_req.cmd = HOST_WRITE_ASK;
			core->bus.host_req.data[0] = (addr & 0xFF);
			core->bus.host_req.data[1] = ((addr >> 8) & 0xFF);
			core->bus.host_req.data[2] = ((addr >> 16) & 0xFF);
			memcpy((void *)(tx_buffer + SPI_HEADER_SIZE), (void *)&(core->bus.host_req),
			       sizeof(struct st_mgmt_req));
			err = if_spi_bulkwrite(core, RS_A2E_CMD_ADDR, tx_buffer, sizeof(struct st_mgmt_req));
		}
	}
	mutex_unlock(&lock);

	return err;
}

s32 rs_spi_mgmt_write(struct rs_core *core, u32 addr, u8 *data, u32 length)
{
	s32 err = -1;

	mutex_lock(&lock);
	if ((rx_buffer != NULL) && (tx_buffer != NULL)) {
		memcpy((void *)(tx_buffer + SPI_HEADER_SIZE), (void *)data, length);
		err = if_spi_bulkwrite(core, addr, tx_buffer, length);

		if (err == 0) {
			*((u32 *)&(core->bus.host_req)) = 0;
			core->bus.host_req.cmd = HOST_MGMT_MSG_ASK;
			memcpy((void *)(tx_buffer + SPI_HEADER_SIZE), (void *)&(core->bus.host_req),
			       sizeof(struct st_mgmt_req));
			err = if_spi_bulkwrite(core, RS_A2E_CMD_ADDR, tx_buffer, sizeof(struct st_mgmt_req));
		}
	}
	mutex_unlock(&lock);

	return err;
}

s32 if_spi_drv_init(void) // param1 : 8/4 byte hdr mode, param2 : dummy buffer lenght
{
	prev_xfer_time = jiffies;
	tx_buffer = kmalloc(WIFI_BUF_SIZE, GFP_KERNEL);
	rx_buffer = kmalloc(WIFI_BUF_SIZE, GFP_KERNEL);

	return spi_register_driver(&da16xxx_spi_driver);
}

void if_spi_drv_deinit(void)
{
	spi_unregister_driver(&da16xxx_spi_driver);
}
