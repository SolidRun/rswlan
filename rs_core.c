// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/module.h>

#include "rs_core.h"
#include "rs_hal.h"
#include "rs_mac.h"
#ifdef CONFIG_RS_SDIO
#include "rs_sdio_ops.h"
#else
#include "rs_spi_ops.h"
#endif
#include "rs_priv.h"
#include "rs_tx.h"
#include "rs_io_map.h"

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

struct device *core_to_dev(struct rs_core *core)
{
#if defined(CONFIG_RS_SDIO)
	return &(core->bus.sdio->dev);
#else
	return &(core->bus.spi->dev);
#endif
}

void core_bus_lock(struct rs_core *core)
{
	mutex_lock(&(core)->bus.lock);
}

void core_bus_unlock(struct rs_core *core)
{
	mutex_unlock(&(core)->bus.lock);
}

void core_mgmt_lock(struct rs_core *core)
{
	mutex_lock(&(core)->bus.mgmt_lock);
}

void core_mgmt_unlock(struct rs_core *core)
{
	mutex_unlock(&(core)->bus.mgmt_lock);
}

s32 core_bus_ops_init_mac_addr(struct rs_core *core, u8 *mac_addr)
{
	s32 err = 0, i;
	u8 *buffer = kmalloc(40, GFP_KERNEL);

	memset(buffer, 0, 40);

	for (i = 0; i < 10; i++) {
		err = core->bus.ops.read(core, FW_IO_MAC_ADDR, buffer, 6);
		if (!err) {
			break;
		}
	}

	if (err) {
		pr_err("rs_sdio_read error %d\n", err);
		goto out;
	}

	if (buffer[0] == 0 && buffer[1] == 0 && buffer[2] == 0) {
		/* When MAC address not assigned at OTP */
		printk("OTP MAC address not assigned.\n");
		printk("Using MAC address from /lib/firmware/rs_settings.ini\n");
		err = 1;
		goto out;
	}

#define MAC_ADDRESS_STR	  "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_ARRAY(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

	pr_info("Get MAC address from OTP:" MAC_ADDRESS_STR, MAC_ADDR_ARRAY(&buffer[0]));

	memcpy(mac_addr, &buffer[0], ETH_ALEN);

out:
	kfree(buffer);

	return err;
}

s32 core_bus_ops_init_bus_addr(struct rs_core *core)
{
	s32 err = 0;
	s32 i;
	char *pbuf = kmalloc(8, GFP_KERNEL);

	if (!pbuf) {
		pr_crit("%s: kmalloc failed\n", __func__);
		err = -ENOMEM;
	}

	if (!err) {
		err = core->bus.ops.read(core, FW_IO_HWQ_LEN_ADDR, (u8 *)pbuf, FW_IO_HWQ_LEN_ADDR_SIZE);
		if (!err) {
			core->bus.addr.hwq_len = *((u32 *)pbuf);
			err = core->bus.ops.read(core, core->bus.addr.hwq_len, pbuf, RS_TXQ_CNT);
			if (!err) {
				for (i = 0; i < RS_TXQ_CNT; i++) {
					core->bus.q[i].size = pbuf[i];
					core->bus.q[i].balance = pbuf[i];
				}
				pr_debug("addr hwq_len:0x%x size: %d %d %d %d\n", core->bus.addr.hwq_len,
					 core->bus.q[0].size, core->bus.q[1].size, core->bus.q[2].size,
					 core->bus.q[3].size);
			}
		}

		if (!err) {
			err = core->bus.ops.read(core, FW_IO_MGMT_TX_ADDR, (u8 *)pbuf,
						 FW_IO_MGMT_TX_ADDR_SIZE);
			if (!err) {
				core->bus.addr.msg_tx = *((u32 *)pbuf);
				pr_debug("addr msg_tx:0x%x\n", core->bus.addr.msg_tx);
			}
		}

		if (!err) {
			err = core->bus.ops.read(core, FW_IO_MGMT_RX_ADDR, (u8 *)pbuf,
						 FW_IO_MGMT_RX_ADDR_SIZE);
			if (!err) {
				core->bus.addr.msg_rx = *((u32 *)pbuf);
				pr_debug("addr msg_rx:0x%x\n", core->bus.addr.msg_rx);
			}
		}

		if (!err) {
			err = core->bus.ops.read(core, FW_IO_DBG_MSG_ADDR, (u8 *)pbuf,
						 FW_IO_DBG_MSG_ADDR_SIZE);
			if (!err) {
				core->bus.addr.dbg_msg = *((u32 *)pbuf);
				pr_debug("addr dbg_msg:0x%x\n", core->bus.addr.dbg_msg);
			}
		}

		if (!err) {
			err = core->bus.ops.read(core, FW_IO_KB_ADDR, (u8 *)pbuf, FW_IO_KB_ADDR_SIZE);
			if (!err) {
				core->bus.addr.kb_data = *((u32 *)pbuf);
				pr_debug("addr kb_data:0x%x\n", core->bus.addr.kb_data);
			}
		}

		if (!err) {
			err = core->bus.ops.read(core, FW_IO_RX_ADDR, (u8 *)pbuf, FW_IO_RX_ADDR_SIZE);
			if (!err) {
				core->bus.addr.rx = *((u32 *)pbuf);
				pr_debug("addr rx_data:0x%x\n", core->bus.addr.rx);
			}
		}

		if (!err) {
			err = core->bus.ops.read(core, FW_IO_TX_ADDR, (u8 *)pbuf, FW_IO_TX_ADDR_SIZE);
			if (!err) {
				core->bus.addr.tx = *((u32 *)pbuf);
				pr_debug("addr tx_data:0x%x\n", core->bus.addr.tx);
			}
		}

		{
			s32 *conf = (s32 *)pbuf;
#ifdef CONFIG_HOST_TX_NO_KICKBACK
			*conf = 1;
			core->bus.ops.write(core, FW_IO_NO_KB, (u8 *)pbuf, 4);
#else
			*conf = 0;
			core->bus.ops.write(core, FW_IO_NO_KB, (u8 *)pbuf, 4);
#endif
		}
	}

	if (pbuf)
		kfree(pbuf);

	return err;
}

#ifdef CONFIG_RS_TL4
/**
 * rs_plat_tl4_fw_upload() - Load the requested FW into embedded side.
 *
 * @rs_core: pointer to platform structure
 * @fw_addr: Virtual address where the fw must be loaded
 * @filename: Name of the fw.
 *
 * Load a fw, stored as a hex file, into the specified address
 */
static s32 rs_plat_tl4_fw_upload(struct rs_core *rs_core, u8 *fw_addr, char *filename)
{
	struct device *dev = rs_platform_get_dev(rs_core);
	const struct firmware *fw;
	s32 err = 0;
	u32 *dst;
	u8 const *file_data;
	char typ0, typ1;
	u32 addr0, addr1;
	u32 dat0, dat1;
	s32 remain;

	err = request_firmware(&fw, filename, dev);
	if (err) {
		return err;
	}
	file_data = fw->data;
	remain = fw->size;

	/* Copy the file on the Embedded side */
	dev_dbg(dev, "\n### Now copy %s firmware, @ = %p\n", filename, fw_addr);

	/* Walk through all the lines of the configuration file */
	while (remain >= 16) {
		u32 data, offset;

		if (sscanf(file_data, "%c:%08X %04X", &typ0, &addr0, &dat0) != 3)
			break;
		if ((addr0 & 0x01) != 0) {
			addr0 = addr0 - 1;
			dat0 = 0;
		} else {
			file_data += 16;
			remain -= 16;
		}
		if ((remain < 16) || (sscanf(file_data, "%c:%08X %04X", &typ1, &addr1, &dat1) != 3) ||
		    (typ1 != typ0) || (addr1 != (addr0 + 1))) {
			typ1 = typ0;
			addr1 = addr0 + 1;
			dat1 = 0;
		} else {
			file_data += 16;
			remain -= 16;
		}

		if (typ0 == 'C') {
			offset = 0x00200000;
			if ((addr1 % 4) == 3)
				offset += 2 * (addr1 - 3);
			else
				offset += 2 * (addr1 + 1);

			data = dat1 | (dat0 << 16);
		} else {
			offset = 2 * (addr1 - 1);
			data = dat0 | (dat1 << 16);
		}
		dst = (u32 *)(fw_addr + offset);
		*dst = data;
	}

	release_firmware(fw);

	return err;
}
#endif

s32 rs_core_on(struct rs_hw_priv *hw_priv)
{
	struct rs_core *rs_core = hw_priv->core;

	if (rs_core->enabled)
		return 0;

	hw_priv->phy_cnt = 1;

	msleep(500); /* FIXME */

	rs_core->enabled = true;

	return 0;
}

s32 core_init(struct rs_core *core, void **priv_data)
{
	s32 err;

	core->enabled = false;

	err = rs_mac_allocate(core, priv_data);

	return err;
}

void core_deinit(struct rs_hw_priv *priv)
{
	rs_mac80211_deinit(priv);
}

MODULE_FIRMWARE(RS_MAC_FW_NAME_SDIO);
MODULE_FIRMWARE(RS_MAC_FW_NAME_SPI);