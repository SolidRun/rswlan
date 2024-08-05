// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>

#include "rs_priv.h"

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

/**
 * @brief: Function that returns content that matches a given tag
 *
 * @file_data: file name
 * @file_size: file size
 * @tag_name: tag name
 * @tag_len: tag length
 *
 * @return[const char*]: Returns phrases after matching tags
 */
static const char *find_tag(const u8 *file_data, u32 file_size, const char *tag_name, u32 tag_len)
{
	u32 curr, line_start = 0, line_size;

	RS_DBG(RS_FN_ENTRY_STR);

	/* Walk through all the lines of the configuration file */
	while (line_start < file_size) {
		/* Search the end of the current line (or the end of the file) */
		for (curr = line_start; curr < file_size; curr++)
			if (file_data[curr] == '\n')
				break;

		/* Compute the line size */
		line_size = curr - line_start;

		/* Check if this line contains the expected tag */
		if ((line_size == (strlen(tag_name) + tag_len)) &&
		    (!strncmp(&file_data[line_start], tag_name, strlen(tag_name))))
			return (&file_data[line_start + strlen(tag_name)]);

		/* Move to next line */
		line_start = curr + 1;
	}

	/* Tag not found */
	return NULL;
}

static s32 mgmt_pkt(struct rs_core *core, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct skb_info *tx_param = (struct skb_info *)info->driver_data;
	s32 status = 0;

	if (!!(tx_param && tx_param->flags & INTERNAL_MGMT_PKT)) {
		status = core->bus.ops.mgmt_pkt_write(core, core->bus.addr.msg_tx, (u8 *)skb->data, skb->len);
		if (status) {
			struct rs_fw_mgmt *mgmt = (struct rs_fw_mgmt *)skb->data;
			RS_ERR("%s: Failed to write to msg_tx: status = %d (id: %d), deinit: %d\n", __func__,
			       status, mgmt->id, core->priv->run_deinit);
		}
		dev_kfree_skb(skb);
		skb = NULL;
	}

	return status;
}

static void core_qos_processor(struct rs_core *core)
{
	struct sk_buff *skb;
	u8 q_num = INVALID_QUEUE;
	s32 status;

	while (1) {
		if (skb_queue_len(&core->mgmt_tx_queue)) {
			q_num = MGMT_SOFT_Q;
		}

		if (q_num == INVALID_QUEUE) {
			RS_INFO("%s: No More Pkt\n", __func__);
			break;
		}

		skb = skb_dequeue(&core->mgmt_tx_queue);

		if (skb == NULL) {
			RS_DBG("skb null\n");
			break;
		}

		if (core->bus.mgmt_tx_stop) {
			dev_kfree_skb(skb);
			break;
		}

		if (q_num == MGMT_SOFT_Q) {
			struct rs_fw_mgmt *mgmt = (struct rs_fw_mgmt *)skb->data;
			status = mgmt_pkt(core, skb);

			if ((core && core->priv && core->priv->run_deinit) && !status) {
				if (mgmt->id == MGMT_RESET_ASK) {
					core->bus.mgmt_tx_stop = true;
					break;
				}
			}
		}

		if (status) {
			break;
		}
	}
}

s32 rs_get_mac_addr(struct rs_hw_priv *priv, const char *filename, u8 *mac_addr)
{
	struct rs_core *core = priv->core;
	const struct firmware *default_mac;
	s32 ret;
	const u8 *t_mac = NULL;

	if (!core->bus.ops.init_mac_addr(core, mac_addr)) {
		return 0;
	}

	/* If MAC address is not provided by OTP,
    ** try to get it from config file (rnxx_settings.ini)
    **/
	if ((ret = request_firmware(&default_mac, filename, priv->dev))) {
		printk(KERN_CRIT "%s: Failed to get %s%s (%d)\n", __func__, "/lib/firmware/", filename, ret);
		return ret;
	} else {
		/* Get MAC Address from default_mac.ini*/
		t_mac = find_tag(default_mac->data, default_mac->size,
				 "MAC_ADDR=", strlen("00:00:00:00:00:00"));
		if (t_mac) {
			sscanf(t_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac_addr + 0, mac_addr + 1,
			       mac_addr + 2, mac_addr + 3, mac_addr + 4, mac_addr + 5);
			RS_INFO("Use default mac: %pM\n", mac_addr);
		} else {
			RS_ERR("MAC Address not found in %s\n", filename);
			release_firmware(default_mac);
			return -1;
		}

		RS_DBG("MAC Address is: %s\n", mac_addr);

		/* Release the configuration file */
		release_firmware(default_mac);
	}

	return 0;
}

void rs_mgmt_tx_thread(struct rs_core *core)
{
	u32 timeout = EVENT_WAIT_FOREVER;

	do {
		rs_wait_event(&core->mgmt_thread.event, timeout);

		if (core->init_done == true) {
			rs_reset_event(&core->mgmt_thread.event);
			core_qos_processor(core);
		}
	} while (kthread_should_stop() == false);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	kthread_complete_and_exit(&(core->mgmt_thread.completion), 0);
#else
	complete_and_exit(&(core->mgmt_thread.completion), 0);
#endif
}

void rs_mgmt_rx_chk_handle(struct rs_hw_priv *hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_event *event = NULL;

	if (!hw || !hw->core) {
		return;
	}

	event = &hw->core->mgmt_thread.event;

	switch (mgmt->id) {
	case MGMT_VERSION_CHK:
		memcpy(&hw->mgmt_return.version_chk, mgmt->param, sizeof(struct rs_version_chk));
		break;
	case MGMT_ADD_IF_CHK:
		memcpy(&hw->mgmt_return.add_if_chk, mgmt->param, sizeof(struct rs_add_if_chk));
		break;
	case MGMT_SET_CHANNEL_CHK:
		memcpy(&hw->mgmt_return.set_chan_chk, mgmt->param, sizeof(struct rs_set_channel_chk));
		break;
	case MGMT_KEY_ADD_CHK:
		memcpy(&hw->mgmt_return.key_add_chk, mgmt->param, sizeof(struct rs_key_add_chk));
		break;
	case MGMT_SET_POWER_CHK:
		memcpy(&hw->mgmt_return.set_power_chk, mgmt->param, sizeof(struct rs_set_power_chk));
		break;
#ifdef CONFIG_RS_P2P_DEBUGFS
	case MGMT_SET_P2P_OPPS_CHK:
		memcpy(&hw->mgmt_return.set_p2p_opps_chk, mgmt->param, sizeof(struct rs_set_p2p_opps_chk));
		break;
	case MGMT_SET_P2P_NOA_CHK:
		memcpy(&hw->mgmt_return.set_p2p_noa_chk, mgmt->param, sizeof(struct rs_set_p2p_noa_chk));
		break;
#endif
	case MGMT_STA_ADD_CHK:
		memcpy(&hw->mgmt_return.sta_add_chk, mgmt->param, sizeof(struct rs_sta_add_chk));
		break;
	case MGMT_CHAN_CTXT_ADD_CHK:
		memcpy(&hw->mgmt_return.add_chanctx_chk, mgmt->param, sizeof(struct rs_chan_ctxt_add_chk));
		break;
	case MGMT_BA_ADD_CHK:
		memcpy(&hw->mgmt_return.ba_add_chk, mgmt->param, sizeof(struct rs_ba_add_chk));
		break;
	case MGMT_BA_DEL_CHK:
		memcpy(&hw->mgmt_return.ba_del_chk, mgmt->param, sizeof(struct rs_ba_del_chk));
		break;
	case SCAN_START_CHK:
		memcpy(&hw->mgmt_return.scan_start_chk, mgmt->param, sizeof(struct rs_scan_start_chk));
		break;
	case SCAN_CANCEL_CHK:
		memcpy(&hw->mgmt_return.scan_cancel_chk, mgmt->param, sizeof(struct rs_scan_cancel_chk));
		break;
	case TDLS_CHAN_SWITCH_CHK:
		memcpy(&hw->mgmt_return.tdls_chan_switch_chk, mgmt->param,
		       sizeof(struct rs_tdls_chan_switch_chk));
		break;
	case DBG_MEM_READ_CHK:
		memcpy(&hw->mgmt_return.mem_read_chk, mgmt->param, sizeof(struct rs_dbg_mem_read_chk));
		break;
	case DBG_GET_SYS_STAT_CHK:
		memcpy(&hw->mgmt_return.get_sys_stat_chk, mgmt->param,
		       sizeof(struct rs_dbg_get_sys_stat_chk));
		break;
	case DBG_RF_PER_CHK:
		memcpy(&hw->mgmt_return.rf_per_chk, mgmt->param, sizeof(struct rs_dbg_rf_per_chk));
		break;
	default:
		hw->msg_rx_handle_callback(hw, mgmt);
		break;
	}

	if (!hw->mgmt_chk_completed) {
		hw->mgmt_chk_completed = true;

		wake_up(&event->mgmt_chk_queue);
	}
}

void rs_flush_mgmt(struct rs_hw_priv *priv)
{
	struct sk_buff *skb;
	struct ieee80211_tx_info *info;
	struct skb_info *tx_param;

	while (1) {
		skb = skb_dequeue(&priv->core->mgmt_tx_queue);
		if (skb) {
			info = IEEE80211_SKB_CB(skb);
			tx_param = (struct skb_info *)info->driver_data;
			if (!!(tx_param->flags & INTERNAL_MGMT_PKT)) {
				dev_kfree_skb(skb);
			} else
				break;
		} else {
			break;
		}
	}

	priv->run_deinit = true;
}

void rs_kill_mgmt_tx_thread(struct rs_core *core)
{
	core->init_done = false;
	rs_kill_thread(&core->mgmt_thread);
	skb_queue_purge(&core->mgmt_tx_queue);
}