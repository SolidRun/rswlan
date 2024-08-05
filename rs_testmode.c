// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>
#include <net/mac80211.h>
#include <net/netlink.h>

#include "rs_core.h"
#include "rs_testmode.h"
#include "rs_mgmt_tx.h"
#include "rs_irq_dbg.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define PRINT_CMD_INFO 0
#define RS_TM_SIZE 20

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_tm_reg(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	u32 mem_addr, val32;
	struct sk_buff *skb;
	s32 status = 0;

	if (!tb[RS_TM_AT_REG_OFFSET]) {
		printk("Error finding register offset\n");
		return -ENOMSG;
	}

	mem_addr = nla_get_u32(tb[RS_TM_AT_REG_OFFSET]);

	switch (nla_get_u32(tb[RS_TM_AT_CMD])) {
	case RS_TM_CMD_A2D_READ_REG: {
		struct rs_dbg_mem_read_chk *mem_read_chk = &rs_hw->mgmt_return.mem_read_chk;

		if ((status = rs_dbg_mem_read_ask(rs_hw, mem_addr, mem_read_chk)))
			return status;

		skb = cfg80211_testmode_alloc_reply_skb(hw->wiphy, RS_TM_SIZE);
		if (!skb) {
			printk("Error allocating memory\n");
			return -ENOMEM;
		}

		val32 = mem_read_chk->mem_data;
		if (nla_put_u32(skb, RS_TM_AT_REG_VALUE32, val32))
			goto nla_put_failure;

		status = cfg80211_testmode_reply(skb);
		if (status < 0)
			printk("Error testmode reply error : %d\n", status);
	} break;

	case RS_TM_CMD_A2D_WRITE_REG: {
		if (!tb[RS_TM_AT_REG_VALUE32]) {
			printk("Error finding value to write\n");
			return -ENOMSG;
		} else {
			val32 = nla_get_u32(tb[RS_TM_AT_REG_VALUE32]);

			if ((status = rs_dbg_mem_write_ask(rs_hw, mem_addr, val32)))
				return status;
		}
	} break;

	default:
		printk("Unknown TM reg cmd ID\n");
		return -ENOSYS;
	}

	return status;

nla_put_failure:
	kfree_skb(skb);
	return -EMSGSIZE;
}

s32 rs_tm_dbg_filter(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	u32 filter;
	s32 status = 0;

	if (!tb[RS_TM_AT_REG_FILTER]) {
		printk("Error finding filter value\n");
		return -ENOMSG;
	}

	filter = nla_get_u32(tb[RS_TM_AT_REG_FILTER]);
	RS_DBG("TM DBG filter, setting: 0x%x\n", filter);

	switch (nla_get_u32(tb[RS_TM_AT_CMD])) {
	case RS_TM_CMD_A2D_LOGMODEFILTER_SET:
		if ((status = rs_dbg_mod_filter_set(rs_hw, filter)) != 0)
			return status;
		break;
	case RS_TM_CMD_A2D_DBGLEVELFILTER_SET:
		if ((status = rs_dbg_lvl_filter_set(rs_hw, filter)) != 0)
			return status;
		break;

	case RS_TM_CMD_A2D_DBGOUTDIR_SET:
		if ((status = rs_dbg_set_dir_out(rs_hw, filter)) != 0) {
			return status;
		}
		(void)rs_irq_dbg_set(rs_hw, filter);
		break;

	default:
		printk("Unknown testmode register command ID\n");
		return -ENOSYS;
	}

	return status;
}

s32 rs_tm_rf_tx(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	s32 status = 0;
	u8 start = 0;
	u16 frequency = 0;
	u16 numFrames = 0;
	u16 frameLen = 0;
	u8 txRate = 0;
	u8 txPower = 0;
	u64 destAddr = 0;
	u64 bssid = 0;
	u8 GI = 0;
	u8 greenField = 0;
	u8 preambleType = 0;
	u8 qosEnable = 0;
	u8 ackPolicy = 0;
	u8 aifsnVal = 0;

	if (!tb[RS_TM_AT_START]) {
		printk("Error finding start attribute\n");
		return -ENOMSG;
	}

	start = nla_get_u8(tb[RS_TM_AT_START]);

	if (start == VALUE_START) {
		frequency = nla_get_u16(tb[RS_TM_AT_CH]);
		numFrames = nla_get_u16(tb[RS_TM_AT_FRAMES_NUM]);
		frameLen = nla_get_u16(tb[RS_TM_AT_FRAMES_LEN]);
		txRate = nla_get_u8(tb[RS_TM_AT_RATE]);
		txPower = nla_get_u8(tb[RS_TM_AT_POWER]);
		destAddr = nla_get_u64(tb[RS_TM_AT_ADDR_DEST]);
		bssid = nla_get_u64(tb[RS_TM_AT_BSSID]);
		GI = nla_get_u8(tb[RS_TM_AT_GI]);
		greenField = nla_get_u8(tb[RS_TM_AT_GREEN]);
		preambleType = nla_get_u8(tb[RS_TM_AT_PREAMBLE]);
		qosEnable = nla_get_u8(tb[RS_TM_AT_QOS]);
		ackPolicy = nla_get_u8(tb[RS_TM_AT_ACK]);
		aifsnVal = nla_get_u8(tb[RS_TM_AT_AIFSN]);
	}

#if (PRINT_CMD_INFO)
	printk("start %d\n", start);
	printk("frequency %d\n", frequency);
	printk("numFrames %d\n", numFrames);
	printk("frameLen %d\n", frameLen);
	printk("txRate %d\n", txRate);
	printk("txPower %d\n", txPower);
	printk("destAddr = %llx\n", destAddr);
	printk("bssid = %llx\n", bssid);
	printk("GI = %d\n", GI);
	printk("greenField %d\n", greenField);
	printk("preambleType %d\n", preambleType);
	printk("qosEnable %d\n", qosEnable);
	printk("ackPolicy %d\n", ackPolicy);
	printk("aifsnVal %d\n", aifsnVal);
#endif

	/*** Send the command to the LMAC ***/
	if ((status = rs_rf_tx_req(rs_hw, start, frequency, numFrames, frameLen, txRate, txPower, destAddr,
				   bssid, GI, greenField, preambleType, qosEnable, ackPolicy, aifsnVal)))
		return status;

	return status;
}

s32 rs_tm_rf_cw(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	s32 status = 0;
	u8 start = 0;
	u8 txPower = 0;
	u16 frequency = 0;

	if (!tb[RS_TM_AT_START]) {
		printk("Error finding start attribute\n");
		return -ENOMSG;
	}

	start = nla_get_u8(tb[RS_TM_AT_START]);

	if (start == VALUE_START) {
		txPower = nla_get_u8(tb[RS_TM_AT_POWER]);
		frequency = nla_get_u16(tb[RS_TM_AT_CH]);
	}

#if (PRINT_CMD_INFO)
	printk("start %d\n", start);
	printk("txPower %d\n", txPower);
	printk("frequency %d\n", frequency);
#endif

	if ((status = rs_rf_cw_req(rs_hw, start, txPower, frequency)))
		return status;

	return status;
}

s32 rs_tm_rf_cont(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	s32 status = 0;
	u8 start = 0;
	u8 txRate = 0;
	u8 txPower = 0;
	u16 frequency = 0;

	if (!tb[RS_TM_AT_START]) {
		printk("Error finding start attribute\n");
		return -ENOMSG;
	}

	start = nla_get_u8(tb[RS_TM_AT_START]);

	if (start == VALUE_START) {
		txRate = nla_get_u8(tb[RS_TM_AT_RATE]);
		txPower = nla_get_u8(tb[RS_TM_AT_POWER]);
		frequency = nla_get_u16(tb[RS_TM_AT_CH]);
	}

#if (PRINT_CMD_INFO)
	printk("start %d\n", start);
	printk("txRate %d\n", txRate);
	printk("txPower %d\n", txPower);
	printk("frequency %d\n", frequency);
#endif

	/*** Send the command to the LMAC ***/
	if ((status = rs_rf_cont_req(rs_hw, start, txRate, txPower, frequency)))
		return status;

	return status;
}

s32 rs_tm_rf_ch(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	s32 status = 0;
	u16 frequency = 0;

	if (!tb[RS_TM_AT_CH]) {
		printk("Error finding channel attribute\n");
		return -ENOMSG;
	}

	frequency = nla_get_u16(tb[RS_TM_AT_CH]);

#if (PRINT_CMD_INFO)
	printk("frequency %d\n", frequency);
#endif

	if ((status = rs_rf_ch_req(rs_hw, frequency)))
		return status;

	return status;
}

s32 rs_tm_rf_per(struct ieee80211_hw *hw, struct nlattr **tb)
{
	struct rs_hw_priv *rs_hw = hw->priv;
	struct sk_buff *skb;
	struct rs_dbg_rf_per_chk *rf_per_chk = &rs_hw->mgmt_return.rf_per_chk;
	s32 status = 0;
	u8 start = 0;

	if (!tb[RS_TM_AT_START]) {
		printk("Error finding start attribute\n");
		return -ENOMSG;
	}

	start = nla_get_u8(tb[RS_TM_AT_START]);

#if (PRINT_CMD_INFO)
	printk("start %d\n", start);
#endif

	if ((status = rs_rf_per_req(rs_hw, start, rf_per_chk)))
		return status;

	if (start == VALUE_PER_GET) {
		u32 pass, fcs, phy, overflow;
		/* Allocate the answer message */
		skb = cfg80211_testmode_alloc_reply_skb(hw->wiphy, 20);
		if (!skb) {
			printk("Error allocating memory\n");
			return -ENOMEM;
		}

		pass = rf_per_chk->pass;
		fcs = rf_per_chk->fcs;
		phy = rf_per_chk->phy;
		overflow = rf_per_chk->overflow;

		if (nla_put_u32(skb, RS_TM_AT_PER_PASS, pass))
			goto nla_put_failure;
		if (nla_put_u32(skb, RS_TM_AT_PER_FCS, fcs))
			goto nla_put_failure;
		if (nla_put_u32(skb, RS_TM_AT_PER_PHY, phy))
			goto nla_put_failure;
		if (nla_put_u32(skb, RS_TM_AT_PER_OVERFLOW, overflow))
			goto nla_put_failure;

#if (PRINT_CMD_INFO)
		printk("pass %d\n", pass);
		printk("fcs %d\n", fcs);
		printk("phy %d\n", phy);
		printk("overflow %d\n", overflow);
#endif

		status = cfg80211_testmode_reply(skb);
		if (status < 0)
			printk("Error sending per msg : %d\n", status);
	}

	return status;

nla_put_failure:
	kfree_skb(skb);
	return -EMSGSIZE;
}

#ifdef CONFIG_RS_SPI
void hw_reset_fw(void);
#endif
s32 rs_tm_reset(struct ieee80211_hw *hw, struct nlattr **tb)
{
	s32 status = 0;

#if (PRINT_CMD_INFO)
	printk("TEST Mode RESET command.\n");
#endif

#ifdef CONFIG_RS_SPI
	hw_reset_fw();
#endif

	return status;
}

s32 rs_tm_host_log_level(struct ieee80211_hw *hw, struct nlattr **tb)
{
	s32 status = 0;
	u8 level = 0;

	if (!tb[RS_TM_AT_REG_VALUE32]) {
		printk("Error finding level attribute\n");
		return -ENOMSG;
	}

	level = nla_get_u8(tb[RS_TM_AT_REG_VALUE32]);

	set_host_log_level(level);
	return status;
}
