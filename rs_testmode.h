// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_TESTMODE_H
#define RS_TESTMODE_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <net/mac80211.h>
#include <net/netlink.h>

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

enum rs_tm_cmd
{
	RS_TM_CMD_A2D_READ_REG = 1,
	RS_TM_CMD_A2D_WRITE_REG,
	RS_TM_CMD_A2D_LOGMODEFILTER_SET,
	RS_TM_CMD_A2D_DBGLEVELFILTER_SET,
	RS_TM_CMD_A2D_TX,
	RS_TM_CMD_A2D_CW,
	RS_TM_CMD_A2D_CONT,
	RS_TM_CMD_A2D_CHANNEL,
	RS_TM_CMD_A2D_PER,
	RS_TM_CMD_A2D_RESET_HW,
	RS_TM_CMD_HOST_LOG_LEVEL,
	RS_TM_CMD_A2D_DBGOUTDIR_SET,
	RS_TM_CMD_MAX,
};

enum rs_tm_attr
{
	RS_TM_AT_NOT_APPLICABLE = 0,
	RS_TM_AT_CMD,
	RS_TM_AT_REG_OFFSET,
	RS_TM_AT_REG_VALUE32,
	RS_TM_AT_REG_FILTER,
	RS_TM_AT_START,
	RS_TM_AT_CH,
	RS_TM_AT_FRAMES_NUM,
	RS_TM_AT_FRAMES_LEN,
	RS_TM_AT_RATE,
	RS_TM_AT_POWER,
	RS_TM_AT_ADDR_DEST,
	RS_TM_AT_BSSID,
	RS_TM_AT_GI,
	RS_TM_AT_GREEN,
	RS_TM_AT_PREAMBLE,
	RS_TM_AT_QOS,
	RS_TM_AT_ACK,
	RS_TM_AT_AIFSN,
	RS_TM_AT_PER_PASS,
	RS_TM_AT_PER_FCS,
	RS_TM_AT_PER_PHY,
	RS_TM_AT_PER_OVERFLOW,
	RS_TM_AT_HOST_LOG_LEVEL,
	RS_TM_AT_MAX,
};

enum
{
	VALUE_STOP = 0,
	VALUE_START,
};

enum
{
	VALUE_PER_STOP = 0,
	VALUE_PER_START,
	VALUE_PER_GET,
	VALUE_PER_RESET,
};

enum rate_value // R_[80211b/g/n] + <Number> Mbps
{
	R_b1 = 0,
	R_b2,
	R_b5_5,
	R_b11,
	R_g6,
	R_g9,
	R_g12,
	R_g18,
	R_g24,
	R_g36,
	R_g48,
	R_g54,
	R_n6_5,
	R_n13,
	R_n19_5,
	R_n26,
	R_n39,
	R_n52,
	R_n58_5,
	R_n65,
};

enum
{
	VALUE_SHORT = 0,
	VALUE_LONG,
};

enum
{
	VALUE_OFF = 0,
	VALUE_ON,
};

enum
{
	VALUE_NO = 0,
	VALUE_NORM,
	VALUE_BA,
	VALUE_CBA,
};

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_tm_reg(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_dbg_filter(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_rf_tx(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_rf_cw(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_rf_cont(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_rf_ch(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_rf_per(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_reset(struct ieee80211_hw *hw, struct nlattr **tb);
s32 rs_tm_host_log_level(struct ieee80211_hw *hw, struct nlattr **tb);

#endif /* RS_TESTMODE_H */
