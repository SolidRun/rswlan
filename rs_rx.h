// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_RX_H
#define RS_RX_H

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

enum rs_rx_status
{
	RS_RX_UNENC = 0,
	RS_RX_ICV_FAIL,
	RS_RX_CCMP_FAIL,
	RS_RX_AMSDU_DISCARD,
	RS_RX_NULL_KEY,
	RS_RX_WEP_SUCCESS,
	RS_RX_TKIP_SUCCESS,
	RS_RX_CCMP_SUCCESS
};

struct rs_rx_ch_info {
	u8 ch_band;
	u8 ch_type;
	u16 ch_freq_prime20;
	u16 ch_freq_cen1;
	u16 ch_freq_cen2;
};

struct rs_rx_info_a {
	u16 rx_buf_size;
	u16 res : 6;
	u8 amdpu_num : 2;
	u32 tsf_l;
	u32 tsf_h;
};

struct rs_rx_sig {
	s8 sig1;
	s8 sig2;
	s8 sig3;
	s8 sig4;
	s8 res;
};

struct rs_rx_info_v {
	u32 res0;
	u32 res1 : 4;
	u32 sgi : 1;
	u32 stbc : 2;
	u32 res2 : 1;
	u32 mcs : 7;
	u32 ptype : 1;
	u32 fmod : 3;
	u32 cbw : 2;
	u32 sts : 3;
	u32 res3 : 1;
	u32 res4 : 1;
	u32 res5 : 2;
	u32 agg : 1;
	u32 fec : 1;
	u32 res6 : 1;
	u32 res7 : 1;
	u8 ant;
	u32 res8 : 9;
	u32 res9 : 6;
	u32 res10 : 1;
	struct rs_rx_sig sig;
};

struct rs_rx_info_b {
	u8 res0;
	u8 res1;
	u8 res2;
	u8 res3;
	u8 res4;
	u8 res5;
	u8 res6;
	u8 res7;
	u8 res8 : 1;
	u8 res9 : 1;
	u8 rx_status : 3;
	u8 res10 : 1;
	u8 res11 : 1;
	u8 res12 : 1;
};

struct rs_rx_info {
	struct rs_rx_info_a rx_info_a;
	struct rs_rx_info_v rx_info_v;
	struct rs_rx_info_b rx_info_b;
	u8 err_fcs : 1;
	u8 res13 : 1;
	u8 res14 : 1;
	u8 res15 : 2;
	u8 rx_success : 1;
	u8 res16 : 1;
	u32 res17 : 10;
	u8 res18 : 1;
	u8 res19 : 2;
	u8 res20 : 4;
	struct rs_rx_ch_info phy_info;
	u32 rx_pat;
};

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_rx_data_handler(struct rs_hw_priv *priv, struct sk_buff *skb);

#endif /* RS_RX_H */
