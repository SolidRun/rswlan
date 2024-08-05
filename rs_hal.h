// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_HAL_H
#define RS_HAL_H

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define RS_CH_BW_20			  			0
#define RS_CH_BW_40			  			1
#define RS_CH_BW_80			  			2
#define RS_CH_BW_160			  		3

#define RS_PHY_MODE_CCK			  		0
#define RS_PHY_MODE_OFDM		  		1
#define RS_PHY_MODE_HT			  		2
#define RS_PHY_MODE_HT_GF		  		3
#define RS_PHY_MODE_VHT			  		4

#define NAV_PROT_NO_PROT_BIT		  	0
#define NAV_PROT_SELF_CTS_BIT		  	1
#define NAV_PROT_RTS_CTS_BIT		  	2
#define NAV_PROT_RTS_CTS_WITH_QAP_BIT	3
#define NAV_PROT_STBC_BIT		  		4

#define RS_RATE_MCS_MASK		  		0x7F
#define RS_RATE_MCS_SHIFT(x)			((x) & RS_RATE_MCS_MASK)
#define RS_RATE_BW_POS			  		7
#define RS_RATE_BW_MASK			  		0x3
#define RS_RATE_BW_SHIFT(x)		  		(((x) & RS_RATE_BW_MASK) << RS_RATE_BW_POS)
#define RS_RATE_SGI_POS			  		9
#define RS_RATE_SGI_MASK		  		0x1
#define RS_RATE_SGI_SHIFT(x)		  	(((x) & RS_RATE_SGI_MASK) << RS_RATE_SGI_POS)
#define RS_RATE_PREAMBLE_POS		  	10
#define RS_RATE_PREAMBLE_MASK		  	0x1
#define RS_RATE_PREAMBLE_SHIFT(x)	  	(((x) & RS_RATE_PREAMBLE_MASK) << RS_RATE_PREAMBLE_POS)
#define RS_RATE_PHY_MODE_POS		  	11
#define RS_RATE_PHY_MODE_MASK		  	0x7
#define RS_RATE_PHY_MODE_SHIFT(x)	  	(((x) & RS_RATE_PHY_MODE_MASK) << RS_RATE_PHY_MODE_POS)
#define RS_RATE_CTS_RTS_POS		  		14
#define RS_RATE_CTS_RTS_MASK		  	0x7
#define RS_RATE_CTS_RTS_SHIFT(x)	  	(((x) & RS_RATE_CTS_RTS_MASK) << RS_RATE_CTS_RTS_POS)
#define RS_RATE_MCS_PROT_POS		  	17
#define RS_RATE_MCS_PROT_MASK		  	0x7F
#define RS_RATE_MCS_PROT_SHIFT(x)	  	(((x) & RS_RATE_MCS_PROT_MASK) << RS_RATE_MCS_PROT_POS)
#define RS_RATE_BW_PROT_POS		  		24
#define RS_RATE_BW_PROT_MASK		  	0x3
#define RS_RATE_BW_PROT_SHIFT(x)	  	(((x) & RS_RATE_BW_PROT_MASK) << RS_RATE_BW_PROT_POS)
#define RS_RATE_PHY_MODE_PROJ_POS	  	26
#define RS_RATE_PHY_MODE_PROJ_MASK	  	0x7
#define RS_RATE_PHY_MODE_PROJ_SHIFT(x)	(((x) & RS_RATE_PHY_MODE_PROJ_MASK) << RS_RATE_PHY_MODE_PROJ_POS)
#define RS_RATE_RETRY_CNT_POS		  	29
#define RS_RATE_RETRY_CNT_MASK		  	0x7
#define RS_RATE_RETRY_CNT_SHIFT(x)	  	(((x) & RS_RATE_RETRY_CNT_MASK) << RS_RATE_RETRY_CNT_POS)

#define RS_TX_POWER_MASK		  		0xFF
#define RS_TX_POWER_SHIFT(x)		  	((x) & RS_TX_POWER_MASK)
#define RS_TX_PWR_PROT_POS		  		8
#define RS_TX_PWR_PROT_MASK		  		0xFF
#define RS_TX_PWR_PROT_SHIFT(x)		  	(((x) & RS_TX_PWR_PROT_MASK) << RS_TX_PWR_PROT_POS)

/// FEC Coding bit
#define FEC_CODING_BIT			  		1U << 6
#define STBC_MASK(stbc)			  		(((stbc + 1) & 0x3) << 7)

#define RS_ANT_CNT_MASK			  		0xFF
#define RS_ANT_CNT_SHIFT(x)		  		((x) & RS_ANT_CNT_MASK)

#define RS_HW_KEY_IDX_MASK		  		0x3FF
#define RS_HW_KEY_IDX_SHIFT(x)		  	((x) & RS_HW_KEY_IDX_MASK)
#define RS_HW_STA_ID_POS		  		10
#define RS_HW_STA_ID_MASK		  		0x3FF
#define RS_HW_STA_ID_SHIFT(x)		  	(((x) & RS_HW_STA_ID_MASK) << RS_HW_STA_ID_POS)

#define RS_RETRY_LONG_MASK		  		0xFF
#define RS_RETRY_LONG_SHIFT(x)		  	((x) & RS_RETRY_LONG_MASK)
#define RS_RETRY_SHORT_POS		  		8
#define RS_RETRY_SHORT_MASK		  		0xFF
#define RS_RETRY_SHORT_SHIFT(x)		  	(((x) & RS_RETRY_SHORT_MASK) << RS_RETRY_SHORT_POS)
#define RS_RTS_THRESHOLD_POS		 	16
#define RS_RTS_THRESHOLD_MASK		 	0xFFF
#define RS_RTS_THRESHOLD_SHIFT(x)	 	(((x) & RS_RTS_THRESHOLD_MASK) << RS_RTS_THRESHOLD_POS)

#define POLICY_TABLE_PATTERN		 	0xBADCAB1E

#define RS_FRAME_AMPDU			  		0xC
#define RS_FIRST_AMPDU			  		0xD
#define RS_LAST_AMPDU			  		0xF

#define RS_CHK_PACKET_AMPDU(kickbackdesc) (((kickbackdesc) & RS_FRAME_AMPDU) == RS_FRAME_AMPDU)
#define RS_CHK_FIRST_AMPDU(kickbackdesc)  ((kickbackdesc) == RS_FIRST_AMPDU)
#define RS_CHK_LAST_AMPDU(kickbackdesc)	  ((kickbackdesc) == RS_LAST_AMPDU)

#define RS_PACKET_NO_ACK		  		0
#define RS_PACKET_NORMAL_ACK		  	1
#define RS_PACKET_BLOCK_ACK		  		2
#define RS_PACKET_COMPRESSED_BLOCK_ACK	3

#define RS_PACKET_ACK_BIT_POS		  	9
#define RS_PACKET_ACK_MASK		  		0x3
#define RS_PACKET_ACK_MASK_SHIFT(ack)	((ack & RS_PACKET_ACK_MASK) << RS_PACKET_ACK_BIT_POS)
#define RS_PHY_GROUD_ID_POS		  		16
#define RS_PHY_GROUD_ID_MASK		  	0x3F
#define RS_PHY_GROUD_ID_MASK_SHIFT(id)	((id & RS_PHY_GROUD_ID_MASK) << RS_PHY_GROUD_ID_POS)
#define RS_PHY_PAID_POS			  		22
#define RS_PHY_PAID_MASK		  		0x1FF
#define RS_PHY_PAID_MASK_SHIFT(id)	  	((id & RS_PHY_PAID_MASK) << RS_PHY_PAID_POS)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct tx_dev_rule {
	u32 tx_pattern;
	u32 perf_ctrl_value;
	u32 antset_value;
	u32 hw_key_value;
	u32 retry_rts_value;
	u32 rate_ctrl_values[RS_TX_MAX_RATES];
	u32 pwr_ctrl_values[RS_TX_MAX_RATES];
};

union rs_kickback_status {
	struct {
		u32 kickback_rts_retries : 8;
		u32 kickback_mpdu_retries : 8;
		u32 kickback_is_retry_limit : 1;
		u32 kickback_expired : 1;
		u32 kickback_ba_received : 1;
		u32 reserved2 : 4;
		u32 kickback_tx_done : 1;
		u32 kickback_xmit_bw : 2;
		u32 kickback_ampdu_status : 4;
		u32 kickback_need_retry : 1;
		u32 kickback_dev_done : 1;
	};
	u32 value;
};

struct rs_dev_txhdr {
	struct tx_dev_rule tx_rule;
	u32 mac_ctrl_value;
	u32 phy_ctrl_value;
	union rs_kickback_status status;
};

#endif // RS_HAL_H
