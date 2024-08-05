// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_TX_H
#define RS_TX_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define BCN_Q			 4

#define RS_TX_LIFETIME_MS	 100

#define RS_SWTXHDR_ALIGN_SZ	 4
#define RS_SWTXHDR_ALIGN_MSK	 (RS_SWTXHDR_ALIGN_SZ - 1)
#define RS_SWTXHDR_ALIGN_PADS(x) ((RS_SWTXHDR_ALIGN_SZ - ((x) & RS_SWTXHDR_ALIGN_MSK)) & RS_SWTXHDR_ALIGN_MSK)
#if RS_SWTXHDR_ALIGN_SZ & RS_SWTXHDR_ALIGN_MSK
#error bad RS_SWTXHDR_ALIGN_SZ
#endif

#define EXTRA_TXHDR_MAX_IDX 1024

#define TID_TO_AC(_tid)                        \
	(((_tid) == 0 || (_tid) == 3) ? BE_Q : \
	 ((_tid) < 3)		      ? BK_Q : \
	 ((_tid) < 6)		      ? VI_Q : \
	 ((_tid) < 8)		      ? VI_Q : \
					BE_Q)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

enum edca_queue
{
	BK_Q,
	BE_Q,
	VI_Q,
	VO_Q,
	MGMT_SOFT_Q,
	MGMT_BEACON_Q
};

typedef struct rs_txhdr {
	struct rs_dev_txhdr dev_hdr;
	u16 sn;
	u8 tid;
	unsigned long jiffies;
	u16 crypto_overhead;
	struct {
		u8 len;
		u8 ack;
		bool phy_mode; //RS_RATE_PHY_MODE
	} ampdu;
	struct rs_vif_priv *vif_priv;
	struct rs_sta_priv *sta_priv;
	struct rs_agg *agg;
#ifdef CONFIG_RS_SPI
#define RS_TX_RETRY_THRESHOLD_VALUE 3
#else
#define RS_TX_RETRY_THRESHOLD_VALUE 7
#endif
	u8 retry;
	bool is_free;
	bool is_drop;
} rs_txhdr_t;

extern rs_txhdr_t exttxhdrs[EXTRA_TXHDR_MAX_IDX];

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

void rs_tx_q_data_lock_init(struct rs_hw_priv *priv);
void rs_tx_q_data_lock_destroy(struct rs_hw_priv *priv);
void rs_tx_q_data_lock(struct rs_hw_priv *priv, u16 ac);
void rs_tx_q_data_unlock(struct rs_hw_priv *priv, u16 ac);

void rs_ops_xmit(struct ieee80211_hw *hw, struct ieee80211_tx_control *control, struct sk_buff *skb);

void rs_tx_bcns(struct rs_hw_priv *rs_hw);

s32 tx_bus_ops_kick(struct rs_hw_priv *priv, void *skb, s32 hw_queue);
s32 tx_bus_ops_recovery(struct rs_hw_priv *priv);
#if defined(CONFIG_HOST_TX_MERGE) && defined(CONFIG_RS_SDIO)
s32 tx_bus_ops_merge_kick(struct rs_hw_priv *priv, s32 cnt, u16 start_tx_seq);
s32 tx_bus_ops_merge_data(struct rs_hw_priv *priv, void *data, s32 hw_queue);
void rs_tx_merge_buf_init(void);
void rs_tx_merge_buf_deinit(void);
#endif
s32 tx_bus_ops_trig(struct rs_hw_priv *priv);
s32 tx_bus_ops_q_update(struct rs_hw_priv *priv);
void rs_tx_work_handler(struct work_struct *work);
s32 rs_tx_kickback_handler(struct rs_hw_priv *priv, void *data);

#endif /* RS_TX_H */
