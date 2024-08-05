// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#include <linux/version.h>
#include <net/mac80211.h>

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_priv.h"
#include "rs_hal.h"
#include "rs_tx.h"
#include "rs_io_map.h"

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

rs_txhdr_t exttxhdrs[EXTRA_TXHDR_MAX_IDX] = {};
static u16 exthdr_idx = 0;

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

/**
 * Write WPI header
 */
static s32 rs_update_wpi_header(struct rs_hw_priv *hw_priv, u8 *wpi_hdr, struct ieee80211_key_conf *conf)
{
	struct rs_wpi_key *key;
	bool overflow, carry;
	s32 i;

	hlist_for_each_entry(key, &hw_priv->wpi_keys, list) {
		if (key->conf == conf)
			break;
	}

	if (!key)
		return -EINVAL;

	/* increment pn */
	if (key->conf->flags & IEEE80211_KEY_FLAG_PAIRWISE) {
		key->pn[0] += 2;
		carry = (key->pn[0] <= 1);
	} else {
		key->pn[0] += 1;
		carry = (key->pn[0] == 0);
	}

	if (carry) {
		for (i = 1; i < WPI_PN_LEN; i++) {
			key->pn[i]++;
			if (key->pn[i])
				break;
		}
	}

	/* update wpi header */
	wpi_hdr[0] = key->conf->keyidx;
	wpi_hdr[1] = 0;
	memcpy(&wpi_hdr[2], key->pn, sizeof(key->pn));

	/* check overflow */
	overflow = 1;
	for (i = 1; i < WPI_PN_LEN && overflow; i++) {
		overflow = (key->pn[i] == 0xff);
	}

	if (overflow) {
		/* TODO: inform user space of needed rekey */
		pr_info("PN overflow is coming");
	}

	return 0;
}

static void rs_fill_dev_rate_ctrl(struct rs_hw_priv *hw_priv, struct ieee80211_tx_info *tx_info,
				  struct rs_dev_txhdr *dev_txhdr, struct ieee80211_sta *sta,
				  bool above_rtsthr, u8 tx_power)
{
	u32 *rate_ctrls;
	u32 *pwr_ctrls;
	struct ieee80211_hw *hw = hw_priv->hw;
	struct ieee80211_rate *bitrates = hw->wiphy->bands[tx_info->band]->bitrates;
	struct ieee80211_bss_conf *conf = &tx_info->control.vif->bss_conf;

	u8 cts_rate;
	u8 stbc_nss = 0;
	u8 sta_stbc_nss = 0;
	s32 use_stbc = 0;
	bool gf_sta, gf_able;

	s32 i;
	s32 bw;

	rate_ctrls = dev_txhdr->tx_rule.rate_ctrl_values;
	pwr_ctrls = dev_txhdr->tx_rule.pwr_ctrl_values;

	if (sta) {
		struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
		sta_stbc_nss = sta_priv->stbc_nss;
	}

	cts_rate = ieee80211_get_rts_cts_rate(hw, tx_info)->hw_value;

	/* GF */
	gf_sta = gf_able = false;

	/* ratectrlinfos / powerctrlinfos */
	for (i = 0; i < hw->max_rates; i++) {
		s32 use_rts, use_cts_protect, use_mcs, use_vht, use_ht, use_sgi;
		u32 *rate_ctrl = &rate_ctrls[i];
		u32 *pwr_ctrl = &pwr_ctrls[i];
		struct ieee80211_tx_rate *rate = &tx_info->control.rates[i];

		if (rate->idx == -1) {
			s32 j;
			for (j = i; j < RS_TX_MAX_RATES; j++) {
				/* 1a) The HW can fetch up to
                 * tx_rule.macretryrts[{short,long}RetryLimit] */
				rate_ctrls[j] = rate_ctrls[i - 1];
				pwr_ctrls[j] = pwr_ctrls[i - 1];
				*rate_ctrl |= RS_RATE_RETRY_CNT_SHIFT(0);
			}
			break;
		}

		*rate_ctrl = 0;
		*rate_ctrl |= RS_RATE_RETRY_CNT_SHIFT(!!i);

		/* set use_{ht,vht,mcs,sgi}, leave use_{rts,cts} */
		if (rate->flags & IEEE80211_TX_RC_MCS) {
			use_ht = 1;
			use_vht = 0;
			use_mcs = 1;
			use_sgi = rate->flags & IEEE80211_TX_RC_SHORT_GI;
		} else if (rate->flags & IEEE80211_TX_RC_VHT_MCS) {
			use_ht = 0;
			use_vht = 1;
			use_mcs = 1;
			use_sgi = rate->flags & IEEE80211_TX_RC_SHORT_GI;
		} else {
			use_ht = use_vht = use_mcs = use_sgi = 0;
		}

		/*
         * RTS/CTS
         * Honor the RTS threshold
         *   minstrel never uses RTS on 1st rate with HT
         *   when using pre-HT the stack behaves as we want wrt RTS
         * The HW can only send RTS to known STAs
         * set use_{rts,cts} */
		use_rts = use_cts_protect = 0;
		if (((rate->flags & IEEE80211_TX_RC_USE_RTS_CTS) || (use_mcs && above_rtsthr)) && sta) {
			use_rts = 1;
		} else {
			if (rate->flags & IEEE80211_TX_RC_USE_CTS_PROTECT)
				use_cts_protect = 1;
			/* HT/GF Protection - ATM mac80211 does not do it */
			else if (use_mcs)
				/* Assumes we can't tx MCS with no bss_conf - FIXME with IBSS et.al. */
				use_cts_protect = conf->use_cts_prot;
		}

		/* set rate_ctrl */
		if (use_mcs) {
			u8 nss;

			*rate_ctrl |= RS_RATE_MCS_SHIFT(rate->idx);

			if (use_ht) {
				nss = rate->idx >> 3;
				/* GF
                 * TODO let GF and SGI be exclusive only for single SS MCSs
                 *      for the moment make it always exclusive */
				if (gf_sta && !use_sgi && (use_rts || use_cts_protect || gf_able)) {
					*rate_ctrl |= RS_RATE_PHY_MODE_SHIFT(RS_PHY_MODE_HT_GF);
					/* for radiotap feedback - should be set by SW RC
                     * minstrel doesn't handle this */
					rate->flags |= IEEE80211_TX_RC_GREEN_FIELD;
				} else {
					*rate_ctrl |= RS_RATE_PHY_MODE_SHIFT(RS_PHY_MODE_HT);
				}
			} else {
				nss = rate->idx >> 4;
				*rate_ctrl |= RS_RATE_PHY_MODE_SHIFT(RS_PHY_MODE_VHT);
			}

			if (i == 0) {
				if (nss < sta_stbc_nss) {
					stbc_nss = nss;
					use_stbc = 1;
				}
			} else if (use_stbc && (nss != stbc_nss))
				use_stbc = 0;

			if (use_sgi) {
				*rate_ctrl |= RS_RATE_SGI_SHIFT(1);
			}
		} else {
			*rate_ctrl |= RS_RATE_MCS_SHIFT(bitrates[rate->idx].hw_value);
			*rate_ctrl |= RS_RATE_PHY_MODE_SHIFT(RS_PHY_MODE_CCK);
			if (!(rate->flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE)) {
				*rate_ctrl |= RS_RATE_PREAMBLE_SHIFT(1);
			}
		}

		if (rate->flags & IEEE80211_TX_RC_40_MHZ_WIDTH || rate->flags & IEEE80211_TX_RC_DUP_DATA) {
			*rate_ctrl |= RS_RATE_BW_SHIFT(RS_CH_BW_40);
		} else if (rate->flags & IEEE80211_TX_RC_80_MHZ_WIDTH) {
			WARN_ON(!use_vht);
			*rate_ctrl |= RS_RATE_BW_SHIFT(RS_CH_BW_80);
		} else if (rate->flags & IEEE80211_TX_RC_160_MHZ_WIDTH) {
			*rate_ctrl |= RS_RATE_BW_SHIFT(RS_CH_BW_160);
		}
		bw = (*rate_ctrl >> RS_RATE_BW_POS) & RS_RATE_BW_MASK;

		*pwr_ctrl = RS_TX_POWER_SHIFT(tx_power);

		if (use_rts || use_cts_protect) {
			/* Choose rts over cts */
			*rate_ctrl |= RS_RATE_CTS_RTS_SHIFT(
				(use_rts ? NAV_PROT_RTS_CTS_BIT : NAV_PROT_SELF_CTS_BIT));
			*rate_ctrl |= RS_RATE_BW_PROT_SHIFT(bw);
			if (bw == RS_CH_BW_20) {
				*rate_ctrl |= RS_RATE_PHY_MODE_PROJ_SHIFT(RS_PHY_MODE_CCK);
			} else {
				*rate_ctrl |= RS_RATE_PHY_MODE_PROJ_SHIFT(RS_PHY_MODE_OFDM);
			}

			if (use_cts_protect) {
				*rate_ctrl |= RS_RATE_MCS_PROT_SHIFT((use_cts_protect ? cts_rate : 0));
			}

			*pwr_ctrl = RS_TX_PWR_PROT_SHIFT(tx_power);
		}
	}

	if (use_stbc) {
		dev_txhdr->tx_rule.perf_ctrl_value |= STBC_MASK(stbc_nss);
	}
}

static s32 txhdr_initialize(struct rs_hw_priv *priv, rs_txhdr_t *txhdr, const struct sk_buff *skb,
			    struct ieee80211_tx_info *tx_info, const u16 sn, const u8 tid)
{
	struct ieee80211_hw *hw = priv->hw;
	struct wiphy *wiphy = hw->wiphy;
	struct rs_dev_txhdr *dev_txhdr = &txhdr->dev_hdr;
	struct ieee80211_sta *sta;
	struct rs_sta_priv *sta_priv;
	struct rs_vif_priv *vif_priv;
	u8 tx_power;
	bool above_rtsthr;

	sta_priv = txhdr->sta_priv;
	sta = sta_priv ? container_of((void *)sta_priv, struct ieee80211_sta, drv_priv) : NULL;
	vif_priv = (struct rs_vif_priv *)(tx_info->control.vif->drv_priv);

	dev_txhdr->phy_ctrl_value |= RS_PHY_GROUD_ID_MASK_SHIFT(63);
	dev_txhdr->phy_ctrl_value |= RS_PHY_GROUD_ID_MASK_SHIFT(63);

	if (!(tx_info->flags & IEEE80211_TX_CTL_NO_ACK)) {
		dev_txhdr->mac_ctrl_value |= RS_PACKET_ACK_MASK_SHIFT(RS_PACKET_NORMAL_ACK);
	}

	/*
     * dev_txhdr.tx_rule {
     */
	if (unlikely(priv->sw_scanning) &&
	    ieee80211_is_probe_req(((struct ieee80211_hdr *)skb_mac_header(skb))->frame_control))
		tx_power = priv->scan_txpower_idx;
	else
		tx_power = vif_priv->txpower_idx;

	dev_txhdr->tx_rule.perf_ctrl_value = priv->perf_ctrl_value;
	above_rtsthr = min_t(u32, skb->len + FCS_LEN, wiphy->frag_threshold) > wiphy->rts_threshold;
	rs_fill_dev_rate_ctrl(priv, tx_info, dev_txhdr, sta, above_rtsthr, tx_power);

	/* tx_pattern */
	dev_txhdr->tx_rule.tx_pattern = POLICY_TABLE_PATTERN;

	/* perf_ctrl */
	if (tx_info->flags & IEEE80211_TX_CTL_LDPC)
		dev_txhdr->tx_rule.perf_ctrl_value |= FEC_CODING_BIT;

	/* antset_value */
	dev_txhdr->tx_rule.antset_value = priv->antset_value; /* antenna set */

	/* mackeyinfo */
	/* beware when prot and sta is unknown */
	dev_txhdr->tx_rule.hw_key_value |= RS_HW_STA_ID_SHIFT((sta_priv ? sta_priv->hw_sta_id : 0));
	if (tx_info->control.hw_key) {
		struct ieee80211_key_conf *key_conf = tx_info->control.hw_key;
		dev_txhdr->tx_rule.hw_key_value |= RS_HW_KEY_IDX_SHIFT(key_conf->hw_key_idx);
		txhdr->crypto_overhead = key_conf->icv_len;
		// REFME:
		// if (tx_info->control.rates[0].flags & IEEE80211_TX_RC_USE_CTS_PROTECT)
		// 	ieee80211_ctstoself_get(priv->hw, tx_info->control.vif,
		// 				skb->data, data_length, tx_info,
		// 				(struct ieee80211_cts *)(skb->data));
		// else
		// 	ieee80211_rts_get(rt2x00dev->hw, tx_info->control.vif,
		// 			skb->data, data_length, tx_info,
		// 			(struct ieee80211_rts *)(skb->data));
	}

	/* retry_rts */
	dev_txhdr->tx_rule.retry_rts_value |= RS_RETRY_SHORT_SHIFT(wiphy->retry_short);
	dev_txhdr->tx_rule.retry_rts_value |= RS_RETRY_LONG_SHIFT(wiphy->retry_long);
	dev_txhdr->tx_rule.retry_rts_value |= RS_RTS_THRESHOLD_SHIFT(wiphy->rts_threshold);

	if (txhdr->agg) {
		u32 mode = (txhdr->dev_hdr.tx_rule.rate_ctrl_values[0] >> RS_RATE_PHY_MODE_POS) &
			   RS_RATE_PHY_MODE_MASK;
		txhdr->ampdu.phy_mode = false;
		if (mode != RS_PHY_MODE_CCK)
			txhdr->ampdu.phy_mode = true;
	}

	return 0;
}

static void tx_kickback_q_head_check(struct rs_hw_priv *priv, s32 hw_queue, u32 idx)
{
	void *txdata = NULL;

	rs_tx_q_data_lock(priv, hw_queue);

	txdata = priv->tx.q[hw_queue].data[idx];
	priv->tx.q[hw_queue].data[idx] = NULL;

	rs_tx_q_data_unlock(priv, hw_queue);

	if (!!txdata) {
		struct sk_buff *skb = txdata;
#ifdef CONFIG_HOST_TX_NO_KICKBACK
		dev_kfree_skb_any(skb);
#else
		rs_txhdr_t *txhdr = &exttxhdrs[*(u16 *)(&skb->cb[46])];
		pr_debug("Discard uncomfirmed txdata i %d s %x\n", idx, txhdr->dev_hdr.status.value);
		priv->tx.q[hw_queue].nb_drop++;
#endif
	}
}

static inline struct rs_vif_priv *rs_get_vif(struct rs_hw_priv *hw, u8 *mac)
{
	struct rs_vif_priv *vif;

	list_for_each_entry(vif, &hw->vifs, list) {
		if (ether_addr_equal(vif->vif->addr, mac))
			return vif;
	}
	return NULL;
}

static s32 tx_queue_and_work(struct sk_buff *skb, struct rs_hw_priv *priv, bool retry)
{
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	s32 hw_queue = tx_info->hw_queue;
	struct sk_buff_head *q = &priv->tx.q[hw_queue].list;

	if (!retry)
		skb_queue_tail(q, skb);
	else
		skb_queue_head(q, skb);

	if (skb_queue_len(q) >= TX_SKB_LIST_MAX) {
		ieee80211_stop_queue(priv->hw, hw_queue);
		priv->tx.q[hw_queue].stops++;
	}

	queue_work(priv->wq, &priv->tx.wk);

	return 0;
}

void rs_ops_xmit(struct ieee80211_hw *hw, struct ieee80211_tx_control *control, struct sk_buff *skb)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_txhdr *txhdr;
	struct ieee80211_hdr *mac_hdr;
	struct rs_vif_priv *vif_priv;
	struct rs_core *core = priv->core;
	struct ieee80211_tx_info *tx_info;
	struct ieee80211_sta *sta = NULL;
	u16 hw_queue;
	u16 sn;
	u8 is_data_qos;
	u8 is_qos_nullfunc;
	u8 tid;

	if (!(skb && skb->len)) {
		RS_ERR("skb is NULL or skb->len is 0\n");
		return;
	}

	if (!core->enabled) {
		RS_ERR("core is not enabled\n");
		return;
	}

	if (control && control->sta)
		sta = control->sta;

	tx_info = IEEE80211_SKB_CB(skb);
	mac_hdr = (struct ieee80211_hdr *)skb->data;

	vif_priv = rs_get_vif(priv, mac_hdr->addr2);
	if (!vif_priv) {
		ieee80211_free_txskb(priv->hw, skb);
		return;
	}

	txhdr = &exttxhdrs[exthdr_idx];
	memset(txhdr, 0, sizeof(struct rs_txhdr));
	*(u16 *)(&skb->cb[46]) = exthdr_idx;
	exthdr_idx = (exthdr_idx + 1) % EXTRA_TXHDR_MAX_IDX;

	if (likely(is_data_qos = !!ieee80211_is_data_qos(mac_hdr->frame_control))) {
		u8 *qos = ieee80211_get_qos_ctl(mac_hdr);
		tid = *qos & IEEE80211_QOS_CTL_TID_MASK;
		skb->priority = TID_TO_AC(tid);
		is_qos_nullfunc = ieee80211_is_qos_nullfunc(mac_hdr->frame_control);
	} else {
		tid = 0;
		skb->priority = BE_Q;
		is_qos_nullfunc = 0;
	}
	hw_queue = skb->priority;
	sn = IEEE80211_SEQ_TO_SN(mac_hdr->seq_ctrl);

	txhdr->sn = sn;
	txhdr->tid = tid;
	txhdr->crypto_overhead = 0;
	txhdr->ampdu.len = 0;
	txhdr->vif_priv = vif_priv;
	txhdr->agg = NULL;

	// print_hex_dump(KERN_INFO,"",DUMP_PREFIX_OFFSET,16,1,mac_hdr,64,0);

	if (sta) {
		txhdr->sta_priv = (struct rs_sta_priv *)sta->drv_priv;
		if (likely(is_data_qos && (tx_info->flags & IEEE80211_TX_CTL_AMPDU) && !is_qos_nullfunc)) {
			struct rs_agg *agg = &txhdr->sta_priv->aggs[tid];
			if (agg->on) {
				txhdr->agg = agg;
			}
			if (unlikely((tx_info->flags & IEEE80211_TX_INTFL_RETRANSMISSION))) {
				if (tx_info->flags & IEEE80211_TX_STATUS_EOSP)
					ieee80211_sta_eosp(control->sta);
				ieee80211_free_txskb(priv->hw, skb);
				return;
			}
		}
	} else {
		if ((vif_priv->vif->type != NL80211_IFTYPE_MESH_POINT) && unlikely(is_data_qos)) {
			ieee80211_free_txskb(priv->hw, skb);
			return;
		}
		txhdr->sta_priv = NULL;
	}
	txhdr->dev_hdr.status.value = 0;
	txhdr->jiffies = jiffies;

	if (tx_info->control.hw_key && tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_SMS4) {
		rs_update_wpi_header(priv, (u8 *)mac_hdr + ieee80211_hdrlen(mac_hdr->frame_control),
				     tx_info->control.hw_key);
	}

	if (unlikely(txhdr_initialize(priv, txhdr, skb, tx_info, sn, tid))) {
		ieee80211_free_txskb(priv->hw, skb);
		return;
	}

	tx_queue_and_work(skb, priv, false);
}

static int tx_retry(struct rs_hw_priv *priv, struct rs_txhdr *txhdr, struct sk_buff *skb)
{
	txhdr->retry++;

	if (txhdr->retry > RS_TX_RETRY_THRESHOLD_VALUE) {
		return -1;
	}

	tx_queue_and_work(skb, priv, true);

	return 0;
}

static void tx_down_rate(struct ieee80211_tx_rate *rate, u32 bw)
{
	int nss;

	// FIXME
	WARN_ON(rate->flags & IEEE80211_TX_RC_DUP_DATA);
	rate->flags &= ~(IEEE80211_TX_RC_40_MHZ_WIDTH | IEEE80211_TX_RC_80_MHZ_WIDTH |
			 IEEE80211_TX_RC_160_MHZ_WIDTH);
	switch (bw) {
	case RS_CH_BW_20:
		if ((rate->flags & IEEE80211_TX_RC_VHT_MCS) && rate->idx == 9)
			rate->idx = 8;
		break;
	case RS_CH_BW_40:
		rate->flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;
		break;
	case RS_CH_BW_80:
		nss = ieee80211_rate_get_vht_nss(rate);
		if (rate->idx == 6 && (nss == 3 || nss == 7))
			rate->idx = 5;
		else if (rate->idx == 9 && nss == 6)
			rate->idx = 8;
		rate->flags |= IEEE80211_TX_RC_80_MHZ_WIDTH;
		break;
	default:
		WARN_ON(1);
	}
}

static void tx_info_update(struct rs_hw_priv *priv, struct rs_txhdr *txhdr, struct sk_buff *skb,
			   struct ieee80211_tx_info *tx_info, union rs_kickback_status rs_txst,
			   struct rs_agg *agg, bool is_ampdu, bool last_ampdu, bool single_ampdu)
{
	s32 tries, i;
	u32 bw;

	if (txhdr->is_drop) {
		s32 hw_queue = tx_info->hw_queue;
		priv->tx.q[hw_queue].nb_drop++;
		dev_kfree_skb_any(skb);
		return;
	}

	if (rs_txst.kickback_tx_done && !(tx_info->flags & IEEE80211_TX_CTL_NO_ACK))
		tx_info->flags |= IEEE80211_TX_STAT_ACK;

	if (is_ampdu) { /// AMPDU.
		tx_info->flags |= IEEE80211_TX_STAT_AMPDU;
		tx_info->status.rates[0].count = 1;
		tx_info->status.rates[1].idx = -1;
		if (last_ampdu) {
			tx_info->status.ampdu_ack_len = agg->ack;
			tx_info->status.ampdu_len = agg->len;
			agg->len = agg->ack = 0;
		} else {
			if (single_ampdu) {
				tx_info->status.ampdu_ack_len = !!rs_txst.kickback_tx_done;
				tx_info->status.ampdu_len = 1;
			} else {
				tx_info->status.ampdu_ack_len = 0;
				tx_info->status.ampdu_len = 0;
			}
		}
	} else { /// MPDU.
		for (i = 0, tries = rs_txst.kickback_mpdu_retries + 1;
		     i < priv->hw->max_rates && tries && tx_info->status.rates[i].idx != -1; i++, tries--) {
			tx_info->status.rates[i].count = 1;
		}
		if (tries)
			tx_info->status.rates[i - 1].count += tries;
		else
			tx_info->status.rates[i].idx = -1;

		if (tx_info->flags & IEEE80211_TX_CTL_AMPDU) {
			tx_info->status.ampdu_ack_len = !!rs_txst.kickback_tx_done;
			tx_info->status.ampdu_len = 1;
		}

		bw = (txhdr->dev_hdr.tx_rule.rate_ctrl_values[0] >> RS_RATE_BW_POS) & RS_RATE_BW_MASK;
		if (rs_txst.kickback_xmit_bw != bw) {
			WARN_ON(rs_txst.kickback_xmit_bw > bw);
			tx_down_rate(&tx_info->status.rates[i - 1], rs_txst.kickback_xmit_bw);
		}
	}

	if (!txhdr->is_free) {
		ieee80211_tx_status(priv->hw, skb);
		txhdr->is_free = true;
	} else {
		dev_kfree_skb(skb);
	}
}

void rs_tx_q_data_lock_init(struct rs_hw_priv *priv)
{
	s32 i = 0;

	for (i = 0; i < RS_TXQ_CNT; i++) {
		mutex_init(&(priv->tx.q[i].data_lock));
	}
}

void rs_tx_q_data_lock_destroy(struct rs_hw_priv *priv)
{
	s32 i = 0;

	for (i = 0; i < RS_TXQ_CNT; i++) {
		mutex_destroy(&(priv->tx.q[i].data_lock));
	}
}

void rs_tx_q_data_lock(struct rs_hw_priv *priv, u16 ac)
{
	mutex_lock(&(priv->tx.q[ac].data_lock));
}

void rs_tx_q_data_unlock(struct rs_hw_priv *priv, u16 ac)
{
	mutex_unlock(&(priv->tx.q[ac].data_lock));
}

s32 rs_tx_kickback_handler(struct rs_hw_priv *priv, void *data)
{
	struct sk_buff *skb = (struct sk_buff *)data;
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	s32 hw_queue = tx_info->hw_queue;
	union rs_kickback_status rs_txst;
	struct rs_txhdr *txhdr;
	struct rs_vif_priv *vif_priv;

	struct rs_agg *agg;
	bool is_agg_phy_mode = false;
	bool first_ampdu = false;
	bool last_ampdu = false;
	bool single_ampdu = false;
	u32 bw;

	txhdr = &exttxhdrs[*(u16 *)(&skb->cb[46])];
	agg = txhdr->agg;
	rs_txst = txhdr->dev_hdr.status;

	if (rs_txst.value == 0) {
		pr_err("cfm: No has txstatus. :(\n");
		return -1;
	}

	vif_priv = (struct rs_vif_priv *)(tx_info->control.vif->drv_priv);

	if (!!rs_txst.kickback_need_retry && (hw_queue < 4 /*BEACON*/)) {
		if (!tx_retry(priv, txhdr, skb)) {
			priv->tx.q[hw_queue].nb_retry++;
			return 0;
		} else
			txhdr->is_drop = true;
	}

	if ((agg != NULL) && ((txhdr->sta_priv != NULL) && (txhdr->sta_priv->sleep == true)) &&
	    (rs_txst.kickback_tx_done == 0)) {
		if (!(tx_info->flags & IEEE80211_TX_CTL_NO_PS_BUFFER))
			tx_info->flags |= IEEE80211_TX_STAT_TX_FILTERED;
		agg = NULL;
		priv->tx.back.nb_res_sta_ps[hw_queue]++;
	} else if ((agg != NULL) && RS_CHK_PACKET_AMPDU(rs_txst.kickback_ampdu_status)) {
		is_agg_phy_mode = true;
		first_ampdu = RS_CHK_FIRST_AMPDU(rs_txst.kickback_ampdu_status);
		last_ampdu = RS_CHK_LAST_AMPDU(rs_txst.kickback_ampdu_status);
		if (first_ampdu) {
			agg->len = agg->ack = 0;
		}

		if (!agg->len) {
			bw = (txhdr->dev_hdr.tx_rule.rate_ctrl_values[0] >> RS_RATE_BW_POS) & RS_RATE_BW_MASK;
			agg->rate = tx_info->control.rates[0];
			if (rs_txst.kickback_xmit_bw != bw) {
				WARN_ON(rs_txst.kickback_xmit_bw > bw);
				tx_down_rate(&agg->rate, rs_txst.kickback_xmit_bw);
			}
		}

		agg->len++;
		priv->tx.ampdu.nb_total_cnt++;
		if (rs_txst.kickback_tx_done) {
			agg->ack++;
			priv->tx.ampdu.nb_total_ack++;
		} else {
			if (time_is_after_jiffies(txhdr->jiffies + msecs_to_jiffies(100))) {
				if (last_ampdu) {
					if (unlikely(!agg->ack)) {
						txhdr->ampdu.phy_mode = false;
					}
				}

				if (!agg->on) {
					// pr_debug("AMPDU: DROP vif %d sid %d, Aleady stopped\n",
					// 	txhdr->sta_priv->vif_id, txhdr->sta_priv->id);
					txhdr->is_drop = true;
				} else if (!tx_retry(priv, txhdr, skb)) {
					priv->tx.q[hw_queue].nb_retry++;
					priv->tx.ampdu.nb_total_retry++;
					return 0;
				} else
					txhdr->is_drop = true;
			} else {
				txhdr->is_drop = true;
			}
		}
	} else if (tx_info->flags & IEEE80211_TX_CTL_AMPDU) {
		is_agg_phy_mode = true;
		single_ampdu = true;
		if (agg != NULL) {
			agg->len = agg->ack = 0;
		}
		priv->tx.ampdu.nb_total_cnt++;
		if (rs_txst.kickback_tx_done) {
			priv->tx.ampdu.nb_total_ack++;
		}
	}

	tx_info_update(priv, txhdr, skb, tx_info, rs_txst, agg, is_agg_phy_mode, last_ampdu, single_ampdu);

	return 0;
}

#ifdef CONFIG_RS_BCN
/**
 *
 */
void rs_tx_bcns(struct rs_hw_priv *hw_priv)
{
	struct sk_buff *skb;
	struct rs_vif_priv *vif_priv;

	list_for_each_entry(vif_priv, &hw_priv->vifs, list) {
		struct ieee80211_vif *vif;
		struct ieee80211_tx_info *tx_info;

		if (unlikely(!vif_priv->bcn_on) || unlikely(ieee80211_queue_stopped(hw_priv->hw, BCN_Q)) ||
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		    !(skb = ieee80211_beacon_get(hw_priv->hw, vif = vif_priv->vif))
#else
		    !(skb = ieee80211_beacon_get(hw_priv->hw, vif = vif_priv->vif, 0))
#endif
		)
			continue;
		tx_info = IEEE80211_SKB_CB(skb);
		tx_info->hw_queue = BCN_Q;

		rs_ops_xmit(hw_priv->hw, NULL, skb);

		while (!ieee80211_queue_stopped(hw_priv->hw, BCN_Q) &&
		       (skb = ieee80211_get_buffered_bc(hw_priv->hw, vif))) {
			rs_ops_xmit(hw_priv->hw, NULL, skb);
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		if (
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
			vif->csa_active &&
#else
			vif->bss_conf.csa_active &&
#endif
			ieee80211_beacon_cntdwn_is_complete(vif))
			ieee80211_csa_finish(vif);
#endif
	}
}
#endif

#if defined(CONFIG_HOST_TX_MERGE) && defined(CONFIG_RS_SDIO)
u8 *tx_merge_buf;

void rs_tx_merge_buf_init(void)
{
	tx_merge_buf = kzalloc((FW_IO_TXBUF_CNT * FW_IO_TX_PACKET_SIZE), GFP_KERNEL);
}

void rs_tx_merge_buf_deinit(void)
{
	kfree(tx_merge_buf);
}

s32 tx_bus_ops_merge_kick(struct rs_hw_priv *priv, s32 cnt, u16 start_tx_seq)
{
	struct rs_core *core = priv->core;
	u16 tmp_seq = 0;
	int err = 0;
	u16 tx_seq = priv->tx.seq;
	// int i;

	(tx_seq == 0) ? (tmp_seq = FW_IO_TXBUF_CNT - 1) : (tmp_seq = tx_seq - 1);

	// pr_info("[+ %s/%d] start_tx_seq: %d, tx_seq: %d, tmp_seq: %d\n", __func__, __LINE__, start_tx_seq, tx_seq, tmp_seq);

	if (tmp_seq >= start_tx_seq) {
		err = core->bus.ops.write(core, core->bus.addr.tx + (start_tx_seq * FW_IO_TX_PACKET_SIZE),
					  tx_merge_buf + (start_tx_seq * FW_IO_TX_PACKET_SIZE),
					  (tmp_seq - start_tx_seq + 1) * FW_IO_TX_PACKET_SIZE);
		if (err) {
			pr_err("rnss_sdio_write failed!!! err = %d\n", err);
			goto out;
		}
	} else {
		err = core->bus.ops.write(core, core->bus.addr.tx + (start_tx_seq * FW_IO_TX_PACKET_SIZE),
					  tx_merge_buf + (start_tx_seq * FW_IO_TX_PACKET_SIZE),
					  (FW_IO_TXBUF_CNT - start_tx_seq) * FW_IO_TX_PACKET_SIZE);
		if (err) {
			pr_err("rnss_sdio_write failed!!! err = %d\n", err);
			goto out;
		}

		err = core->bus.ops.write(core, core->bus.addr.tx, tx_merge_buf,
					  (tmp_seq + 1) * FW_IO_TX_PACKET_SIZE);
		if (err) {
			pr_err("rnss_sdio_write failed!!! err = %d\n", err);
			goto out;
		}
	}

out:
	return err;
}

s32 tx_bus_ops_merge_data(struct rs_hw_priv *priv, void *data, s32 hw_queue)
{
	s32 err;
	// struct rs_core *core = priv->core;
	struct sk_buff *skb = (struct sk_buff *)data;
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	struct rs_txhdr *txhdr = &exttxhdrs[(*(u16 *)(&skb->cb[46])];
	const u16 data_len = skb->len + txhdr->crypto_overhead;
	u32 total_len = 0;
	bool is_ampdu = !!(tx_info->flags & IEEE80211_TX_CTL_AMPDU);
	bool is_agg_phy_mode = (txhdr->agg && txhdr->ampdu.phy_mode);

	struct rs_tx_data_header {
		u8 index;
		u8 hw_queue;
		u16 data_len;
		u8 kickback_idx;
		u8 tid;
		u8 vid;
		u8 sid;
		u16 sn;
#define FLAG_AGG1_BIT BIT(1) // Indicated this packet is AMPDU.
#define FLAG_AGG2_BIT BIT(2) // Indicated this packet needs PHY AMPDU processing.
		u16 flags1;
		u32 flags2;
	} *hdr;

	u32 *tx_q_idx = &priv->tx.q[hw_queue].i;
	u8 *b = priv->tx.b2k; // Tx Buffer.
	u16 *s = &priv->tx.seq; // Tx seq.

	(void)memset(b, 0, FW_IO_TX_PACKET_SIZE);

	total_len = sizeof(struct rs_tx_data_header) + sizeof(struct rs_dev_txhdr) + data_len;
	total_len += ALIGN_4BYTE(total_len);
	total_len += 4 /*PATTERN_SIZE*/;

	/* Add stuct tx_data_header */
	hdr = (struct rs_tx_data_header *)(b);
	hdr->hw_queue = hw_queue;
	hdr->index = *s;
	hdr->data_len = data_len;
	hdr->kickback_idx = *tx_q_idx;
	// #ifdef CONFIG_HOST_TX_NO_KICKBACK
	// 	if (!is_agg)
	// 		hdr->kickback_idx = 0xff;
	// #endif
	hdr->tid = txhdr->tid;
	hdr->vid = 0;
	if (txhdr->vif_priv)
		hdr->vid = txhdr->vif_priv->vif_index;
	hdr->sid = 0;
	if (txhdr->sta_priv)
		hdr->sid = txhdr->sta_priv->id;
	hdr->sn = txhdr->sn;
	hdr->flags1 = 0;
	if (is_ampdu) {
		hdr->flags1 |= FLAG_AGG1_BIT;
		if (is_agg_phy_mode) {
			hdr->flags1 |= FLAG_AGG2_BIT;
			hdr->flags2 = txhdr->dev_hdr.tx_rule.rate_ctrl_values[0];
		}
	}
	b += sizeof(struct rs_tx_data_header);

	/* Add tx-hw-header */
	memcpy(b, (void *)&txhdr->dev_hdr, sizeof(struct rs_dev_txhdr));
	b += sizeof(struct rs_dev_txhdr);

	/* Add mac80211 packet data */
	memcpy(b, (void *)skb->data, data_len);
	b += data_len;

	/* Adjust 4 bytes align */
	b += ALIGN_4BYTE(priv->tx.b2k - b);

	/* Add End Pattern */
	*((u32 *)(b)) = 0xdeadbeef;

	// err = core->bus.ops.write(core, core->bus.addr.tx + (*s * FW_IO_TX_PACKET_SIZE), priv->tx.b2k, total_len);
	// if (!err) {
	// 	*s = (*s + 1) % FW_IO_TXBUF_CNT; /* Increase tx_seq */
	// 	if (!core->bus.ops.tx_trig) {
	// 		*((u32 *)(priv->tx.b4)) = *s;
	// 		err = core->bus.ops.write(core, RS_A2E_TXCMD_ADDR, priv->tx.b4, 4);
	// 	}
	// }
	// pr_info("[+ %s/%d] @@ *s:%d, [[%p]]\n", __func__, __LINE__, *s, tx_merge_buf);

	memcpy(tx_merge_buf + (*s * FW_IO_TX_PACKET_SIZE), priv->tx.b2k, total_len);
	*s = (*s + 1) % FW_IO_TXBUF_CNT; /* Increase tx_seq */
	err = 0;

	if (!err) {
		tx_kickback_q_head_check(priv, hw_queue, *tx_q_idx);

#ifdef CONFIG_HOST_TX_NO_KICKBACK
		if (!is_ampdu) {
			union rs_kickback_status rs_txst = {};
			rs_txst.kickback_tx_done = 1;

			rs_tx_q_data_lock(priv, hw_queue);

			priv->tx.q[hw_queue].data[*tx_q_idx] = (void *)skb_copy(skb, GFP_ATOMIC);
			*tx_q_idx = (*tx_q_idx + 1) % TX_BACKUP_DATA_SIZE;

			rs_tx_q_data_unlock(priv, hw_queue);

			tx_info_update(priv, txhdr, skb, tx_info, rs_txst, NULL, false, false, false);
		} else
#endif
		{
			rs_tx_q_data_lock(priv, hw_queue);

			priv->tx.q[hw_queue].data[*tx_q_idx] = (void *)skb;
			*tx_q_idx = (*tx_q_idx + 1) % TX_BACKUP_DATA_SIZE;

			rs_tx_q_data_unlock(priv, hw_queue);
		}
		priv->tx.q[hw_queue].nb_kick++;

	} else {
		priv->tx.q[hw_queue].nb_drop++;
	}

	return err;
}
#endif // defined(CONFIG_HOST_TX_MERGE) &&  defined(CONFIG_RS_SDIO)

s32 tx_bus_ops_kick(struct rs_hw_priv *priv, void *data, s32 hw_queue)
{
	s32 err;
	struct rs_core *core = priv->core;
	struct sk_buff *skb = (struct sk_buff *)data;
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	struct rs_txhdr *txhdr = &exttxhdrs[*(u16 *)(&skb->cb[46])];
	const u16 data_len = skb->len + txhdr->crypto_overhead;
	u32 total_len = 0;
	bool is_ampdu = !!(tx_info->flags & IEEE80211_TX_CTL_AMPDU);
	bool is_agg_phy_mode = (txhdr->agg && txhdr->ampdu.phy_mode);

	struct rs_tx_data_header {
		u8 index;
		u8 hw_queue;
		u16 data_len;
		u8 kickback_idx;
		u8 tid;
		u8 vid;
		u8 sid;
		u16 sn;
#define FLAG_AGG1_BIT BIT(1) // Indicated this packet is AMPDU.
#define FLAG_AGG2_BIT BIT(2) // Indicated this packet needs PHY AMPDU processing.
		u16 flags1;
		u32 flags2;
	} *hdr;

	u32 *tx_q_idx = &priv->tx.q[hw_queue].i;
	u8 *b = priv->tx.b2k; // Tx Buffer.
	u16 *s = &priv->tx.seq; // Tx seq.

	(void)memset(b, 0, FW_IO_TX_PACKET_SIZE);

	total_len = sizeof(struct rs_tx_data_header) + sizeof(struct rs_dev_txhdr) + data_len;
	total_len += ALIGN_4BYTE(total_len);
	total_len += 4 /*PATTERN_SIZE*/;

	/* Add stuct tx_data_header */
	hdr = (struct rs_tx_data_header *)(b);
	hdr->hw_queue = hw_queue;
	hdr->index = *s;
	hdr->data_len = data_len;
	hdr->kickback_idx = *tx_q_idx;
	// #ifdef CONFIG_HOST_TX_NO_KICKBACK
	// 	if (!is_agg)
	// 		hdr->kickback_idx = 0xff;
	// #endif
	hdr->tid = txhdr->tid;
	hdr->vid = 0;
	if (txhdr->vif_priv)
		hdr->vid = txhdr->vif_priv->vif_index;
	hdr->sid = 0;
	if (txhdr->sta_priv)
		hdr->sid = txhdr->sta_priv->id;
	hdr->sn = txhdr->sn;
	hdr->flags1 = 0;
	if (is_ampdu) {
		hdr->flags1 |= FLAG_AGG1_BIT;
		if (is_agg_phy_mode) {
			hdr->flags1 |= FLAG_AGG2_BIT;
			hdr->flags2 = txhdr->dev_hdr.tx_rule.rate_ctrl_values[0];
		}
	}
	b += sizeof(struct rs_tx_data_header);

	/* Add tx-hw-header */
	memcpy(b, (void *)&txhdr->dev_hdr, sizeof(struct rs_dev_txhdr));
	b += sizeof(struct rs_dev_txhdr);

	/* Add mac80211 packet data */
	memcpy(b, (void *)skb->data, data_len);
	b += data_len;

	/* Adjust 4 bytes align */
	b += ALIGN_4BYTE(priv->tx.b2k - b);

	/* Add End Pattern */
	*((u32 *)(b)) = 0xdeadbeef;

	err = core->bus.ops.write(core, core->bus.addr.tx + (*s * FW_IO_TX_PACKET_SIZE), priv->tx.b2k,
				  total_len);
	if (!err) {
		*s = (*s + 1) % FW_IO_TXBUF_CNT; /* Increase tx_seq */
	}

	if (!err) {
		tx_kickback_q_head_check(priv, hw_queue, *tx_q_idx);

#ifdef CONFIG_HOST_TX_NO_KICKBACK
		if (!is_ampdu) {
			union rs_kickback_status rs_txst = {};
			rs_txst.kickback_tx_done = 1;

			rs_tx_q_data_lock(priv, hw_queue);

			priv->tx.q[hw_queue].data[*tx_q_idx] = (void *)skb_copy(skb, GFP_ATOMIC);
			*tx_q_idx = (*tx_q_idx + 1) % TX_KICK_DATA_MAX;

			rs_tx_q_data_unlock(priv, hw_queue);

			tx_info_update(priv, txhdr, skb, tx_info, rs_txst, NULL, false, false, false);
		} else
#endif
		{
			rs_tx_q_data_lock(priv, hw_queue);

			priv->tx.q[hw_queue].data[*tx_q_idx] = (void *)skb;
			*tx_q_idx = (*tx_q_idx + 1) % TX_KICK_DATA_MAX;

			rs_tx_q_data_unlock(priv, hw_queue);
		}
		priv->tx.q[hw_queue].nb_kick++;
		priv->tx.balance[hw_queue]++;

	} else {
		priv->tx.q[hw_queue].nb_drop++;
	}

	return err;
}

s32 tx_bus_ops_recovery(struct rs_hw_priv *priv)
{
	s32 err;
	struct rs_core *core = priv->core;
	u8 *b = priv->tx.b2k;
	u16 *s = &priv->tx.seq;

	*((u32 *)(b)) = 0xffffffff;
	b += 4;
	// *((u32 *)(b)) = 0xdeadbeef;
	b[0] = 0xde;
	b[1] = 0xad;
	b[2] = 0xbe;
	b[3] = 0xef;

	err = core->bus.ops.write(core, core->bus.addr.tx + (*s * FW_IO_TX_PACKET_SIZE), priv->tx.b2k, 8);
	if (!err) {
		err = core->bus.ops.tx_trig(priv);
	}

	return err;
}

s32 tx_bus_ops_trig(struct rs_hw_priv *priv)
{
	struct rs_core *core = priv->core;
	s32 err = -1;

	*((u32 *)&(core->bus.host_req)) = 0;
	core->bus.host_req.cmd = HOST_TX_ASK;

	err = core->bus.ops.write(core, RS_A2E_CMD_ADDR, (u8 *)&(core->bus.host_req),
				  sizeof(struct st_mgmt_req));

	return err;
}

s32 tx_bus_ops_q_update(struct rs_hw_priv *priv)
{
	s32 err = 0;
	s32 i;
	struct rs_core *core = priv->core;
	u8 *b = priv->tx.b2k; // Tx Buffer.

	err = core->bus.ops.read(core, core->bus.addr.hwq_len, b, RS_TXQ_CNT);
	if (!err) {
		priv->tx.total_balance = 0;

		for (i = 0; i < RS_TXQ_CNT; i++) {
			priv->tx.busq[i].balance = b[i];
			if (priv->tx.busq[i].balance > priv->tx.busq[i].size) {
				pr_err("Bus Q balance integrity error, value %d\n", priv->tx.busq[i].balance);
				priv->tx.busq[i].balance = priv->tx.busq[i].size;
			}
			priv->tx.balance[i] = priv->tx.busq[i].size - priv->tx.busq[i].balance;
			priv->tx.total_balance += priv->tx.balance[i];
		}

		if (priv->tx.total_balance >= FW_IO_TXBUF_CNT) {
			msleep(1);
			priv->tx.bus_q_full_cnt++;
			if (priv->tx.bus_q_full_cnt > 100) {
				pr_err("BusQ fulled over 100ms, %d\n", i);
				priv->tx.bus_q_full_cnt = 0;
				err = core->bus.ops.tx_rec(priv);
			}
		} else {
			priv->tx.bus_q_full_cnt = 0;
		}
	} else {
		pr_err("Bus Q balance update fail, bus read err %d\n", err);
	}

	return err;
}

void rs_tx_work_handler(struct work_struct *work)
{
	struct rs_hw_priv *priv = container_of(work, struct rs_hw_priv, tx.wk);
	struct rs_core *core = priv->core;
	s32 pending = 0;
	s32 total_tx_cnt = 0;
	s32 i;
	s32 skb_balance;

	static int stop_cnt = 0;

	if (priv->tx.deinit)
		return;

	if (!!priv->tx.status) {
		if (stop_cnt++ > (60 * 1000 /*1SEC*/)) {
			pr_warn("Tx status recovery\n");
			priv->tx.status = TX_Q_STATUS_NONE;
		} else {
			msleep(1);
			queue_work(priv->wq, &priv->tx.wk);
			return;
		}
	} else {
		stop_cnt = 0;
	}

	/* Updates BUS Queue status for Tx data sending */
	core->bus.ops.q_update(priv);

	/* Handling that to send Tx data heading to PHY */
	for (i = 0; i < RS_TXQ_CNT; i++) {
		struct sk_buff_head *q = &priv->tx.q[i].list;
		// spinlock_t *lock = &priv->tx.q[i].lock;
		struct bus_q *busq = &priv->tx.busq[i];
		struct sk_buff *skb;
		s32 kick_count = 0;
#if defined(CONFIG_HOST_TX_MERGE) && defined(CONFIG_RS_SDIO)
		u32 count = 0;
		u16 start_tx_seq = priv->tx.seq;
#endif

		if (busq->balance < 0) {
			pr_err("tx_work: HWQ[%d] bad balance %d, left TxQ len %d !!!\n", i, busq->balance,
			       skb_queue_len(q));
			busq->balance = 0;
		}

		while ((priv->tx.total_balance < FW_IO_TXBUF_CNT) &&
		       (priv->tx.balance[i] < priv->tx.busq[i].size)) {
			skb = skb_dequeue(q);
			skb_balance = skb_queue_len(q);

			if (skb) {
				struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
				s32 hw_queue = tx_info->hw_queue;

				if (i != hw_queue) {
					pr_err("tx_work: hw_queue %d != %d i :(\n", hw_queue, i);
				}

#if defined(CONFIG_HOST_TX_MERGE) && defined(CONFIG_RS_SDIO)
				priv->core->bus.ops.tx_merge_data(priv, (void *)skb, hw_queue);
				count++;
#else
				priv->core->bus.ops.tx_kick(priv, (void *)skb, hw_queue);
#endif
				priv->tx.busq[hw_queue].balance--;
				kick_count++;

				if (skb_balance == 0) {
					goto WAKE_Q_CHECK;
				}
			} else {
WAKE_Q_CHECK:
				if (ieee80211_queue_stopped(priv->hw, i) && !priv->ch_switch_stop_tx) {
					ieee80211_wake_queue(priv->hw, i);
					// pr_debug("txqing: ieee80211_wake_queue[%d]\n", i);
				}
				break;
			}
		}

#if defined(CONFIG_HOST_TX_MERGE) && defined(CONFIG_RS_SDIO)
		if (count) {
			// pr_info("[+ %s/%d] count: %d\n", __func__, __LINE__, count);
			priv->core->bus.ops.tx_merge_kick(priv, kick_count, start_tx_seq);
		}
#endif

		if (kick_count) {
			/* Tx interrupt request */
			if (!!core->bus.ops.tx_trig)
				core->bus.ops.tx_trig(priv);
		}
		total_tx_cnt += kick_count;

		{
			s32 lefts = skb_queue_len(q);
			if (lefts > 0) {
				pending++;
			}
		}
	}

	if (pending || total_tx_cnt) {
		queue_work(priv->wq, &priv->tx.wk);
	}
}
