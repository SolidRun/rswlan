// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>
#include <net/mac80211.h>

#include "rs_defs.h"
#include "rs_rx.h"
#include "rs_hal.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define RX_DMA_OVER_PATTERN 0xAAAAAA00

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

static void rx_status_vect_phy_info_updates(struct ieee80211_rx_status *status,
	struct rs_rx_info_v *infov, struct rs_rx_ch_info *phy_info)
{
	if (infov->fmod > RS_PHY_MODE_OFDM) {
		status->rate_idx = infov->mcs;

		if (infov->fmod == RS_PHY_MODE_HT)
			status->enc_flags |= RX_ENC_HT;
		else if (infov->fmod == RS_PHY_MODE_HT_GF)
			status->enc_flags |= RX_ENC_HT | RX_ENC_FLAG_HT_GF;
		else {
			status->enc_flags |= RX_ENC_VHT;
			status->nss = (infov->stbc ? infov->stbc : infov->sts) + 1;
		}

		if (infov->sgi)
			status->enc_flags |= RX_ENC_FLAG_SHORT_GI;

		if (infov->fec)
			status->enc_flags |= RX_ENC_FLAG_LDPC;

	} else {
		if (phy_info->ch_band == NL80211_BAND_5GHZ)
			status->rate_idx -= 4; /* rs_ratetable_5ghz[0].hw_value == 4 */
		if (!infov->ptype)
			status->enc_flags |= RX_ENC_FLAG_SHORTPRE;
	}

	if (infov->cbw == RS_CH_BW_40)
		status->bw |= RATE_INFO_BW_40;
	else if (infov->cbw == RS_CH_BW_80)
		status->bw |= RATE_INFO_BW_80;
	else if (infov->cbw == RS_CH_BW_160)
		status->bw |= phy_info->ch_freq_cen2 ? RATE_INFO_BW_80 : RATE_INFO_BW_160;
	status->band = phy_info->ch_band;
	status->freq = phy_info->ch_freq_prime20;
	status->signal = infov->sig.sig1;

	if (hweight32(infov->ant) > 1) {
		status->flag |= RX_FLAG_NO_SIGNAL_VAL;
		status->chains = infov->ant;
		status->chain_signal[0] = infov->sig.sig1;
		status->chain_signal[1] = infov->sig.sig2;
		status->chain_signal[2] = infov->sig.sig3;
		status->chain_signal[3] = infov->sig.sig4;
	}
	else {
		status->antenna = infov->ant;
	}
}

static s32 rx_status_info_updates(struct rs_hw_priv *rs_hw, struct ieee80211_rx_status *status,
				  struct rs_rx_info *rxhdr)
{
	s32 ret = 0;

	memset(status, 0, sizeof(struct ieee80211_rx_status));

	if (unlikely(!rxhdr->rx_success)) {
		RS_DBG("err_fcs:%d\n", rxhdr->err_fcs);
		if (rxhdr->err_fcs)
			status->flag |= RX_FLAG_FAILED_FCS_CRC;
		else
			status->flag |= RX_FLAG_FAILED_PLCP_CRC;
		return -1;
	}

	status->mactime = le64_to_cpu(((u64)(rxhdr->rx_info_a.tsf_h) << 32) | rxhdr->rx_info_a.tsf_l);
	status->flag |= RX_FLAG_MACTIME_END;

	rx_status_vect_phy_info_updates(status, &(rxhdr->rx_info_v), &(rxhdr->phy_info));

	if ((rxhdr->rx_info_v.fmod > RS_PHY_MODE_OFDM) && (rxhdr->rx_info_v.agg)) {
		status->flag |= RX_FLAG_AMPDU_DETAILS;
		status->ampdu_reference = rxhdr->rx_info_a.amdpu_num;
	}

	switch (rxhdr->rx_info_b.rx_status) {
	case RS_RX_UNENC:
		break;
	case RS_RX_ICV_FAIL:
	case RS_RX_AMSDU_DISCARD:
	case RS_RX_NULL_KEY:
	case RS_RX_CCMP_FAIL:
		ret = -1;
		break;
	case RS_RX_WEP_SUCCESS:
	case RS_RX_TKIP_SUCCESS:
	case RS_RX_CCMP_SUCCESS:
		status->flag |= RX_FLAG_DECRYPTED;
		break;
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_rx_data_handler(struct rs_hw_priv *priv, struct sk_buff *skb)
{
	struct rs_rx_info *rs_rx_info;
	struct ieee80211_rx_status *rx_status;
	u32 rx_pattern;
	s32 mpdu_offset = sizeof(struct rs_rx_info);
	s32 push_back = 0;
	u8 err = 0;

	rx_pattern = ((struct rs_rx_info *)skb->data)->rx_pat;

	if (rx_pattern != RX_DMA_OVER_PATTERN) {
		pr_err("RX wrong pattern 0x%x\n", rx_pattern);
		err = -1;
		priv->rx.nb_err_fmt++;
		dev_kfree_skb_any(skb);
		return err;
	}

	rs_rx_info = (struct rs_rx_info *)skb->data;

	rx_status = IEEE80211_SKB_RXCB(skb);

	if (unlikely(rx_status_info_updates(priv, rx_status, rs_rx_info)))
		push_back = 1;
	else if (unlikely(rs_rx_info->rx_info_b.rx_status == RS_RX_UNENC)) {
		struct ieee80211_hdr *mac_hdr = (struct ieee80211_hdr *)(skb->data + mpdu_offset);
		if (ieee80211_has_protected(mac_hdr->frame_control))
			push_back = 1;
	}

	if (push_back) {
		pr_debug("RX invalid packet header\n");
		priv->rx.nb_err_fmt++;
		dev_kfree_skb_any(skb);
		return err;
	}
	skb_reserve(skb, mpdu_offset);

	skb_put(skb, le32_to_cpu(rs_rx_info->rx_info_a.rx_buf_size));

	if (rs_rx_info->rx_info_b.rx_status == RS_RX_WEP_SUCCESS ||
	    rs_rx_info->rx_info_b.rx_status == RS_RX_TKIP_SUCCESS)
		skb_put(skb, IEEE80211_WEP_ICV_LEN);
	if (rs_rx_info->rx_info_b.rx_status == RS_RX_CCMP_SUCCESS)
		skb_put(skb, IEEE80211_CCMP_MIC_LEN);

	spin_lock_bh(&priv->rx_lock);

	if (!err && !priv->rx.deinit)
		ieee80211_rx(priv->hw, skb);
	else
		dev_kfree_skb_any(skb);

	spin_unlock_bh(&priv->rx_lock);

	return err;
}
