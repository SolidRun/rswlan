// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>
#include <linux/sched/clock.h>

#include "rs_mgmt_tx.h"
#include "rs_mac.h"
#include "rs_params.h"
#include "rs_priv.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define CONFIG_RS_DBG

#define RS_MAC80211_CHANGEABLE                                                                  \
	(ACCEPT_BA_BIT | ACCEPT_BAR_BIT | ACCEPT_OTHER_DATA_FRAMES_BIT | ACCEPT_PROBE_ASK_BIT | \
	 ACCEPT_PS_POLL_BIT)

#define RS_MAC80211_NOT_CHANGEABLE                                                                   \
	(ACCEPT_QO_S_NULL_BIT | ACCEPT_Q_DATA_BIT | ACCEPT_DATA_BIT | ACCEPT_OTHER_MGMT_FRAMES_BIT | \
	 ACCEPT_MY_UNICAST_BIT | ACCEPT_BROADCAST_BIT | ACCEPT_BEACON_BIT | ACCEPT_PROBE_RESP_BIT)

#define RS_DEFAULT_RX_FILTER (RS_MAC80211_CHANGEABLE | RS_MAC80211_NOT_CHANGEABLE)

#define RS_LPCA_PPM	     20 // Low Power Clock accuracy
#define RS_UAPSD_TIMEOUT     300 // UAPSD Timer timeout, in ms (Default: 300). If 0, UAPSD is disabled

static const s32 bw2chnl[] = {
	[NL80211_CHAN_WIDTH_20_NOHT] = RS_CHAN_BW_20, [NL80211_CHAN_WIDTH_20] = RS_CHAN_BW_20,
#ifdef CONFIG_SUPPORT_5G
	[NL80211_CHAN_WIDTH_40] = RS_CHAN_BW_49,      [NL80211_CHAN_WIDTH_80] = RS_CHAN_BW_80,
	[NL80211_CHAN_WIDTH_160] = RS_CHAN_BW_160,    [NL80211_CHAN_WIDTH_80P80] = RS_CHAN_BW_80P80,
#endif
};

const s32 chnl2bw[] = {
	[RS_CHAN_BW_20] = NL80211_CHAN_WIDTH_20,
#ifdef CONFIG_SUPPORT_5G
	[RS_CHAN_BW_49] = NL80211_CHAN_WIDTH_40,   [RS_CHAN_BW_80] = NL80211_CHAN_WIDTH_80,
	[RS_CHAN_BW_160] = NL80211_CHAN_WIDTH_160, [RS_CHAN_BW_80P80] = NL80211_CHAN_WIDTH_80P80,
#endif
};

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

static inline u8 ampdudensity2usec(u8 ampdudensity)
{
	switch (ampdudensity) {
	case IEEE80211_HT_MPDU_DENSITY_NONE:
		return 0;
	case IEEE80211_HT_MPDU_DENSITY_0_25:
	case IEEE80211_HT_MPDU_DENSITY_0_5:
	case IEEE80211_HT_MPDU_DENSITY_1:
		return 1;
	case IEEE80211_HT_MPDU_DENSITY_2:
		return 2;
	case IEEE80211_HT_MPDU_DENSITY_4:
		return 4;
	case IEEE80211_HT_MPDU_DENSITY_8:
		return 8;
	case IEEE80211_HT_MPDU_DENSITY_16:
		return 16;
	default:
		return 0;
	}
}

static inline bool use_pairwise_key(struct cfg80211_crypto_settings *crypto)
{
	if ((crypto->cipher_group == WLAN_CIPHER_SUITE_WEP40) ||
	    (crypto->cipher_group == WLAN_CIPHER_SUITE_WEP104))
		return false;

	return true;
}

static inline bool is_atomic_mgmt(s32 id)
{
	return ((id == MGMT_TIM_UPDATE_ASK) || (id == MGMT_BFMER_ENABLE_ASK) ||
		(id == TDLS_PEER_TRAFFIC_IND_ASK));
}

static inline uint8_t passive_scan_flag(u32 flags)
{
	if (flags & (IEEE80211_CHAN_NO_IR | IEEE80211_CHAN_RADAR))
		return RS_SCAN_PASSIVE_BIT;
	return 0;
}

static struct sk_buff *rs_alloc_skb(struct rs_hw_priv *hw_priv, s32 len, u16 mgmt_id, u16 task_id)
{
	struct sk_buff *skb;
	struct rs_fw_mgmt *mgmt;
	u16 frame_len = sizeof(struct rs_fw_mgmt) + len;

	skb = dev_alloc_skb(frame_len);
	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return NULL;
	}
	memset(skb->data, 0, frame_len);

	mgmt = (struct rs_fw_mgmt *)skb->data;
	mgmt->id = mgmt_id;
	mgmt->dest_id = task_id;
	mgmt->src_id = RS_HOST_T_ID;
	mgmt->param_len = len;

	skb_put(skb, frame_len);

	return skb;
}

static void wait_mgmt_chk(struct rs_hw_priv *hw)
{
	struct rs_core *core = hw->core;
	struct rs_event *event = &core->mgmt_thread.event;
	u32 waiting_time = 2000; // 2sec

	hw->mgmt_chk_completed = false;

	wait_event_timeout(event->mgmt_chk_queue, (hw->mgmt_chk_completed == true),
			   msecs_to_jiffies(waiting_time));

	hw->mgmt_chk_completed = false;
}

static s32 set_skb_event(struct rs_core *core, struct sk_buff *skb)
{
	struct sk_buff *temp_skb = NULL;
	struct skb_info *tx_params = NULL;
	struct rs_fw_mgmt *mgmt = NULL;

	temp_skb = skb;

	if (unlikely(in_atomic()) == 0) {
		MGMT_LOCK(core);
	}

	mgmt = (struct rs_fw_mgmt *)(temp_skb->data);

	temp_skb->priority = MGMT_SOFT_Q;
	tx_params = (struct skb_info *)&(IEEE80211_SKB_CB(temp_skb)->driver_data);
	tx_params->flags |= INTERNAL_MGMT_PKT;

	skb_queue_tail(&core->mgmt_tx_queue, temp_skb);
	rs_set_event(&core->mgmt_thread.event);
	/* If it is atomic mgmt, it should not give msleep. */
	if (!is_atomic_mgmt(mgmt->id)) {
		wait_mgmt_chk(core->priv);
	}

	if (unlikely(in_atomic()) == 0) {
		MGMT_UNLOCK(core);
	}

	return 0;
}

static void *get_mgmt_param(struct sk_buff *skb)
{
	struct rs_fw_mgmt *mgmt = (struct rs_fw_mgmt *)skb->data;

	if (!mgmt) {
		RS_WARN("%s: skb->data is not assigned\n", __func__);
		dev_kfree_skb(skb);
		return NULL;
	}

	if (mgmt->param_len == 0)
		return NULL;
	else
		return mgmt->param;
}

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_reset(struct rs_hw_priv *hw_priv)
{
	struct rs_reset_req *req;
	struct sk_buff *skb;
	u64 ts = local_clock();
	unsigned long rem_nsec = do_div(ts, 1000000000);
	u32 bt_coex;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_reset_req), MGMT_RESET_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_reset_req *)get_mgmt_param(skb);

	/* u64 nsec time to u32 usec time (usec) */
	req->time = rem_nsec / 1000 + ts * 1000000;
	bt_coex = rs_get_bt_coex();
	/* Set BT coexistence */
	if (bt_coex < 4) {
		req->bt_coex = bt_coex;
	} else {
		req->bt_coex = 0;
		printk("bt_coex parameter force to 0 !!! (Must 0 to 3)\n");
	}

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dev_start(struct rs_hw_priv *hw_priv)
{
	struct rs_dev_start_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dev_start_req), MGMT_START_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dev_start_req *)get_mgmt_param(skb);

	memcpy(&req->phy_cfg, &hw_priv->phy_config, sizeof(hw_priv->phy_config));
	req->uapsd_timeout = RS_UAPSD_TIMEOUT;
	req->lp_clk_accuracy = RS_LPCA_PPM;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_version_req(struct rs_hw_priv *hw_priv, struct rs_version_chk *cfm)
{
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, 0, MGMT_VERSION_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_add_if(struct rs_hw_priv *hw_priv, const unsigned char *mac, enum nl80211_iftype iftype, bool p2p,
	      struct rs_add_if_chk *cfm)
{
	struct rs_add_if_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_add_if_req), MGMT_ADD_IF_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_add_if_req *)get_mgmt_param(skb);

	memcpy(&(req->addr.addr[0]), mac, ETH_ALEN);
	switch (iftype) {
	case NL80211_IFTYPE_STATION:
		req->iftype = IF_STA;
		break;

	case NL80211_IFTYPE_ADHOC:
		req->iftype = IF_IBSS;
		break;
	case NL80211_IFTYPE_AP:
		req->iftype = IF_AP;
		break;
	case NL80211_IFTYPE_MESH_POINT:
		req->iftype = IF_MESH_POINT;
		break;
	case NL80211_IFTYPE_AP_VLAN:
		return -1;
	case NL80211_IFTYPE_MONITOR:
		req->iftype = IF_MONITOR;
		req->uf = false;
		break;
	default:
		req->iftype = IF_STA;
		break;
	}

	req->p2p = p2p;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_remove_if(struct rs_hw_priv *hw_priv, u8 vif_index)
{
	struct rs_remove_if_req *remove_if_req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_remove_if_req), MGMT_REMOVE_IF_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	remove_if_req = (struct rs_remove_if_req *)get_mgmt_param(skb);

	remove_if_req->vif_index = vif_index;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_channel(struct rs_hw_priv *hw_priv, s32 phy_idx, struct rs_set_channel_chk *cfm)
{
	struct cfg80211_chan_def *chandef = &hw_priv->hw->conf.chandef;
	struct rs_set_channel_req *req;
	enum nl80211_chan_width width;
	u16 center_freq, center_freq1, center_freq2;
	s8 tx_power = 0;
	enum nl80211_band band;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	if (phy_idx >= hw_priv->phy_cnt)
		return -ENOTSUPP;

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_channel_req), MGMT_SET_CHANNEL_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_channel_req *)get_mgmt_param(skb);

	if (phy_idx == 0) {
		width = chandef->width;
		band = chandef->chan->band;
		center_freq = chandef->chan->center_freq;
		center_freq1 = chandef->center_freq1;
		center_freq2 = chandef->center_freq2;
		tx_power = chandef->chan->max_power;
	} else {
		struct rs_sec_phy_chan *chan = &hw_priv->sec_phy_chan;

		width = chnl2bw[chan->type];
		band = chan->band;
		center_freq = chan->prim20_freq;
		center_freq1 = chan->center_freq1;
		center_freq2 = chan->center_freq2;
	}

	req->band = band;
	req->type = bw2chnl[width];
	req->prim20_freq = center_freq;
	req->center1_freq = center_freq1;
	req->center2_freq = center_freq2;
	req->index = phy_idx;
	req->tx_power = tx_power;

	RS_DBG("mac80211:   freq=%d(c1:%d - c2:%d)/width=%d - band=%d\n"
	       "   hw(%d): prim20=%d(c1:%d - c2:%d)/ type=%d - band=%d\n",
	       center_freq, center_freq1, center_freq2, width, band, phy_idx, req->prim20_freq,
	       req->center1_freq, req->center2_freq, req->type, req->band);

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_key_add(struct rs_hw_priv *hw_priv, u8 vif_id, u8 sta_id, bool pairwise, u8 *key, u8 key_len,
	       u8 key_idx, u8 cipher_suite, struct rs_key_add_chk *cfm)
{
	struct rs_key_add_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_key_add_req), MGMT_KEY_ADD_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_key_add_req *)get_mgmt_param(skb);

	if (sta_id != 0xFF) {
		req->sta_id = sta_id;
	} else {
		req->sta_id = sta_id;
		req->key_idx = (u8)key_idx; /* only useful for default keys */
	}
	req->pairwise = pairwise;
	req->vif_id = vif_id;
	req->key.length = key_len;
	memcpy(&(req->key.array[0]), key, key_len);

	req->cipher_suite = cipher_suite;

	RS_DBG("%s: sta_id:%d key_idx:%d vif_id:%d cipher:%d key_len:%d\n", __func__, req->sta_id,
	       req->key_idx, req->vif_id, req->cipher_suite, req->key.length);
#if defined(CONFIG_RS_DBG) || defined(CONFIG_DYNAMIC_DEBUG)
	print_hex_dump_bytes("key: ", DUMP_PREFIX_OFFSET, req->key.array, req->key.length);
#endif

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_key_del(struct rs_hw_priv *hw_priv, uint8_t hw_key_idx)
{
	struct rs_key_del_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_key_del_req), MGMT_KEY_DEL_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_key_del_req *)get_mgmt_param(skb);

	req->hw_key_idx = hw_key_idx;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_bcn_change(struct rs_hw_priv *hw_priv, u8 vif_id, void *bcn_addr, u16 bcn_len, u16 tim_oft,
		  u16 tim_len, u16 *csa_oft)
{
	struct rs_bcn_change_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_bcn_change_req), MGMT_BCN_CHANGE_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_bcn_change_req *)get_mgmt_param(skb);

	// req->bcn_ptr = bcn_addr;
	req->bcn_len = bcn_len;
	req->tim_oft = tim_oft;
	req->tim_len = tim_len;
	req->vif_id = vif_id;

	memcpy(req->bcn_ptr, bcn_addr, bcn_len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	BUILD_BUG_ON_MSG(IEEE80211_MAX_CNTDWN_COUNTERS_NUM != RS_BCN_MAX_CSA_CPT,
			 "RS_BCN_MAX_CSA_CPT and IEEE80211_MAX_CNTDWN_COUNTERS_NUM "
			 "have different value");
#else
	BUILD_BUG_ON_MSG(IEEE80211_MAX_CSA_COUNTERS_NUM != RS_BCN_MAX_CSA_CPT,
			 "RS_BCN_MAX_CSA_CPT and IEEE80211_MAX_CSA_COUNTERS_NUM "
			 "have different value");
#endif

	if (csa_oft) {
		s32 i;
		for (i = 0; i < RS_BCN_MAX_CSA_CPT; i++) {
			req->csa_oft[i] = csa_oft[i];
		}
	}

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_roc(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif, struct ieee80211_channel *chan, u32 duration)
{
	struct rs_remain_on_channel_req *req;
	struct cfg80211_chan_def chandef;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_remain_on_channel_req), MGMT_REMAIN_ON_CHANNEL_ASK,
			   MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	cfg80211_chandef_create(&chandef, chan, NL80211_CHAN_NO_HT);

	req = (struct rs_remain_on_channel_req *)get_mgmt_param(skb);

	req->op_code = MGMT_ROC_OP_START;
	req->vif_index = vif->vif_index;
	req->duration_ms = duration;
	req->band = chan->band;
	req->type = bw2chnl[chandef.width];
	req->prim20_freq = chan->center_freq;
	req->center1_freq = chandef.center_freq1;
	req->center2_freq = chandef.center_freq2;
	req->tx_power = chan->max_power;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_cancel_roc(struct rs_hw_priv *hw_priv)
{
	struct rs_remain_on_channel_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_remain_on_channel_req), MGMT_REMAIN_ON_CHANNEL_ASK,
			   MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_remain_on_channel_req *)get_mgmt_param(skb);

	req->op_code = MGMT_ROC_OP_CANCEL;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_power(struct rs_hw_priv *hw_priv, u8 vif_id, s8 pwr, struct rs_set_power_chk *cfm)
{
	struct rs_set_power_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_power_req), MGMT_SET_POWER_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_power_req *)get_mgmt_param(skb);

	req->vif_id = vif_id;
	req->power = pwr;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_edca(struct rs_hw_priv *hw_priv, u8 hw_queue, u32 param, bool uapsd, u8 vif_index)
{
	struct rs_set_edca_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_edca_req), MGMT_SET_EDCA_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_edca_req *)get_mgmt_param(skb);

	req->ac_param = param;
	req->uapsd = uapsd;
	req->hw_queue = hw_queue;
	req->vif_index = vif_index;

	return set_skb_event(hw_priv->core, skb);
}

#ifdef CONFIG_RS_P2P_DEBUGFS
s32 rs_p2p_opps_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv, u8 ctw,
		    struct rs_set_p2p_opps_chk *cfm)
{
	struct rs_set_p2p_opps_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_p2p_opps_req), MGMT_SET_P2P_OPPS_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_p2p_opps_req *)get_mgmt_param(skb);

	req->vif_index = vif_priv->vif_index;
	req->ctwindow = ctw;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_p2p_noa_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv, u8 count, u8 interval,
		   u8 duration, bool dyn_noa, struct rs_set_p2p_noa_chk *cfm)
{
	struct rs_set_p2p_noa_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_p2p_noa_req), MGMT_SET_P2P_NOA_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_p2p_noa_req *)get_mgmt_param(skb);

	req->vif_index = vif_priv->vif_index;
	req->noa_inst_nb = 0;
	req->count = count;

	if (count) {
		req->duration_us = duration * 1024;
		req->interval_us = interval * 1024;
		req->start_offset = (interval - duration - 10) * 1024;
		req->dyn_noa = dyn_noa;
	}

	return set_skb_event(hw_priv->core, skb);
}
#endif /* CONFIG_RS_P2P_DEBUGFS */

s32 rs_sta_add(struct rs_hw_priv *hw_priv, struct ieee80211_sta *sta, u8 vif_index,
	       struct rs_sta_add_chk *cfm)
{
	struct rs_sta_add_req *req;
	u32 *phy_value;
	struct rs_sta_priv *sta_priv;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_sta_add_req), MGMT_STA_ADD_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_sta_add_req *)get_mgmt_param(skb);

	memcpy(&(req->mac_addr.addr[0]), &(sta->addr[0]), ETH_ALEN);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	if (sta->ht_cap.ht_supported) {
		if (sta->vht_cap.vht_supported) {
			s32 vht_exp =
				(sta->vht_cap.cap & IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
				IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
			req->ampdu_size_max_vht = (1 << (IEEE80211_HT_MAX_AMPDU_FACTOR + vht_exp)) - 1;
		}

		req->ampdu_size_max_ht =
			(1 << (IEEE80211_HT_MAX_AMPDU_FACTOR + sta->ht_cap.ampdu_factor)) - 1;
		req->ampdu_spacing_min = ampdudensity2usec(sta->ht_cap.ampdu_density);
	}
#else
	if (sta->deflink.ht_cap.ht_supported) {
		if (sta->deflink.vht_cap.vht_supported) {
			s32 vht_exp = (sta->deflink.vht_cap.cap &
				       IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
				      IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
			req->ampdu_size_max_vht = (1 << (IEEE80211_HT_MAX_AMPDU_FACTOR + vht_exp)) - 1;
		}

		req->ampdu_size_max_ht =
			(1 << (IEEE80211_HT_MAX_AMPDU_FACTOR + sta->deflink.ht_cap.ampdu_factor)) - 1;
		req->ampdu_spacing_min = ampdudensity2usec(sta->deflink.ht_cap.ampdu_density);
	}
#endif
	sta_priv = (struct rs_sta_priv *)sta->drv_priv;

	req->vif_index = vif_index;
	req->tdls_sta = sta->tdls;
	phy_value = (u32 *)&(req->paid_gid);
	*phy_value |= RS_PHY_GROUD_ID_MASK_SHIFT(sta_priv->gid);
	*phy_value |= RS_PHY_PAID_MASK_SHIFT(sta_priv->paid);

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_sta_del(struct rs_hw_priv *hw_priv, u8 sta_id)
{
	struct rs_sta_del_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_sta_del_req), MGMT_STA_DEL_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_sta_del_req *)get_mgmt_param(skb);

	req->sta_id = sta_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_filter(struct rs_hw_priv *hw_priv, u32 filter)
{
	struct rs_set_filter_req *req;
	u32 rx_filter = 0;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_filter_req), MGMT_SET_FILTER_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_filter_req *)get_mgmt_param(skb);

#if 0 /* removed */
    if (filter & FIF_PROMISC_IN_BSS)
        rx_filter |= ACCEPT_UNICAST_BIT;
#endif
	if (filter & FIF_ALLMULTI)
		rx_filter |= ACCEPT_MULTICAST_BIT;

	if (filter & (FIF_FCSFAIL | FIF_PLCPFAIL))
		rx_filter |= ACCEPT_ERROR_FRAMES_BIT;

	if (filter & FIF_BCN_PRBRESP_PROMISC)
		rx_filter |= ACCEPT_OTHER_BSSID_BIT;

	if (filter & FIF_CONTROL)
		rx_filter |= ACCEPT_OTHER_CNTRL_FRAMES_BIT | ACCEPT_CF_END_BIT | ACCEPT_ACK_BIT |
			     ACCEPT_CTS_BIT | ACCEPT_RTS_BIT | ACCEPT_BA_BIT | ACCEPT_BAR_BIT;

	if (filter & FIF_OTHER_BSS)
		rx_filter |= ACCEPT_OTHER_BSSID_BIT;

	if (filter & FIF_PSPOLL) {
		rx_filter |= ACCEPT_PS_POLL_BIT;
	}

	if (filter & FIF_PROBE_REQ) {
		rx_filter |= ACCEPT_PROBE_ASK_BIT;
		rx_filter |= ACCEPT_ALL_BEACON_BIT;
	}

	rx_filter |= RS_MAC80211_NOT_CHANGEABLE;

	if (ieee80211_hw_check(hw_priv->hw, AMPDU_AGGREGATION))
		rx_filter |= ACCEPT_BA_BIT;

	req->filter = rx_filter;

	RS_DBG("new total_flags = 0x%08x\nrx filter set to  0x%08x\n", filter, rx_filter);

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_add_chanctx(struct rs_hw_priv *hw_priv, struct ieee80211_chanctx_conf *ctx,
		   struct rs_chan_ctxt_add_chk *cfm)
{
	struct rs_chan_ctxt_add_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_chan_ctxt_add_req), MGMT_CHAN_CTXT_ADD_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_chan_ctxt_add_req *)get_mgmt_param(skb);

	req->band = ctx->def.chan->band;
	req->type = bw2chnl[ctx->def.width];
	req->prim20_freq = ctx->def.chan->center_freq;
	req->center1_freq = ctx->def.center_freq1;
	req->center2_freq = ctx->def.center_freq2;
	req->tx_power = ctx->def.chan->max_power;

	RS_DBG("mac80211:   freq=%d(c1:%d - c2:%d)/width=%d - band=%d\n"
	       "          prim20=%d(c1:%d - c2:%d)/ type=%d - band=%d\n",
	       ctx->def.chan->center_freq, ctx->def.center_freq1, ctx->def.center_freq2, ctx->def.width,
	       ctx->def.chan->band, req->prim20_freq, req->center1_freq, req->center2_freq, req->type,
	       req->band);

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_del_chanctx(struct rs_hw_priv *hw_priv, u8 index)
{
	struct rs_chan_ctxt_del_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_chan_ctxt_del_req), MGMT_CHAN_CTXT_DEL_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_chan_ctxt_del_req *)get_mgmt_param(skb);

	req->index = index;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_link_chanctx(struct rs_hw_priv *hw_priv, u8 vif_id, u8 chan_idx, u8 chan_switch)
{
	struct rs_chan_ctxt_link_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_chan_ctxt_link_req), MGMT_CHAN_CTXT_LINK_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_chan_ctxt_link_req *)get_mgmt_param(skb);

	req->vif_index = vif_id;
	req->chan_index = chan_idx;
	req->chan_switch = chan_switch;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_unlink_chanctx(struct rs_hw_priv *hw_priv, u8 vif_id)
{
	struct rs_chan_ctxt_unlink_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_chan_ctxt_unlink_req), MGMT_CHAN_CTXT_UNLINK_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_chan_ctxt_unlink_req *)get_mgmt_param(skb);

	req->vif_index = vif_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_update_chanctx(struct rs_hw_priv *hw_priv, struct ieee80211_chanctx_conf *ctx)
{
	struct rs_chan_ctxt_update_req *req;
	struct rs_chanctx *chanctx;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_chan_ctxt_update_req), MGMT_CHAN_CTXT_UPDATE_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_chan_ctxt_update_req *)get_mgmt_param(skb);

	chanctx = (struct rs_chanctx *)ctx->drv_priv;
	req->chan_index = chanctx->index;
	req->band = ctx->def.chan->band;
	req->type = bw2chnl[ctx->def.width];
	req->prim20_freq = ctx->def.chan->center_freq;
	req->center1_freq = ctx->def.center_freq1;
	req->center2_freq = ctx->def.center_freq2;
	req->tx_power = ctx->def.chan->max_power;

	RS_DBG("mac80211:   freq=%d(c1:%d - c2:%d)/width=%d - band=%d\n"
	       "          prim20=%d(c1:%d - c2:%d)/ type=%d - band=%d\n",
	       ctx->def.chan->center_freq, ctx->def.center_freq1, ctx->def.center_freq2, ctx->def.width,
	       ctx->def.chan->band, req->prim20_freq, req->center1_freq, req->center2_freq, req->type,
	       req->band);

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_sched_chanctx(struct rs_hw_priv *hw_priv, u8 vif_id, u8 chan_idx, u8 type)
{
	struct rs_chan_ctxt_sched_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_chan_ctxt_sched_req), MGMT_CHAN_CTXT_SCHED_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_chan_ctxt_sched_req *)get_mgmt_param(skb);

	req->vif_index = vif_id;
	req->chan_index = chan_idx;
	req->type = type;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dtim_req(struct rs_hw_priv *hw_priv, u8 dtim_period)
{
	struct rs_set_dtim_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_dtim_req), MGMT_SET_DTIM_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_dtim_req *)get_mgmt_param(skb);

	req->dtim_period = dtim_period;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_basic_rates(struct rs_hw_priv *hw_priv, u32 basic_rates, u8 vif_id, u8 band)
{
	struct rs_set_basic_rates_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_basic_rates_req), MGMT_SET_BASIC_RATES_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_basic_rates_req *)get_mgmt_param(skb);

	req->basic_rates = basic_rates;
	req->vif_id = vif_id;
	req->band = band;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_beacon_int(struct rs_hw_priv *hw_priv, u16 beacon_int, u8 vif_id)
{
	struct rs_set_beacon_int_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_beacon_int_req), MGMT_SET_BEACON_INT_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_beacon_int_req *)get_mgmt_param(skb);

	req->beacon_int = beacon_int;
	req->vif_id = vif_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_bssid(struct rs_hw_priv *hw_priv, const u8 *bssid, u8 vif_id)
{
	struct rs_set_bssid_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_bssid_req), MGMT_SET_BSSID_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_bssid_req *)get_mgmt_param(skb);

	memcpy(&(req->bssid[0]), bssid, ETH_ALEN);
	req->vif_id = vif_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_vif_state(struct rs_hw_priv *hw_priv, bool active, u16 aid, u8 vif_id)
{
	struct rs_set_vif_state_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_vif_state_req), MGMT_SET_VIF_STATE_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_vif_state_req *)get_mgmt_param(skb);

	req->active = active;
	req->aid = aid;
	req->vif_id = vif_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_idle(struct rs_hw_priv *hw_priv, s32 idle)
{
	s32 err = 0;
	struct rs_set_idle_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_idle_req), MGMT_SET_IDLE_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_idle_req *)get_mgmt_param(skb);

	req->hw_idle = idle;

	msleep(100);

	err = set_skb_event(hw_priv->core, skb);

	return err;
}

s32 rs_set_ps_mode(struct rs_hw_priv *hw_priv, u8 ps_mode)
{
	struct rs_set_ps_mode_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_ps_mode_req), MGMT_SET_PS_MODE_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_ps_mode_req *)get_mgmt_param(skb);

	req->new_state = ps_mode;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_ps_options(struct rs_hw_priv *hw_priv, bool listen_bcmc, u16 listen_interval, u8 vif_id)
{
	struct rs_set_ps_options_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_ps_options_req), MGMT_SET_PS_OPTIONS_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_ps_options_req *)get_mgmt_param(skb);

	req->listen_interval = listen_interval;
	req->dont_listen_bc_mc = !listen_bcmc;
	req->vif_index = vif_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_set_slottime(struct rs_hw_priv *hw_priv, s32 use_short_slot)
{
	struct rs_set_slottime_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_set_slottime_req), MGMT_SET_SLOTTIME_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_set_slottime_req *)get_mgmt_param(skb);

	req->slottime = use_short_slot ? 9 : 20;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_ba_add(struct rs_hw_priv *hw_priv, uint8_t type, uint8_t sta_id, u16 tid, uint8_t bufsz, uint16_t ssn,
	      struct rs_ba_add_chk *cfm)
{
	struct rs_ba_add_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_ba_add_req), MGMT_BA_ADD_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_ba_add_req *)get_mgmt_param(skb);

	req->type = type;
	req->sta_id = sta_id;
	req->tid = (u8)tid;
	req->bufsz = bufsz;
	req->ssn = ssn;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_ba_del(struct rs_hw_priv *hw_priv, uint8_t sta_id, u16 tid, struct rs_ba_del_chk *cfm)
{
	struct rs_ba_del_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_ba_del_req), MGMT_BA_DEL_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_ba_del_req *)get_mgmt_param(skb);

	req->type = 0;
	req->sta_id = sta_id;
	req->tid = (u8)tid;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_scan_req(struct rs_hw_priv *hw_priv, struct ieee80211_vif *vif, struct cfg80211_scan_request *param,
		struct rs_scan_start_chk *cfm)
{
	struct rs_scan_start_req *req;
	s32 i;
	struct rs_vif_priv *vif_priv;
	uint8_t chan_flags = 0;
	struct sk_buff *skb;
	u8 mac_addr[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	RS_DBG(RS_FN_ENTRY_STR);

	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_scan_start_req), SCAN_START_ASK, SCAN_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_scan_start_req *)get_mgmt_param(skb);

	req->vif_id = vif_priv->vif_index;
	req->n_channels = (u8)min_t(s32, RS_SCAN_CHANNEL_MAX, param->n_channels);
	req->n_ssids = (u8)min_t(s32, RS_SCAN_SSID_MAX, param->n_ssids);
	memcpy(req->bssid, mac_addr, ETH_ALEN);
	req->no_cck = param->no_cck;

	if (req->n_ssids == 0)
		chan_flags |= RS_SCAN_PASSIVE_BIT;
	for (i = 0; i < req->n_ssids; i++) {
		s32 j;
		for (j = 0; j < param->ssids[i].ssid_len; j++)
			req->ssids[i].ssid[j] = param->ssids[i].ssid[j];
		req->ssids[i].ssid_len = param->ssids[i].ssid_len;
	}

	if (param->ie) {
		req->ie_len = param->ie_len;
		memcpy(req->ie, param->ie, param->ie_len);
		req->ie_addr = (size_t)req->ie;
	} else {
		req->ie_len = 0;
		req->ie_addr = 0;
	}

	for (i = 0; i < req->n_channels; i++) {
		struct ieee80211_channel *chan = param->channels[i];

		req->chan[i].band = chan->band;
		req->chan[i].center_freq = chan->center_freq;
		req->chan[i].flags = chan_flags | passive_scan_flag(chan->flags);
		req->chan[i].max_reg_power = chan->max_reg_power;
	}

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_scan_cancel_req(struct rs_hw_priv *hw_priv, struct rs_scan_cancel_chk *cfm)
{
	struct rs_scan_cancel_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_scan_cancel_req), SCAN_CANCEL_ASK, SCAN_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_scan_cancel_req *)get_mgmt_param(skb);

	return set_skb_event(hw_priv->core, skb);
}

void rs_tdls_ps(struct rs_hw_priv *hw_priv, bool ps_mode)
{
	if (!hw_priv->ps_on)
		return;

	rs_set_ps_mode(hw_priv, ps_mode);
}

s32 rs_tim_update(struct rs_hw_priv *hw_priv, u8 vif_id, u16 aid, u8 tx_status)
{
	struct rs_tim_update_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_tim_update_req), MGMT_TIM_UPDATE_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_tim_update_req *)get_mgmt_param(skb);

	req->aid = aid;
	req->tx_avail = tx_status;
	req->vif_id = vif_id;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_tdls_chan_switch_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv,
			    struct ieee80211_sta *sta, u8 oper_class, struct cfg80211_chan_def *chandef,
			    struct rs_tdls_chan_switch_chk *cfm, u8 action)
{
	struct rs_tdls_chan_switch_req *req;
	struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	if (hw_priv->tdls_info.chsw_en) {
		printk("TDLS channel switch already enabled for another TDLS station\n");
		return -ENOTSUPP;
	}

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_tdls_chan_switch_req), TDLS_CHAN_SWITCH_ASK, TDLS_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_tdls_chan_switch_req *)get_mgmt_param(skb);

	req->vif_index = vif_priv->vif_index;
	req->sta_id = sta_priv->id;
	memcpy(&(req->peer_mac_addr.addr[0]), &sta->addr[0], ETH_ALEN);
	req->initiator = sta->tdls_initiator;
	req->band = chandef->chan->band;
	req->type = bw2chnl[chandef->width];
	req->prim20_freq = chandef->chan->center_freq;
	req->center1_freq = chandef->center_freq1;
	req->center2_freq = chandef->center_freq2;
	req->tx_power = chandef->chan->max_power;
	req->op_class = oper_class;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_tdls_cancel_chan_switch_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv,
				   struct ieee80211_sta *sta, struct rs_tdls_cancel_chan_switch_chk *cfm)
{
	struct rs_tdls_cancel_chan_switch_req *req;
	struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_tdls_cancel_chan_switch_req),
			   TDLS_CANCEL_CHAN_SWITCH_ASK, TDLS_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_tdls_cancel_chan_switch_req *)get_mgmt_param(skb);

	req->vif_index = vif_priv->vif_index;
	req->sta_id = sta_priv->id;
	memcpy(&(req->peer_mac_addr.addr[0]), &sta->addr[0], ETH_ALEN);

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dbg_trigger_req(struct rs_hw_priv *hw_priv, char *mgmt)
{
	struct rs_dbg_trigger_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_trigger_req), MGMT_DBG_TRIGGER_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_trigger_req *)get_mgmt_param(skb);

	strncpy(req->error, mgmt, sizeof(req->error));

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dbg_mem_read_ask(struct rs_hw_priv *hw_priv, u32 mem_addr, struct rs_dbg_mem_read_chk *cfm)
{
	struct rs_dbg_mem_read_ask *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_mem_read_ask), DBG_MEM_READ_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_mem_read_ask *)get_mgmt_param(skb);

	req->mem_addr = mem_addr;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dbg_mem_write_ask(struct rs_hw_priv *hw_priv, u32 mem_addr, u32 mem_data)
{
	struct rs_dbg_mem_write_ask *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_mem_write_ask), DBG_MEM_WRITE_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_mem_write_ask *)get_mgmt_param(skb);

	req->mem_addr = mem_addr;
	req->mem_data = mem_data;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dbg_mod_filter_set(struct rs_hw_priv *hw_priv, u32 filter)
{
	struct rs_dbg_filter_mode_set *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_filter_mode_set), DBG_SET_FILTER_MODE_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_filter_mode_set *)get_mgmt_param(skb);

	req->filter_mode = filter;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dbg_lvl_filter_set(struct rs_hw_priv *hw_priv, u32 filter)
{
	struct rs_dbg_lvl_filter_set *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_lvl_filter_set), DBG_SET_FILTER_LEVEL_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_lvl_filter_set *)get_mgmt_param(skb);

	req->filter_level = filter;

	return set_skb_event(hw_priv->core, skb);
}

int rs_dbg_set_dir_out(struct rs_hw_priv *hw_priv, u32 direction)
{
	struct rs_dbg_set_dir_out *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_set_dir_out), DBG_SET_OUT_DIR_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_set_dir_out *)get_mgmt_param(skb);

	req->dir_out = direction;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_dbg_get_sys_stat_req(struct rs_hw_priv *hw_priv, struct rs_dbg_get_sys_stat_chk *cfm)
{
	// void* req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, 0, DBG_GET_SYS_STAT_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_cfg_rssi_req(struct rs_hw_priv *hw_priv, u8 vif_index, s32 rssi_thold, u32 rssi_hyst)
{
	struct rs_cfg_rssi_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_cfg_rssi_req), MGMT_CFG_RSSI_ASK, MM_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_cfg_rssi_req *)get_mgmt_param(skb);

	req->vif_index = vif_index;
	req->rssi_thold = (s8)rssi_thold;
	req->rssi_hyst = (u8)rssi_hyst;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_rf_tx_req(struct rs_hw_priv *hw_priv, u8 start, u16 frequency, u16 numFrames, u16 frameLen, u8 txRate,
		 u8 txPower, u64 destAddr, u64 bssid, u8 GI, u8 greenField, u8 preambleType, u8 qosEnable,
		 u8 ackPolicy, u8 aifsnVal)
{
	struct rs_dbg_rf_tx_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_rf_tx_req), DBG_RF_TX_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_rf_tx_req *)get_mgmt_param(skb);

	req->start = start;
	req->frequency = frequency;
	req->numFrames = numFrames;
	req->frameLen = frameLen;
	req->txRate = txRate;
	req->txPower = txPower;
	req->destAddr = destAddr;
	req->bssid = bssid;
	req->GI = GI;
	req->greenField = greenField;
	req->preambleType = preambleType;
	req->qosEnable = qosEnable;
	req->ackPolicy = ackPolicy;
	req->aifsnVal = aifsnVal;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_rf_cw_req(struct rs_hw_priv *hw_priv, u8 start, u8 txPower, u16 frequency)
{
	struct rs_dbg_rf_cw_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_rf_cw_req), DBG_RF_CW_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_rf_cw_req *)get_mgmt_param(skb);

	req->start = start;
	req->frequency = frequency;
	req->txPower = txPower;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_rf_cont_req(struct rs_hw_priv *hw_priv, u8 start, u8 txRate, u8 txPower, u16 frequency)
{
	struct rs_dbg_rf_cont_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_rf_cont_req), DBG_RF_CONT_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_rf_cont_req *)get_mgmt_param(skb);

	req->start = start;
	req->frequency = frequency;
	req->txPower = txPower;
	req->txRate = txRate;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_rf_ch_req(struct rs_hw_priv *hw_priv, u16 frequency)
{
	struct rs_dbg_rf_ch_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_rf_ch_req), DBG_RF_CH_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_rf_ch_req *)get_mgmt_param(skb);

	req->freqency = frequency;

	return set_skb_event(hw_priv->core, skb);
}

s32 rs_rf_per_req(struct rs_hw_priv *hw_priv, u8 start, struct rs_dbg_rf_per_chk *cfm)
{
	struct rs_dbg_rf_per_req *req;
	struct sk_buff *skb;

	RS_DBG(RS_FN_ENTRY_STR);

	skb = rs_alloc_skb(hw_priv, sizeof(struct rs_dbg_rf_per_req), DBG_RF_PER_ASK, DBG_T);

	if (!skb) {
		RS_WARN("%s: Failed in allocation of skb\n", __func__);
		return -ENOMEM;
	}

	req = (struct rs_dbg_rf_per_req *)get_mgmt_param(skb);

	req->start = start;

	return set_skb_event(hw_priv->core, skb);
}
