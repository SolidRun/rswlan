// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"
#include "rs_tx.h"
#include <linux/version.h>

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define CONFIG_RS_DBG
#define rs_cmd_e2amgmt rs_e2a_mgmt

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

typedef s32 (*mgmt_cb_fct)(struct rs_hw_priv *rs_hw, struct rs_cmd_e2amgmt *mgmt);

static s32 freq_to_idx(struct rs_hw_priv *rs_hw, s32 freq)
{
	struct ieee80211_supported_band *sband;
	s32 band, ch, idx = 0;

	for (band = NL80211_BAND_2GHZ; band < NUM_NL80211_BANDS; band++) {
		sband = rs_hw->hw->wiphy->bands[band];
		if (!sband) {
			continue;
		}

		for (ch = 0; ch < sband->n_channels; ch++, idx++) {
			if (sband->channels[ch].center_freq == freq) {
				goto exit;
			}
		}
	}

	BUG_ON(1);

exit:
	return idx;
}

static inline s32 chan_pre_switch_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_chanctx *chan_ctxt;
	s32 chan_idx = ((struct rs_channel_pre_switch_int *)mgmt->param)->chan_index;

	RS_DBG(RS_FN_ENTRY_STR);

	list_for_each_entry(chan_ctxt, &rs_hw->chan_ctxts, list) {
		if (chan_ctxt->index == chan_idx) {
			chan_ctxt->active = false;
			rs_hw->ch_switch_stop_tx = true;
			break;
		}
	}

	rs_hw->tx.status |= TX_Q_STATUS_CHAN;

	return 0;
}

static inline s32 chan_switch_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_chanctx *chan_ctxt;
	struct rs_sta_priv *sta_priv;
	struct rs_vif_priv *vif_priv;
	s32 chan_idx = ((struct rs_channel_switch_int *)mgmt->param)->chan_index;
	bool roc = ((struct rs_channel_switch_int *)mgmt->param)->roc;
	bool roc_tdls = ((struct rs_channel_switch_int *)mgmt->param)->roc_tdls;

	RS_DBG(RS_FN_ENTRY_STR);

	if (roc_tdls) {
		u8 vif_index = ((struct rs_channel_switch_int *)mgmt->param)->vif_index;
		// Enable traffic only for TDLS station
		list_for_each_entry(vif_priv, &rs_hw->vifs, list) {
			if (vif_priv->vif_index == vif_index) {
				list_for_each_entry(sta_priv, &vif_priv->stations, list) {
					if (sta_priv->tdls.active) {
						vif_priv->roc_tdls = true;
						// rs_txq_tdls_sta_start(sta_priv, RS_TXQ_STOP_CHAN, rs_hw);
						break;
					}
				}
				break;
			}
		}
	} else if (!roc) {
		// nothing to do
	} else {
		// u8 vif_index = ((struct rs_channel_switch_int *)mgmt->param)->vif_index;

		// Inform the host that the offchannel period has been started
		ieee80211_ready_on_channel(rs_hw->hw);
	}

	/* keep cur_chan up to date */
	list_for_each_entry(chan_ctxt, &rs_hw->chan_ctxts, list) {
		if (chan_ctxt->index == chan_idx) {
			chan_ctxt->active = true;
			rs_hw->ch_switch_stop_tx = false;
			rs_hw->cur_freq = chan_ctxt->ctx->def.center_freq1;
			rs_hw->cur_band = chan_ctxt->ctx->def.chan->band;
			break;
		}
	}

	rs_hw->tx.status &= ~TX_Q_STATUS_CHAN;

	return 0;
}

static inline s32 tdls_chan_switch_chk(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	return 0;
}

static inline s32 tdls_chan_switch_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_chanctx *chan_ctxt;
	u8 chan_idx = ((struct rs_tdls_chan_switch_int *)mgmt->param)->chan_ctxt_index;

	RS_DBG(RS_FN_ENTRY_STR);

	// Enable channel context
	list_for_each_entry(chan_ctxt, &rs_hw->chan_ctxts, list) {
		if (chan_ctxt->index == chan_idx) {
			chan_ctxt->active = true;
			rs_hw->cur_freq = chan_ctxt->ctx->def.center_freq1;
			rs_hw->cur_band = chan_ctxt->ctx->def.chan->band;
		}
	}

	return 0;
}

static inline s32 tdls_chan_switch_base_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_vif_priv *vif_priv;
	u8 vif_index = ((struct rs_tdls_chan_switch_base_int *)mgmt->param)->vif_index;
	struct rs_sta_priv *sta_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	// Disable traffic for associated VIF
	list_for_each_entry(vif_priv, &rs_hw->vifs, list) {
		if (vif_priv->vif_index == vif_index) {
			if (vif_priv->chanctx)
				vif_priv->chanctx->active = false;
			list_for_each_entry(sta_priv, &vif_priv->stations, list) {
				if (sta_priv->tdls.active) {
					vif_priv->roc_tdls = false;
					// rs_txq_tdls_sta_stop(sta_priv, RS_TXQ_STOP_CHAN, rs_hw);
					break;
				}
			}
			break;
		}
	}

	return 0;
}

static inline s32 tdls_peer_ps_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_vif_priv *vif_priv;
	u8 vif_index = ((struct rs_tdls_peer_ps_int *)mgmt->param)->vif_index;
	bool ps_on = ((struct rs_tdls_peer_ps_int *)mgmt->param)->ps_on;
	u8 sta_id = ((struct rs_tdls_peer_ps_int *)mgmt->param)->sta_id;
	struct rs_sta_priv *sta_priv;
	list_for_each_entry(vif_priv, &rs_hw->vifs, list) {
		if (vif_priv->vif_index == vif_index) {
			list_for_each_entry(sta_priv, &vif_priv->stations, list) {
				if (sta_priv->id == sta_id) {
					sta_priv->tdls.ps_on = ps_on;
					if (ps_on) {
						// disable TXQ for TDLS peer
						// rs_txq_tdls_sta_stop(sta_priv, RS_TXQ_STOP_STA_PS, rs_hw);
					} else {
						// Enable TXQ for TDLS peer
						// rs_txq_tdls_sta_start(sta_priv, RS_TXQ_STOP_STA_PS, rs_hw);
					}
					break;
				}
			}
			break;
		}
	}
	return 0;
}

static inline s32 remain_on_channel_exp_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	RS_DBG(RS_FN_ENTRY_STR);

	ieee80211_remain_on_channel_expired(rs_hw->hw);

	return 0;
}

static inline s32 p2p_vif_ps_change_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	s32 vif_id = ((struct rs_p2p_vif_ps_change_int *)mgmt->param)->vif_index;
	int ps_state = ((struct rs_p2p_vif_ps_change_int *)mgmt->param)->ps_state;
	struct rs_vif_priv *vif_entry;

	RS_DBG(RS_FN_ENTRY_STR);

	// Look for VIF entry
	list_for_each_entry(vif_entry, &rs_hw->vifs, list) {
		if (vif_entry->vif_index == vif_id) {
			goto found_vif;
		}
	}

	goto exit;

found_vif:
	if (ps_state == MGMT_PS_MODE_OFF)
		rs_hw->tx.status &= ~TX_Q_STATUS_PS;
    else
		rs_hw->tx.status |= TX_Q_STATUS_PS;

exit:
	return 0;
}

static inline s32 channel_survey_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_channel_survey_int *ind = (struct rs_channel_survey_int *)mgmt->param;
	// Get the channel index
	s32 idx = freq_to_idx(rs_hw, ind->freq);
	// Get the survey
	struct rs_survey_info_priv *rs_survey = &rs_hw->survey[idx];

	RS_DBG(RS_FN_ENTRY_STR);

	// Store the received parameters
	rs_survey->chan_time_ms = ind->chan_time_ms;
	rs_survey->chan_time_busy_ms = ind->chan_time_busy_ms;
	rs_survey->noise_dbm = ind->noise_dbm;
	rs_survey->filled = (SURVEY_INFO_TIME | SURVEY_INFO_TIME_BUSY);
#if 0
    printk("freq %d, time %d ms, busy %d ms, noise %d\n",
	    ind->freq,
	    ind->chan_time_ms,
	    ind->chan_time_busy_ms,
	    ind->noise_dbm
	    );
#endif
	if (ind->noise_dbm != 0) {
		rs_survey->filled |= SURVEY_INFO_NOISE_DBM;
	}

	return 0;
}

static inline s32 rx_p2p_noa_upd_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	return 0;
}

static inline s32 rssi_status_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_rssi_status_int *ind = (struct rs_rssi_status_int *)mgmt->param;
	s32 vif_id = ind->vif_index;
	bool rssi_status = ind->rssi_status;
	s32 sig = 0; /* TODO : what's the sig value */

	struct rs_vif_priv *vif_entry;

	RS_DBG(RS_FN_ENTRY_STR);

	list_for_each_entry(vif_entry, &rs_hw->vifs, list) {
		if (vif_entry->vif_index == vif_id) {
			ieee80211_cqm_rssi_notify(vif_entry->vif,
						  rssi_status ? NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW :
								NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH,
						  sig, /* added */
						  GFP_KERNEL);
		}
	}
	return 0;
}

static inline s32 csa_counter_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_csa_counter_int *ind = (struct rs_csa_counter_int *)mgmt->param;
	struct rs_vif_priv *vif;
	bool found = false;

	RS_DBG(RS_FN_ENTRY_STR);

	// Look for VIF entry
	list_for_each_entry(vif, &rs_hw->vifs, list) {
		if (vif->vif_index == ind->vif_index) {
			found = true;
			break;
		}
	}

	if (found) {
		if (ind->csa_count == 1) {
			ieee80211_csa_finish(vif->vif);
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
			ieee80211_beacon_update_cntdwn(vif->vif);
#else
			ieee80211_csa_update_counter(vif->vif);
#endif
		}
	}

	return 0;
}

static inline s32 connection_loss_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	struct rs_vif_priv *vif_priv;
	u8 vif_id;

	RS_DBG(RS_FN_ENTRY_STR);

	vif_id = ((struct mgmt_connection_loss_ind *)mgmt->param)->vif_id;

	/* Search the VIF entry corresponding to the instance number */
	list_for_each_entry(vif_priv, &rs_hw->vifs, list) {
		if (vif_priv->vif_index == vif_id) {
			ieee80211_connection_loss(vif_priv->vif);
			break;
		}
	}

	return 0;
}

#ifdef CONFIG_RS_BCN
static inline s32 rx_prm_tbtt_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	RS_DBG(RS_FN_ENTRY_STR);

	rs_tx_bcns(rs_hw);

	return 0;
}
#endif

static inline s32 scan_done_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	struct cfg80211_scan_info info = {
		.aborted = false,
	};
#endif

	RS_DBG(RS_FN_ENTRY_STR);

	if (rs_hw->hw_scanning) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		ieee80211_scan_completed(rs_hw->hw, &info);
#else
		ieee80211_scan_completed(rs_hw->hw, false);
#endif
		rs_hw->hw_scanning = false;
	}

	rs_hw->tx.status &= ~TX_Q_STATUS_SCAN;

	return 0;
}

static inline s32 dbg_error_ind(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	RS_DBG(RS_FN_ENTRY_STR);

	// rs_error_ind(rs_hw);

	return 0;
}

static mgmt_cb_fct mgmt_rx_hdlrs[RS_MGMT_I(MGMT_MAX)] = {
	[RS_MGMT_I(MGMT_CONNECTION_LOSS_IND)] = connection_loss_ind,
	[RS_MGMT_I(MGMT_CHANNEL_SWITCH_IND)] = chan_switch_ind,
	[RS_MGMT_I(MGMT_CHANNEL_PRE_SWITCH_IND)] = chan_pre_switch_ind,
	[RS_MGMT_I(MGMT_REMAIN_ON_CHANNEL_EXP_IND)] = remain_on_channel_exp_ind,
#ifdef CONFIG_RS_BCN
	[RS_MGMT_I(MGMT_PRIMARY_TBTT_IND)] = rx_prm_tbtt_ind,
#endif
	[RS_MGMT_I(MGMT_P2P_VIF_PS_CHANGE_IND)] = p2p_vif_ps_change_ind,
	[RS_MGMT_I(MGMT_CSA_COUNTER_IND)] = csa_counter_ind,
	[RS_MGMT_I(MGMT_CHANNEL_SURVEY_IND)] = channel_survey_ind,
	[RS_MGMT_I(MGMT_RSSI_STATUS_IND)] = rssi_status_ind,
};

static mgmt_cb_fct scan_hdlrs[RS_MGMT_I(SCAN_MAX)] = {
	[RS_MGMT_I(SCAN_DONE_IND)] = scan_done_ind,
};

static mgmt_cb_fct dbg_hdlrs[RS_MGMT_I(DBG_MAX)] = {
	[RS_MGMT_I(DBG_ERROR_IND)] = dbg_error_ind,
};

static mgmt_cb_fct tdls_hdlrs[RS_MGMT_I(TDLS_MAX)] = {
	[RS_MGMT_I(TDLS_CHAN_SWITCH_CHK)] = tdls_chan_switch_chk,
	[RS_MGMT_I(TDLS_CHAN_SWITCH_IND)] = tdls_chan_switch_ind,
	[RS_MGMT_I(TDLS_CHAN_SWITCH_BASE_IND)] = tdls_chan_switch_base_ind,
	[RS_MGMT_I(TDLS_PEER_PS_IND)] = tdls_peer_ps_ind,
};

static mgmt_cb_fct *mgmt_hdlrs[] = {
	[MM_T] = mgmt_rx_hdlrs,
	[DBG_T] = dbg_hdlrs,
	[SCAN_T] = scan_hdlrs,
	[TDLS_T] = tdls_hdlrs,
};

static s32 run_callback(struct rs_hw_priv *rs_hw, struct rs_cmd_e2amgmt *mgmt, mgmt_cb_fct cb)
{
	s32 res;

	spin_lock(&rs_hw->cb_lock);
	res = cb(rs_hw, mgmt);
	spin_unlock(&rs_hw->cb_lock);

	return res;
}

s32 rs_rx_handle_callbck(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *mgmt)
{
	mgmt_cb_fct cb = NULL;

	if (RS_MGMT_T(mgmt->id) > TDLS_T) {
		return -EINVAL;
	}

	cb = mgmt_hdlrs[RS_MGMT_T(mgmt->id)][RS_MGMT_I(mgmt->id)];

	if (!cb)
		return 0;

	return run_callback(rs_hw, mgmt, cb);
}