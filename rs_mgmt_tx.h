// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_MGMT_TX_H
#define RS_MGMT_TX_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

enum rs_chan_types
{
	RS_CHAN_BW_20,
	RS_CHAN_BW_49,
	RS_CHAN_BW_80,
	RS_CHAN_BW_160,
	RS_CHAN_BW_80P80,
	RS_CHAN_BW_OTHER,
};

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_reset(struct rs_hw_priv *hw_priv);
s32 rs_dev_start(struct rs_hw_priv *hw_priv);
s32 rs_version_req(struct rs_hw_priv *hw_priv, struct rs_version_chk *cfm);
s32 rs_add_if(struct rs_hw_priv *hw_priv, const unsigned char *mac, enum nl80211_iftype iftype, bool p2p,
	      struct rs_add_if_chk *cfm);
s32 rs_remove_if(struct rs_hw_priv *hw_priv, u8 vif_index);
s32 rs_set_channel(struct rs_hw_priv *hw_priv, s32 phy_idx, struct rs_set_channel_chk *cfm);
s32 rs_key_add(struct rs_hw_priv *hw_priv, u8 vif_id, u8 sta_id, bool pairwise, u8 *key, u8 key_len,
	       u8 key_idx, u8 cipher_suite, struct rs_key_add_chk *cfm);
s32 rs_key_del(struct rs_hw_priv *hw_priv, uint8_t hw_key_idx);
s32 rs_bcn_change(struct rs_hw_priv *hw_priv, u8 vif_id, void *bcn_addr, u16 bcn_len, u16 tim_oft,
		  u16 tim_len, u16 *csa_oft);
s32 rs_tim_update(struct rs_hw_priv *hw_priv, u8 vif_id, u16 aid, u8 tx_status);
s32 rs_roc(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif, struct ieee80211_channel *chan, u32 duration);
s32 rs_cancel_roc(struct rs_hw_priv *hw_priv);
s32 rs_set_power(struct rs_hw_priv *hw_priv, u8 vif_id, s8 pwr, struct rs_set_power_chk *cfm);
s32 rs_set_edca(struct rs_hw_priv *hw_priv, u8 hw_queue, u32 param, bool uapsd, u8 vif_id);

#ifdef CONFIG_RS_P2P_DEBUGFS
s32 rs_p2p_opps_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv, u8 ctw,
		    struct rs_set_p2p_opps_chk *cfm);
s32 rs_p2p_noa_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv, u8 count, u8 interval,
		   u8 duration, bool dyn_noa, struct rs_set_p2p_noa_chk *cfm);
#endif /* CONFIG_RS_P2P_DEBUGFS */

s32 rs_sta_add(struct rs_hw_priv *hw_priv, struct ieee80211_sta *sta, u8 vif_index,
	       struct rs_sta_add_chk *cfm);
s32 rs_sta_del(struct rs_hw_priv *hw_priv, u8 sta_id);
s32 rs_set_filter(struct rs_hw_priv *hw_priv, u32 filter);
s32 rs_add_chanctx(struct rs_hw_priv *hw_priv, struct ieee80211_chanctx_conf *ctx,
		   struct rs_chan_ctxt_add_chk *cfm);
s32 rs_del_chanctx(struct rs_hw_priv *hw_priv, u8 index);
s32 rs_link_chanctx(struct rs_hw_priv *hw_priv, u8 vif_id, u8 chan_idx, u8 chan_switch);
s32 rs_unlink_chanctx(struct rs_hw_priv *hw_priv, u8 vif_id);
s32 rs_update_chanctx(struct rs_hw_priv *hw_priv, struct ieee80211_chanctx_conf *ctx);
s32 rs_sched_chanctx(struct rs_hw_priv *hw_priv, u8 vif_id, u8 chan_idx, u8 type);

s32 rs_dtim_req(struct rs_hw_priv *hw_priv, u8 dtim_period);
s32 rs_set_basic_rates(struct rs_hw_priv *hw_priv, u32 basic_rates, u8 vif_id, u8 band);
s32 rs_set_beacon_int(struct rs_hw_priv *hw_priv, u16 beacon_int, u8 vif_id);
s32 rs_set_bssid(struct rs_hw_priv *hw_priv, const u8 *bssid, u8 vif_id);
s32 rs_set_vif_state(struct rs_hw_priv *hw_priv, bool active, u16 aid, u8 vif_id);
s32 rs_set_idle(struct rs_hw_priv *hw_priv, s32 idle);
s32 rs_set_ps_mode(struct rs_hw_priv *hw_priv, u8 ps_mode);
s32 rs_set_ps_options(struct rs_hw_priv *hw_priv, bool listen_bcmc, u16 listen_interval, u8 vif_id);
s32 rs_set_slottime(struct rs_hw_priv *hw_priv, s32 use_short_slot);
s32 rs_ba_add(struct rs_hw_priv *hw_priv, uint8_t type, uint8_t sta_id, u16 tid, uint8_t bufsz, uint16_t ssn,
	      struct rs_ba_add_chk *cfm);
s32 rs_ba_del(struct rs_hw_priv *hw_priv, uint8_t sta_id, u16 tid, struct rs_ba_del_chk *cfm);
s32 rs_scan_req(struct rs_hw_priv *hw_priv, struct ieee80211_vif *vif, struct cfg80211_scan_request *param,
		struct rs_scan_start_chk *cfm);
s32 rs_scan_cancel_req(struct rs_hw_priv *hw_priv, struct rs_scan_cancel_chk *cfm);
s32 rs_tdls_chan_switch_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv,
			    struct ieee80211_sta *sta, u8 oper_class, struct cfg80211_chan_def *chandef,
			    struct rs_tdls_chan_switch_chk *cfm, u8 action);
s32 rs_tdls_cancel_chan_switch_req(struct rs_hw_priv *hw_priv, struct rs_vif_priv *vif_priv,
				   struct ieee80211_sta *sta, struct rs_tdls_cancel_chan_switch_chk *cfm);
void rs_tdls_ps(struct rs_hw_priv *hw_priv, bool ps_mode);

s32 rs_dbg_trigger_req(struct rs_hw_priv *hw_priv, char *msg);
s32 rs_dbg_mem_read_ask(struct rs_hw_priv *hw_priv, u32 mem_addr, struct rs_dbg_mem_read_chk *cfm);
s32 rs_dbg_mem_write_ask(struct rs_hw_priv *hw_priv, u32 mem_addr, u32 mem_data);
s32 rs_dbg_mod_filter_set(struct rs_hw_priv *hw_priv, u32 filter);
s32 rs_dbg_lvl_filter_set(struct rs_hw_priv *hw_priv, u32 filter);
s32 rs_dbg_set_dir_out(struct rs_hw_priv *hw_priv, u32 direction);
s32 rs_dbg_get_sys_stat_req(struct rs_hw_priv *hw_priv, struct rs_dbg_get_sys_stat_chk *cfm);
s32 rs_cfg_rssi_req(struct rs_hw_priv *hw_priv, u8 vif_index, s32 rssi_thold, u32 rssi_hyst);

s32 rs_rf_tx_req(struct rs_hw_priv *hw_priv, u8 start, u16 frequency, u16 numFrames, u16 frameLen, u8 txRate,
		 u8 txPower, u64 destAddr, u64 bssid, u8 GI, u8 greenField, u8 preambleType, u8 qosEnable,
		 u8 ackPolicy, u8 aifsnVal);
s32 rs_rf_cw_req(struct rs_hw_priv *hw_priv, u8 start, u8 txPower, u16 frequency);
s32 rs_rf_cont_req(struct rs_hw_priv *hw_priv, u8 start, u8 txRate, u8 txPower, u16 frequency);
s32 rs_rf_ch_req(struct rs_hw_priv *hw_priv, u16 frequency);
s32 rs_rf_per_req(struct rs_hw_priv *hw_priv, u8 reset, struct rs_dbg_rf_per_chk *cfm);

#endif /* RS_MGMT_TX_H */
