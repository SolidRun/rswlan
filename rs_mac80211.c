
// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */
#include <net/mac80211.h>
#include <linux/version.h>

#include "rs_mac.h"
#include "rs_mgmt_tx.h"
#include "rs_mgmt_rx.h"
#include "rs_testmode.h"
#include "rs_tx.h"
#include "rs_priv.h"
#include "rs_irq.h"
#include "rs_irq_dbg.h"
#include "rs_params.h"

#define RS_PRINT_CHK_ERR(req) printk(KERN_CRIT "%s: Status Error(%d)\n", #req, (req##_chk)->status)

#define RATE(_bitrate, _hw_value, _flags)                                          \
	{                                                                          \
		.bitrate = (_bitrate), .hw_value = (_hw_value), .flags = (_flags), \
	}

#define CHAN2G(_channel, _freq)                                                                             \
	{                                                                                                   \
		.band = NL80211_BAND_2GHZ, .hw_value = (_channel), .center_freq = (_freq), .max_power = 30, \
	}

#define RS_HT_CAPABILITIES                                      \
	{                                                       \
		.ht_supported = true,                         \
        .cap = 0,                                     \
        .ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K,   \
        .ampdu_density = IEEE80211_HT_MPDU_DENSITY_8, \
        .mcs = {                                      \
            .rx_mask = {                              \
                0xff,                                 \
                0,                                    \
                0,                                    \
                0,                                    \
                0,                                    \
                0,                                    \
                0,                                    \
                0,                                    \
                0,                                    \
                0,                                    \
            },                                        \
            .rx_highest = cpu_to_le16(65),            \
            .tx_params = IEEE80211_HT_MCS_TX_DEFINED, \
        }, \
	}

static struct ieee80211_channel rs_2ghz_channels[] = {
	CHAN2G(1, 2412),  CHAN2G(2, 2417),  CHAN2G(3, 2422),  CHAN2G(4, 2427),	CHAN2G(5, 2432),
	CHAN2G(6, 2437),  CHAN2G(7, 2442),  CHAN2G(8, 2447),  CHAN2G(9, 2452),	CHAN2G(10, 2457),
	CHAN2G(11, 2462), CHAN2G(12, 2467), CHAN2G(13, 2472), CHAN2G(14, 2484),
};

#define MAX_ROCD 500

#ifdef CONFIG_NL80211_TESTMODE
static const struct nla_policy rs_tm_gnl_msg_policy[RS_TM_AT_MAX] = {
    [RS_TM_AT_CMD]     = {.type = NLA_U32,},
    [RS_TM_AT_REG_OFFSET]  = {.type = NLA_U32,},
    [RS_TM_AT_REG_VALUE32] = {.type = NLA_U32,},
    [RS_TM_AT_REG_FILTER]  = {.type = NLA_U32,},

    /* RF commands */
    [RS_TM_AT_START]       = {.type = NLA_U8,},
    [RS_TM_AT_CH]          = {.type = NLA_U16,},
    [RS_TM_AT_FRAMES_NUM]  = {.type = NLA_U16,},
    [RS_TM_AT_FRAMES_LEN]  = {.type = NLA_U16,},
    [RS_TM_AT_RATE]        = {.type = NLA_U8,},
    [RS_TM_AT_POWER]       = {.type = NLA_U8,},
    [RS_TM_AT_ADDR_DEST]   = {.type = NLA_U64,},
    [RS_TM_AT_BSSID]       = {.type = NLA_U64,},
    [RS_TM_AT_GI]          = {.type = NLA_U8,},
    [RS_TM_AT_GREEN]       = {.type = NLA_U8,},
    [RS_TM_AT_PREAMBLE]    = {.type = NLA_U8,},
    [RS_TM_AT_QOS]         = {.type = NLA_U8,},
    [RS_TM_AT_ACK]         = {.type = NLA_U8,},
    [RS_TM_AT_AIFSN]       = {.type = NLA_U8,},

    [RS_TM_AT_PER_PASS]    = {.type = NLA_U32,},
    [RS_TM_AT_PER_FCS]     = {.type = NLA_U32,},
    [RS_TM_AT_PER_PHY]     = {.type = NLA_U32,},
    [RS_TM_AT_PER_OVERFLOW]= {.type = NLA_U32,},
    [RS_TM_AT_HOST_LOG_LEVEL] = {.type = NLA_U32,},

};
#endif /* CONFIG_NL80211_TESTMODE */

static struct ieee80211_iface_limit rs_iface_limits[] = {
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_STATION),
	},
	{
		.max = 1,
		.types = BIT(NL80211_IFTYPE_AP) | BIT(NL80211_IFTYPE_P2P_CLIENT) | BIT(NL80211_IFTYPE_P2P_GO),
	},
};

static struct ieee80211_iface_combination rs_combinations[] = { {
	.limits = rs_iface_limits,
	.n_limits = ARRAY_SIZE(rs_iface_limits),
	.num_different_channels = 1,
	.max_interfaces = 2,
} };

enum hw_rate_ofdm
{
	HW_RATE_OFDM_48M = 0,
	HW_RATE_OFDM_24M,
	HW_RATE_OFDM_12M,
	HW_RATE_OFDM_6M,
	HW_RATE_OFDM_54M,
	HW_RATE_OFDM_36M,
	HW_RATE_OFDM_18M,
	HW_RATE_OFDM_9M,
};

enum hw_rate_cck
{
	HW_RATE_CCK_LP_11M = 0,
	HW_RATE_CCK_LP_5_5M,
	HW_RATE_CCK_LP_2M,
	HW_RATE_CCK_LP_1M,
	HW_RATE_CCK_SP_11M,
	HW_RATE_CCK_SP_5_5M,
	HW_RATE_CCK_SP_2M,
};

static struct ieee80211_rate rs_ratetable[] = {
	{ .bitrate = 10, .hw_value = HW_RATE_CCK_LP_1M },
	{ .bitrate = 20,
	  .hw_value = HW_RATE_CCK_LP_2M,
	  .hw_value_short = HW_RATE_CCK_SP_2M,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 55,
	  .hw_value = HW_RATE_CCK_LP_5_5M,
	  .hw_value_short = HW_RATE_CCK_SP_5_5M,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 110,
	  .hw_value = HW_RATE_CCK_LP_11M,
	  .hw_value_short = HW_RATE_CCK_SP_11M,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },

	{ .bitrate = 60, .hw_value = HW_RATE_OFDM_6M },
	{ .bitrate = 90, .hw_value = HW_RATE_OFDM_9M },
	{ .bitrate = 120, .hw_value = HW_RATE_OFDM_12M },
	{ .bitrate = 180, .hw_value = HW_RATE_OFDM_18M },
	{ .bitrate = 240, .hw_value = HW_RATE_OFDM_24M },
	{ .bitrate = 360, .hw_value = HW_RATE_OFDM_36M },
	{ .bitrate = 480, .hw_value = HW_RATE_OFDM_48M },
	{ .bitrate = 540, .hw_value = HW_RATE_OFDM_54M },
};

static struct ieee80211_supported_band rs_band_2GHz = {
	.channels = rs_2ghz_channels,
	.n_channels = ARRAY_SIZE(rs_2ghz_channels),
	.bitrates = rs_ratetable,
	.n_bitrates = ARRAY_SIZE(rs_ratetable),
	.ht_cap = RS_HT_CAPABILITIES,
};

static const s32 rs_ac2hwq[IEEE80211_NUM_ACS] = { [NL80211_TXQ_Q_VO] = VO_Q,
  [NL80211_TXQ_Q_VI] = VI_Q, [NL80211_TXQ_Q_BE] = BE_Q, [NL80211_TXQ_Q_BK] = BK_Q };

static s32 rs_ops_start(struct ieee80211_hw *hw)
{
	s32 error = 0;
	struct rs_hw_priv *priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;

	if (WARN_ON(test_bit(RS_DEV_STARTED, &priv->drv_flags)))
		return -EBUSY;

	if ((error = rs_dev_start(priv)))
		return error;

	if (rs_set_idle(priv, 1))
		return -EIO;

	set_bit(RS_DEV_STARTED, &priv->drv_flags);

	ieee80211_wake_queues(hw);

	return error;
}

static void rs_ops_stop(struct ieee80211_hw *hw)
{
	struct rs_hw_priv *priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;

	rs_set_idle(priv, 1);

	ieee80211_stop_queues(hw);

	rs_reset(priv);

	clear_bit(RS_DEV_STARTED, &priv->drv_flags);
}

static s32 rs_ops_add_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_vif_priv *vif_priv;
	struct rs_add_if_chk *add_if_chk = &priv->mgmt_return.add_if_chk;
	s32 ac;
	s32 error = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	INIT_LIST_HEAD(&vif_priv->list_chan_ctxt);
	INIT_LIST_HEAD(&vif_priv->stations);

	if ((error = rs_add_if(priv, vif->addr, vif->type, vif->p2p, add_if_chk)))
		return error;

	if (add_if_chk->status != 0) {
		RS_PRINT_CHK_ERR(add_if);
		return -EIO;
	}

	vif_priv->vif = vif;
	vif_priv->vif_index = add_if_chk->vif_index;

	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++)
		vif->hw_queue[ac] = rs_ac2hwq[ac];

	if ((vif->type == NL80211_IFTYPE_AP) || (vif->type == NL80211_IFTYPE_MESH_POINT)) {
		vif->cab_queue = BCN_Q;
	} else {
		vif->cab_queue = IEEE80211_INVAL_HW_QUEUE;
	}

	vif->driver_flags |= IEEE80211_VIF_SUPPORTS_CQM_RSSI | IEEE80211_VIF_BEACON_FILTER;

	spin_lock_bh(&priv->cb_lock);
	list_add_tail(&vif_priv->list, &priv->vifs);
	spin_unlock_bh(&priv->cb_lock);

	return 0;
}

static void rs_ops_remove_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct rs_hw_priv *priv;
	struct rs_vif_priv *vif_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	spin_lock_bh(&priv->cb_lock);
	if (vif_priv->vif) {
		vif_priv->vif = NULL;
		list_del(&vif_priv->list);

		if (vif_priv->chanctx) {
			list_del(&vif_priv->list_chan_ctxt);
		}
	}
	spin_unlock_bh(&priv->cb_lock);

	rs_remove_if(priv, vif_priv->vif_index);
}

static s32 rs_ops_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	u32 link_id,
#endif
	u16 ac, const struct ieee80211_tx_queue_params *params)
{
	struct rs_hw_priv *priv;
	u8 hw_queue, aifs, cwmin, cwmax;
	u32 param;
	struct rs_vif_priv *vif_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	hw_queue = rs_ac2hwq[ac];

	aifs = params->aifs;
	cwmin = fls(params->cw_min);
	cwmax = fls(params->cw_max);

	param = (u32)(aifs << 0);
	param |= (u32)(cwmin << 4);
	param |= (u32)(cwmax << 8);
	param |= (u32)(params->txop) << 12;

	return rs_set_edca(priv, hw_queue, param, params->uapsd, vif_priv->vif_index);
}

static s32 rs_ops_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	struct rs_vif_priv *vif_priv = (struct rs_vif_priv *)vif->drv_priv;
	struct rs_sta_add_chk *sta_add_chk = &priv->mgmt_return.sta_add_chk;
	s32 error = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	if (vif->type == NL80211_IFTYPE_AP && priv->sta_cnt < RS_REMOTE_STA_MAX - 1)
		priv->sta_cnt++;

	if (priv->sta_cnt >= RS_REMOTE_STA_MAX - 1) {
		pr_info("Max number of stations reached\n");
		priv->sta_cnt--;
		return -EOPNOTSUPP;
	}

	if ((error = rs_sta_add(priv, sta, vif_priv->vif_index, sta_add_chk)))
		return error;

	if (sta_add_chk->status != 0) {
		RS_PRINT_CHK_ERR(sta_add);
		return -EOPNOTSUPP;
	}

	sta_priv->id = sta_add_chk->sta_id;
	sta_priv->hw_sta_id = sta_add_chk->hw_sta_id;
	sta_priv->vif_id = vif_priv->vif_index;
	sta_priv->sleep = 0;

	if (sta->tdls) {
		pr_debug("Add TDLS STA %i (%pM)\n", sta_priv->id, sta->addr);
		priv->tdls_info.n_sta++;
		rs_tdls_ps(priv, MGMT_PS_MODE_OFF);
		sta_priv->tdls.active = true;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	if (sta->ht_cap.ht_supported)
#else
	if (sta->deflink.ht_cap.ht_supported)
#endif
	{
		u8 stbc_nss;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
		if (sta->vht_cap.vht_supported) {
			stbc_nss = (sta->vht_cap.cap & IEEE80211_VHT_CAP_RXSTBC_MASK) >> 8;
			stbc_nss = (stbc_nss <= 4) ? stbc_nss : 0;
		} else {
			stbc_nss = (sta->ht_cap.cap & IEEE80211_HT_CAP_RX_STBC) >>
				   IEEE80211_HT_CAP_RX_STBC_SHIFT;
		}
#else
		if (sta->deflink.vht_cap.vht_supported) {
			stbc_nss = (sta->deflink.vht_cap.cap & IEEE80211_VHT_CAP_RXSTBC_MASK) >> 8;
			stbc_nss = (stbc_nss <= 4) ? stbc_nss : 0;
		} else {
			stbc_nss = (sta->deflink.ht_cap.cap & IEEE80211_HT_CAP_RX_STBC) >>
				   IEEE80211_HT_CAP_RX_STBC_SHIFT;
		}
#endif
		sta_priv->stbc_nss = min_t(u8, stbc_nss, priv->stbc_nss);
	} else {
		sta_priv->stbc_nss = 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	if (sta->vht_cap.vht_supported)
#else
	if (sta->deflink.vht_cap.vht_supported)
#endif
	{
		u16 paid, gid;
		const u8 *mac = NULL;

		switch (vif->type) {
		case NL80211_IFTYPE_STATION:
			if (sta->tdls) {
				mac = (void *)vif->bss_conf.bssid;
				if (mac) {
					paid = (sta->aid & 0x1ff) +
					       (((mac[5] & 0x0f) ^ ((mac[5] & 0xf0) >> 4)) << 5);
					paid &= 0x1ff;
					gid = 63;
				} else {
					paid = 0;
					gid = 0;
				}
				break;
			} else {
				mac = (void *)sta->addr;
				paid = (mac[4] >> 7) | (mac[5] << 1);
				gid = 0;
				break;
			}
		case NL80211_IFTYPE_MESH_POINT:
			mac = (void *)sta->addr;
			paid = (mac[4] >> 7) | (mac[5] << 1);
			gid = 0;
			break;
		case NL80211_IFTYPE_AP:
			mac = (void *)vif->addr;
			paid = (sta->aid & 0x1ff) + (((mac[5] & 0x0f) ^ ((mac[5] & 0xf0) >> 4)) << 5);
			paid &= 0x1ff;
			gid = 63;
			break;
		default:
			paid = 0;
			gid = 63;
			break;
		}
		sta_priv->paid = paid;
		sta_priv->gid = gid;
		RS_DBG("%s: VHT sta %pM to %pM - partial AID %d - GID %d\n", __func__, sta->addr, mac, paid,
		       gid);
	}

	spin_lock_bh(&priv->cb_lock);
	list_add_tail(&sta_priv->list, &vif_priv->stations);
	spin_unlock_bh(&priv->cb_lock);

	return 0;
}

static s32 rs_ops_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta)
{
	struct rs_hw_priv *priv;
	struct rs_sta_priv *sta_priv;
	s32 error = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	spin_lock_bh(&priv->cb_lock);
	list_del(&sta_priv->list);
	spin_unlock_bh(&priv->cb_lock);

	if ((error = rs_sta_del(priv, sta_priv->id)))
		return error;

	if ((sta->tdls) && (priv->tdls_info.n_sta)) {
		priv->tdls_info.n_sta--;
		if (priv->tdls_info.n_sta == 0) {
			RS_DBG("%s: no TDLS STAs connected: disable TDLS link and enable PS\n", __func__);
			rs_tdls_ps(priv, priv->tdls_info.next_ps_mode);
		}
		sta_priv->tdls.active = false;
		printk("Del TDLS STA %i (%pM)\n", sta_priv->id, sta->addr);
	}

	priv->sta_cnt--;
	if (priv->sta_cnt < 0)
		priv->sta_cnt = 0;

	return 0;
}

static void rs_ops_sta_notify(struct ieee80211_hw *hw, struct ieee80211_vif *vif, enum sta_notify_cmd cmd,
			      struct ieee80211_sta *sta)
{
	if ((vif->type == NL80211_IFTYPE_AP) || (vif->type == NL80211_IFTYPE_AP_VLAN)) {
		struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
		sta_priv->sleep = (cmd == STA_NOTIFY_SLEEP);
	}
}

static void rs_ops_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u32 queues, bool drop)
{
	struct rs_hw_priv *priv = hw->priv;

	RS_DBG(RS_FN_ENTRY_STR);

	if (test_bit(RS_DEV_RESTARTING, &priv->drv_flags)) {
		printk(KERN_CRIT "%s: bypassing (RS_DEV_RESTARTING set)\n", __func__);
		return;
	}
}

static s32 rs_ops_config(struct ieee80211_hw *hw, u32 changed)
{
	struct rs_hw_priv *priv;
	s32 error = 0;
	u8 ps_mode;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;

	if (priv->ps_on) {
		if (changed & IEEE80211_CONF_CHANGE_PS) {
			if ((hw->conf.flags & IEEE80211_CONF_PS) == IEEE80211_CONF_PS && rs_get_ps()) {
				ps_mode = MGMT_PS_MODE_ON_DYN;
			} else {
				ps_mode = MGMT_PS_MODE_OFF;
			}
			priv->tdls_info.next_ps_mode = ps_mode;
			if (priv->tdls_info.n_sta == 0) {
				error = rs_set_ps_mode(priv, ps_mode);
			}
		}
	}

	if (changed & IEEE80211_CONF_CHANGE_RETRY_LIMITS) {
	}

	if (changed & IEEE80211_CONF_CHANGE_SMPS) {
	}

	if (changed & IEEE80211_CONF_CHANGE_LISTEN_INTERVAL) {
	}

	if (changed & IEEE80211_CONF_CHANGE_MONITOR) {
	}

	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		RS_DBG("rs_ops_config IEEE80211_CONF_CHANGE_POWER\n");
	}

	if (changed & IEEE80211_CONF_CHANGE_IDLE) {
		if (rs_set_idle(priv, !!(hw->conf.flags & IEEE80211_CONF_IDLE)))
			return -EIO;
	}

	return error;
}

static void rs_ops_bss_info_changed(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
	struct ieee80211_bss_conf *info,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	u32 changed
#else
	u64 changed
#endif
)
{
	struct rs_hw_priv *priv;
	struct rs_vif_priv *vif_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	if (changed & BSS_CHANGED_ASSOC) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		if (rs_set_vif_state(priv, info->assoc, info->aid, vif_priv->vif_index))
#else
		if (rs_set_vif_state(priv, vif->cfg.assoc, vif->cfg.aid, vif_priv->vif_index))
#endif
			return;
		if (priv->ps_on) {
			if (rs_set_ps_options(priv, true, 0, vif_priv->vif_index))
				return;
		}
	}

	if (changed & BSS_CHANGED_BSSID) {
		if (rs_set_bssid(priv, info->bssid, vif_priv->vif_index))
			return;
	}

	if (changed & BSS_CHANGED_BEACON_INT) {
		if (rs_set_beacon_int(priv, info->beacon_int, vif_priv->vif_index))
			return;
		if ((vif->type == NL80211_IFTYPE_AP) || (vif->type == NL80211_IFTYPE_MESH_POINT)) {
			if (rs_dtim_req(priv, info->dtim_period))
				return;
		}
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		if (rs_set_vif_state(priv, info->enable_beacon, 0, vif_priv->vif_index))
			return;
		vif_priv->bcn_on = info->enable_beacon;
	}

	if (changed & BSS_CHANGED_BEACON) {
		struct sk_buff *skb;
		struct ieee80211_mutable_offsets offs;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		skb = ieee80211_beacon_get_template(priv->hw, vif, &offs);
#else
		skb = ieee80211_beacon_get_template(priv->hw, vif, &offs, 0);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		if (rs_bcn_change(priv, vif_priv->vif_index, skb->data, skb->len, offs.tim_offset,
				  offs.tim_length, offs.cntdwn_counter_offs))
			return;
#else
		if (rs_bcn_change(priv, vif_priv->vif_index, skb->data, skb->len, offs.tim_offset,
				  offs.tim_length, NULL))
			return;
#endif
		dev_kfree_skb_any(skb);
	}

	if ((changed & BSS_CHANGED_BASIC_RATES) && info->chandef.chan) {
		s32 shift = hw->wiphy->bands[info->chandef.chan->band]->bitrates[0].hw_value;
		if (rs_set_basic_rates(priv, info->basic_rates << shift, vif_priv->vif_index,
				       info->chandef.chan->band))
			return;
	}

	if (changed & BSS_CHANGED_ERP_SLOT) {
		if (rs_set_slottime(priv, info->use_short_slot))
			return;
	}

	if (changed & BSS_CHANGED_TXPOWER) {
		if (rs_set_power(priv, vif_priv->vif_index, info->txpower,
				 &priv->mgmt_return.set_power_chk))
			return;

		vif_priv->txpower = info->txpower;
		vif_priv->txpower_idx = info->txpower;
	}

	if (changed & BSS_CHANGED_ERP_PREAMBLE) {
	}

	if (changed & BSS_CHANGED_ERP_CTS_PROT) {
	}

	if (changed & BSS_CHANGED_HT) {
	}

	if (changed & BSS_CHANGED_P2P_PS) {
	}

	if (changed & BSS_CHANGED_CQM) {
		if (rs_cfg_rssi_req(priv, vif_priv->vif_index, info->cqm_rssi_thold, info->cqm_rssi_hyst))
			return;
	}
}

static u64 rs_ops_prepare_multicast(struct ieee80211_hw *hw, struct netdev_hw_addr_list *mc_list)
{
	return netdev_hw_addr_list_count(mc_list);
}

static void rs_ops_configure_filter(struct ieee80211_hw *hw, u32 changed_flags, u32 *total_flags,
				    u64 multicast)
{
	struct rs_hw_priv *priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;

	RS_DBG("    total_flags = 0x%08x\n", *total_flags);

	if (!test_bit(RS_DEV_STARTED, &priv->drv_flags)) {
		*total_flags = 0;
		return;
	}

	if (multicast)
		*total_flags |= FIF_ALLMULTI;
	else
		*total_flags &= ~FIF_ALLMULTI;

	rs_set_filter(priv, *total_flags);

	*total_flags &= ~(1 << 31);
}

static s32 rs_alloc_wpi_key(struct rs_hw_priv *priv, bool is_ap_if, struct ieee80211_key_conf *conf)
{
	struct rs_wpi_key *key;
	s32 i;
	key = kzalloc(sizeof(struct rs_wpi_key), GFP_KERNEL);

	if (key == NULL)
		return -ENOMEM;

	key->conf = conf;
	for (i = 0; i < WPI_PN_LEN; i += 2) {
		key->pn[i] = 0x36;
		key->pn[i + 1] = 0x5c;
	}

	if (conf->flags & IEEE80211_KEY_FLAG_PAIRWISE && is_ap_if)
		key->pn[0]++;

	hlist_add_head(&key->list, &priv->wpi_keys);

	return 0;
}

static s32 rs_free_wpi_key(struct rs_hw_priv *priv, struct ieee80211_key_conf *conf)
{
	struct rs_wpi_key *key;

	hlist_for_each_entry(key, &priv->wpi_keys, list) {
		if (key->conf == conf)
			break;
	}

	if (!key)
		return -EINVAL;

	hlist_del(&key->list);
	kfree(key);

	return 0;
}

static s32 rs_ops_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd, struct ieee80211_vif *vif,
			  struct ieee80211_sta *sta, struct ieee80211_key_conf *key)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_key_add_chk *key_add_chk = &priv->mgmt_return.key_add_chk;
	s32 i, error = 0;
	u8 cipher_suite = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	switch (cmd) {
	case SET_KEY:
		switch (key->cipher) {
		case WLAN_CIPHER_SUITE_WEP40:
			cipher_suite = MAC_CIPHER_WEP40;
			break;
		case WLAN_CIPHER_SUITE_WEP104:
			cipher_suite = MAC_CIPHER_WEP104;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			cipher_suite = MAC_CIPHER_TKIP;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			cipher_suite = MAC_CIPHER_CCMP;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			return -EOPNOTSUPP;
		case WLAN_CIPHER_SUITE_SMS4:
			cipher_suite = MAC_CIPHER_SM54;
			for (i = 0; i < WPI_SUBKEY_LEN / 2; i++) {
				u8 tmp;
				tmp = key->key[i];
				key->key[i] = key->key[WPI_SUBKEY_LEN - 1 - i];
				key->key[WPI_SUBKEY_LEN - 1 - i] = tmp;
			}
			for (i = 0; i < WPI_SUBKEY_LEN / 2; i++) {
				u8 tmp;
				tmp = key->key[i + WPI_SUBKEY_LEN];
				key->key[i + WPI_SUBKEY_LEN] = key->key[WPI_KEY_LEN - 1 - i];
				key->key[WPI_KEY_LEN - 1 - i] = tmp;
			}
			key->icv_len = WPI_MIC_LEN;
			break;
		default:
			return -EINVAL;
		}

		if ((error = rs_key_add(priv, ((struct rs_vif_priv *)vif->drv_priv)->vif_index,
					sta ? ((struct rs_sta_priv *)sta->drv_priv)->id : 0xFF,
					((key->flags & IEEE80211_KEY_FLAG_PAIRWISE) ==
					 IEEE80211_KEY_FLAG_PAIRWISE),
					key->key, key->keylen, key->keyidx, cipher_suite, key_add_chk)))
			return error;

		if (key_add_chk->status != 0) {
			RS_PRINT_CHK_ERR(key_add);
			return -EIO;
		}

		key->hw_key_idx = priv->mgmt_return.key_add_chk.hw_key_idx;

		if (key->cipher == WLAN_CIPHER_SUITE_SMS4) {
			key->flags |= IEEE80211_KEY_FLAG_PUT_IV_SPACE;
			if (rs_alloc_wpi_key(priv, vif->type == NL80211_IFTYPE_AP, key))
				return -ENOMEM;
		} else
			key->flags |= IEEE80211_KEY_FLAG_GENERATE_IV;
		if (key->cipher == WLAN_CIPHER_SUITE_TKIP)
			key->flags |= IEEE80211_KEY_FLAG_GENERATE_MMIC;

		break;

	case DISABLE_KEY:
		error = rs_key_del(priv, key->hw_key_idx);
		if (key->cipher == WLAN_CIPHER_SUITE_SMS4)
			rs_free_wpi_key(priv, key);
		break;

	default:
		error = -EINVAL;
		break;
	}

	return error;
}

#ifdef CONFIG_VENDOR_RS_AMSDUS_TX
static s32 rs_ops_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
	enum ieee80211_ampdu_mlme_action action, struct ieee80211_sta *sta, u16 tid,
	u16 *ssn, u8 buf_size, bool *amsdu_supported)
#else
static s32 rs_ops_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_ampdu_params *params)
#endif
{
	enum ieee80211_ampdu_mlme_action action = params->action;
	struct ieee80211_sta *sta = params->sta;
	u16 tid = params->tid;
	u16 ssn = params->ssn;
	u8 buf_size = params->buf_size;

	struct rs_hw_priv *priv = hw->priv;
	struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	struct rs_agg *ampdu = &sta_priv->aggs[tid];
	s32 err = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	if ((!ieee80211_hw_check(hw, AMPDU_AGGREGATION) || !rs_get_agg_tx()) &&
	    action == IEEE80211_AMPDU_TX_START)
		return -ENOTSUPP;

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		err = rs_ba_add(priv, BA_AGMT_RX, sta_priv->id, tid, ssn, buf_size,
				&priv->mgmt_return.ba_add_chk);
		pr_debug("AMPDU: RX START vif %d sid %d tid %d\n", sta_priv->vif_id, sta_priv->id, tid);
		break;
	case IEEE80211_AMPDU_TX_START:
		ampdu->on = true;
		ampdu->ssn = ssn;
		ampdu->sn = 0;
		ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		pr_debug("AMPDU: TX START vif %d sid %d tid %d\n", sta_priv->vif_id, sta_priv->id, tid);
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
		if (ampdu->on) {
			ampdu->on = false;
			ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
			pr_debug("AMPDU: TX STOP vif %d sid %d tid %d\n", sta_priv->vif_id, sta_priv->id,
				 tid);
		}
		break;
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		ampdu->on = false;
		err = rs_ba_del(priv, sta_priv->id, tid, &priv->mgmt_return.ba_del_chk);
		if (priv->mgmt_return.ba_del_chk.status != BA_AGMT_DELETED &&
		    priv->mgmt_return.ba_del_chk.status != BA_AGMT_DOESNT_EXIST) {
			pr_err("AMPDU: TX FLUSH_%d err %d\n", action, priv->mgmt_return.ba_del_chk.status);
			err = -EIO;
		}
		pr_debug("AMPDU: TX FLUSH_%d vif %d sid %d tid %d\n", action, sta_priv->vif_id, sta_priv->id,
			 tid);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		params->buf_size = min_t(size_t, params->buf_size, 16);
		buf_size = params->buf_size;
		err = rs_ba_add(priv, BA_AGMT_TX, sta_priv->id, tid, buf_size, ampdu->ssn,
				&priv->mgmt_return.ba_add_chk);
		if (err) {
			pr_err("AMPDU: TXOP err %d\n", err);
		} else if ((priv->mgmt_return.ba_add_chk.status != BA_AGMT_ESTABLISHED) &&
			   (priv->mgmt_return.ba_add_chk.status != BA_AGMT_ALREADY_EXISTS)) {
			pr_err("AMPDU: TXOP err status %d\n", priv->mgmt_return.ba_add_chk.status);
			err = -EIO;
		} else {
			ampdu->sn = ampdu->ssn;
			pr_debug("AMPDU: TXOP vif %d sid %d tid %d\n", sta_priv->vif_id, sta_priv->id, tid);
		}
		break;
	default:
		break;
	}

	return err;
}

#ifdef CONFIG_NL80211_TESTMODE
static s32 rs_op_tm_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif, void *data, s32 len)
{
	struct nlattr *tb[RS_TM_AT_MAX];
	struct rs_hw *priv;
	s32 result;

	RS_DBG(RS_FN_ENTRY_STR);
	priv = hw->priv;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	result = nla_parse(tb, RS_TM_AT_MAX - 1, data, len, rs_tm_gnl_msg_policy, NULL);
	if (result != 0) {
		printk("Error parsing the gnl message : %d\n", result);
		return result;
	}
#endif
	if (!tb[RS_TM_AT_CMD]) {
		printk("Error finding testmode command type\n");
		return -ENOMSG;
	}

	switch (nla_get_u32(tb[RS_TM_AT_CMD])) {
	case RS_TM_CMD_A2D_READ_REG:
	case RS_TM_CMD_A2D_WRITE_REG:
		result = rs_tm_reg(hw, tb);
		break;
	case RS_TM_CMD_A2D_LOGMODEFILTER_SET:
	case RS_TM_CMD_A2D_DBGLEVELFILTER_SET:
	case RS_TM_CMD_A2D_DBGOUTDIR_SET:
		result = rs_tm_dbg_filter(hw, tb);
		break;
	case RS_TM_CMD_A2D_TX:
		result = rs_tm_rf_tx(hw, tb);
		break;
	case RS_TM_CMD_A2D_CW:
		result = rs_tm_rf_cw(hw, tb);
		break;
	case RS_TM_CMD_A2D_CONT:
		result = rs_tm_rf_cont(hw, tb);
		break;
	case RS_TM_CMD_A2D_CHANNEL:
		result = rs_tm_rf_ch(hw, tb);
		break;
	case RS_TM_CMD_A2D_PER:
		result = rs_tm_rf_per(hw, tb);
		break;
	case RS_TM_CMD_A2D_RESET_HW:
		result = rs_tm_reset(hw, tb);
		break;
	case RS_TM_CMD_HOST_LOG_LEVEL:
		result = rs_tm_host_log_level(hw, tb);
		break;
	default:
		printk("Unknown testmode command\n");
		result = -ENOSYS;
		break;
	}

	return result;
}
#endif

static bool rs_ops_tx_frames_pending(struct ieee80211_hw *hw)
{
	return 0;
}

void rs_ops_sw_scan_start(struct ieee80211_hw *hw, struct ieee80211_vif *vif, const u8 *mac_addr)
{
	struct rs_hw_priv *priv = hw->priv;

	priv->sw_scanning = true;
}

static void rs_ops_sw_scan_complete(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_vif_priv *vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	priv->sw_scanning = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
	if (!vif->bss_conf.idle)
#endif
	{
		struct rs_set_power_chk *set_power_chk = &priv->mgmt_return.set_power_chk;
		rs_set_power(priv, vif_priv->vif_index, vif->bss_conf.txpower, set_power_chk);
		vif_priv->txpower = set_power_chk->power;
		vif_priv->txpower_idx = set_power_chk->radio_idx;
	}
}

static s32 rs_ops_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			  struct ieee80211_scan_request *hw_req)
{
	struct cfg80211_scan_request *req = &hw_req->req;
	struct rs_hw_priv *priv = hw->priv;
	struct rs_scan_start_chk *scan_start_chk = &priv->mgmt_return.scan_start_chk;
	s32 error;

	RS_DBG(RS_FN_ENTRY_STR);

	priv->tx.status |= TX_Q_STATUS_SCAN;

	if ((error = rs_scan_req(priv, vif, req, scan_start_chk))) {
		priv->tx.status &= ~TX_Q_STATUS_SCAN;
		return error;
	}

	if (scan_start_chk->status != 0) {
		rs_scan_req(priv, vif, req, scan_start_chk);
		if (scan_start_chk->status != 0) {
			priv->tx.status &= ~TX_Q_STATUS_SCAN;
			RS_PRINT_CHK_ERR(scan_start);
		}
		return -EIO;
	}

	priv->hw_scanning = true;

	return 0;
}

static void rs_ops_cancel_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct rs_hw_priv *priv = hw->priv;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	struct cfg80211_scan_info info = {
		.aborted = true,
	};
#endif

	RS_DBG(RS_FN_ENTRY_STR);

	if (priv->hw_scanning) {
		rs_scan_cancel_req(priv, &priv->mgmt_return.scan_cancel_chk);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		ieee80211_scan_completed(hw, &info);
#else
		ieee80211_scan_completed(hw, true);
#endif
		priv->hw_scanning = false;
	}

	priv->tx.status &= ~TX_Q_STATUS_SCAN;
}

static s32 rs_ops_add_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_chanctx *chanctx;
	struct rs_chan_ctxt_add_chk *add_chanctx_chk = &priv->mgmt_return.add_chanctx_chk;
	s32 error = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	chanctx = (struct rs_chanctx *)ctx->drv_priv;

	chanctx->ctx = ctx;

	if ((error = rs_add_chanctx(priv, ctx, add_chanctx_chk)))
		return error;

	if (add_chanctx_chk->status != 0) {
		RS_PRINT_CHK_ERR(add_chanctx);
		return -EIO;
	}

	INIT_LIST_HEAD(&chanctx->list);
	INIT_LIST_HEAD(&chanctx->vifs);

	chanctx->index = add_chanctx_chk->index;
	chanctx->active = false;

	spin_lock_bh(&priv->cb_lock);
	list_add_tail(&chanctx->list, &priv->chan_ctxts);
	spin_unlock_bh(&priv->cb_lock);

	return 0;
}

static void rs_ops_remove_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx)
{
	struct rs_hw_priv *priv;
	struct rs_chanctx *chanctx;
	struct rs_vif_priv *vif_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	chanctx = (struct rs_chanctx *)ctx->drv_priv;

	chanctx->ctx = NULL;

	spin_lock_bh(&priv->cb_lock);
	list_for_each_entry(vif_priv, &chanctx->vifs, list) {
		list_del(&vif_priv->list_chan_ctxt);
	}

	list_del(&chanctx->list);
	spin_unlock_bh(&priv->cb_lock);

	rs_del_chanctx(priv, chanctx->index);
}

static void rs_ops_change_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx, u32 changed)
{
	RS_DBG(RS_FN_ENTRY_STR);

	rs_update_chanctx(hw->priv, ctx);
}

static s32 rs_ops_remain_on_channel(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				    struct ieee80211_channel *chan, s32 duration,
				    enum ieee80211_roc_type type)
{
	struct rs_hw_priv *priv;
	struct rs_vif_priv *vif_priv;
	s32 error = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	error = rs_roc(priv, vif_priv, chan, duration);

	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
static s32 rs_ops_cancel_remain_on_channel(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
#else
static s32 rs_ops_cancel_remain_on_channel(struct ieee80211_hw *hw)
#endif
{
	s32 error = 0;

	RS_DBG(RS_FN_ENTRY_STR);

	error = rs_cancel_roc(hw->priv);

	return error;
}

static s32 rs_ops_assign_vif_chanctx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    struct ieee80211_bss_conf *link_conf,
#endif
    struct ieee80211_chanctx_conf *ctx)
{
	struct rs_hw_priv *priv;
	struct rs_chanctx *chanctx;
	struct rs_vif_priv *vif_priv;
	s32 ret;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	chanctx = (struct rs_chanctx *)ctx->drv_priv;
	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	WARN_ON(vif_priv->chanctx);

	ret = rs_link_chanctx(priv, vif_priv->vif_index, chanctx->index, 0);
	if (ret)
		return ret;

	spin_lock_bh(&priv->cb_lock);

	vif_priv->chanctx = chanctx;

	list_add_tail(&vif_priv->list_chan_ctxt, &chanctx->vifs);

	spin_unlock_bh(&priv->cb_lock);

	return 0;
}

static void rs_ops_unassign_vif_chanctx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	struct ieee80211_bss_conf *link_conf,
#endif
	struct ieee80211_chanctx_conf *ctx)
{
	struct rs_hw_priv *priv;
	struct rs_vif_priv *vif_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	priv = hw->priv;
	vif_priv = (struct rs_vif_priv *)vif->drv_priv;

	WARN_ON(!vif_priv->chanctx);

	spin_lock_bh(&priv->cb_lock);
	vif_priv->chanctx = NULL;

	list_del(&vif_priv->list_chan_ctxt);
	spin_unlock_bh(&priv->cb_lock);

	rs_unlink_chanctx(priv, vif_priv->vif_index);
}

static s32 rs_ops_switch_vif_chanctx(struct ieee80211_hw *hw, struct ieee80211_vif_chanctx_switch *vifs,
				     s32 n_vifs, enum ieee80211_chanctx_switch_mode mode)
{
	struct ieee80211_chanctx_conf *new_ctx, *old_ctx;
	struct ieee80211_vif *vif;
	struct rs_hw_priv *priv = hw->priv;
	s32 i, ret;

	RS_DBG(RS_FN_ENTRY_STR);

	for (i = 0; i < n_vifs; i++) {
		new_ctx = vifs[i].new_ctx;
		old_ctx = vifs[i].old_ctx;
		vif = vifs[i].vif;

		if (mode == CHANCTX_SWMODE_SWAP_CONTEXTS) {
			rs_ops_unassign_vif_chanctx(hw, vif,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
						    NULL,
#endif
						    old_ctx);
			rs_ops_remove_chanctx(hw, old_ctx);

			ret = rs_ops_add_chanctx(hw, new_ctx);
			if (ret)
				return ret;
			ret = rs_ops_assign_vif_chanctx(hw, vif,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
							NULL,
#endif
							new_ctx);
			if (ret)
				return ret;
		} else {
			struct rs_vif_priv *vif_priv = (struct rs_vif_priv *)vif->drv_priv;
			struct rs_chanctx *chanctx = (struct rs_chanctx *)new_ctx->drv_priv;
			WARN_ON(!vif_priv->chanctx);

			ret = rs_link_chanctx(priv, vif_priv->vif_index, chanctx->index, 1);
			if (ret)
				return ret;

			spin_lock_bh(&priv->cb_lock);

			vif_priv->chanctx = chanctx;

			list_del(&vif_priv->list_chan_ctxt);

			list_add_tail(&vif_priv->list_chan_ctxt, &chanctx->vifs);

			spin_unlock_bh(&priv->cb_lock);
		}
	}

	return 0;
}

static void rs_ops_mgd_prepare_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	struct ieee80211_prep_tx_info *info
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	u16 duration
#endif
)
{
	struct rs_vif_priv *vif_priv;
	struct rs_chanctx *chanctx;

	RS_DBG(RS_FN_ENTRY_STR);

	vif_priv = (struct rs_vif_priv *)vif->drv_priv;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
	chanctx = (struct rs_chanctx *)vif->chanctx_conf->drv_priv;
#else
	chanctx = (struct rs_chanctx *)vif->bss_conf.chanctx_conf->drv_priv;
#endif

	rs_sched_chanctx(hw->priv, vif_priv->vif_index, chanctx->index, 1);
}

static s32 rs_ops_set_tim(struct ieee80211_hw *hw, struct ieee80211_sta *sta, bool set)
{
	struct rs_sta_priv *sta_priv;

	RS_DBG(RS_FN_ENTRY_STR);

	sta_priv = (struct rs_sta_priv *)sta->drv_priv;

	return rs_tim_update(hw->priv, sta_priv->vif_id, sta->aid, set ? 1 : 0);
}

static s32 rs_ops_get_survey(struct ieee80211_hw *hw, s32 idx, struct survey_info *survey)
{
	struct rs_hw_priv *priv = hw->priv;
	struct ieee80211_supported_band *sband;
	struct rs_survey_info_priv *rs_survey;

	RS_DBG(RS_FN_ENTRY_STR);

	if (idx >= ARRAY_SIZE(priv->survey))
		return -ENOENT;

	rs_survey = &priv->survey[idx];

	sband = hw->wiphy->bands[NL80211_BAND_2GHZ];
	if (sband && idx >= sband->n_channels) {
		idx -= sband->n_channels;
		sband = NULL;
	}

	if (!sband) {
		sband = hw->wiphy->bands[NL80211_BAND_5GHZ];

		if (!sband || idx >= sband->n_channels)
			return -ENOENT;
	}

	survey->channel = &sband->channels[idx];
	survey->filled = rs_survey->filled;

	if (rs_survey->filled != 0) {
		survey->time = (u64)rs_survey->chan_time_ms;
		survey->time_busy = (u64)rs_survey->chan_time_busy_ms;
		survey->noise = rs_survey->noise_dbm;
		rs_survey->filled = 0;
	}

	return 0;
}

static s32 rs_ops_tdls_channel_switch(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				      struct ieee80211_sta *sta, u8 oper_class,
				      struct cfg80211_chan_def *chandef, struct sk_buff *tmpl_skb,
				      u32 ch_sw_tm_ie_off)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_vif_priv *vif_priv = (struct rs_vif_priv *)vif->drv_priv;
	struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	struct rs_tdls_chan_switch_chk *tdls_chan_switch_chk = &priv->mgmt_return.tdls_chan_switch_chk;
	s32 error;

	if ((error = rs_tdls_chan_switch_req(priv, vif_priv, sta, oper_class, chandef, tdls_chan_switch_chk,
					     5)))
		return error;

	if (!tdls_chan_switch_chk->status) {
		sta_priv->tdls.chsw_en = true;
		priv->tdls_info.chsw_en = true;
	}

	return tdls_chan_switch_chk->status;
}

static void rs_ops_tdls_cancel_channel_switch(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
					      struct ieee80211_sta *sta)
{
	struct rs_hw_priv *priv = hw->priv;
	struct rs_vif_priv *vif_priv = (struct rs_vif_priv *)vif->drv_priv;
	struct rs_sta_priv *sta_priv = (struct rs_sta_priv *)sta->drv_priv;
	struct rs_tdls_cancel_chan_switch_chk cfm;

	if ((!rs_tdls_cancel_chan_switch_req(priv, vif_priv, sta, &cfm))) {
		sta_priv->tdls.chsw_en = false;
		priv->tdls_info.chsw_en = false;
	}
}

static void rs_ops_tdls_recv_channel_switch(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
					    struct ieee80211_tdls_ch_sw_params *params)
{
	return;
}

static void rs_ops_reconfig_complete(struct ieee80211_hw *hw, enum ieee80211_reconfig_type type)
{
	struct rs_hw_priv *priv = hw->priv;

	RS_DBG(RS_FN_ENTRY_STR);

	if (!WARN_ON(type != IEEE80211_RECONFIG_TYPE_RESTART))
		clear_bit(RS_DEV_STACK_RESTARTING, &priv->drv_flags);
}

struct ieee80211_ops rs_ops = {
	.tx = rs_ops_xmit,
	.start = rs_ops_start,
	.stop = rs_ops_stop,
#ifdef CONFIG_PM_SLEEP
#endif
	.add_interface = rs_ops_add_interface,
	.remove_interface = rs_ops_remove_interface,
	.flush = rs_ops_flush,
	.config = rs_ops_config,
	.bss_info_changed = rs_ops_bss_info_changed,
	.prepare_multicast = rs_ops_prepare_multicast,
	.configure_filter = rs_ops_configure_filter,
	.set_key = rs_ops_set_key,
	.sta_add = rs_ops_sta_add,
	.sta_remove = rs_ops_sta_remove,
	.sta_notify = rs_ops_sta_notify,
	.conf_tx = rs_ops_conf_tx,
	.ampdu_action = rs_ops_ampdu_action,
	CFG80211_TESTMODE_CMD(rs_op_tm_cmd).set_tim = rs_ops_set_tim,
	.tx_frames_pending = rs_ops_tx_frames_pending,
	.sw_scan_start = rs_ops_sw_scan_start,
	.sw_scan_complete = rs_ops_sw_scan_complete,
	.hw_scan = rs_ops_hw_scan,
	.cancel_hw_scan = rs_ops_cancel_hw_scan,
	.add_chanctx = rs_ops_add_chanctx,
	.remove_chanctx = rs_ops_remove_chanctx,
	.change_chanctx = rs_ops_change_chanctx,
	.assign_vif_chanctx = rs_ops_assign_vif_chanctx,
	.unassign_vif_chanctx = rs_ops_unassign_vif_chanctx,
	.switch_vif_chanctx = rs_ops_switch_vif_chanctx,
	.mgd_prepare_tx = rs_ops_mgd_prepare_tx,
	.remain_on_channel = rs_ops_remain_on_channel,
	.cancel_remain_on_channel = rs_ops_cancel_remain_on_channel,
	.get_survey = rs_ops_get_survey,
	.reconfig_complete = rs_ops_reconfig_complete,
	.tdls_channel_switch = rs_ops_tdls_channel_switch,
	.tdls_cancel_channel_switch = rs_ops_tdls_cancel_channel_switch,
	.tdls_recv_channel_switch = rs_ops_tdls_recv_channel_switch,
#ifdef CONFIG_MAC80211_TXQ
	.wake_tx_queue = rs_ops_wake_tx_queue,
#endif
};

static void rs_set_vers(struct rs_hw_priv *priv)
{
	u32 vers = priv->mgmt_return.version_chk.fw_version;

	RS_DBG(RS_FN_ENTRY_STR);

	snprintf(priv->hw->wiphy->fw_version, sizeof(priv->hw->wiphy->fw_version), "%d.%d.%d.%d",
		 (vers & (0xff << 24)) >> 24, (vers & (0xff << 16)) >> 16, (vers & (0xff << 8)) >> 8,
		 (vers & (0xff << 0)) >> 0);

	printk("MACSW version %s\n", priv->hw->wiphy->fw_version);
}

static s32 init_priv_tx_rx_properties(struct rs_hw_priv *priv)
{
	s32 i;

	INIT_WORK(&priv->tx.wk, rs_tx_work_handler);

	rs_tx_q_data_lock_init(priv);

	for (i = 0; i < RS_TXQ_CNT; i++) {
		skb_queue_head_init(&priv->tx.q[i].list);
		// spin_lock_init(&priv->tx.q[i].lock);
	}
	priv->tx.b2k = kmalloc(2048, GFP_KERNEL);
	priv->tx.b4 = kmalloc(4, GFP_KERNEL);
	if (!priv->tx.b2k || !priv->tx.b4) {
		pr_err("failed kmalloc Tx buffer.\n");
		return -ENOMEM;
	}

	priv->tx.seq = 0;

	priv->tx.back.b2k = kmalloc(2048, GFP_KERNEL);
	priv->tx.back.b4 = kmalloc(4, GFP_KERNEL);

	priv->rx.b4 = kmalloc(4, GFP_KERNEL);

	priv->tx.status = TX_Q_STATUS_NONE;

	return 0;
}

static s32 deinit_priv_tx_rx_properties(struct rs_hw_priv *priv)
{
	s32 i, j;
	struct sk_buff *skb;

	priv->tx.deinit = true;
	priv->rx.deinit = true;

	for (i = 0; i < RS_TXQ_CNT; i++) {
		rs_tx_q_data_lock(priv, i);

		for (j = 0; j < TX_KICK_DATA_MAX; j++) {
			if (priv->tx.q[i].data[j]) {
				skb = (struct sk_buff *)priv->tx.q[i].data[j];
				priv->tx.q[i].data[j] = NULL;
				ieee80211_free_txskb(priv->hw, skb);
			}
		}

		while ((skb = skb_dequeue(&priv->tx.q[i].list)) != NULL) {
			ieee80211_free_txskb(priv->hw, skb);
		}

		rs_tx_q_data_unlock(priv, i);
	}

	if (priv->tx.b2k)
		kfree(priv->tx.b2k);
	if (priv->tx.b4)
		kfree(priv->tx.b4);
	if (priv->tx.back.b2k)
		kfree(priv->tx.back.b2k);
	if (priv->tx.back.b4)
		kfree(priv->tx.back.b4);

	flush_work(&priv->tx.wk);

	if (priv->rx.b4)
		kfree(priv->rx.b4);

	rs_tx_q_data_lock_destroy(priv);

	return 0;
}

s32 rs_mac_allocate(struct rs_core *core, void **priv_data)
{
	struct rs_hw_priv *priv;
	struct ieee80211_hw *hw = NULL;
	struct wiphy *wiphy = NULL;
	// struct rs_conf_file init_conf;
	u8 mac_addr[ETH_ALEN] = { 0 };
	s32 ret = 0;
	s32 i;

	RS_DBG(RS_FN_ENTRY_STR);

	hw = ieee80211_alloc_hw(sizeof(struct rs_hw_priv), &rs_ops);
	if (!hw) {
		dev_err(core_to_dev(core), "ieee80211_alloc_hw failed\n");
		ret = -ENOMEM;
		goto err_out;
	}

	wiphy = hw->wiphy;

	priv = hw->priv;
	priv->hw = hw;
	priv->core = core;
	core->priv = priv;
	priv->dev = core_to_dev(core);
	SET_IEEE80211_DEV(hw, priv->dev);
	priv->tx.busq = core->bus.q;

	priv->fw_dbgfile = NULL;
	priv->fw_dbgoutdir = 0; // default is UART

	if ((ret = rs_get_mac_addr(priv, RS_DEFAULT_MAC_PATH, &mac_addr[0]))) {
		wiphy_err(wiphy, "mac addr get failed\n");
		goto err_mac_addr;
	}

	priv->sec_phy_chan.band = NL80211_BAND_2GHZ;
	priv->sec_phy_chan.type = RS_CHAN_BW_20;
	priv->sec_phy_chan.prim20_freq = 2412;
	priv->sec_phy_chan.center_freq1 = 2412;
	priv->sec_phy_chan.center_freq2 = 0;

	SET_IEEE80211_PERM_ADDR(hw, mac_addr);
	if (!WARN_ON(RS_VIF_DEV_MAX & (RS_VIF_DEV_MAX - 1)))
		*(u32 *)(wiphy->addr_mask + 2) = cpu_to_be32(RS_VIF_DEV_MAX - 1);

	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
	ieee80211_hw_set(hw, QUEUE_CONTROL);
	ieee80211_hw_set(hw, WANT_MONITOR_VIF);
	ieee80211_hw_set(hw, SUPPORTS_HT_CCK_RATES);
#ifdef CONFIG_SUPPORT_5G
	ieee80211_hw_set(hw, SPECTRUM_MGMT);
#endif

	wiphy->bands[NL80211_BAND_2GHZ] = &rs_band_2GHz;
#ifdef CONFIG_SUPPORT_5G
	wiphy->bands[NL80211_BAND_5GHZ] = &rs_band_5GHz;
#endif
	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP) |
				 // If set, wpa_supplicant always create a dedicated interface for p2p
				 // BIT(NL80211_IFTYPE_P2P_DEVICE)  |
				 BIT(NL80211_IFTYPE_P2P_CLIENT) | BIT(NL80211_IFTYPE_P2P_GO);
	wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL | WIPHY_FLAG_HAS_CHANNEL_SWITCH;

	if (rs_get_mesh()) {
		wiphy->interface_modes |= BIT(NL80211_IFTYPE_MESH_POINT);
		rs_iface_limits[0].types |= BIT(NL80211_IFTYPE_MESH_POINT);
	}

	wiphy->max_remain_on_channel_duration = MAX_ROCD;
	wiphy->features |= NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE;

	wiphy->iface_combinations = rs_combinations;
	wiphy->n_iface_combinations = ARRAY_SIZE(rs_combinations);

	wiphy->max_ap_assoc_sta = RS_REMOTE_STA_MAX - 2;

	hw->max_rates = hw->max_report_rates = min(RS_TX_MAX_RATES, IEEE80211_TX_MAX_RATES);
	hw->max_rate_tries = 1;

	hw->max_listen_interval = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	hw->max_rx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF;
#else
	hw->max_rx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF_HT;
#endif

	hw->vif_data_size = sizeof(struct rs_vif_priv);
	hw->sta_data_size = sizeof(struct rs_sta_priv);
	hw->chanctx_data_size = sizeof(struct rs_chanctx);
	hw->queues = RS_TXQ_CNT;
	hw->offchannel_tx_hw_queue = VO_Q;
	// Set UAPSD queues
	hw->uapsd_queues = IEEE80211_WMM_IE_STA_QOSINFO_AC_VO;

	priv->msg_rx_handle_callback = rs_rx_handle_callbck;

	INIT_LIST_HEAD(&priv->vifs);
	INIT_LIST_HEAD(&priv->chan_ctxts);

	for (i = 0; i < RS_SCAN_CHANNEL_MAX; i++) {
		priv->survey[i].filled = 0;
	}

	spin_lock_init(&priv->tx_lock);
	spin_lock_init(&priv->rx_lock);
	spin_lock_init(&priv->cb_lock);

	priv->wq = alloc_workqueue("rswlan_wq", WQ_UNBOUND | WQ_HIGHPRI, WQ_UNBOUND_MAX_ACTIVE);
	if (!priv->wq) {
		pr_err("failed alloc_workqueue\n");
		return -ENOMEM;
	}
	init_priv_tx_rx_properties(priv);
	(void)rs_irq_handler_init(core);

	if ((ret = rs_core_on(priv)))
		goto err_platon;

	/* Reset LMAC */
	if ((ret = rs_reset(priv)))
		goto err_lmac_reqs;

	if ((ret = rs_version_req(priv, &priv->mgmt_return.version_chk)))
		goto err_lmac_reqs;

	rs_set_vers(priv);

	if ((ret = rs_handle_dynparams(priv, wiphy)))
		goto err_lmac_reqs;

	if ((ret = ieee80211_register_hw(hw))) {
		wiphy_err(wiphy, "Could not register ieee80211 device (err=%d)\n", ret);
		goto err_register_hw;
	}

	*priv_data = priv;

	if ((ret = rs_dbgfs_register(priv, "rs"))) {
		wiphy_err(wiphy, "Failed to register debugfs entries");
		goto err_debugfs;
	}

	return 0;

err_debugfs:
err_register_hw:
err_lmac_reqs:
	priv->core->enabled = false;
err_platon:
err_mac_addr:
	ieee80211_free_hw(hw);
err_out:
	return ret;
}

void rs_mac80211_deinit(struct rs_hw_priv *priv)
{
	priv->run_deinit = true;

	(void)rs_irq_dbg_set(priv, 0);

	rs_dbgfs_unregister(priv);
	ieee80211_unregister_hw(priv->hw);
	priv->core->enabled = false;
	rs_flush_mgmt(priv);

	(void)deinit_priv_tx_rx_properties(priv);
	flush_workqueue(priv->wq);
	destroy_workqueue(priv->wq);

	(void)rs_irq_handler_deinit(priv->core);
	ieee80211_free_hw(priv->hw);
}