// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#include <linux/module.h>

#include "rs_defs.h"
#include "rs_tx.h"
#include "rs_hal.h"

#define COMMON_PARAM(name, default_softmac, default_fullmac) .name = default_softmac,
#define SOFTMAC_PARAM(name, default)			     .name = default,
#define FULLMAC_PARAM(name, default)

#define BFMER_BIT      ((u32)0x00040000)
#define MU_MIMO_TX_BIT ((u32)0x00080000)

static bool ps_mode = true;

module_param_named(ps_mode, ps_mode, bool, S_IRUGO);
MODULE_PARM_DESC(ps_mode, "Use Power Save mode (Default: 1-Enabled)");

static bool agg_tx = true;
module_param_named(agg_tx, agg_tx, bool, S_IRUGO);
MODULE_PARM_DESC(agg_tx, "Use A-MPDU in TX (Default: 1)");

static bool mesh = false;
module_param_named(mesh, mesh, bool, S_IRUGO);
MODULE_PARM_DESC(mesh, "Enable Meshing Capability (Default: 0-Disabled)");

static bool tdls = false;
module_param_named(tdls, tdls, bool, S_IRUGO);
MODULE_PARM_DESC(tdls, "Enable TDLS (Default: 1-Enabled)");

static bool ldpc_on = false;
module_param_named(ldpc_on, ldpc_on, bool, S_IRUGO);
MODULE_PARM_DESC(ldpc_on, "Enable LDPC (Default: 1)");

#if defined(CONFIG_RS_SDIO) || defined(CONFIG_RS_SPI)

static int bt_coex = 0;
module_param_named(bt_coex, bt_coex, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(bt_coex, "BT-COEX. (Default: 0: off)");

#if defined(CONFIG_RS_SPI)

static bool fw_sflash = false;
module_param_named(fw_sflash, fw_sflash, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(fw_sflash, "lmacfw using SFLASH, not download image (Default: 0)");

#endif
#endif

static int check_dev_feature(struct rs_hw_priv *rs_hw, struct wiphy *wiphy)
{
	u32 sys_feat = rs_hw->mgmt_return.version_chk.dev_features;
	int res = 0;

	if (sys_feat & BIT(MGMT_FEAT_CMON_BIT)) {
		ieee80211_hw_set(rs_hw->hw, CONNECTION_MONITOR);
	}

	if (!(sys_feat & BIT(MGMT_FEAT_TDLS_BIT))) {
		tdls = false;
	}

	if (sys_feat & BIT(MGMT_FEAT_WAPI_BIT)) {
		rs_enable_wapi(rs_hw);
	}

	// if (sys_feat & BIT(MGMT_FEAT_AMPDU_BIT)) {
	// 	agg_tx = true;
	// }

	return res;
}

s32 rs_handle_dynparams(struct rs_hw_priv *rs_hw, struct wiphy *wiphy)
{
	struct ieee80211_hw *hw = rs_hw->hw;
	struct ieee80211_supported_band *band_2GHz = wiphy->bands[NL80211_BAND_2GHZ];
	s32 ret;
	s32 nss;

	ret = check_dev_feature(rs_hw, wiphy);
	if (ret)
		return ret;

	// ieee80211_hw_set(hw, HOST_BROADCAST_PS_BUFFERING); // autobcn is enable as default
	if (agg_tx)
		ieee80211_hw_set(hw, AMPDU_AGGREGATION);
	ieee80211_hw_set(hw, CONNECTION_MONITOR);
	ieee80211_hw_set(hw, CHANCTX_STA_CSA);

	if (ps_mode) {
		rs_hw->ps_on = true;
		ieee80211_hw_set(hw, SUPPORTS_PS);
		ieee80211_hw_set(hw, SUPPORTS_DYNAMIC_PS);
	}

	if (tdls) {
		wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS;
		wiphy->features |= NL80211_FEATURE_TDLS_CHANNEL_SWITCH;
	}

	nss = 1;

	rs_hw->perf_ctrl_value = 0;
	rs_hw->antset_value |= RS_ANT_CNT_SHIFT(nss);
	rs_hw->stbc_nss = nss >> 1;

	band_2GHz->ht_cap.cap |= 1 << IEEE80211_HT_CAP_RX_STBC_SHIFT;

	band_2GHz->ht_cap.cap |= IEEE80211_HT_CAP_MAX_AMSDU;

	band_2GHz->ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;
	band_2GHz->ht_cap.mcs.rx_highest = cpu_to_le16(72 * nss);
	band_2GHz->ht_cap.cap |= IEEE80211_HT_CAP_GRN_FLD;

	if (ldpc_on) {
		band_2GHz->ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;
	}

	hw->wiphy->max_scan_ssids = RS_SCAN_SSID_MAX;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
	return 0;
}

bool rs_get_mesh(void)
{
	return mesh;
}

u32 rs_get_bt_coex(void)
{
	return bt_coex;
}

bool rs_get_agg_tx(void)
{
	return agg_tx;
}

bool rs_get_ps(void)
{
	return ps_mode;
}

#if defined(CONFIG_RS_SPI)
bool rs_get_fw_sflash(void)
{
	return fw_sflash;
}
#endif