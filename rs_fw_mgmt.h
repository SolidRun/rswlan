// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_FW_MGMT_H
#define RS_FW_MGMT_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/types.h>

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define ETH_ALEN	       6
#define MAC_SSID_LEN	       32
#define RS_SEC_KEY_LEN	       32 // TKIP keys 256 bits (max length) with MIC keys
#define RS_IV_LEN	       4
#define RS_EIV_LEN	       4
#define RS_HOST_T_ID	       100

#define RS_FW_FIRST_MGMT(task) ((rs_fw_mgmt_id_t)((task) << 10))

#define RS_MGMT_T(mgmt)	       ((rs_fw_task_id_t)((mgmt) >> 10))
#define RS_MGMT_I(mgmt)	       ((mgmt) & ((1 << 10) - 1))

#define RS_PHY_CFG_BUF_SIZE    16
#define RS_BCN_MAX_CSA_CPT     2

#define RS_SCAN_SSID_MAX       2
#define RS_SCAN_CHANNEL_2G     14
#define RS_SCAN_CHANNEL_5G     28
#define RS_SCAN_CHANNEL_MAX    RS_SCAN_CHANNEL_2G
#define RS_SCAN_PASSIVE_BIT    BIT(0)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct rs_mac_addr {
	u16 addr[ETH_ALEN / 2];
};

struct rs_mac_ssid {
	u8 ssid_len;
	u8 ssid[MAC_SSID_LEN];
};

struct rs_mac_sec_key {
	u8 length;
	u32 array[RS_SEC_KEY_LEN / 4];
};

struct rx_seciv {
	u8 iv[RS_IV_LEN];
	u8 ext_iv[RS_EIV_LEN];
};

/// @brief  FW Configure Type
enum
{
	MM_T = 0,
	DBG_T,
	SCAN_T,
	TDLS_T,
	LAST_T = TDLS_T,
	API_T,
	MAX_T,
};

/// @brief FW Power-Save status
enum mgmt_ps_mode_state
{
	MGMT_PS_MODE_OFF,
	MGMT_PS_MODE_ON,
	MGMT_PS_MODE_ON_DYN,
};

enum mgmt_remain_on_channel_op
{
	MGMT_ROC_OP_START = 0,
	MGMT_ROC_OP_CANCEL,
};

typedef u16 rs_fw_mgmt_id_t;

typedef u16 rs_fw_task_id_t;

struct rs_fw_mgmt {
	rs_fw_mgmt_id_t id;
	rs_fw_task_id_t dest_id;
	rs_fw_task_id_t src_id;
	u16 param_len;
	u32 param[];
};

enum mgmt_mgmt_tag
{
	MGMT_RESET_ASK = RS_FW_FIRST_MGMT(MM_T),
	MGMT_RESET_CHK,
	MGMT_START_ASK,
	MGMT_START_CHK,
	MGMT_VERSION_ASK,
	MGMT_VERSION_CHK,
	MGMT_ADD_IF_ASK,
	MGMT_ADD_IF_CHK,
	MGMT_REMOVE_IF_ASK,
	MGMT_REMOVE_IF_CHK,
	MGMT_STA_ADD_ASK,
	MGMT_STA_ADD_CHK,
	MGMT_STA_DEL_ASK,
	MGMT_STA_DEL_CHK,
	MGMT_SET_FILTER_ASK,
	MGMT_SET_FILTER_CHK,
	MGMT_SET_CHANNEL_ASK,
	MGMT_SET_CHANNEL_CHK,
	MGMT_SET_DTIM_ASK,
	MGMT_SET_DTIM_CHK,
	MGMT_SET_BEACON_INT_ASK,
	MGMT_SET_BEACON_INT_CHK,
	MGMT_SET_BASIC_RATES_ASK,
	MGMT_SET_BASIC_RATES_CHK,
	MGMT_SET_BSSID_ASK,
	MGMT_SET_BSSID_CHK,
	MGMT_SET_EDCA_ASK,
	MGMT_SET_EDCA_CHK,
	MGMT_SET_MODE_ASK,
	MGMT_SET_MODE_CHK,
	MGMT_SET_VIF_STATE_ASK,
	MGMT_SET_VIF_STATE_CHK,
	MGMT_SET_SLOTTIME_ASK,
	MGMT_SET_SLOTTIME_CHK,
	MGMT_SET_IDLE_ASK,
	MGMT_SET_IDLE_CHK,
	MGMT_KEY_ADD_ASK,
	MGMT_KEY_ADD_CHK,
	MGMT_KEY_DEL_ASK,
	MGMT_KEY_DEL_CHK,
	MGMT_BA_ADD_ASK,
	MGMT_BA_ADD_CHK,
	MGMT_BA_DEL_ASK,
	MGMT_BA_DEL_CHK,
	MGMT_PRIMARY_TBTT_IND,
	MGMT_SECONDARY_TBTT_IND,
	MGMT_SET_POWER_ASK,
	MGMT_SET_POWER_CHK,
	MGMT_DBG_TRIGGER_ASK,
	MGMT_SET_PS_MODE_ASK,
	MGMT_SET_PS_MODE_CHK,
	MGMT_CHAN_CTXT_ADD_ASK,
	MGMT_CHAN_CTXT_ADD_CHK,
	MGMT_CHAN_CTXT_DEL_ASK,
	MGMT_CHAN_CTXT_DEL_CHK,
	MGMT_CHAN_CTXT_LINK_ASK,
	MGMT_CHAN_CTXT_LINK_CHK,
	MGMT_CHAN_CTXT_UNLINK_ASK,
	MGMT_CHAN_CTXT_UNLINK_CHK,
	MGMT_CHAN_CTXT_UPDATE_ASK,
	MGMT_CHAN_CTXT_UPDATE_CHK,
	MGMT_CHAN_CTXT_SCHED_ASK,
	MGMT_CHAN_CTXT_SCHED_CHK,
	MGMT_BCN_CHANGE_ASK,
	MGMT_BCN_CHANGE_CHK,
	MGMT_TIM_UPDATE_ASK,
	MGMT_TIM_UPDATE_CHK,
	MGMT_CONNECTION_LOSS_IND,
	MGMT_CHANNEL_SWITCH_IND,
	MGMT_CHANNEL_PRE_SWITCH_IND,
	MGMT_REMAIN_ON_CHANNEL_ASK,
	MGMT_REMAIN_ON_CHANNEL_CHK,
	MGMT_REMAIN_ON_CHANNEL_EXP_IND,
	MGMT_PS_CHANGE_IND,
	MGMT_TRAFFIC_ASK_IND,
	MGMT_SET_PS_OPTIONS_ASK,
	MGMT_SET_PS_OPTIONS_CHK,
	MGMT_P2P_VIF_PS_CHANGE_IND,
	MGMT_CSA_COUNTER_IND,
	MGMT_CHANNEL_SURVEY_IND,
	MGMT_BFMER_ENABLE_ASK,
	MGMT_SET_P2P_NOA_ASK,
	MGMT_SET_P2P_OPPS_ASK,
	MGMT_SET_P2P_NOA_CHK,
	MGMT_SET_P2P_OPPS_CHK,
	MGMT_P2P_NOA_UPD_IND,
	MGMT_CFG_RSSI_ASK,
	MGMT_RSSI_STATUS_IND,
	MGMT_CSA_FINISH_IND,
	MGMT_CSA_TRAFFIC_IND,
	MGMT_MU_GROUP_UPDATE_ASK,
	MGMT_MU_GROUP_UPDATE_CHK,
	MGMT_ANT_DIV_INIT_ASK,
	MGMT_ANT_DIV_STOP_ASK,
	MGMT_ANT_DIV_UPDATE_ASK,
	MGMT_SWITCH_ANTENNA_ASK,
	MGMT_MAX,
};

/// @brief Interface Type
enum
{
	IF_STA,
	IF_IBSS,
	IF_AP,
	IF_MESH_POINT,
	IF_MONITOR,
};

/// @brief Block-Ack Type
enum
{
	BA_AGMT_TX,
	BA_AGMT_RX,
};

/// @brief Block-Ack Agrement Status
enum
{
	BA_AGMT_ESTABLISHED,
	BA_AGMT_ALREADY_EXISTS,
	BA_AGMT_DELETED,
	BA_AGMT_DOESNT_EXIST,
};

/// @brief FW Features supported
enum mgmt_features
{
	MGMT_FEAT_BCN_BIT = 0,
	MGMT_FEAT_AUTOBCN_BIT,
	MGMT_FEAT_HWSCAN_BIT,
	MGMT_FEAT_CMON_BIT,
	MGMT_FEAT_MROLE_BIT,
	MGMT_FEAT_RADAR_BIT,
	MGMT_FEAT_PS_BIT,
	MGMT_FEAT_UAPSD_BIT,
	MGMT_FEAT_DPSM_BIT,
	MGMT_FEAT_AMPDU_BIT,
	MGMT_FEAT_AMSDU_BIT,
	MGMT_FEAT_CHNL_CTXT_BIT,
	MGMT_FEAT_REORD_BIT,
	MGMT_FEAT_P2P_BIT,
	MGMT_FEAT_P2P_GO_BIT,
	MGMT_FEAT_UMAC_BIT,
	MGMT_FEAT_VHT_BIT,
	MGMT_FEAT_BFMEE_BIT,
	MGMT_FEAT_BFMER_BIT,
	MGMT_FEAT_WAPI_BIT,
	MGMT_FEAT_MFP_BIT,
	MGMT_FEAT_MU_MIMO_RX_BIT,
	MGMT_FEAT_MU_MIMO_TX_BIT,
	MGMT_FEAT_MESH_BIT,
	MGMT_FEAT_TDLS_BIT,
	MGMT_FEAT_ANT_DIV_BIT,
	MGMT_FEAT_UF_BIT,
	MGMT_AMSDU_MAX_SIZE_BIT0,
	MGMT_AMSDU_MAX_SIZE_BIT1,
};

struct rs_phy_cfg_tag {
	u32 parameters[RS_PHY_CFG_BUF_SIZE];
};

struct rs_reset_req {
	u64 time;
	u32 bt_coex;
};

struct rs_dev_start_req {
	struct rs_phy_cfg_tag phy_cfg;
	u32 uapsd_timeout;
	u16 lp_clk_accuracy;
};

struct rs_set_channel_req {
	u8 band; // 2.4GHz or 5GHz
	u8 type; // 20,40,80,160 or 80+80 MHz
	u16 prim20_freq; // Primary 20MHz channel (in MHz)
	u16 center1_freq; // Contiguous channel or center of Primary 80+80
	u16 center2_freq; // Non-contiguous secondary 80+80
	u8 index;
	s8 tx_power; // Max tx power
};

struct rs_set_channel_chk {
	u8 radio_idx;
	s8 power;
};

struct rs_set_dtim_req {
	u8 dtim_period;
};

struct rs_set_power_req {
	u8 vif_id;
	s8 power;
};

struct rs_set_power_chk {
	u8 radio_idx;
	s8 power;
};

struct rs_set_beacon_int_req {
	u16 beacon_int;
	u8 vif_id;
};

struct rs_set_basic_rates_req {
	u32 basic_rates;
	u8 vif_id;
	u8 band;
};

struct rs_set_bssid_req {
	u8 bssid[ETH_ALEN];
	u8 vif_id;
};

struct rs_set_filter_req {
	u32 filter;
};

struct rs_add_if_req {
	u8 iftype;
	struct rs_mac_addr addr;
	bool p2p;
	bool uf;
};

struct rs_add_if_chk {
	u8 status;
	u8 vif_index;
};

struct rs_set_edca_req {
	u32 ac_param;
	bool uapsd;
	u8 hw_queue;
	u8 vif_index;
};

struct rs_set_idle_req {
	u8 hw_idle;
};

struct rs_set_slottime_req {
	u8 slottime;
};

struct rs_set_vif_state_req {
	u16 aid;
	bool active;
	u8 vif_id;
};

struct rs_remove_if_req {
	u8 vif_index;
};

struct rs_version_chk {
	u32 fw_version;
	u32 dev_features;
};

struct rs_sta_add_req {
	u32 ampdu_size_max_vht;
	u32 paid_gid;
	u16 ampdu_size_max_ht;
	struct rs_mac_addr mac_addr;
	u8 ampdu_spacing_min;
	u8 vif_index;
	bool tdls_sta;
};

struct rs_sta_add_chk {
	u8 status;
	u8 sta_id;
	u8 hw_sta_id;
};

struct rs_sta_del_req {
	u8 sta_id;
};

// struct rs_sta_del_chk {
// 	u8 status;
// };

// struct mgmt_setpowermode_req {
// 	u8 mode;
// 	u8 sta_id;
// };

// struct mgmt_setpowermode_chk {
// 	u8 status;
// };

struct rs_key_add_req {
	u8 key_idx;
	u8 sta_id;
	struct rs_mac_sec_key key;
	u8 cipher_suite;
	u8 vif_id;
	u8 spp;
	bool pairwise;
};

struct rs_key_add_chk {
	u8 status;
	u8 hw_key_idx;
};

struct rs_key_del_req {
	u8 hw_key_idx;
};

struct rs_ba_add_req {
	u8 type;
	u8 sta_id;
	u8 tid;
	u8 bufsz;
	u16 ssn;
};

struct rs_ba_add_chk {
	u8 sta_id;
	u8 tid;
	u8 status;
};

struct rs_ba_del_req {
	u8 type;
	u8 sta_id;
	u8 tid;
};

struct rs_ba_del_chk {
	u8 sta_id;
	u8 tid;
	u8 status;
};

struct rs_chan_ctxt_add_req {
	u8 band;
	u8 type;
	u16 prim20_freq;
	u16 center1_freq;
	u16 center2_freq;
	s8 tx_power;
};

struct rs_chan_ctxt_add_chk {
	u8 status;
	u8 index;
};

struct rs_chan_ctxt_del_req {
	u8 index;
};

struct rs_chan_ctxt_link_req {
	u8 vif_index;
	u8 chan_index;
	u8 chan_switch;
};

struct rs_chan_ctxt_unlink_req {
	u8 vif_index;
};

struct rs_chan_ctxt_update_req {
	u8 chan_index;
	u8 band;
	u8 type;
	u16 prim20_freq;
	u16 center1_freq;
	u16 center2_freq;
	s8 tx_power;
};

struct rs_chan_ctxt_sched_req {
	u8 vif_index;
	u8 chan_index;
	u8 type;
};

struct rs_channel_switch_int {
	u8 chan_index;
	bool roc;
	u8 vif_index;
	bool roc_tdls;
};

struct rs_channel_pre_switch_int {
	u8 chan_index;
};

struct mgmt_connection_loss_ind {
	u8 vif_id;
};

struct rs_dbg_trigger_req {
	char error[64];
};

struct rs_set_ps_mode_req {
	u8 new_state;
};

struct rs_bcn_change_req {
	u8 bcn_ptr[512];
	u16 bcn_len;
	u16 tim_oft;
	u8 tim_len;
	u8 vif_id;
	u8 csa_oft[RS_BCN_MAX_CSA_CPT];
};

struct rs_tim_update_req {
	u16 aid;
	u8 tx_avail;
	u8 vif_id;
};

struct rs_remain_on_channel_req {
	u8 op_code;
	u8 vif_index;
	u8 band;
	u8 type;
	u16 prim20_freq;
	u16 center1_freq;
	u16 center2_freq;
	u32 duration_ms;
	s8 tx_power;
};

struct rs_remain_on_channel_chk {
	u8 op_code;
	u8 status;
	u8 chan_ctxt_index;
};

struct rs_remain_on_channel_exp_int {
	u8 vif_index;
	u8 chan_ctxt_index;
};

struct rs_set_uapsd_tmr_req {
	u8 action;
	u32 timeout;
};

struct rs_set_uapsd_tmr_chk {
	u8 status;
};

struct rs_ps_change_int {
	u8 sta_id;
	u8 ps_state;
};

struct rs_p2p_vif_ps_change_int {
	u8 vif_index;
	u8 ps_state;
};

struct rs_traffic_req_int {
	u8 sta_id;
	u8 pkt_cnt;
	bool uapsd;
};

struct rs_set_ps_options_req {
	u8 vif_index;
	u16 listen_interval;
	bool dont_listen_bc_mc;
};

struct rs_csa_counter_int {
	u8 vif_index;
	u8 csa_count;
};

struct rs_channel_survey_int {
	u16 freq;
	s8 noise_dbm;
	u32 chan_time_ms;
	u32 chan_time_busy_ms;
};

struct rs_set_p2p_noa_req {
	u8 vif_index;
	u8 noa_inst_nb;
	u8 count;
	bool dyn_noa;
	u32 duration_us;
	u32 interval_us;
	u32 start_offset;
};

struct rs_set_p2p_opps_req {
	u8 vif_index;
	u8 ctwindow;
};

struct rs_set_p2p_noa_chk {
	u8 status;
};

struct rs_set_p2p_opps_chk {
	u8 status;
};

struct rs_p2p_noa_upd_int {
	u8 vif_index;
	u8 noa_inst_nb;
	u8 noa_type;
	u8 count;
	u32 duration_us;
	u32 interval_us;
	u32 start_time;
};

struct rs_cfg_rssi_req {
	u8 vif_index;
	s8 rssi_thold;
	u8 rssi_hyst;
};

struct rs_rssi_status_int {
	u8 vif_index;
	bool rssi_status;
};

struct rs_csa_finish_int {
	u8 vif_index;
	u8 status;
	u8 chan_idx;
};

struct rs_csa_traffic_int {
	u8 vif_index;
	bool enable;
};

struct rs_mu_group_update_req {
	u8 sta_id;
	u8 group_cnt;
	struct {
		u8 group_id;
		u8 user_pos;
	} groups[0];
};

enum scan_mgmt_type
{
	SCAN_START_ASK = RS_FW_FIRST_MGMT(SCAN_T),
	SCAN_START_CHK,
	SCAN_DONE_IND,
	SCAN_CANCEL_ASK,
	SCAN_CANCEL_CHK,
	SCAN_MAX,
};

struct rs_scan_chan_t {
	u16 center_freq;
	u8 band;
	u8 flags;
	s8 max_reg_power;
};

struct rs_scan_start_req {
	struct rs_scan_chan_t chan[RS_SCAN_CHANNEL_MAX];
	struct rs_mac_ssid ssids[RS_SCAN_SSID_MAX];
	u8 bssid[ETH_ALEN];
	u32 ie_addr;
	u8 ie[256];
	u16 ie_len;
	u8 vif_id;
	u8 n_channels;
	u8 n_ssids;
	bool no_cck;
};

struct rs_scan_start_chk {
	u8 status;
};

struct rs_scan_cancel_req {};

struct rs_scan_cancel_chk {
	u8 status;
};

enum dbg_mgmt_type
{
	DBG_MEM_READ_ASK = RS_FW_FIRST_MGMT(DBG_T),
	DBG_MEM_READ_CHK,
	DBG_MEM_WRITE_ASK,
	DBG_MEM_WRITE_CHK,
	DBG_SET_FILTER_MODE_ASK,
	DBG_SET_FILTER_MODE_CHK,
	DBG_SET_FILTER_LEVEL_ASK,
	DBG_SET_FILTER_LEVEL_CHK,
	DBG_SET_OUT_DIR_ASK,
	DBG_SET_OUT_DIR_CHK,
	DBG_ERROR_IND,
	DBG_GET_SYS_STAT_ASK,
	DBG_GET_SYS_STAT_CHK,
	DBG_RF_TX_ASK,
	DBG_RF_TX_CHK,
	DBG_RF_CW_ASK,
	DBG_RF_CW_CHK,
	DBG_RF_CONT_ASK,
	DBG_RF_CONT_CHK,
	DBG_RF_CH_ASK,
	DBG_RF_CH_CHK,
	DBG_RF_PER_ASK,
	DBG_RF_PER_CHK,
	DBG_MAX,
};

struct rs_dbg_mem_read_ask {
	u32 mem_addr;
};

struct rs_dbg_mem_read_chk {
	u32 mem_addr;
	u32 mem_data;
};

/// Structure containing the parameters of the @ref DBG_MEM_WRITE_ASK message.
struct rs_dbg_mem_write_ask {
	u32 mem_addr;
	u32 mem_data;
};

/// Structure containing the parameters of the @ref DBG_MEM_WRITE_CHK message.
struct rs_dbg_mem_write_chk {
	u32 mem_addr;
	u32 mem_data;
};

struct rs_dbg_filter_mode_set {
	u32 filter_mode;
};

struct rs_dbg_lvl_filter_set {
	u32 filter_level;
};

struct rs_dbg_set_dir_out {
	u32 dir_out;
};

struct rs_dbg_get_sys_stat_chk {
	u32 cpu_sleep_time;
	u32 doze_time;
	u32 stats_time;
};

struct rs_dbg_rf_tx_req {
	u64 bssid;
	u64 destAddr;
	u16 frequency;
	u16 numFrames;
	u16 frameLen;
	u8 start;
	u8 txRate;
	u8 txPower;
	u8 GI;
	u8 greenField;
	u8 preambleType;
	u8 qosEnable;
	u8 ackPolicy;
	u8 aifsnVal;
};
struct rs_dbg_rf_cw_req {
	u8 start;
	u8 txPower;
	u16 frequency;
};

struct rs_dbg_rf_cont_req {
	u16 frequency;
	u8 start;
	u8 txRate;
	u8 txPower;
};

struct rs_dbg_rf_ch_req {
	u16 freqency;
};

struct rs_dbg_rf_per_req {
	u8 start;
};

struct rs_dbg_rf_per_chk {
	u32 pass;
	u32 fcs;
	u32 phy;
	u32 overflow;
};

enum tdls_mgmt_tag
{
	TDLS_CHAN_SWITCH_ASK = RS_FW_FIRST_MGMT(TDLS_T),
	TDLS_CHAN_SWITCH_CHK,
	TDLS_CHAN_SWITCH_IND,
	TDLS_CHAN_SWITCH_BASE_IND,
	TDLS_CANCEL_CHAN_SWITCH_ASK,
	TDLS_CANCEL_CHAN_SWITCH_CHK,
	TDLS_PEER_PS_IND,
	TDLS_PEER_TRAFFIC_IND_ASK,
	TDLS_PEER_TRAFFIC_IND_CHK,
	TDLS_MAX
};

struct rs_tdls_chan_switch_req {
	u8 vif_index;
	u8 sta_id;
	struct rs_mac_addr peer_mac_addr;
	bool initiator;
	u8 band;
	u8 type;
	u16 prim20_freq;
	u16 center1_freq;
	u16 center2_freq;
	s8 tx_power;
	u8 op_class;
};

struct rs_tdls_cancel_chan_switch_req {
	u8 vif_index;
	u8 sta_id;
	struct rs_mac_addr peer_mac_addr;
};

struct rs_tdls_chan_switch_chk {
	u8 status;
};

struct rs_tdls_cancel_chan_switch_chk {
	u8 status;
};

struct rs_tdls_chan_switch_int {
	u8 vif_index;
	u8 chan_ctxt_index;
	u8 status;
};

struct rs_tdls_chan_switch_base_int {
	u8 vif_index;
	u8 chan_ctxt_index;
};

struct rs_tdls_peer_ps_int {
	u8 vif_index;
	u8 sta_id;
	struct rs_mac_addr peer_mac_addr;
	bool ps_on;
};

struct rs_tdls_peer_traffic_ind_req {
	u8 vif_index;
	u8 sta_id;
	struct rs_mac_addr peer_mac_addr;
	u8 dialog_token;
	u8 last_tid;
	u16 last_sn;
};

struct rs_tdls_peer_traffic_ind_chk {
	u8 status;
};

#endif // RS_FW_MGMT_H
