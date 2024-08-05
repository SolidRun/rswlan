// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_DEFS_H
#define RS_DEFS_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <net/mac80211.h>

#include "rs_core.h"
#include "rs_debugfs.h"
#include "rs_fw_mgmt.h"
#include "rs_hal.h"
#include "rs_params.h"
#include "rs_utils.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define WPI_HDR_LEN	   18
#define WPI_PN_LEN	   16
#define WPI_PN_OFST	   2
#define WPI_MIC_LEN	   16
#define WPI_KEY_LEN	   32
#define WPI_SUBKEY_LEN	   16

#define VIF_TYPE(vif_priv) (vif_priv->vif->type)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct rs_e2a_mgmt {
	u16 id;
	u16 dummy_dest_id;
	u16 dummy_src_id;
	u16 param_len;
	u32 param[15];
	u32 pattern;
};

struct rs_chanctx {
	struct list_head list;
	struct list_head vifs;
	struct ieee80211_chanctx_conf *ctx;
	u8 index;
	bool active;
};

struct rs_tdls {
	bool active;
	bool chsw_en;
	bool ps_on;
};

//-- ieee80211_vif's drv_priv
struct rs_vif_priv {
	struct list_head list;
	struct list_head list_chan_ctxt;
	struct list_head stations;
	struct ieee80211_vif *vif;
	struct rs_chanctx *chanctx;
	u8 vif_index;
	u8 bcn_on;
	s8 txpower;
	u8 txpower_idx;
	bool roc_tdls;
};

struct rs_agg {
	bool on;
	u16 ssn;
	u16 sn;
	u8 len;
	u8 ack;
	struct ieee80211_tx_rate rate;
};

struct rs_sta_priv {
	struct list_head list;
	u8 id;
	u8 hw_sta_id;
	u8 vif_id;
	u8 stbc_nss;
	u16 gid;
	u16 paid;
	bool sleep;
	struct rs_tdls tdls;
	struct rs_agg aggs[IEEE80211_NUM_TIDS];
};

struct rs_sec_phy_chan {
	u16 prim20_freq;
	u16 center_freq1;
	u16 center_freq2;
	enum nl80211_band band;
	u8 type;
};

struct rs_wpi_key {
	struct hlist_node list;
	struct ieee80211_key_conf *conf;
	u8 pn[16];
};

struct rs_survey_info_priv {
	u32 filled;
	u32 chan_time_ms;
	u32 chan_time_busy_ms;
	s8 noise_dbm;
};

struct rs_tdls_info {
	u8 n_sta;
	bool chsw_en;
	u8 next_ps_mode;
};

struct rs_mgmt_return {
	struct rs_version_chk version_chk;
	struct rs_add_if_chk add_if_chk;
	struct rs_set_channel_chk set_chan_chk;
	struct rs_key_add_chk key_add_chk;
	struct rs_set_power_chk set_power_chk;
#ifdef CONFIG_RS_P2P_DEBUGFS
	struct rs_set_p2p_opps_chk set_p2p_opps_chk;
	struct rs_set_p2p_noa_chk set_p2p_noa_chk;
#endif
	struct rs_sta_add_chk sta_add_chk;
	struct rs_chan_ctxt_add_chk add_chanctx_chk;
	struct rs_ba_add_chk ba_add_chk;
	struct rs_ba_del_chk ba_del_chk;
	struct rs_scan_start_chk scan_start_chk;
	struct rs_scan_cancel_chk scan_cancel_chk;
	struct rs_tdls_chan_switch_chk tdls_chan_switch_chk;
	struct rs_dbg_mem_read_chk mem_read_chk;
	struct rs_dbg_get_sys_stat_chk get_sys_stat_chk;
	struct rs_dbg_rf_per_chk rf_per_chk;
};

struct rs_hw_priv {
	struct device *dev;
	struct ieee80211_hw *hw;
	struct ieee80211_vif *_vifs[4];
	struct list_head vifs;
	struct list_head chan_ctxts;
	enum nl80211_band cur_band;
	u16 cur_freq;

	unsigned long drv_flags;
	struct rs_core *core;

	spinlock_t tx_lock;
	spinlock_t rx_lock;
	spinlock_t cb_lock;

	struct rs_dbgfs_t debugfs;
	struct rs_sec_phy_chan sec_phy_chan;
	u8 phy_cnt;
	u8 stbc_nss;
	u32 perf_ctrl_value;
	u32 antset_value;
	u8 chan_ctxt_req;
	struct rs_phy_cfg_tag phy_config;

	struct hlist_head wpi_keys;

	bool sw_scanning;
	u8 scan_txpower_idx;
	bool hw_scanning;

	struct rs_survey_info_priv survey[RS_SCAN_CHANNEL_MAX];

	struct rs_tdls_info tdls_info;

	bool ps_on;

	s32 dbglvl;
	struct rs_file *fw_dbgfile;
	s32 fw_dbgoutdir;
	u8 fw_dbg_idx;
	bool run_deinit;

	s32 sta_cnt;
	struct workqueue_struct *wq;
	struct {
		struct work_struct wk; /* Work-Queue Thread for Tx */
		struct bus_q *busq; /* Tx Hw AC Queues status */
		u8 *b2k; /* Allocated 2KB sized memory pointer1 for Bus xmit */
		u8 *b4; /* Allocated 4B sized memory pointer2 for Bus xmit */
		u16 seq; /* Number of tx packet sequence for Bus xmit */
		u32 balance[RS_TXQ_CNT];
		u32 total_balance;
		u32 bus_tolerence;
		u32 bus_q_full_cnt;
		struct {
#define TX_SKB_LIST_MAX 64
			struct sk_buff_head list; /* mac80211 Upper layer sk_buff data buffer */
			/* backup data */
			struct mutex data_lock;
#define TX_KICK_DATA_MAX 256
			void *data[TX_KICK_DATA_MAX]; /* Tx backup data(pointer of sk_buff) */
			u32 i; /* Index of Tx backup data */
			/* statistics */
			u32 stops;
			u32 nb_kick; /* Number of kick try */
			u32 nb_retry; /* Number of kick retry */
			u32 nb_drop; /* Number of drop */
		} q[RS_TXQ_CNT];
		enum
		{
			TX_Q_STATUS_NONE = 0,
			TX_Q_STATUS_SCAN = BIT(0),
			TX_Q_STATUS_CHAN = BIT(1),
			TX_Q_STATUS_PS = BIT(2),
		} status;
		struct {
#define TX_KICKBACK_DATA_MAX 256
			s32 kb_idx; /*  Kickback Q Index of BUS */
			/* buffer */
			u8 *b2k; /* Allocated 2KB sized buffer for Bus xmit */
			u8 *b4; /* Allocated 4B sized buffer for Bus xmit */
			/* statistics */
			u32 nb_kick[RS_TXQ_CNT]; /* Number of kickBack */
			u32 nb_res_sta_ps[RS_TXQ_CNT]; /* Number of KB reson 2 */
			u32 nb_res_5[RS_TXQ_CNT]; /* Number of KB reson 5 */
			u32 nb_err_status[RS_TXQ_CNT]; /* Number of KB error status 0 */
			u32 nb_err_data[RS_TXQ_CNT]; /* Number of KB error data NULL */
			u32 nb_err_fmt; /* Number of KB error wrong format */
			u32 nb_err_proc; /* Number of KB error process error */
		} back;
		struct {
			u32 nb_total_cnt;
			u32 nb_total_ack;
			u32 nb_total_retry;
		} ampdu;
		bool deinit;
	} tx;

	struct {
		u8 *b4; /* Allocated 4B sized memory pointer2 for Bus xmit */
		u16 rx_idx; /* Rx BUS queue index */
		/* statistics */
		u32 nb_kick;
		u32 nb_err_bus;
		u32 nb_err_len;
		u32 nb_err_fmt;
		bool deinit;
	} rx;

	u8 msg_rx_idx;

	struct {
		struct work_struct wk;
		struct work_struct wk_rx;
		struct work_struct wk_tx_kb;
		struct work_struct wk_misc;
	} irq;

	struct rs_mgmt_return mgmt_return;

	bool mgmt_chk_completed;
	bool ch_switch_stop_tx;

	s32 (*check_hw_queue_status)(struct rs_hw_priv *hw_priv, u8 q_num);
	s32 (*determine_event_timeout)(struct rs_hw_priv *hw_priv);

	s32 (*msg_rx_handle_callback)(struct rs_hw_priv *, struct rs_e2a_mgmt *);
};

enum RS_DBGLVL
{
	RS_DBGLVL_LOG = 0x00000001,
	RS_DBGLVL_DUMP = 0x00000002,
};

#endif /* RS_DEFS_H */
