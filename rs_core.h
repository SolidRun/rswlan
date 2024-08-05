// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_CORE_H
#define RS_CORE_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/mmc/sdio_func.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spi/spi.h>
#include <linux/time.h>

#include "rs_io_map.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#undef ENABLE_IRQ_THREAD

#define RS_DEFAULT_MAC_PATH	 "default_mac.ini"
#define RS_MAC_FW_BASE_NAME_SDIO "lmacfw_sdio"
#define RS_MAC_FW_BASE_NAME_SPI	 "lmacfw_spi"

#define RS_MAC_FW_NAME_SDIO	 RS_MAC_FW_BASE_NAME_SDIO ".bin"
#define RS_MAC_FW_NAME_SPI	 RS_MAC_FW_BASE_NAME_SPI ".bin"

#define NUM_EDCA_QUEUES		 4
#define INTERNAL_MGMT_PKT	 0x99

#define ALIGN_4BYTE(len)	 ((4 - ((len) % 4)) % 4)
#define ALIGN_8BYTE(len)	 ((8 - ((len) % 8)) % 8)
#define PATTERN_SIZE		 4

// Write command id
#define HOST_WRITE_ASK		 (0x00)

// HW reset command id
#define HOST_RESET_ASK		 (0x10)

// MGMT command id
#define HOST_MGMT_MSG_ASK	 (0x20)

// TX command id
#define HOST_TX_ASK		 (0x40)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

/**
 * @brief: host request
 * @cmd: command id
 * @data: command data
 */
struct st_mgmt_req {
	uint8_t cmd;
	uint8_t data[3];
};

struct rs_hw_priv;

struct bus_addr {
	u32 hwq_len; // Modem Q length Address
	u32 msg_tx; // Command Request Address
	u32 msg_rx; // Command Response Address
	u32 kb_data; // KickBack Data Address
	u32 rx; // Rx Data Start Address
	u32 tx; // Tx Data Start Address
	u32 dbg_msg; // Debug Message Address
};

struct bus_q {
	char size; // Size of device q.
	char balance; // Number of packets that can be put into device q.
};

struct rs_event {
	atomic_t event_condition;
	wait_queue_head_t event_queue;
	wait_queue_head_t mgmt_chk_queue;
};

struct rs_thread {
	void (*thread_function)(void *);
	struct completion completion;
	struct task_struct *task;
	struct rs_event event;
};

struct wmm_qinfo {
	s32 weight;
	s32 wme_params;
	s32 pkt_contended;
	s32 txop;
};

struct skb_info {
	s8 rssi;
	u32 flags;
	u16 channel;
	s8 tid;
	s8 sta_id;
	u8 internal_hdr_size;
	struct ieee80211_vif *vif;
	u8 vap_id;
	bool have_key;
};

struct rs_core {
	struct rs_hw_priv *priv;

	// new tx msg
	struct rs_thread mgmt_thread;
	struct sk_buff_head mgmt_tx_queue;
	bool init_done;
	bool mgmt_q_block;

#ifdef ENABLE_IRQ_THREAD
	// rx thread
	struct rs_thread rx_thread;
	bool rx_thread_init_done;

	// tx kickbback thread
	struct rs_thread tx_kb_thread;
	bool tx_kb_thread_init_done;
#endif
	bool irq_init_done;

	bool enabled;

	/* CMD Message */
	struct workqueue_struct *wq_msg;
	struct work_struct wk_msg;

	struct {
		struct mutex lock; // Mutex lock for BUS R/W safe
		struct mutex mgmt_lock; // Mutext lock for MGMT TX safe
		union {
			struct sdio_func *sdio;
			struct spi_device *spi;
		};

		struct {
			s32 reset;
			s32 irq0;
			s32 irq0_nb; // IRQ Number of irq0 line
		} gpio;
		struct {
			s32 (*read)(struct rs_core *rs_core, u32 addr, u8 *data, u32 length);
			s32 (*write)(struct rs_core *rs_core, u32 addr, u8 *data, u32 length);
			void (*deinit)(struct rs_core *rs_core);
			s32 (*init_mac_addr)(struct rs_core *core, u8 *macaddr);
			s32 (*init_bus_addr)(struct rs_core *core);
#if defined(CONFIG_HOST_TX_MERGE) && defined(CONFIG_RS_SDIO)
			s32 (*tx_merge_data)(struct rs_hw_priv *priv, void *data, s32 ac);
			s32 (*tx_merge_kick)(struct rs_hw_priv *priv, s32 cnt, u16 start_tx_seq);
#endif
			s32 (*tx_kick)(struct rs_hw_priv *priv, void *data, s32 ac);
			s32 (*tx_rec)(struct rs_hw_priv *priv);
			s32 (*tx_trig)(struct rs_hw_priv *priv);
			s32 (*q_update)(struct rs_hw_priv *priv);
			s32 (*irq_status)(struct rs_core *core, u32 *value);
			void (*irq_work)(struct work_struct *work);
			s32 (*irq_kickback)(struct rs_core *core, bool irq);
			s32 (*mgmt_pkt_write)(struct rs_core *, u32, u8 *, u32);
		} ops;

		u8 irq_value[FW_IO_IRQ_STATUS_SIZE];

		struct st_mgmt_req host_req;

		struct bus_addr addr;
		struct bus_q q[RS_TXQ_CNT];
		bool mgmt_tx_stop;
	} bus;
};

enum rs_dbg_level
{
	RS_DBG_OFF = 0,
	RS_DBG_ERROR,
	RS_DBG_WARN,
	RS_DBG_INFO,
	RS_DBG_TRACE,
	RS_DBG_DEBUG,
	RS_DBG_VERBOSE,
};

extern u32 log_level;

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 core_init(struct rs_core *rs_core, void **platform_data);
void core_deinit(struct rs_hw_priv *hw_priv);

s32 rs_core_on(struct rs_hw_priv *hw_priv);

struct device *core_to_dev(struct rs_core *core);

void core_bus_lock(struct rs_core *core);
void core_bus_unlock(struct rs_core *core);
void core_mgmt_lock(struct rs_core *core);
void core_mgmt_unlock(struct rs_core *core);

#define BUS_LOCK(core_ptr)    core_bus_lock(core_ptr)
#define BUS_UNLOCK(core_ptr)  core_bus_unlock(core_ptr)
#define MGMT_LOCK(core_ptr)   core_mgmt_lock(core_ptr)
#define MGMT_UNLOCK(core_ptr) core_mgmt_unlock(core_ptr)

s32 core_bus_ops_init_mac_addr(struct rs_core *core, u8 *mac_addr);
s32 core_bus_ops_init_bus_addr(struct rs_core *core);

#endif /* RS_CORE_H */
