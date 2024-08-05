// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"
#include "rs_priv.h"
#include "rs_io_map.h"
#include "rs_irq.h"
#include "rs_irq_dbg.h"

#include "rs_irq_tx_kb.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#ifdef ENABLE_IRQ_THREAD
#define ENABLE_THREAD
#endif

#undef KB_DEBUG

#define KB_IDX()     (*(FW_IO_KB_IDX()))
#define KB_THRESHOLD (FW_IO_KB_CNT / 2)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

struct kickback_data {
	u16 ac;
	u16 index;
	u32 status;
};

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

static s32 irq_tx_kb(struct rs_hw_priv *hw_priv, struct kickback_data *kb_buf, s32 kb_cnt)
{
	s32 ret = 0;
	s32 i = 0;
	struct sk_buff *skb = NULL;
	u16 data_idx = 0;
	u16 kb_ac = 0;
	rs_txhdr_t *txhdr = NULL;

	for (i = 0; i < kb_cnt; i++) {
		kb_ac = kb_buf[i].ac;
		if (kb_ac > RS_TXQ_CNT) {
			pr_err("kickback: abnormal AC: %d \n", kb_ac);
			hw_priv->tx.back.nb_err_fmt++;
			continue;
		}

		hw_priv->tx.back.nb_kick[kb_ac]++;

		data_idx = kb_buf[i].index;
		if ((kb_buf[i].status == 0) || (data_idx >= TX_KICK_DATA_MAX)) {
			pr_warn("kickback:ac[%d]:status[%d]:idx[%d]\n", kb_ac, kb_buf[i].status, data_idx);
			hw_priv->tx.back.nb_err_status[kb_ac]++;
			continue;
		}

		rs_tx_q_data_lock(hw_priv, kb_ac);

		skb = (struct sk_buff *)(hw_priv->tx.q[kb_ac].data[data_idx]);
		hw_priv->tx.q[kb_ac].data[data_idx] = NULL;

		rs_tx_q_data_unlock(hw_priv, kb_ac);

		if (skb == NULL) {
			hw_priv->tx.back.nb_err_data[kb_ac]++;
		} else {
			txhdr = &exttxhdrs[*(u16 *)(&(skb->cb[46]))];
			txhdr->dev_hdr.status.value = kb_buf[i].status;

			if (rs_tx_kickback_handler(hw_priv, skb)) {
				hw_priv->tx.back.nb_err_proc++;
			}
		}
	}

	return ret;
}

static s32 irq_tx_kb_handler(struct rs_core *core)
{
	s32 ret = -1;
	struct rs_hw_priv *hw_priv = NULL;
	u8 *kb_buf = NULL;
	s16 kb_idx = 0;
	s16 kb_len = sizeof(struct kickback_data);
	s16 q_cnt = 0, q_l_cnt = 0, q_r_cnt = 0;
	u32 kb_l_len = 0, kb_r_len = 0;
	u32 addr = 0;
	s16 kb_cnt = 0;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		while (hw_priv->tx.back.kb_idx != KB_IDX()) {
			kb_idx = KB_IDX();

			q_l_cnt = RS_Q_L_CNT(hw_priv->tx.back.kb_idx, kb_idx);
			q_r_cnt = RS_Q_R_CNT(hw_priv->tx.back.kb_idx, kb_idx, FW_IO_KB_CNT);
			q_cnt = q_l_cnt + q_r_cnt;

			kb_buf = kzalloc((q_cnt * kb_len), GFP_KERNEL);
			if (kb_buf != NULL) {
				ret = 0;

				if (q_r_cnt > 0) {
					addr = core->bus.addr.kb_data + (hw_priv->tx.back.kb_idx * kb_len);
					kb_r_len = q_r_cnt * kb_len;

					if ((ret = core->bus.ops.read(core, addr, (u8 *)kb_buf, kb_r_len)) !=
					    0) {
						pr_err("Failed to read r_kb data\n");
					}
				}
				if ((ret == 0) && (q_l_cnt > 0)) {
					addr = core->bus.addr.kb_data;
					kb_l_len = q_l_cnt * kb_len;

					if ((ret = core->bus.ops.read(core, addr, (u8 *)(kb_buf) + kb_r_len,
								      kb_l_len)) != 0) {
						pr_err("Failed to read l_kb data\n");
					}
				}

				if (ret == 0) {
					ret = irq_tx_kb(hw_priv, (struct kickback_data *)kb_buf, q_cnt);
					kb_cnt += q_cnt;
				}
			}

			if (kb_buf != NULL) {
				kfree(kb_buf);
				kb_buf = NULL;
			}

			hw_priv->tx.back.kb_idx = kb_idx;
		}
	}

#ifdef KB_DEBUG
	if (kb_cnt >= (FW_IO_KB_CNT - 2)) {
		printk("P:%s:kb_cnt[%d]\n", __func__, kb_cnt);
	}
#endif

	return ret;
}

#ifdef ENABLE_THREAD
static void tx_kb_thread(struct rs_core *core)
{
	u32 timeout = EVENT_WAIT_FOREVER;

	if (core != NULL) {
		do {
			rs_wait_event(&(core->tx_kb_thread.event), timeout);

			if (core->tx_kb_thread_init_done == true) {
				rs_reset_event(&(core->tx_kb_thread.event));
				irq_tx_kb_handler(core);
			}
		} while (kthread_should_stop() == false);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		kthread_complete_and_exit(&(core->tx_kb_thread.completion), 0);
#else
		complete_and_exit(&(core->tx_kb_thread.completion), 0);
#endif
	}
}
#endif
////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_tx_kb_init(struct rs_core *core)
{
	s32 ret = 0;
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

#ifdef ENABLE_THREAD
		// rs_init_event(&(*core)->mgmt_thread.event);
		rs_init_event(&(core->tx_kb_thread.event));
		ret = rs_create_kthread(core, &(core->tx_kb_thread), tx_kb_thread, "Tx_KB-Thread");

		if (ret == 0) {
			core->tx_kb_thread_init_done = true;
		} else {
			// ret = -ENOMEM;
		}
#else
		INIT_WORK(&(hw_priv->irq.wk_tx_kb), rs_irq_tx_kb_work);
#endif
	}

	return ret;
}

void rs_irq_tx_kb_deinit(struct rs_core *core)
{
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

#ifdef ENABLE_THREAD
		rs_kill_thread(&core->tx_kb_thread);
		core->tx_kb_thread_init_done = false;
#else
		flush_work(&(hw_priv->irq.wk_tx_kb));
#endif
	}
}

void rs_irq_tx_kb_work(struct work_struct *work)
{
	struct rs_hw_priv *hw_priv = NULL;

	if (work != NULL) {
		hw_priv = container_of(work, struct rs_hw_priv, irq.wk_tx_kb);

		if ((hw_priv != NULL) && (hw_priv->core != NULL)) {
			(void)irq_tx_kb_handler(hw_priv->core);
		}
	}
}

s32 rs_irq_tx_kb_handler(struct rs_core *core)
{
	s32 ret = 0;
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		if ((core->irq_init_done == true) && (hw_priv->run_deinit == false)) {
			if (hw_priv->tx.back.kb_idx != KB_IDX()) {
				// printk("P:%s:kb_idx:h[%d]:fw[%d]\n", __func__, hw_priv->tx.back.kb_idx, KB_IDX());
#ifdef ENABLE_THREAD
				rs_set_event(&(core->tx_kb_thread.event));
#else
				queue_work(hw_priv->wq, &(hw_priv->irq.wk_tx_kb));
#endif
			}
		}
	}

	return ret;
}
