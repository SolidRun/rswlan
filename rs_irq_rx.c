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

#include "rs_irq_rx.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#ifdef ENABLE_IRQ_THREAD
#define ENABLE_THREAD
#endif

#undef RX_DEBUG

#define RX_IDX()	(*(FW_IO_RX_IDX()))
#define RS_RX_INFO_SIZE (sizeof(struct rs_rx_info))
#define RX_PRE_HDR_SIZE (4)
#define RX_THRESHOLD	(FW_IO_RXBUF_CNT / 4)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

static s32 irq_rx_handler(struct rs_core *core)
{
	struct rs_hw_priv *hw_priv = NULL;
	s32 ret = -1;
	u16 length = 0;
	struct sk_buff *skb = NULL;
	u8 *rx_buf = NULL;
	u32 addr = 0;
	s32 rx_cnt = 0;
#ifdef RX_DEBUG
	s32 q_cnt = 0;
#endif

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

#ifdef RX_DEBUG
		q_cnt = RS_Q_CNT(hw_priv->rx.rx_idx, RX_IDX(), FW_IO_RXBUF_CNT);
#endif

		while (hw_priv->rx.rx_idx != RX_IDX()) {
			if ((core->irq_init_done == false) || (hw_priv->run_deinit == true)) {
				if (skb != NULL) {
					dev_kfree_skb_any(skb);
					skb = NULL;
				}
				ret = -1;
				break;
			}

			if (skb == NULL) {
				skb = dev_alloc_skb(FW_IO_RX_PACKET_SIZE);
			}
			if (skb != NULL) {
				rx_buf = skb->data;
			} else {
				ret = -1;
				break;
			}

			hw_priv->rx.nb_kick++;

			addr = core->bus.addr.rx + (hw_priv->rx.rx_idx * FW_IO_RX_PACKET_SIZE);

			if ((ret = core->bus.ops.read(core, addr, rx_buf, RX_PRE_HDR_SIZE)) != 0) {
				hw_priv->rx.nb_err_bus++;
				if (skb != NULL) {
					dev_kfree_skb_any(skb);
					skb = NULL;
				}
				break;
			}

			rx_cnt++;

			length = ((struct rs_rx_info *)rx_buf)->rx_info_a.rx_buf_size;

			if ((length > 0) && (length < (FW_IO_RX_PACKET_SIZE - RS_RX_INFO_SIZE))) {
				addr += RX_PRE_HDR_SIZE;
				rx_buf += RX_PRE_HDR_SIZE;
				length += (RS_RX_INFO_SIZE - RX_PRE_HDR_SIZE);
				if ((ret = core->bus.ops.read(core, addr, rx_buf, length)) == 0) {
					if ((ret = rs_rx_data_handler(hw_priv, skb)) != 0) {
						skb = NULL;
						break;
					}
					skb = NULL;
				} else {
					hw_priv->rx.nb_err_bus++;
					if (skb != NULL) {
						dev_kfree_skb_any(skb);
						skb = NULL;
					}
					break;
				}
			}

			hw_priv->rx.rx_idx = (hw_priv->rx.rx_idx + 1) % FW_IO_RXBUF_CNT;

			if ((rx_cnt % RX_THRESHOLD) == 0) {
				(void)core->bus.ops.irq_status(core, NULL);
			}
		}
#ifdef RX_DEBUG
		if (rx_cnt >= (FW_IO_RXBUF_CNT - 2)) {
			printk("P:%s:rx_cnt[%d]:q_cnt[%d]:hdr[%ld]:pdu[%d]\n", __func__, rx_cnt, q_cnt,
			       RS_RX_INFO_SIZE, length);
		}
#endif
	}

	return ret;
}

#ifdef ENABLE_THREAD
static void rx_thread(struct rs_core *core)
{
	u32 timeout = EVENT_WAIT_FOREVER;

	if (core != NULL) {
		do {
			rs_wait_event(&(core->rx_thread.event), timeout);

			if (core->rx_thread_init_done == true) {
				rs_reset_event(&(core->rx_thread.event));
				(void)irq_rx_handler(core);
			}
		} while (kthread_should_stop() == false);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		kthread_complete_and_exit(&(core->rx_thread.completion), 0);
#else
		complete_and_exit(&(core->rx_thread.completion), 0);
#endif
	}
}
#endif

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_rx_init(struct rs_core *core)
{
	s32 ret = 0;
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

#ifdef ENABLE_THREAD
		// rs_init_event(&(*core)->mgmt_thread.event);
		rs_init_event(&(core->rx_thread.event));
		ret = rs_create_kthread(core, &(core->rx_thread), rx_thread, "Rx-Thread");

		if (ret == 0) {
			core->rx_thread_init_done = true;
		} else {
			// ret = -ENOMEM;
		}
#else
		INIT_WORK(&(hw_priv->irq.wk_rx), rs_irq_rx_work);
#endif
	}

	return ret;
}

void rs_irq_rx_deinit(struct rs_core *core)
{
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

#ifdef ENABLE_THREAD
		rs_kill_thread(&(core->rx_thread));
		core->rx_thread_init_done = false;
#else
		flush_work(&(hw_priv->irq.wk_rx));
#endif
	}
}

void rs_irq_rx_work(struct work_struct *work)
{
	struct rs_hw_priv *hw_priv = NULL;

	if (work != NULL) {
		hw_priv = container_of(work, struct rs_hw_priv, irq.wk_rx);

		if ((hw_priv != NULL) && (hw_priv->core != NULL)) {
			(void)irq_rx_handler(hw_priv->core);
		}
	}
}

s32 rs_irq_rx_handler(struct rs_core *core)
{
	s32 ret = 0;
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		if ((core->irq_init_done == true) && (hw_priv->run_deinit == false)) {
			if (hw_priv->rx.rx_idx != RX_IDX()) {
#ifdef ENABLE_THREAD
				ret = irq_rx_handler(core);
				// rs_set_event(&(core->rx_thread.event));
#else
				ret = irq_rx_handler(core);
				// queue_work(hw_priv->wq, &(hw_priv->irq.wk_rx));
#endif
			}
		}
	}

	return ret;
}
