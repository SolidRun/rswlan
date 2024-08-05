// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"
#include "rs_priv.h"
#include "rs_io_map.h"
#include "rs_irq_dbg.h"

#include "rs_irq_misc.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define MGMT_RX_IDX() (*(FW_IO_MGMT_RX_IDX()))
#define DBG_IDX()     (*(FW_IO_DBG_IDX()))

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

static s32 rs_irq_mgmt_rx_handler(struct rs_core *core)
{
	s32 ret = -1;
	struct rs_hw_priv *hw_priv = NULL;
	struct rs_e2a_mgmt *msg = NULL;
	u32 addr = 0;
	u32 msg_len = sizeof(struct rs_e2a_mgmt);

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		if (hw_priv->msg_rx_idx != MGMT_RX_IDX()) {
			msg = kzalloc(msg_len, GFP_KERNEL);

			if (msg != NULL) {
				while (hw_priv->msg_rx_idx != MGMT_RX_IDX()) {
					if (hw_priv->core->irq_init_done == false) {
						break;
					}

					addr = core->bus.addr.msg_rx + (hw_priv->msg_rx_idx * msg_len);
					/* Read MSG Response data */
					ret = core->bus.ops.read(core, addr, (u8 *)msg, msg_len);

					if (ret == 0) {
						/* FW MSG_BUF Sync. */
						hw_priv->msg_rx_idx =
							(hw_priv->msg_rx_idx + 1) % FW_IO_MGMT_RX_CNT;
						rs_mgmt_rx_chk_handle(hw_priv, msg);
					} else {
						break;
					}
				}
			}

			if (msg != NULL) {
				kfree(msg);
			}
		}
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_misc_init(struct rs_core *core)
{
	s32 ret = -1;
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		INIT_WORK(&(hw_priv->irq.wk_misc), rs_irq_misc_work);

		ret = 0;
	}

	return ret;
}

void rs_irq_misc_deinit(struct rs_core *core)
{
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		flush_work(&(hw_priv->irq.wk_misc));
	}
}

void rs_irq_misc_work(struct work_struct *work)
{
	struct rs_hw_priv *hw_priv = NULL;

	if (work != NULL) {
		hw_priv = container_of(work, struct rs_hw_priv, irq.wk_misc);

		if ((hw_priv != NULL) && (hw_priv->core != NULL)) {
			rs_irq_mgmt_rx_handler(hw_priv->core);
			rs_irq_dbg_handler(hw_priv->core);
		}
	}
}

s32 rs_irq_misc_handler(struct rs_core *core)
{
	s32 ret = 0;
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		if (core->irq_init_done == true) {
			if ((hw_priv->msg_rx_idx != MGMT_RX_IDX()) || (hw_priv->fw_dbg_idx != DBG_IDX())) {
				queue_work(hw_priv->wq, &(hw_priv->irq.wk_misc));
			}
		}
	}

	return ret;
}
