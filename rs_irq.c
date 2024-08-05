// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"
#include "rs_priv.h"
#include "rs_io_map.h"
#include "rs_irq_misc.h"
#include "rs_irq_rx.h"
#include "rs_irq_tx_kb.h"

#include "rs_irq.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

static u8 old_irq_status[FW_IO_IRQ_STATUS_SIZE] = { 0 };

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_bus_ops_status(struct rs_core *core, u32 *value)
{
	s32 ret = -1;

	if ((core != NULL) && (core->irq_init_done == true)) {
		if ((core->bus.ops.read(core, FW_IO_IRQ_STATUS, (u8 *)(core->bus.irq_value),
					FW_IO_IRQ_STATUS_SIZE)) != 0) {
			pr_err("Failed bus_read\n");
		} else {
			if (value != NULL) {
				if (*value == 1) {
					if (memcmp(old_irq_status, core->bus.irq_value,
						   FW_IO_IRQ_STATUS_SIZE) != 0) {
						(void)memcpy(old_irq_status, core->bus.irq_value,
							     FW_IO_IRQ_STATUS_SIZE);

						ret = 0;
					}
				}
			} else {
				ret = 0;
			}
		}
	}

	return ret;
}

s32 rs_irq_handler_init(struct rs_core *core)
{
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		if (core->bus.ops.irq_work != NULL) {
			INIT_WORK(&hw_priv->irq.wk, core->bus.ops.irq_work);
		}
		(void)rs_irq_rx_init(core);
		(void)rs_irq_tx_kb_init(core);
		(void)rs_irq_misc_init(core);

		core->irq_init_done = true;
	}

	return 0;
}

void rs_irq_handler_deinit(struct rs_core *core)
{
	struct rs_hw_priv *hw_priv = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		core->irq_init_done = false;

		if (core->bus.ops.irq_work) {
			flush_work(&(hw_priv->irq.wk));
		}

		rs_irq_rx_deinit(core);
		rs_irq_tx_kb_deinit(core);
		rs_irq_misc_deinit(core);
	}
}

s32 rs_isr_main(struct rs_core *core)
{
	s32 ret = 0;
	u32 value = 1;

	if (core != NULL) {
		while ((ret = core->bus.ops.irq_status(core, &value)) == 0) {
			(void)rs_irq_tx_kb_handler(core);
			(void)rs_irq_misc_handler(core);
			(void)rs_irq_rx_handler(core);
		}
	}

	return ret;
}

irqreturn_t rs_irq_handler(s32 irq, void *dev_id)
{
	struct rs_core *core = (struct rs_core *)dev_id;

	if ((core != NULL) && (core->priv != NULL) && (core->irq_init_done == true)) {
		if (irq > 0) {
			if (core->bus.ops.irq_work != NULL) {
				disable_irq_nosync(irq);
				queue_work(core->priv->wq, &core->priv->irq.wk);
			}
		} else {
			(void)rs_isr_main(core);
		}
	}

	return IRQ_HANDLED;
}
