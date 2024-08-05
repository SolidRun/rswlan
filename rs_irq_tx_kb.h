// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_IRQ_TX_KB_H
#define RS_IRQ_TX_KB_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_priv.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_tx_kb_init(struct rs_core *core);
void rs_irq_tx_kb_deinit(struct rs_core *core);

void rs_irq_tx_kb_work(struct work_struct *work);
s32 rs_irq_tx_kb_handler(struct rs_core *core);

#endif /* RS_IRQ_TX_KB_H */
