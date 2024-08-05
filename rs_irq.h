// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_IRQ_H
#define RS_IRQ_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/interrupt.h>
#include "rs_core.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

// #define RS_Q_CNT(spos, epos, max)   ((spos) <= (epos) ? (epos) - (spos) : ((epos) + ((max)-spos)))

// 0 1(spos) 2 3 4 5(epos) 6 7 8 9 , max(10)
// L_CNT = 0 , R_CNT = 4

// 0 1(epos) 2 3 4 5(spos) 6 7 8 9 , max(10)
// L_CNT = 1 , R_CNT = 5

#define RS_Q_L_CNT(spos, epos)	    ((spos) <= (epos) ? 0 : (epos))
#define RS_Q_R_CNT(spos, epos, max) ((spos) <= (epos) ? (epos) - (spos) : (max) - (spos))
#define RS_Q_CNT(spos, epos, max)   (RS_Q_L_CNT(spos, epos) + RS_Q_R_CNT(spos, epos, max))

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_handler_init(struct rs_core *core);
void rs_irq_handler_deinit(struct rs_core *core);

s32 rs_isr_main(struct rs_core *core);
irqreturn_t rs_irq_handler(s32 irq, void *dev_id);

s32 rs_irq_bus_ops_status(struct rs_core *core, u32 *value);

#endif /* RS_IRQ_H */
