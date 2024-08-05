// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_MGMT_RX_H
#define RS_MGMT_RX_H

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

void rs_rx_handle_msg(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *msg);
s32 rs_rx_handle_callbck(struct rs_hw_priv *rs_hw, struct rs_e2a_mgmt *msg);

#endif /* RS_MGMT_RX_H */
