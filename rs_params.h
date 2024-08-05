// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_PARAMS_H
#define RS_PARAMS_H

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct rs_hw_priv;
struct wiphy;

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_handle_dynparams(struct rs_hw_priv *rs_hw, struct wiphy *wiphy);
void rs_enable_wapi(struct rs_hw_priv *rs_hw);
void rs_enable_mfp(struct rs_hw_priv *rs_hw);
bool rs_get_mesh(void);
u32 rs_get_bt_coex(void);
bool rs_get_agg_tx(void);
bool rs_get_ps(void);
#if defined(CONFIG_RS_SPI)
bool rs_get_fw_sflash(void);
#endif

#endif /* RS_PARAMS_H */
