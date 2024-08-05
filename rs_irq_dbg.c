// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/time.h>
#include "rs_defs.h"
#include "rs_priv.h"
#include "rs_file.h"

#include "rs_irq_dbg.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define RS_WIFI_NAME  "rsmac"
#define CURRENT_PATH  "./"
#define DBG_FILE_LEN  (28) // rsmac(4)_20230727(8)_103910(6) + _(3) + .log(4)
#define DBG_FILE_MODE (0644)

#define DBG_IDX()     (*(FW_IO_DBG_IDX()))

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

static u8 *get_dbg_fname(void)
{
	struct timespec64 now = { 0 };
	struct tm tm_now = { 0 };
	u8 *fname = NULL;

	fname = kzalloc(DBG_FILE_LEN, GFP_KERNEL);
	if (fname != NULL) {
		ktime_get_real_ts64(&now);
		time64_to_tm(now.tv_sec, 0, &tm_now);

		sprintf(fname, "%s%s_%04ld%02d%02d_%02d%02d%02d.log", CURRENT_PATH, RS_WIFI_NAME,
			tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday, tm_now.tm_hour,
			tm_now.tm_min, tm_now.tm_sec);

		RS_DBG(fname);
		// printk("%s:fname[%s]\n", __func__, fname);
	}

	return fname;
}

static s32 rs_irq_dbg_init(struct rs_hw_priv *priv)
{
	s32 ret = -1;
	u8 *fname = NULL;

	if (priv != NULL) {
		if (priv->fw_dbgoutdir == 3) { // file
			if (priv->fw_dbgfile == NULL) {
				priv->fw_dbgfile = kzalloc(sizeof(struct rs_file), GFP_KERNEL);
				if (priv->fw_dbgfile != NULL) {
					fname = get_dbg_fname();
					if (fname != NULL) {
						ret = rs_f_open(priv->fw_dbgfile, fname, O_CREAT | O_WRONLY,
								DBG_FILE_MODE);

						kfree(fname);
					}
				}
			}
		}
	}

	return ret;
}

static s32 rs_irq_dbg_deinit(struct rs_hw_priv *priv)
{
	s32 ret = -1;

	if ((priv != NULL) && (priv->fw_dbgfile != NULL)) {
		ret = rs_f_close(priv->fw_dbgfile);
		if (ret == 0) {
			kfree(priv->fw_dbgfile);
			priv->fw_dbgfile = NULL;
		}
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_irq_dbg_set(struct rs_hw_priv *priv, s32 fw_dbgoutdir)
{
	s32 ret = -1;
	s32 old_dbgoutdir = 0;

	if (priv != NULL) {
		old_dbgoutdir = priv->fw_dbgoutdir;
		priv->fw_dbgoutdir = fw_dbgoutdir;

		if (priv->fw_dbgoutdir == 3) {
			if (old_dbgoutdir != 3) {
				rs_irq_dbg_init(priv);
			}
		} else {
			if (old_dbgoutdir == 3) {
				ret = rs_irq_dbg_deinit(priv);
			}
		}
	}

	return ret;
}

s32 rs_irq_dbg_handler(struct rs_core *core)
{
	s32 ret = -1;
	struct rs_hw_priv *hw_priv = NULL;
	struct rs_fwdbg_data_t *dbg_msg = NULL;

	if ((core != NULL) && (core->priv != NULL)) {
		hw_priv = core->priv;

		if ((hw_priv->core->irq_init_done == true) && (hw_priv->run_deinit == false)) {
			if (hw_priv->fw_dbg_idx != DBG_IDX()) {
				dbg_msg = kzalloc(sizeof(struct rs_fwdbg_data_t), GFP_KERNEL);
				if (dbg_msg != NULL) {
					/* Read Debug Message */
					ret = core->bus.ops.read(core, core->bus.addr.dbg_msg, (u8 *)dbg_msg,
								 sizeof(struct rs_fwdbg_data_t));
				}

				if (ret == 0) {
					if (dbg_msg->magic == 0x000CACA0) {
						if (hw_priv->fw_dbgoutdir == 2) { // kmsg
							pr_info(RS_WIFI_NAME ": %s",
								(char *)(dbg_msg->data));
						} else if (hw_priv->fw_dbgoutdir == 3) { // file
							(void)rs_f_write(
								hw_priv->fw_dbgfile,
								(const u8 *)(dbg_msg->data),
								(s32)strlen((const char *)(dbg_msg->data)));
						}
					}
				}

				if (dbg_msg != NULL) {
					kfree(dbg_msg);
				}

				hw_priv->fw_dbg_idx = DBG_IDX();
			}
		}
	}

	return ret;
}