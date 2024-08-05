// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_UTILS_H
#define RS_UTILS_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/skbuff.h>

#include "rs_fw_mgmt.h"
#include "rs_core.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define RS_FN_ENTRY_STR	  ">>> %s()\n", __func__
#define LOG_LEVEL_MIN	  RS_DBG_OFF
#define LOG_LEVEL_MAX	  RS_DBG_VERBOSE
#define LOG_LEVEL_DEFAULT RS_DBG_WARN

#define set_host_log_level(level) do { \
	log_level = level; } while (0)

#define RS_DBG_LEVEL(level, format, arg...) do { \
	if (level <= log_level) { printk(format, ##arg); } } while (0)

#define RS_ERR(format, arg...)	 RS_DBG_LEVEL(RS_DBG_ERROR, format, ##arg)
#define RS_WARN(format, arg...)	 RS_DBG_LEVEL(RS_DBG_WARN, format, ##arg)
#define RS_INFO(format, arg...)	 RS_DBG_LEVEL(RS_DBG_INFO, format, ##arg)
#define RS_TRACE(format, arg...) RS_DBG_LEVEL(RS_DBG_TRACE, format, ##arg)
#define RS_DBG(format, arg...)	 RS_DBG_LEVEL(RS_DBG_DEBUG, format, ##arg)
#define RS_VERB(format, arg...)	 RS_DBG_LEVEL(RS_DBG_VERBOSE, format, ##arg)
#define RS_DUMP(priv, prefix_str, buf, len) do { \
	if (((priv)->dbglvl & RS_DBGLVL_DUMP)) { \
		print_hex_dump(KERN_INFO, pr_fmt(prefix_str), DUMP_PREFIX_OFFSET, \
			16, 1, buf, total_len, true); \
			printk(KERN_INFO "\n"); \
	} } while (0)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

enum rs_dev_flag
{
	RS_DEV_RESTARTING,
	RS_DEV_STACK_RESTARTING,
	RS_DEV_STARTED,
};

#endif /* RS_UTILS_H */
