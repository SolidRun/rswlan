// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_DEBUGFS_H
#define RS_DEBUGFS_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define RS_DBGFS_CTF(name, parent, mode) do { \
	if (!debugfs_create_file(#name, mode, \
		parent, hw_priv, &rs_dbgfs_##name##_ops)) \
			goto err; \
	} while (0)

#define RS_DBGFS_RD(name) \
	static ssize_t rs_dbgfs_##name##_read(struct file *file, \
		char __user *user_buf, size_t count, loff_t *ppos);

#define RS_DBGFS_WR(name) \
	static ssize_t rs_dbgfs_##name##_write(struct file *file, \
		const char __user *user_buf, size_t count, loff_t *ppos);

#define RS_DBGFS_OPS_RD(name) \
	RS_DBGFS_RD(name); \
	static const struct file_operations rs_dbgfs_##name##_ops = { \
		.read = rs_dbgfs_##name##_read, \
		.open = simple_open, \
		.llseek = generic_file_llseek, \
	};

#define RS_DBGFS_OPS_WR(name) \
	RS_DBGFS_WR(name); \
	static const struct file_operations rs_dbgfs_##name##_ops = { \
		.write = rs_dbgfs_##name##_write, \
		.open = simple_open, \
		.llseek = generic_file_llseek, \
	};

#define RS_DBGFS_OPS_RW(name) \
	RS_DBGFS_RD(name); \
	RS_DBGFS_WR(name); \
	static const struct file_operations rs_dbgfs_##name##_ops = { \
		.write = rs_dbgfs_##name##_write, \
		.read = rs_dbgfs_##name##_read, \
		.open = simple_open, \
		.llseek = generic_file_llseek, \
	};

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct rs_phy_ch_t {
	u32 info1;
	u32 info2;
};

struct rs_fwdbg_data_t {
	u32 data[64];
	u32 magic;
};

struct rs_hw_priv;
struct rs_sta_priv;

#ifdef CONFIG_RS_DEBUGFS
struct rs_dbgfs_t {
	struct dentry *dir;
	bool unregistering;
};
s32 rs_dbgfs_register(struct rs_hw_priv *hw_priv, const char *name);
void rs_dbgfs_unregister(struct rs_hw_priv *hw_priv);
#else /*!CONFIG_RS_DEBUGFS*/
struct rs_dbgfs_t {};
static inline s32 rs_dbgfs_register(struct rs_hw_priv *hw_priv, const char *name)
{
	return 0;
}
static inline void rs_dbgfs_unregister(struct rs_hw_priv *hw_priv)
{
}
#endif /* CONFIG_RS_DEBUGFS */
#endif /* RS_DEBUGFS_H */
