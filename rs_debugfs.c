// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/sort.h>

#include "rs_debugfs.h"
#include "rs_mgmt_tx.h"
#include "rs_tx.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define RS_TX_PAYLOAD_MAX 6

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

static ssize_t rs_dbgfs_stats_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	struct rs_hw_priv *priv = file->private_data;
	char *buf;
	s32 ret;
	s32 i;
	ssize_t read;
	int max_ampdu_buf;
	s32 bufsz;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	max_ampdu_buf = IEEE80211_MAX_AMPDU_BUF;
#else
	max_ampdu_buf = IEEE80211_MAX_AMPDU_BUF_HT;
#endif

	bufsz = (10 + RS_TX_PAYLOAD_MAX + RS_TXQ_CNT + max_ampdu_buf) * 50;

	buf = kmalloc(bufsz, GFP_ATOMIC);
	if (buf == NULL)
		return 0;

	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "\nPHY Q Size   ");
	for (i = 0; i < RS_TXQ_CNT; i++)
		ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "  [%1d]:%3d", i,
				 priv->tx.busq[i].size);

	// priv->core->bus.ops.q_update(priv);

	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "\nPHY Q Balance");
	for (i = 0; i < RS_TXQ_CNT; i++)
		ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "  [%1d]:%3d", i,
				 priv->tx.busq[i].balance);

	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "\nTx Q Status  ");
	for (i = 0; i < RS_TXQ_CNT; i++)
		ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "  [%1d]:%3d", i,
				 !ieee80211_queue_stopped(priv->hw, i));
	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "   %x", priv->tx.status);

	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "\nTx Q Stops   ");
	for (i = 0; i < RS_TXQ_CNT; i++)
		ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "  [%1d]:%3d", i,
				 priv->tx.q[i].stops);

	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "\nTx Q Piledup ");
	for (i = 0; i < RS_TXQ_CNT; i++)
		ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "  [%1d]:%3d", i,
				 skb_queue_len(&priv->tx.q[i].list));

	ret += scnprintf(&buf[ret], min_t(size_t, bufsz - 1, count - ret), "\n");

	read = simple_read_from_buffer(user_buf, count, ppos, buf, ret);

	kfree(buf);

	return read;
}

static ssize_t rs_dbgfs_stats_write(struct file *file, const char __user *user_buf, size_t count,
				    loff_t *ppos)
{
	// struct rs_hw_priv *priv = file->private_data;

	return count;
}

RS_DBGFS_OPS_RW(stats);

static ssize_t rs_dbgfs_fw_dbg_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	char help[] = "usage: [MOD:<ALL|KE|DBG|IPC|DMA|MM|TX|RX|PHY>]* "
		      "[DBG:<NONE|CRT|ERR|WRN|INF|VRB>]\n";

	return simple_read_from_buffer(user_buf, count, ppos, help, sizeof(help));
}

static ssize_t rs_dbgfs_fw_dbg_write(struct file *file, const char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	struct rs_hw_priv *priv = file->private_data;
	char buf[32];
	s32 idx = 0;
	u32 mod = 0;
	size_t len = min_t(size_t, count, sizeof(buf) - 1);

	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';

#define RS_MOD_TOKEN(str, val)                               \
	if (strncmp(&buf[idx], str, sizeof(str) - 1) == 0) { \
		idx += sizeof(str) - 1;                      \
		mod |= val;                                  \
		continue;                                    \
	}

#define RS_DBG_TOKEN(str, val)                               \
	if (strncmp(&buf[idx], str, sizeof(str) - 1) == 0) { \
		idx += sizeof(str) - 1;                      \
		dbg = val;                                   \
		goto dbg_done;                               \
	}

	while ((idx + 4) < len) {
		if (strncmp(&buf[idx], "MOD:", 4) == 0) {
			idx += 4;
			RS_MOD_TOKEN("ALL", 0xffffffff);
			RS_MOD_TOKEN("KE", BIT(0));
			RS_MOD_TOKEN("DBG", BIT(1));
			RS_MOD_TOKEN("IPC", BIT(2));
			RS_MOD_TOKEN("DMA", BIT(3));
			RS_MOD_TOKEN("MM", BIT(4));
			RS_MOD_TOKEN("TX", BIT(5));
			RS_MOD_TOKEN("RX", BIT(6));
			RS_MOD_TOKEN("PHY", BIT(7));
			idx++;
		} else if (strncmp(&buf[idx], "DBG:", 4) == 0) {
			u32 dbg = 0;
			idx += 4;
			RS_DBG_TOKEN("NONE", 0);
			RS_DBG_TOKEN("CRT", 1);
			RS_DBG_TOKEN("ERR", 2);
			RS_DBG_TOKEN("WRN", 3);
			RS_DBG_TOKEN("INF", 4);
			RS_DBG_TOKEN("VRB", 5);
			idx++;
			continue;
dbg_done:
			rs_dbg_lvl_filter_set(priv, dbg);
		} else {
			idx++;
		}
	}

	if (mod) {
		rs_dbg_mod_filter_set(priv, mod);
	}

	return count;
}

RS_DBGFS_OPS_RW(fw_dbg);

static ssize_t rs_dbgfs_dbglvl_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	struct rs_hw_priv *priv = file->private_data;

	char buf[8];
	s32 len = 0;

	len += scnprintf(buf, min_t(size_t, sizeof(buf) - 1, count), "%d\n", priv->dbglvl);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t rs_dbgfs_dbglvl_write(struct file *file, const char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	struct rs_hw_priv *priv = file->private_data;
	char buf[32];
	size_t len = min_t(size_t, count, sizeof(buf) - 1);

	s32 err;

	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';

	err = kstrtol(buf, 0, (long *)&priv->dbglvl);

	return count;
}

RS_DBGFS_OPS_RW(dbglvl);

static ssize_t rs_dbgfs_sys_stats_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	struct rs_hw_priv *priv = file->private_data;
	char buf[3 * 64];
	s32 len = 0;
	ssize_t read;
	s32 error = 0;
	u32 sleep_int, sleep_frac, doze_int, doze_frac;
	struct rs_dbg_get_sys_stat_chk *sys_stat_chk = &priv->mgmt_return.get_sys_stat_chk;

	RS_DBG(RS_FN_ENTRY_STR);

	/* Get the information from the FW */
	if ((error = rs_dbg_get_sys_stat_req(priv, sys_stat_chk)))
		return error;

	if (sys_stat_chk->stats_time == 0)
		return 0;

	sleep_int = ((sys_stat_chk->cpu_sleep_time * 100) / sys_stat_chk->stats_time);
	sleep_frac = (((sys_stat_chk->cpu_sleep_time * 100) % sys_stat_chk->stats_time) * 10) /
		     sys_stat_chk->stats_time;
	doze_int = ((sys_stat_chk->doze_time * 100) / sys_stat_chk->stats_time);
	doze_frac = (((sys_stat_chk->doze_time * 100) % sys_stat_chk->stats_time) * 10) /
		    sys_stat_chk->stats_time;

	len += scnprintf(buf, min_t(size_t, sizeof(buf) - 1, count), "\nSystem statistics:\n");
	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "  CPU sleep [%%]: %d.%d\n",
			 sleep_int, sleep_frac);
	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "  Doze      [%%]: %d.%d\n",
			 doze_int, doze_frac);

	read = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	return read;
}

RS_DBGFS_OPS_RD(sys_stats);

static ssize_t rs_dbgfs_bus_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	struct rs_hw_priv *priv = file->private_data;
	char buf[1024];
	s32 len = 0;
	ssize_t read;
	s32 i;

	RS_DBG(RS_FN_ENTRY_STR);

	len += scnprintf(buf, min_t(size_t, sizeof(buf) - 1, count), "BUS trasmit statistics:\n");

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " Kick count   ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.q[i].nb_kick);
	}

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n Kick retry   ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.q[i].nb_retry);
	}

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n Kick drop    ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.q[i].nb_drop);
	}

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n Kick balance ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.balance[i]);
	}

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n\n Kick-Back    ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.back.nb_kick[i]);
	}

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n KB for STA PS");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.back.nb_res_sta_ps[i]);
	}
	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n KB status 0  ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.back.nb_err_status[i]);
	}
	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n KB data null ");
	for (i = 0; i < RS_TXQ_CNT; i++) {
		len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), " [%1d]:%3d", i,
				 priv->tx.back.nb_err_data[i]);
	}

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n KB Wrong fmt  %d",
			 priv->tx.back.nb_err_fmt);

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count), "\n KB Err-Proc   %d",
			 priv->tx.back.nb_err_proc);
	// for (i = 0; i < RS_TXQ_CNT; i++) {
	//     len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count),
	//             " [%1d]:%5d", i, priv->tx.nb_kkcb_err_proc[i]);
	// }

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count),
			 "\n Rx count      %d, Err bus %d len %d fmt %d", priv->rx.nb_kick,
			 priv->rx.nb_err_bus, priv->rx.nb_err_len, priv->rx.nb_err_fmt);

	len += scnprintf(&buf[len], min_t(size_t, sizeof(buf) - 1, count),
			 "\n AMPDU         ACKed %d / Tatal %d Retry %d\n", priv->tx.ampdu.nb_total_ack,
			 priv->tx.ampdu.nb_total_cnt, priv->tx.ampdu.nb_total_retry);

	read = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	return read;
}

static ssize_t rs_dbgfs_bus_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	// struct rs_hw_priv *priv = file->private_data;

	/* Prevent from interrupt preemption as these statistics are updated under
     * interrupt */
	// spin_lock_bh(&priv->tx_lock);
	// memset(&priv->stats, 0, sizeof(priv->stats));
	// spin_unlock_bh(&priv->tx_lock);

	return count;
}
RS_DBGFS_OPS_RW(bus);

#ifdef CONFIG_RS_P2P_DEBUGFS
static ssize_t rs_dbgfs_opps_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	struct rs_hw_priv *rw_hw = file->private_data;
	struct rs_vif_priv *rw_vif;
	char buf[32];
	size_t len = min_t(size_t, count, sizeof(buf) - 1);
	s32 ctw;

	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';

	/* Read the written CT Window (provided in ms) value */
	if (sscanf(buf, "ctw=%d", &ctw) > 0) {
		/* Check if at least one VIF is configured as P2P GO */
		list_for_each_entry(rw_vif, &rw_hw->vifs, list) {
			if ((VIF_TYPE(rw_vif) == NL80211_IFTYPE_AP) && rw_vif->vif->p2p) {
				/* Forward request to the embedded and wait for confirmation */
				rs_p2p_opps_req(rw_hw, rw_vif, (u8)ctw, &rw_hw->mgmt_return.set_p2p_opps_chk);

				break;
			}
		}
	}

	return count;
}

RS_DBGFS_OPS_WR(opps);

static ssize_t rs_dbgfs_noa_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	struct rs_hw_priv *rw_hw = file->private_data;
	struct rs_vif_priv *rw_vif;
	char buf[64];
	size_t len = min_t(size_t, count, sizeof(buf) - 1);
	s32 noa_count, interval, duration, dyn_noa;

	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';

	/* Read the written NOA information */
	if (sscanf(buf, "count=%d interval=%d duration=%d dyn=%d", &noa_count, &interval, &duration,
		   &dyn_noa) > 0) {
		/* Check if at least one VIF is configured as P2P GO */
		list_for_each_entry(rw_vif, &rw_hw->vifs, list) {
			if ((VIF_TYPE(rw_vif) == NL80211_IFTYPE_AP) && rw_vif->vif->p2p) {
				/* Forward request to the embedded and wait for confirmation */
				rs_p2p_noa_req(rw_hw, rw_vif, (u8)noa_count, (u8)interval, (u8)duration,
					       (dyn_noa > 0), &rw_hw->mgmt_return.set_p2p_noa_chk);

				break;
			}
		}
	}

	return count;
}

RS_DBGFS_OPS_WR(noa);
#endif /* CONFIG_RS_P2P_DEBUGFS */

s32 rs_dbgfs_register(struct rs_hw_priv *hw_priv, const char *name)
{
	struct dentry *phyd = hw_priv->hw->wiphy->debugfsdir;
	struct rs_dbgfs_t *rs_dbgfs_t = &hw_priv->debugfs;
	struct dentry *dir_drv;

	if (!(dir_drv = debugfs_create_dir(name, phyd)))
		return -ENOMEM;

	rs_dbgfs_t->dir = dir_drv;
	rs_dbgfs_t->unregistering = false;

	RS_DBGFS_CTF(stats, dir_drv, S_IWUSR | S_IRUSR);
	RS_DBGFS_CTF(bus, dir_drv, S_IWUSR | S_IRUSR);

	return 0;

err:
	rs_dbgfs_unregister(hw_priv);
	return -ENOMEM;
}

void rs_dbgfs_unregister(struct rs_hw_priv *hw_priv)
{
	struct rs_dbgfs_t *rs_dbgfs_t = &hw_priv->debugfs;

	if (!hw_priv->debugfs.dir)
		return;

	rs_dbgfs_t->unregistering = true;
	debugfs_remove_recursive(hw_priv->debugfs.dir);
	hw_priv->debugfs.dir = NULL;
}
