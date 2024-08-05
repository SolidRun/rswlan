// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#include <linux/version.h>

#include "rs_mgmt_tx.h"
#include "rs_version.h"
#if defined(CONFIG_RS_SDIO)
#include "rs_sdio_ops.h"
#elif defined(CONFIG_RS_SPI)
#include "rs_spi_ops.h"
#endif

#define RS_WLAN_DESCRIPTION  "Renesas 11n driver for Linux"
#define RS_WLAN_COPYRIGHT    "Copyright(c) 2021 Renesas"
#define RS_WLAN_AUTHOR       "Renesas"
#define RS_WLAN_VERSION      MODULE_VER_NUM

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
static struct ieee80211_cipher_scheme rs_cs[] ={
    {
        .cipher = WLAN_CIPHER_SUITE_SMS4,
        .iftype = (BIT(NL80211_IFTYPE_STATION) |
                   BIT(NL80211_IFTYPE_MESH_POINT) |
                   BIT(NL80211_IFTYPE_AP)),
        .hdr_len = WPI_HDR_LEN,
        .pn_len = WPI_PN_LEN,
        .pn_off = WPI_PN_OFST,
        .key_idx_off = 0,
        .key_idx_mask = 0x1,
        .key_idx_shift = 0,
        .mic_len = IEEE80211_CCMP_MIC_LEN
        /* This value is used by mac82011 to strip the MIC. In our case MIC is
           stripped by the HW and readded in rx_data_handler(). As there is way
           to distinguish CCMP from WPI in this function, always use CCMP size
           even if WPI MIC length is actually 16 bytes.
        */
    }
};
#endif

void rs_enable_wapi(struct rs_hw_priv *rs_hw) {
    struct ieee80211_hw *hw = rs_hw->hw;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
    hw->n_cipher_schemes = ARRAY_SIZE(rs_cs);
    hw->cipher_schemes = rs_cs;
#endif    
    hw->wiphy->flags |= WIPHY_FLAG_CONTROL_PORT_PROTOCOL;
}

static void __used rs_restart_hw(struct rs_hw_priv *rs_hw)
{
    struct rs_vif_priv *vif_priv, *__rs_vif;
    s32 ret;
    unsigned long now = jiffies;
    static struct {
        unsigned long last;
        u32 cnt;
    } restart_recs = { .last = 0, .cnt = 0 };

    printk(RS_FN_ENTRY_STR);

    rs_hw->drv_flags = BIT(RS_DEV_RESTARTING);

    rs_hw->core->enabled = false;

    ieee80211_stop_queues(rs_hw->hw);

    if (restart_recs.cnt) {
        if (jiffies_to_msecs(now - restart_recs.last) > 3000) {
            restart_recs.cnt = 0;
        } else if (restart_recs.cnt > 5) {
            printk(KERN_CRIT "%s: Too many failures .. aborting\n", __func__);
            return;
        }
    }
    restart_recs.cnt++;
    restart_recs.last = now;

    if (rs_core_on(rs_hw)) {
        printk(KERN_CRIT "%s: Couldn't turn platform on .. aborting\n", __func__);
        return;
    }

    if ((ret = rs_reset(rs_hw)))  {
        printk(KERN_CRIT "%s: Couldn't reset the LMAC .. aborting\n", __func__);
        return;
    }

    list_for_each_entry_safe(vif_priv, __rs_vif, &rs_hw->vifs, list) {
        list_del(&vif_priv->list);
        vif_priv->vif = NULL;
    }

    set_bit(RS_DEV_STACK_RESTARTING, &rs_hw->drv_flags);
    clear_bit(RS_DEV_RESTARTING, &rs_hw->drv_flags);

    ieee80211_restart_hw(rs_hw->hw);
}

static s32 __init rs_mod_init(void)
{
    RS_DBG(RS_FN_ENTRY_STR);
    rs_print_version();
#if defined(CONFIG_RS_SDIO)
    return if_sdio_drv_init();
#elif defined(CONFIG_RS_SPI)
    return if_spi_drv_init();
#endif
}

static void __exit rs_mod_exit(void)
{
    RS_DBG(RS_FN_ENTRY_STR);
#if defined(CONFIG_RS_SDIO)
    if_sdio_drv_deinit();
#elif defined(CONFIG_RS_SPI)
    if_spi_drv_deinit();
#endif
}

module_init(rs_mod_init);
module_exit(rs_mod_exit);

MODULE_DESCRIPTION(RS_WLAN_DESCRIPTION);
MODULE_VERSION(RS_WLAN_VERSION);
MODULE_AUTHOR(RS_WLAN_COPYRIGHT " " "Renesas");
MODULE_LICENSE("GPL");
