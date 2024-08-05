// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"
#include "rs_priv.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define MANUFACTURER_CODE           0x296   /* vendor Renesas (DA16200) */
#define MANUFACTURER_ID_NROM_BASE   0x5347  /* MROM device id  */
#define MANUFACTURER_ID_DA16K_BASE  0x5349  /* WIFI device id  */

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

static const struct sdio_device_id da16k_sdio_devices[] = {
    /*load driver*/
    {SDIO_DEVICE(MANUFACTURER_CODE, (MANUFACTURER_ID_DA16K_BASE | 0x0))},
    /*download firmware*/
    {SDIO_DEVICE(MANUFACTURER_CODE, (MANUFACTURER_ID_NROM_BASE | 0x0))},
    {},
};

MODULE_DEVICE_TABLE(sdio, da16k_sdio_devices);

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

s32 sdio_probe_init_core(struct sdio_func* func,
    struct rs_core** rs_core);
s32 sdio_probe_fw_download(struct sdio_func* func);

static s32 da16k_sdio_probe(struct sdio_func *sdio,
                            const struct sdio_device_id *id)
{
    s32 err = -ENODEV;
    struct rs_core *core = NULL;
    void *drvdata;

    dev_dbg(&sdio->dev, "probe\n");

    err = sdio_probe_init_core(sdio, &core);

    if (!err) {
        err = core->bus.ops.init_bus_addr(core);
    }

    if (!err) {
        err = core_init(core, &drvdata);
    }

    if (err) {
        core->bus.ops.deinit(core);
    }

    return err;
}

static s32 da16k_sdio_fw_probe(struct sdio_func *sdio,
                               const struct sdio_device_id *id)
{
    s32 ret = -ENODEV;

    dev_dbg(&sdio->dev, "fw_probe\n");

    ret = sdio_probe_fw_download(sdio);

    return ret;
}

static void da16k_sdio_remove(struct sdio_func *sdio)
{
    struct rs_core *core = sdio_get_drvdata(sdio);

    dev_dbg(&sdio->dev, "remove\n");

    core_deinit(core->priv);

    core->bus.ops.deinit(core);

    sdio_set_drvdata(sdio, NULL);
}

static void da16k_sdio_fw_remove(struct sdio_func *sdio)
{
    struct rs_hw_priv *hw_priv;
    struct rs_core *rs_core;

    rs_core = sdio_get_drvdata(sdio);
    hw_priv = rs_core->priv;

    dev_dbg(&sdio->dev, "fw_remove\n");

    sdio_set_drvdata(sdio, NULL);
}

static struct sdio_driver da16k_sdio_drv[] = {
    /*load da16200 driver*/
    {
        .name = "DA16200_sdio",
        .id_table = &da16k_sdio_devices[0],
        .probe = da16k_sdio_probe,
        .remove = da16k_sdio_remove
    },
    /*wifi fw download to NROM in SDIO interface*/
    {
        .name = "DA16200_sdio_fw_download",
        .id_table = &da16k_sdio_devices[1],
        .probe = da16k_sdio_fw_probe,
        .remove = da16k_sdio_fw_remove
    }
};

s32 if_sdio_drv_init(void)
{
    sdio_register_driver(&da16k_sdio_drv[1]);        // firmware download
    return sdio_register_driver(&da16k_sdio_drv[0]); // load sdio
}

void if_sdio_drv_deinit(void)
{
    sdio_unregister_driver(&da16k_sdio_drv[1]);
    sdio_unregister_driver(&da16k_sdio_drv[0]);
}