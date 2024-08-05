// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_IF_SPI_H
#define RS_IF_SPI_H

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define DA16xxx_SPI_BASE_ADDR	      (0x5008)
#define DA16xxx_DATA_LENGTH	      (0x50080248)
#define DA16xxx_DATA_ADDRESS	      (0x5008024C)
#define DA16xxx_SPI_BASE_ADDR_REG     (0x50080250)
#define DA16xxx_GEN_CMD_ADDR	      (0x50080254)
#define DA16xxx_RESP_ADDR	      (0x50080258)
#define DA16xxx_ATCMD_ADDR	      (0x50080260)

#define DA16xxx_CPU_RESET_MAN_ADDR    (0x50002010)
#define DA16xxx_BOOT_MODE_ADDR	      (0x50000000)
#define DA16xxx_MANUAL_RESET_0_ADDR   (0x500802d0)
#define DA16xxx_MANUAL_RESET_1_ADDR   (0x500802d0)

#define DA16xxx_MANUAL_RESET_0_VALUE  (0x0)
#define DA16xxx_MANUAL_RESET_1_VALUE  (0x0)
#define DA16xxx_MANUAL_RESET_0_VALUE2 (0xff)
#define DA16xxx_MANUAL_RESET_1_VALUE2 (0xff)

#define DA16xxx_KNOWN_LENGTH_FLAG     (0x80000000)

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_spi_bus_read(struct rs_core *rs_core, u32 addr, u8 *data, u32 length);
s32 rs_spi_bus_write(struct rs_core *rs_core, u32 addr, u8 *data, u32 length);
s32 rs_spi_tx_write(struct rs_core *core, u32 addr, u8 *data, u32 length);
s32 rs_spi_mgmt_write(struct rs_core *core, u32 addr, u8 *data, u32 length);
s32 if_spi_drv_init(void);
void if_spi_drv_deinit(void);
s32 if_spi_change_header_mode_8B(struct rs_core *core);

#endif // RS_IF_SPI_H
