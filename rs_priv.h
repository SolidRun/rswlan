// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_PRIV_H
#define RS_PRIV_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_core.h"
#include "rs_defs.h"
#include "rs_spi_ops.h"
#include "rs_mgmt_tx.h"
#include "rs_rx.h"
#include "rs_tx.h"
#include <linux/firmware.h>
#include <linux/gpio.h>

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

// Tx cfm buffer count
#define TX_KB_BUF_CNT	   16

//-------------------------------------------------------------

// FW BUS Address declarations.
#define RS_A2E_CMD_ADDR	   0x50080254

// BOOT mode of SRAM
#define BOOT_MODE_SRAM	   0x01
#define BOOT_MODE_ADDR	   0x50000000
#define SRAM_BASE_ADDR	   0x8B800

#define BURST_LENGTH	   1024
#define GPIOA_PE_PS	   0x50001228

// SPI only
#define SPI_CHECK_ADDR	   0x50080270
#define SPI_CHECK_BIT	   4
#define SPI_CHECK_DATA	   0x12341234

// SDIO only
#define SDIO_BLOCK_SIZE	   512

#define EVENT_WAIT_FOREVER 0
#define WME_NUM_AC	   4
#define INVALID_QUEUE	   0xff

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct reg_n_addr {
	u32 addr;
	u32 value;
};

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

static inline s32 rs_init_event(struct rs_event *pevent)
{
	atomic_set(&pevent->event_condition, 1);
	init_waitqueue_head(&pevent->event_queue);
	init_waitqueue_head(&pevent->mgmt_chk_queue);
	return 0;
}

static inline s32 rs_wait_event(struct rs_event *event, u32 timeout)
{
	s32 status = 0;

	if (!timeout)
		status = wait_event_interruptible(event->event_queue,
						  (atomic_read(&event->event_condition) == 0));
	else
		status = wait_event_interruptible_timeout(
			event->event_queue, (atomic_read(&event->event_condition) == 0), timeout);
	return status;
}

static inline void rs_set_event(struct rs_event *event)
{
	atomic_set(&event->event_condition, 0);
	wake_up_interruptible(&event->event_queue);
}

static inline void rs_reset_event(struct rs_event *event)
{
	atomic_set(&event->event_condition, 1);
}

static inline s32 rs_create_kthread(struct rs_core *core, struct rs_thread *thread, void *func_ptr, u8 *name)
{
	init_completion(&thread->completion);
	thread->task = kthread_run(func_ptr, core, "%s", name);
	if (IS_ERR(thread->task)) {
		pr_err("failed to create %s thread\n", name);
		return (s32)PTR_ERR(thread->task);
	}

	return 0;
}

static inline void rs_kill_thread(struct rs_thread *handle)
{
	if ((handle != NULL) && (handle->task != NULL)) {
		rs_set_event(&(handle->event));
		kthread_stop(handle->task);
		handle->task = NULL;
	}
}

s32 rs_get_mac_addr(struct rs_hw_priv *hw_priv, const char *filename, u8 *mac_addr);
void rs_mgmt_tx_thread(struct rs_core *core);
void rs_mgmt_rx_chk_handle(struct rs_hw_priv *hw, struct rs_e2a_mgmt *msg);
void rs_flush_mgmt(struct rs_hw_priv *priv);
void rs_kill_mgmt_tx_thread(struct rs_core *core);

#endif /* RS_PRIV_H */