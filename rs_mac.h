// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */
#ifndef RS_MAC_H
#define RS_MAC_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "rs_defs.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFINITION

#define ACCEPT_UNKNOWN_BIT		((u32)0x40000000)
#define ACCEPT_OTHER_DATA_FRAMES_BIT	((u32)0x20000000)
#define ACCEPT_QO_S_NULL_BIT		((u32)0x10000000)
#define ACCEPT_QCFWO_DATA_BIT		((u32)0x08000000)
#define ACCEPT_Q_DATA_BIT		((u32)0x04000000)
#define ACCEPT_CFWO_DATA_BIT		((u32)0x02000000)
#define ACCEPT_DATA_BIT			((u32)0x01000000)
#define ACCEPT_OTHER_CNTRL_FRAMES_BIT	((u32)0x00800000)
#define ACCEPT_CF_END_BIT		((u32)0x00400000)
#define ACCEPT_ACK_BIT			((u32)0x00200000)
#define ACCEPT_CTS_BIT			((u32)0x00100000)
#define ACCEPT_RTS_BIT			((u32)0x00080000)
#define ACCEPT_PS_POLL_BIT		((u32)0x00040000)
#define ACCEPT_BA_BIT			((u32)0x00020000)
#define ACCEPT_BAR_BIT			((u32)0x00010000)
#define ACCEPT_OTHER_MGMT_FRAMES_BIT	((u32)0x00008000)
#define ACCEPT_ALL_BEACON_BIT		((u32)0x00002000)
#define ACCEPT_NOT_EXPECTED_BA_BIT	((u32)0x00001000)
#define ACCEPT_DECRYPT_ERROR_FRAMES_BIT ((u32)0x00000800)
#define ACCEPT_BEACON_BIT		((u32)0x00000400)
#define ACCEPT_PROBE_RESP_BIT		((u32)0x00000200)
#define ACCEPT_PROBE_ASK_BIT		((u32)0x00000100)
#define ACCEPT_MY_UNICAST_BIT		((u32)0x00000080)
#define ACCEPT_UNICAST_BIT		((u32)0x00000040)
#define ACCEPT_ERROR_FRAMES_BIT		((u32)0x00000020)
#define ACCEPT_OTHER_BSSID_BIT		((u32)0x00000010)
#define ACCEPT_BROADCAST_BIT		((u32)0x00000008)
#define ACCEPT_MULTICAST_BIT		((u32)0x00000004)
#define DONT_DECRYPT_BIT		((u32)0x00000002)
#define EXC_UNENCRYPTED_BIT		((u32)0x00000001)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

enum mac_cipher_suite {
	MAC_CIPHER_WEP40,
	MAC_CIPHER_TKIP,
	MAC_CIPHER_CCMP,
	MAC_CIPHER_WEP104,
	MAC_CIPHER_SM54,
	MAC_CIPHER_AES_CMAC,
	MAC_CIPHER_INVALID = 0xFF
};

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_mac_allocate(struct rs_core *rs_core, void **platform_data);
void rs_mac80211_deinit(struct rs_hw_priv *rs_hw);

#endif /* RS_MAC_H */