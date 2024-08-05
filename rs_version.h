// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_VERSION_H
#define RS_VERSION_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include "version_gen.h"

////////////////////////////////////////////////////////////////////////////////
/// FUNCTION

static inline void rs_print_version(void)
{
	printk(VERSION COMPILE_TIME "\n");
}

#endif /* RS_VERSION_H */
