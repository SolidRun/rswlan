// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

#ifndef RS_FILE_H
#define RS_FILE_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/fs.h>

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

struct rs_file {
	struct file *file;

	s32 pos;
	s32 flags;
	s32 mode;
};

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_f_open(struct rs_file *file, const u8 *file_path, s32 flags, s32 mode);
s32 rs_f_close(struct rs_file *file);
s32 rs_f_read(struct rs_file *file, u8 *buf, s32 buf_len);
s32 rs_f_write(struct rs_file *file, const u8 *buf, s32 buf_len);

#endif /* RS_FILE_H */
