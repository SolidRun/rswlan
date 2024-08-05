// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * Copyright (C) [2022-2023] Renesas Electronics Corporation and/or its affiliates.
 */

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

#include <linux/version.h>
#include <linux/uaccess.h>

#include "rs_file.h"

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#ifndef CONFIG_SET_FS

#define F_FS_INIT()
#define F_FS_SET()
#define F_FS_RST()

#else

#define F_FS_INIT() static mm_segment_t fs = 0;
#define F_FS_SET()                 \
	{                          \
		fs = get_fs();     \
		set_fs(KERNEL_DS); \
	}
#define F_FS_RST() set_fs(fs)

#endif

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFITION

////////////////////////////////////////////////////////////////////////////////
/// LOCAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// LOCAL FUNCTION

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

s32 rs_f_open(struct rs_file *file, const u8 *file_path, s32 flags, s32 mode)
{
	s32 ret = -1;
	F_FS_INIT();

	if (file != NULL) {
		F_FS_SET();
		file->file = filp_open((const char *)file_path, (int)flags, mode);
		F_FS_RST();

		if (file->file != NULL) {
			ret = 0;
			file->flags = flags;
			file->mode = mode;
		} else {
			ret = -1;
		}
	}

	return ret;
}

s32 rs_f_close(struct rs_file *file)
{
	s32 ret = -1;
	F_FS_INIT();

	if ((file != NULL) && (file->file != NULL)) {
		F_FS_SET();
		ret = filp_close(file->file, NULL);
		F_FS_RST();
		if (ret == 0) {
			file->file = NULL;
			file->flags = -1;
			file->mode = -1;
		}
	}

	return ret;
}

s32 rs_f_read(struct rs_file *file, u8 *buf, s32 buf_len)
{
	s32 ret = -1;
	loff_t pos = 0;
	F_FS_INIT();

	if ((file != NULL) && (file->file != NULL) && (buf != NULL)) {
		pos = file->pos;
		F_FS_SET();
		ret = kernel_read(file->file, (char __user *)buf, buf_len, &pos);
		F_FS_RST();
		if (ret >= 0) {
			file->pos = (s32)pos;
		}
	}

	return ret;
}

s32 rs_f_write(struct rs_file *file, const u8 *buf, s32 buf_len)
{
	s32 ret = -1;
	loff_t pos = 0;
	F_FS_INIT();

	if ((file != NULL) && (file->file != NULL) && (buf != NULL)) {
		pos = file->pos;
		F_FS_SET();
		ret = kernel_write(file->file, (const char __user *)buf, buf_len, &pos);
		F_FS_RST();
		if (ret >= 0) {
			file->pos = (s32)pos;
		}
	}

	return ret;
}
