/*
 * keyd.h - Public API for keyd.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 */

#ifndef __KEYD_H__
#define __KEYD_H__

#include <stdint.h>

#define KEYD_SOCKET "keyd.sock"

enum keyd_ops {
	KEYD_CMD_UNKNOWN = 0,
	KEYD_CMD_VERSION = 1,
	KEYD_CMD_GET,
	KEYD_CMD_STORE,
	KEYD_CMD_DELETE,
	KEYD_CMD_GETTEXT,
	KEYD_CMD_GETFULLKEYID,
	KEYD_CMD_KEYITER,
	KEYD_CMD_CLOSE,
	KEYD_CMD_QUIT
};

enum keyd_reply {
	KEYD_REPLY_OK = 0,
	KEYD_REPLY_UNKNOWN_CMD = 1
};

static uint32_t keyd_version = 2;

#endif /* __KEYD_H__ */
