/*
 * keyd.h - Public API for keyd.
 *
 * Copyright 2004,2011 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
	KEYD_CMD_QUIT,
	KEYD_CMD_STATS,
	KEYD_CMD_GETSKSHASH,
	KEYD_CMD_LAST			/* Placeholder */
};

enum keyd_reply {
	KEYD_REPLY_OK = 0,
	KEYD_REPLY_UNKNOWN_CMD = 1
};

static uint32_t keyd_version = 3;

struct keyd_stats {
	time_t started;
	uint32_t connects;
	uint32_t command_stats[KEYD_CMD_LAST];
};

#endif /* __KEYD_H__ */
