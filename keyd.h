/**
 * @file keyd.h
 * @brief Public API for keyd.
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

/**
 * @brief The name of the keyd Unix domain socket
 */
#define KEYD_SOCKET "keyd.sock"

/**
 * @brief keyd commands
 */
enum keyd_ops {
	KEYD_CMD_UNKNOWN = 0,
	KEYD_CMD_VERSION = 1,
	KEYD_CMD_GET_ID,
	KEYD_CMD_STORE,
	KEYD_CMD_DELETE,
	KEYD_CMD_GET_TEXT,
	KEYD_CMD_GETFULLKEYID,
	KEYD_CMD_KEYITER,
	KEYD_CMD_CLOSE,
	KEYD_CMD_QUIT,
	KEYD_CMD_STATS,
	KEYD_CMD_GET_SKSHASH,
	KEYD_CMD_GET_FP,
	KEYD_CMD_LAST			/* Placeholder */
};

/**
 * @brief Reply codes for keyd commands
 */
enum keyd_reply {
	KEYD_REPLY_OK = 0,
	KEYD_REPLY_UNKNOWN_CMD = 1
};

/**
 * @brief Version of the keyd protocol currently supported
 */
static const uint32_t keyd_version = 4;

/**
 * @brief Response structure for the @a KEYD_CMD_STATS response
 */
struct keyd_stats {
	/** Unix time of when the keyd daemon was started */
	time_t started;
	/** Number of connects we've seen to keyd */
	uint32_t connects;
	/** Count of the number of times each command has been used */
	uint32_t command_stats[KEYD_CMD_LAST];
};

#endif /* __KEYD_H__ */
