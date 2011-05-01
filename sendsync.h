/*
 * sendsync.c - Routines to send a key sync mail.
 *
 * Copyright 1999, 2002, 2005, 2011 Jonathan McDowell <noodles@earth.li>
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

#ifndef __SENDSYNC_H_
#define __SENDSYNC_H_

#include "keystructs.h"

/**
 *	sendkeysync - Send a key sync mail to our peers.
 *	keys: The list of keys to send.
 *
 *	Takes a list of keys and sends out a keysync mail to all our peers.
 */
int sendkeysync(struct openpgp_publickey *keys);

#endif /* __SENDSYNC_H */
