/*
 * key-store.h - High level routines to load + save OpenPGP packets/keys
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __KEY_STORE_H__
#define __KEY_STORE_H__

#include "build-config.h"
#include "keystructs.h"
#include "onak.h"

/**
 *	onak_read_openpgp_file - Reads a set of OpenPGP packets from a file
 *	@file: The file to open and read
 *	@packets: The returned packet list
 *
 *	This function opens the supplied file and tries to parse it as a set
 *	of OpenPGP packets. It will attempt to autodetect if the file is ASCII
 *	armored, or binary packets, and adapt accordingly. The packets read are
 *	returned in the packets parameter. It is the callers responsbility to
 *	free the packet memory when it is no longe required, e.g. using
 *	free_packet_list.
 *
 *	Returns a status code indicating any error.
 */
onak_status_t onak_read_openpgp_file(const char *file,
		struct openpgp_packet_list **packets);

#endif /* __KEY_STORE_H__ */
