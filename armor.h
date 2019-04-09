/**
 * @file armor.h
 * @brief Routines to (de)armor OpenPGP packet streams.
 *
 * Copyright 2002-2004, 2011 Jonathan McDowell <noodles@earth.li>
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

#ifndef __ARMOR_H__
#define __ARMOR_H__

#include "keystructs.h"

/**
 * @brief Takes a list of OpenPGP packets and armors it.
 * @param putchar_func The function to output the next armor character.
 * @param ctx The context pointer for putchar_func.
 * @param packets The list of packets to output.
 *
 * This function ASCII armors a list of OpenPGP packets and outputs it
 * using putchar_func.
 */
int armor_openpgp_stream(int (*putchar_func)(void *ctx, size_t count,
						void *c),
				void *ctx,
				struct openpgp_packet_list *packets);

/**
 * @brief Reads & decodes an ACSII armored OpenPGP msg.
 * @param getchar_func The function to get the next character from the stream.
 * @param ctx The context pointer for getchar_func.
 * @param packets The list of packets.
 *
 * This function uses getchar_func to read characters from an ASCII
 * armored OpenPGP stream and outputs the data as a linked list of
 * packets.
 */
int dearmor_openpgp_stream(int (*getchar_func)(void *ctx, size_t count,
					void *c),
				void *ctx,
				struct openpgp_packet_list **packets);

#endif /* __ARMOR_H__ */
