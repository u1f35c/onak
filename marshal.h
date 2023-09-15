/*
 * marshal.h - SKS compatible marshalling routines
 *
 * Copyright 2011 Jonathan McDowell <noodles@earth.li>
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

#ifndef __MARSHAL_H__
#define __MARSHAL_H__

#include "keyid.h"
#include "keystructs.h"

/**
 *	marshal_publickey - Output an OpenPGP key as a byte stream
 *	@putchar_func: The function to put the next character to the stream
 *	@ctx: A pointer to the context structure for putchar_func.
 *	@key: The key to output.
 *
 *	Takes an OpenPGP key and marshals it to a byte stream - writes
 *	a 32 bit size of the forthcoming data in network byte order and
 *	then the flattened byte representation of the key.
 */
void marshal_publickey(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				const struct openpgp_publickey *key);

/**
 *	unmarshal_publickey - Turn a byte stream into an OpenPGP key
 *	@getchar_func: The function to get the next character from the stream
 *	@ctx: A pointer to the context structure for getchar_func.
 *
 *	Returns an OpenPGP structure which is the unmarshalled result of
 *	the input byte stream - ie the inverse of marshal_publickey.
 */
struct openpgp_publickey *unmarshal_publickey(size_t (*getchar_func)(void *ctx,
				size_t count,
				void *c),
				void *ctx);

/**
 *	marshal_skshash - Output an SKS hash as a byte stream
 *	@putchar_func: The function to put the next character to the stream
 *	@ctx: A pointer to the context structure for putchar_func.
 *	@hash: The hash to output.
 *
 *	Takes an SKS hash and marshals it to a byte stream - writes
 *	a 32 bit size of the forthcoming data (16 bytes) in network byte order
 *	and then the byte representation of the hash.
 */
void marshal_skshash(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				const struct skshash *hash);

/**
 *	unmarshal_skshash - Turn a byte stream into an SKS hash structure
 *	@getchar_func: The function to get the next character from the stream
 *	@ctx: A pointer to the context structure for getchar_func.
 *
 *	Returns an SKS hash structure which is the unmarshalled result of
 *	the input byte stream - ie the inverse of marshal_skshash.
 */
struct skshash *unmarshal_skshash(size_t (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx);

/**
 *	marshal_string - Output a string as a byte stream
 *	@putchar_func: The function to put the next character to the stream
 *	@ctx: A pointer to the context structure for putchar_func.
 *	@string: The string to output.
 *
 *	Takes a string and marshals it to a byte stream - writes a 32 bit size
 *	of the forthcoming data in network byte order and then the string.
 */
void marshal_string(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				const char *string);

/**
 *	unmarshal_string - Turn a byte stream into a string
 *	@getchar_func: The function to get the next character from the stream
 *	@ctx: A pointer to the context structure for getchar_func.
 *
 *	Returns a string which is the unmarshalled result of the input byte
 *	stream - ie the inverse of marshal_string.
 */
char *unmarshal_string(size_t (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx);

/**
 *	marshal_array - Outputs an array as a byte stream
 *	@putchar_func: The function to put the next character to the stream
 *	@ctx: A pointer to the context structure for putchar_func.
 *	@marshal_func: The function to use to marshal each array element.
 *	@array: A pointer to the array to marshal
 *	@size:: The number of elements in the array.
 *
 *	Takes an array and marshals it into a byte stream. Outputs a 32 bit
 *	count of the elements in the array in network byte order and then
 *	calls marshal_func for each element in the array to provide the
 *	marshalled contents.
 */
void marshal_array(size_t (*putchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				void (*marshal_func)(size_t
					(*putchar_func)(void *ctx,
						size_t count, void *c),
					void *ctx, const void *item),
				void **array,
				int size);

/**
 *	unmarshal_array - Turn a byte stream into an array of elements
 *	@getchar_func: The function to get the next character from the stream
 *	@ctx: A pointer to the context structure for getchar_func.
 *	@unmarshal_func: The function to use to unmarshal each array element.
 *	@size: A pointer to where to store the number of elements unmarshalled
 *
 *	Takes a byte stream and unmarshals it into an array of elements,
 *	as determined by the supplied unmarshal_func function. ie the reverse
 *	of marshal_array.
 */
void **unmarshal_array(size_t (*getchar_func)(void *ctx, size_t count,
				void *c),
				void *ctx,
				void *(*unmarshal_func)(size_t
					(*getchar_func)(void *ctx,
						size_t count, void *c),
					void *ctx),
				int *size);

#endif /* __MARSHAL_H__ */
