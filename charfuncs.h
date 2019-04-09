/**
 * @file charfuncs.h
 * @brief Routines for dealing with character streams.
 *
 * Copyright 2002 Jonathan McDowell <noodles@earth.li>
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

#ifndef __CHARFUNCS_H__
#define __CHARFUNCS_H__

#include <stdlib.h>

/**
 * @brief Shared with CGI buffer stuff...
 */
struct buffer_ctx {
	/** The data buffer. */
	char *buffer;
	/** Our current position in the buffer. */
	size_t offset;
	/** The size of the data buffer. */
	size_t size;
};

/**
 * @brief Fetches a char from a buffer.
 * @param ctx Our buffer context structure.
 * @param count The number of characters to get from the buffer.
 * @param c Where to put the characters retrieved.
 */
int buffer_fetchchar(void *ctx, size_t count, void *c);

/**
 * @brief Puts a char to a buffer.
 * @param ctx Our buffer context structure.
 * @param count The number of characters to put into the buffer.
 * @param c The characters to add to the buffer.
 *
 * Adds characters to the buffer references by the buffer context. If we
 * fill it then we double the size of the current buffer and then add the
 * rest.
 */
int buffer_putchar(void *ctx, size_t count, void *c);

/**
 * @brief Fetches a char from a file.
 */
int file_fetchchar(void *fd, size_t count, void *c);

/**
 * @brief Puts a char to a file.
 */
int file_putchar(void *fd, size_t count, void *c);

/**
 * @brief Gets a char from stdin.
 */
int stdin_getchar(void *ctx, size_t count, void *c);

/**
 * @brief Puts a char to stdout.
 */
int stdout_putchar(void *ctx, size_t count, void *c);

#endif /* __CHARFUNCS_H__ */
