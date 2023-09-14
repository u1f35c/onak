/*
 * onak.h - Common onak definitions
 *
 * Copyright 2012 Jonathan McDowell <noodles@earth.li>
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

#ifndef __ONAK_H__
#define __ONAK_H__

typedef enum {
	ONAK_E_OK = 0,
	ONAK_E_NOMEM,
	ONAK_E_NOT_FOUND,
	ONAK_E_INVALID_PARAM,
	ONAK_E_INVALID_PKT,
	ONAK_E_UNKNOWN_VER,
	ONAK_E_UNSUPPORTED_FEATURE,
	ONAK_E_BAD_SIGNATURE,
	ONAK_E_WEAK_SIGNATURE,
	ONAK_E_IO_ERROR,
} onak_status_t;

#endif /* __ONAK_H__ */
