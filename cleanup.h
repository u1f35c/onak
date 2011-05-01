/*
 * cleanup.h - Cleanup and shutdown framework.
 *
 * Copyright 2004 Jonathan McDowell <noodles@earth.li>
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

#ifndef __CLEANUP_H__
#define __CLEANUP_H__

#include <stdbool.h>

/*
 *	trytocleanup - say we should try to cleanup.
 *
 *      This function sets the cleanup flag indicating we want to try and
 *      cleanup ASAP.
 */
void trytocleanup(void);

/*
 *	cleanup - indicate if we should try to cleanup.
 *
 *	This function returns a bool which indicates if we want to cleanup and
 *	exit ASAP.
 */
bool cleanup(void);

/*
 *	catchsignals - Register signal handlers for various signals.
 *
 *	This function registers a signal handler for various signals (PIPE,
 *	ALRM, INT, TERM, HUP) that sets the cleanup flag so we try to exit
 *	ASAP, but cleanly.
 */
void catchsignals(void);

#endif /* __CLEANUP_H__ */
