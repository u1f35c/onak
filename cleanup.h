/*
 * cleanup.h - Cleanup and shutdown framework.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
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
