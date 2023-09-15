/*
 * cleanup.c - Cleanup and shutdown framework.
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <signal.h>
#include <stdbool.h>

#include "cleanup.h"
#include "log.h"
#include "onak-conf.h"

static bool should_cleanup = false;

/*
 *	trytocleanup - say we should try to cleanup.
 *
 *      This function sets the cleanup flag indicating we want to try and
 *      cleanup ASAP.
 */
void trytocleanup(void)
{
	logthing(LOGTHING_INFO, "Setting cleanup flag.");
	should_cleanup = true;

	return;
}

/*
 *	cleanup - indicate if we should try to cleanup.
 *
 *	This function returns a bool which indicates if we want to cleanup and
 *	exit ASAP.
 */
bool cleanup(void)
{
	return(should_cleanup);
}

/**
 *	sig_cleanup - set the cleanup flag when we receive a signal
 *
 *	This is our signal handler; all it does it log the fact we got a signal
 *	and set the cleanup flag.
 */
void sig_cleanup(int signal)
{
	logthing(LOGTHING_INFO, "Got signal %d.", signal);
	trytocleanup();

	return;
}

/**
 *	catchsignals - Register signal handlers for various signals.
 *
 *	This function registers a signal handler for various signals (PIPE,
 *	ALRM, INT, TERM, HUP) that sets the cleanup flag so we try to exit
 *	ASAP, but cleanly.
 */
void catchsignals(void)
{
	if (config.use_keyd) {
		return;
	}

	logthing(LOGTHING_INFO, "Catching signals");

	signal(SIGALRM, &sig_cleanup);
	signal(SIGPIPE, &sig_cleanup);
	signal(SIGTERM, &sig_cleanup);
	signal(SIGINT, &sig_cleanup);
	signal(SIGHUP, &sig_cleanup);

	return;
}
