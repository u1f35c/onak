/*
 * cleanup.c - Cleanup and shutdown framework.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2004 Project Purple
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cleanup.h"
#include "keydb.h"
#include "log.h"

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
	logthing(LOGTHING_INFO, "Catching signals");

	signal(SIGALRM, &sig_cleanup);
	signal(SIGPIPE, &sig_cleanup);
	signal(SIGTERM, &sig_cleanup);
	signal(SIGINT, &sig_cleanup);
	signal(SIGHUP, &sig_cleanup);

	return;
}
