/*
 * log.c - Simple logging framework.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2003 Project Purple
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

/*
 *	logthres - holds the minimum log level we'll output
 *
 *	This variable keeps track of the threshold we've set for outputting
 *	logs - if we're asked to log something below this level we won't output
 *	it.
 */
static loglevels logthres = LOGTHING_DEBUG;

/*
 *	logappname - the name of the application using us.
 *
 *	This holds information about the name of the application we're being
 *	called by. It's set when we're initialized.
 */
static char *logappname = NULL;

/*
 *	logfilename - the file to log to.
 *
 *	The full name and path of the file we should log to.
 */
static char *logfilename = NULL;

/*
 *	initlogthing - initialize the logging module
 *	@appname: The application name to use in the log.
 *	@filename: The filename to log to. NULL means stderr.
 *
 *      This function sets up the logging module ready to log. The appname is
 *      written as part of every log entry and the filename is the file we
 *      should log to. If the appname is NULL then none is written. If the
 *      filename is NULL all output is sent to stderr.
 */
int initlogthing(const char *appname, const char *filename)
{
	if (appname != NULL) {
		logappname = strdup(appname);
	}

	if (filename != NULL) {
		logfilename = strdup(filename);
	}

	return 0;
}

/*
 *	cleanuplogthing - clean up the logging module
 *
 *      This function cleans up the logging module after use.
 */
void cleanuplogthing(void)
{
	if (logappname != NULL) {
		free(logappname);
		logappname = NULL;
	}

	if (logfilename != NULL) {
		free(logfilename);
		logfilename = NULL;
	}

	return;
}

/*
 *	setlogthreshold - set the threshold for log output
 *	@loglevel: The minimum log level we should output
 *
 *	Sets the threshold for log output; anything logged with a log level
 *	lower than this will be silently dropped. Returns the old log threshold
 *	value.
 */
loglevels setlogthreshold(loglevels loglevel)
{
	loglevels oldlevel;

	oldlevel = logthres;
	logthres = loglevel;

	return oldlevel;
}

/*
 *	logthing - output a log entry
 *      @loglevel: The level of the log.
 *      @format: A format string, followed by any parameters required.
 *
 *	This function outputs a log entry. A leading time/date stamp and a
 *	trailing newline are automatically added. The loglevel is compared to
 *	the current log threshold and if equal or above the log entry is
 *	output. The format parameter is of the same nature as that used in
 *	printf.
 */
int logthing(loglevels loglevel, const char *format, ...)
{
	FILE      *logfile = NULL;
	struct tm *timestamp = NULL;
	time_t     timer = 0;
	va_list    ap;

	if (loglevel >= logthres) {
		timer = time(NULL);
		timestamp = localtime(&timer);

		if (logfilename != NULL) {
			logfile = fopen(logfilename, "a");
			flockfile(logfile);
		} else {
			logfile = stderr;
		}
	
		fprintf(logfile, "[%02d/%02d/%4d %02d:%02d:%02d] %s[%d]: ",
				timestamp->tm_mday,
				timestamp->tm_mon + 1,
				timestamp->tm_year + 1900,
				timestamp->tm_hour,
				timestamp->tm_min,
				timestamp->tm_sec,
				(logappname == NULL) ? "" : logappname,
				getpid());
		va_start(ap, format);
		vfprintf(logfile, format, ap);
		va_end(ap);
		fprintf(logfile, "\n");


		if (logfilename != NULL) {
			funlockfile(logfile);
			fclose(logfile);
			logfile = NULL;
		}
	}

	return 0;
}
