/*
 * log.c - Simple logging framework.
 *
 * Copyright 2003 Jonathan McDowell <noodles@earth.li>
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
static loglevels logthres = LOGTHING_NOTICE;

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
 *	getlogthreshold - get the threshold for log output
 *
 *	Returns the threshold for log output; anything logged with a log level
 *	lower than this will be silently dropped.
 */
loglevels getlogthreshold(void)
{
	return logthres;
}

/*
 *	vflog - write a log entry to an already opened log file.
 *      @logfile: The FILE * handle of the open log file.
 *      @format: A format string.
 *      @ap: The va_list of the parmeters for the format string.
 *
 *	This function outputs a log entry to an opened file. A leading
 *	time/date stamp and a trailing newline are automatically added. The
 *	format parameter is of the same nature as that used in vprintf.
 */
static void vflog(FILE *logfile, const char *format, va_list ap)
{
	struct tm *timestamp = NULL;
	time_t     timer = 0;

	timer = time(NULL);
	timestamp = localtime(&timer);

	fprintf(logfile, "[%02d/%02d/%4d %02d:%02d:%02d] %s[%d]: ",
			timestamp->tm_mday,
			timestamp->tm_mon + 1,
			timestamp->tm_year + 1900,
			timestamp->tm_hour,
			timestamp->tm_min,
			timestamp->tm_sec,
			(logappname == NULL) ? "" : logappname,
			getpid());
	vfprintf(logfile, format, ap);
	fprintf(logfile, "\n");

	return;
}

/*
 *	flog - write a log entry to an already opened log file.
 *      @logfile: The FILE * handle of the open log file.
 *      @format: A format string.
 *
 *	This function outputs a log entry to an opened file. A leading
 *	time/date stamp and a trailing newline are automatically added. The
 *	format parameter is of the same nature as that used in printf.
 */
static void flog(FILE *logfile, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vflog(logfile, format, ap);
	va_end(ap);
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
	va_list    ap;

	if (loglevel >= logthres) {
		if (logfilename != NULL) {
			logfile = fopen(logfilename, "a");
			if (logfile != NULL) {
				flockfile(logfile);
			} else {
				logfile = stderr;
				flog(logfile, "Couldn't open logfile: %s",
						logfilename);
			}
		} else {
			logfile = stderr;
		}
	
		va_start(ap, format);
		vflog(logfile, format, ap);
		va_end(ap);

		if (logfile != stderr) {
			funlockfile(logfile);
			fclose(logfile);
			logfile = NULL;
		}
	}

	return 0;
}
