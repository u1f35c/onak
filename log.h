/*
 * log.h - Simple logging framework.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2003 Project Purple
 */

#ifndef __LOG_H__
#define __LOG_H__

/*
 *	loglevels - levels of severity for a log entry
 *
 *	These provide various different levels of severity for a log entry. In
 *	acesending order they are:
 *
 *	LOGTHING_TRACE
 *	LOGTHING_DEBUG
 *	LOGTHING_INFO
 *	LOGTHING_NOTICE
 *	LOGTHING_ERROR
 *	LOGTHING_SERIOUS
 *	LOGTHING_CRITICAL
 *
 *	By default the log threshold is set to LOGTHING_NOTICE, meaning
 *	anything with a lower priority won't be output.
 */
typedef enum {
	LOGTHING_TRACE = 0,
	LOGTHING_DEBUG = 1,
	LOGTHING_INFO = 2,
	LOGTHING_NOTICE = 3,
	LOGTHING_ERROR = 4,
	LOGTHING_SERIOUS = 5,
	LOGTHING_CRITICAL = 6
} loglevels;

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
int initlogthing(const char *appname, const char *filename);

/*
 *	cleanuplogthing - clean up the logging module
 *
 *      This function cleans up the logging module after use.
 */
void cleanuplogthing(void);

/*
 *	setlogthreshold - set the threshold for log output
 *	@loglevel: The minimum log level we should output
 *
 *	Sets the threshold for log output; anything logged with a log level
 *	lower than this will be silently dropped. Returns the old log threshold
 *	value.
 */
loglevels setlogthreshold(loglevels loglevel);

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
int logthing(loglevels loglevel, const char *format, ...);

#endif /* __LOG_H__ */
