/*
 * onak-conf.c - Routines related to runtime config.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ll.h"
#include "log.h"
#include "onak-conf.h"

/*
 *	config - Runtime configuration for onak.
 *
 *	This is the default config; normally overridden with values from the
 *	config file.
 */
struct onak_config config = {
	128,			/* maxkeys */
	NULL,			/* thissite */
	NULL,			/* adminemail */
	NULL,			/* mta */
	NULL,			/* syncsites */
	NULL,			/* logfile */

	/*
	 * Options for directory backends.
	 */
	NULL,			/* db_dir */

	/*
	 * Options for the Postgres backend.
	 */
	NULL,			/* pg_dbhost */
	NULL,			/* pg_dbname */
	NULL,			/* pg_dbuser */
	NULL,			/* pg_dbpass */
};

void readconfig(void) {
	FILE *conffile;
	char  curline[1024];
	int   i;

	curline[1023] = 0;
	conffile = fopen(CONFIGFILE, "r");
	if (conffile != NULL) {
		fgets(curline, 1023, conffile);

		while (!feof(conffile)) {
		for (i = strlen(curline) - 1; isspace(curline[i]); i--) {
			curline[i] = 0;
		}

		if (curline[0] == '#' || curline[0] == 0) {
			/*
			 * Comment line, ignore.
			 */
		} else if (!strncmp("db_dir ", curline, 7)) {
			config.db_dir = strdup(&curline[7]);
		} else if (!strncmp("debug ", curline, 6)) {
			/*
			 * Not supported yet; ignore for compatibility with
			 * pksd.
			 */
		} else if (!strncmp("default_language ", curline, 17)) {
			/*
			 * Not supported yet; ignore for compatibility with
			 * pksd.
			 */
		} else if (!strncmp("mail_delivery_client ", curline, 21)) {
			config.mta = strdup(&curline[21]);
		} else if (!strncmp("maintainer_email ", curline, 17)) {
			config.adminemail = strdup(&curline[17]);
		} else if (!strncmp("mail_intro_file ", curline, 16)) {
			/*
			 * Not supported yet; ignore for compatibility with
			 * pksd.
			 */
		} else if (!strncmp("help_dir ", curline, 9)) {
			/*
			 * Not supported yet; ignore for compatibility with
			 * pksd.
			 */
		} else if (!strncmp("max_last ", curline, 9)) {
			/*
			 * Not supported yet; ignore for compatibility with
			 * pksd.
			 */
		} else if (!strncmp("max_reply_keys ", curline, 15)) {
			config.maxkeys = atoi(&curline[15]);
		} else if (!strncmp("pg_dbhost ", curline, 10)) {
			config.pg_dbhost = strdup(&curline[10]);
		} else if (!strncmp("pg_dbname ", curline, 10)) {
			config.pg_dbname = strdup(&curline[10]);
		} else if (!strncmp("pg_dbuser ", curline, 10)) {
			config.pg_dbuser = strdup(&curline[10]);
		} else if (!strncmp("pg_dbpass ", curline, 10)) {
			config.pg_dbpass = strdup(&curline[10]);
		} else if (!strncmp("syncsite ", curline, 9)) {
			config.syncsites =
				lladd(config.syncsites, strdup(&curline[9]));
		} else if (!strncmp("logfile ", curline, 8)) {
			config.logfile = strdup(&curline[8]);
		} else if (!strncmp("this_site ", curline, 10)) {
			config.thissite = strdup(&curline[10]);
		} else if (!strncmp("socket_name ", curline, 12) ||
				!strncmp("pks_bin_dir ", curline, 12) ||
				!strncmp("mail_dir ", curline, 9) ||
				!strncmp("www_port ", curline, 9)) {
			/*
			 * Not applicable; ignored for compatibility with pksd.
			 */
		} else {
			logthing(LOGTHING_ERROR,
				"Unknown config line: %s", curline);
		}

			fgets(curline, 1023, conffile);
		}
		fclose(conffile);
	} else {
		logthing(LOGTHING_NOTICE,
				"Couldn't open config file; using defaults.");
	}
}

void cleanupconfig(void) {
	if (config.thissite != NULL) {
		free(config.thissite);
		config.thissite = NULL;
	}
	if (config.adminemail != NULL) {
		free(config.adminemail);
		config.adminemail = NULL;
	}
	if (config.mta != NULL) {
		free(config.mta);
		config.mta = NULL;
	}
	if (config.db_dir != NULL) {
		free(config.db_dir);
		config.db_dir = NULL;
	}
	if (config.pg_dbhost != NULL) {
		free(config.pg_dbhost);
		config.pg_dbhost = NULL;
	}
	if (config.pg_dbname != NULL) {
		free(config.pg_dbname);
		config.pg_dbname = NULL;
	}
	if (config.pg_dbuser != NULL) {
		free(config.pg_dbuser);
		config.pg_dbuser = NULL;
	}
	if (config.pg_dbpass != NULL) {
		free(config.pg_dbpass);
		config.pg_dbpass = NULL;
	}
	if (config.syncsites != NULL) {
		llfree(config.syncsites, free);
		config.syncsites = NULL;
	}
	if (config.logfile != NULL) {
		free(config.logfile);
		config.logfile = NULL;
	}
}
