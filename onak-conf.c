/*
 * onak-conf.c - Routines related to runtime config.
 *
 * Copyright 2002,2012 Jonathan McDowell <noodles@earth.li>
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

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ll.h"
#include "log.h"
#include "onak-conf.h"

extern struct onak_dbctx *DBINIT(bool readonly);

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

	false,			/* use_keyd */
	".",			/* sock_dir */

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

	/*
	 * Options for dynamic backends.
	 */
	NULL,			/* db_backend */
	NULL,			/* backends_dir */

	DBINIT,			/* Default db initialisation function */

	true,			/* Check packet sig hashes */
};

bool parsebool(char *str, bool fallback)
{
	if (!strcasecmp(str, "false") || !strcasecmp(str, "no") ||
			!strcasecmp(str, "0")) {
		return false;
	} else if (!strcasecmp(str, "true") || !strcasecmp(str, "yes") ||
			!strcasecmp(str, "1")) {
		return true;
	} else {
		logthing(LOGTHING_CRITICAL,
			"Couldn't parse %s as a boolean config variable, "
			"returning fallback of '%s'.",
			str,
			fallback ? "true" : "false");
		return fallback;
	}
}

void readconfig(const char *configfile) {
	FILE *conffile;
	char  curline[1024];
	int   i;
	char *dir, *conf;
	size_t len;

	curline[1023] = 0;
	if (configfile == NULL) {
		conffile = NULL;
		if ((dir = getenv("XDG_CONFIG_HOME")) != NULL) {
			len = strlen(dir) + 1 + 9 + 1; /* dir + / + onak.conf + NUL */
			conf = malloc(len);
			snprintf(conf, len, "%s/onak.conf", dir);
			conffile = fopen(conf, "r");
			free(conf);
		} else if ((dir = getenv("HOME")) != NULL) {
			len = strlen(dir) + 18 + 1; /* dir + /.config/onak.conf + NUL */
			conf = malloc(len);
			snprintf(conf, len, "%s/.config/onak.conf", dir);
			conffile = fopen(conf, "r");
			free(conf);
		}
		if (conffile == NULL) {
			conffile = fopen(CONFIGFILE, "r");
		}
	} else {
		conffile = fopen(configfile, "r");
	}
	if (conffile != NULL) {
		if (!fgets(curline, 1023, conffile)) {
			logthing(LOGTHING_CRITICAL,
				"Problem reading configuration file.");
			fclose(conffile);
			return;
		}

		while (!feof(conffile)) {
			for (i = strlen(curline) - 1;
					i >= 0 && isspace(curline[i]);
					i--) {
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
		} else if (!strncmp("loglevel ", curline, 9)) {
			setlogthreshold(atoi(&curline[9]));
		} else if (!strncmp("this_site ", curline, 10)) {
			config.thissite = strdup(&curline[10]);
		} else if (!strncmp("socket_name ", curline, 12) ||
				!strncmp("pks_bin_dir ", curline, 12) ||
				!strncmp("mail_dir ", curline, 9) ||
				!strncmp("www_port ", curline, 9)) {
			/*
			 * Not applicable; ignored for compatibility with pksd.
			 */
		} else if (!strncmp("db_backend ", curline, 11)) {
			config.db_backend = strdup(&curline[11]);
		} else if (!strncmp("backends_dir ", curline, 13)) {
			config.backends_dir = strdup(&curline[13]);
		} else if (!strncmp("use_keyd ", curline, 9)) {
			config.use_keyd = parsebool(&curline[9],
						config.use_keyd);
		} else if (!strncmp("sock_dir ", curline, 9)) {
			config.sock_dir = strdup(&curline[9]);
		} else if (!strncmp("check_sighash ", curline, 9)) {
			config.check_sighash = parsebool(&curline[9],
						config.check_sighash);
		} else {
			logthing(LOGTHING_ERROR,
				"Unknown config line: %s", curline);
		}

			if (!fgets(curline, 1023, conffile) &&
					!feof(conffile)) {
				logthing(LOGTHING_CRITICAL,
					"Problem reading configuration file.");
				break;
			}
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
	if (config.db_backend != NULL) {
		free(config.db_backend);
		config.db_backend = NULL;
	}
	if (config.backends_dir != NULL) {
		free(config.backends_dir);
		config.backends_dir = NULL;
	}
}
