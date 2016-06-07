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

extern struct onak_dbctx *DBINIT(struct onak_db_config *dbcfg, bool readonly);

/*
 *	config - Runtime configuration for onak.
 *
 *	This is the default config; normally overridden with values from the
 *	config file.
 */
struct onak_config config = {
	.maxkeys = 128,
	.thissite = NULL,
	.adminemail = NULL,
	.mta = NULL,
	.syncsites = NULL,
	.logfile = NULL,

	.use_keyd = false,
	.sock_dir = NULL,

	.backends = NULL,
	.backends_dir = NULL,

	.dbinit = DBINIT,

	.check_sighash = true,

	.bin_dir = NULL,
	.mail_dir = NULL,
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

static bool parseconfigline(char *line)
{
	if (line[0] == '#' || line[0] == 0) {
		/*
		 * Comment line, ignore.
		 */
	} else if (!strncmp("db_dir ", line, 7)) {
		config.backend->location = strdup(&line[7]);
	} else if (!strncmp("debug ", line, 6)) {
		/*
		 * Not supported yet; ignore for compatibility with
		 * pksd.
		 */
	} else if (!strncmp("default_language ", line, 17)) {
		/*
		 * Not supported yet; ignore for compatibility with
		 * pksd.
		 */
	} else if (!strncmp("mail_delivery_client ", line, 21)) {
		config.mta = strdup(&line[21]);
	} else if (!strncmp("maintainer_email ", line, 17)) {
		config.adminemail = strdup(&line[17]);
	} else if (!strncmp("mail_intro_file ", line, 16)) {
		/*
		 * Not supported yet; ignore for compatibility with
		 * pksd.
		 */
	} else if (!strncmp("help_dir ", line, 9)) {
		/*
		 * Not supported yet; ignore for compatibility with
		 * pksd.
		 */
	} else if (!strncmp("max_last ", line, 9)) {
		/*
		 * Not supported yet; ignore for compatibility with
		 * pksd.
		 */
	} else if (!strncmp("max_reply_keys ", line, 15)) {
		config.maxkeys = atoi(&line[15]);
	} else if (!strncmp("pg_dbhost ", line, 10)) {
		config.backend->hostname = strdup(&line[10]);
	} else if (!strncmp("pg_dbname ", line, 10)) {
		config.backend->location = strdup(&line[10]);
	} else if (!strncmp("pg_dbuser ", line, 10)) {
		config.backend->username = strdup(&line[10]);
	} else if (!strncmp("pg_dbpass ", line, 10)) {
		config.backend->password = strdup(&line[10]);
	} else if (!strncmp("syncsite ", line, 9)) {
		config.syncsites =
			lladd(config.syncsites, strdup(&line[9]));
	} else if (!strncmp("logfile ", line, 8)) {
		config.logfile = strdup(&line[8]);
	} else if (!strncmp("loglevel ", line, 9)) {
		setlogthreshold(atoi(&line[9]));
	} else if (!strncmp("this_site ", line, 10)) {
		config.thissite = strdup(&line[10]);
	} else if (!strncmp("socket_name ", line, 12) ||
			!strncmp("www_port ", line, 9)) {
		/*
		 * Not applicable; ignored for compatibility with pksd.
		 */
	} else if (!strncmp("pks_bin_dir ", line, 12)) {
		config.bin_dir = strdup(&line[12]);
	} else if (!strncmp("mail_dir ", line, 9)) {
		config.mail_dir = strdup(&line[9]);
	} else if (!strncmp("db_backend ", line, 11)) {
		config.backend->type = strdup(&line[11]);
		config.backend->name = strdup(&line[11]);
		config.db_backend = strdup(&line[11]);
	} else if (!strncmp("backends_dir ", line, 13)) {
		config.backends_dir = strdup(&line[13]);
	} else if (!strncmp("use_keyd ", line, 9)) {
		config.use_keyd = parsebool(&line[9],
					config.use_keyd);
	} else if (!strncmp("sock_dir ", line, 9)) {
		config.sock_dir = strdup(&line[9]);
	} else if (!strncmp("check_sighash ", line, 9)) {
		config.check_sighash = parsebool(&line[9],
					config.check_sighash);
	} else {
		return false;
	}

	return true;
}

void readconfig(const char *configfile) {
	FILE *conffile;
	char  curline[1024];
	int   i;
	char *dir, *conf;
	size_t len;
	struct onak_db_config *backend;

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

		/* Add a single DB configuration */
		backend = calloc(1, sizeof(*backend));
		config.backend = backend;
		config.backends = lladd(NULL, backend);

		while (!feof(conffile)) {
			/* Strip any trailing white space */
			for (i = strlen(curline) - 1;
					i >= 0 && isspace(curline[i]);
					i--) {
				curline[i] = 0;
			}

			/* Strip any leading white space */
			i = 0;
			while (curline[i] != 0 && isspace(curline[i])) {
				i++;
			}

			if (!parseconfigline(&curline[i])) {
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

void cleanupdbconfig(void *object)
{
	struct onak_db_config *dbconfig = (struct onak_db_config *) object;

	if (dbconfig->name != NULL) {
		free(dbconfig->name);
		dbconfig->name = NULL;
	}
	if (dbconfig->type != NULL) {
		free(dbconfig->type);
		dbconfig->type = NULL;
	}
	if (dbconfig->location != NULL) {
		free(dbconfig->location);
		dbconfig->location = NULL;
	}
	if (dbconfig->hostname != NULL) {
		free(dbconfig->hostname);
		dbconfig->hostname = NULL;
	}
	if (dbconfig->username != NULL) {
		free(dbconfig->username);
		dbconfig->username = NULL;
	}
	if (dbconfig->password != NULL) {
		free(dbconfig->password);
		dbconfig->password = NULL;
	}

	free(dbconfig);
}

void cleanupconfig(void) {
	/* Free any defined DB backend configuration first */
	llfree(config.backends, cleanupdbconfig);
	config.backends = NULL;

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
	if (config.sock_dir != NULL) {
		free(config.sock_dir);
		config.sock_dir = NULL;
	}
	if (config.bin_dir != NULL) {
		free(config.bin_dir);
		config.bin_dir = NULL;
	}
	if (config.mail_dir != NULL) {
		free(config.mail_dir);
		config.mail_dir = NULL;
	}
}
