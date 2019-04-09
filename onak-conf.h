/**
 * @file onak-conf.h
 * @brief Routines related to runtime config.
 *
 * Copyright 2002 Jonathan McDowell <noodles@earth.li>
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

#ifndef __ONAK_CONF_H_
#define __ONAK_CONF_H_

#include <stdbool.h>

#include "ll.h"

/**
 * @brief Backend database configuration.
 *
 */
struct onak_db_config {
	/** Name, as used to refer to individual backend instances */
	char *name;
	/** Backend type [e.g. db4, pg, fs, file] */
	char *type;
	/** Location information; directory for file backed, DB name for DBs */
	char *location;
	/** Database backend hostname, if appropriate */
	char *hostname;
	/** Database backend username, if appropriate */
	char *username;
	/** Database backend password, if appropriate */
	char *password;
};

/**
 * @brief Runtime configuration for onak.
 *
 * This structure holds various runtime configuration options for onak. It
 * will eventually be populated from the config file.
 */
struct onak_config {
	/*
	 * Generic options.
	 */
	/** The maximum number of keys a query should return. */
	int maxkeys;
	/** Our email address that servers sync with. */
	char *thissite;
	/** The email address of the server admin. */
	char *adminemail;
	/** The mta to invoke to send sync mails. */
	char *mta;
	/** List of email address for sites we sync with via email */
	struct ll *syncsites;
	/** A linked list of sites we sync with. */
	char *logfile;

	/** Set if we're using keyd as the backend. */
	bool use_keyd;
	/** The path to the directory the keyd socket lives in. */
	char *sock_dir;

	/** List of backend configurations */
	struct ll *backends;

	/* The default backend to use */
	struct onak_db_config *backend;

	/*
	 * Options for the dynamic backend.
	 */
	/** Name of the DB backend we're using */
	char *db_backend;
	/** Directory where backend .so files can be found */
	char *backends_dir;

	/** Pointer to the initialisation function for our loaded DB backend */
	struct onak_dbctx *(*dbinit)(struct onak_db_config *, bool);

	/** Should we verify signature hashes match? */
	bool check_sighash;

	/*
	 * Options used by the email handling script.
	 * None of the C code uses this information, but we should be able
	 * to parse it.
	 */
	/** Location of the onak binary, so the mail script can find it. */
	char *bin_dir;
	/** Where incoming mail gets queue, one file per mail. */
	char *mail_dir;
};

/**
 * @brief The variable containing our runtime config.
 */
extern struct onak_config config;

/**
 * @brief read the onak config.
 * @param configfile the config file to read.
 *
 * Read in our config file. If config file is NULL read in the compile
 * time default.
 */
void readconfig(const char *configfile);

/**
 * @brief write the onak config.
 * @param configfile the config file to write to.
 *
 * Write out the config file. If config file is NULL write it to STDOUT.
 */
void writeconfig(const char *configfile);

/**
 * @brief clean up the config when we're shutting down.
 */
void cleanupconfig(void);


/**
 * @brief Find a specified backend configuration by name.
 */
struct onak_db_config *find_db_backend_config(struct ll *backends, char *name);

#endif /* __ONAK_CONF_H_ */
