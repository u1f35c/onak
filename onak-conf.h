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

#include "keydb.h"

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

	/*
	 * Options for any database backend that needs a directory, be it the
	 * file, db2 or db3 options.
	 */
	/** The path to the directory containing the database files. */
	char *db_dir;
	
	/*
	 * Options for the Postgres backend.
	 */
	/** The host that Postgres is running on. */
	char *pg_dbhost;
	/** The database name. */
	char *pg_dbname;
	/** The user we should connect as. */
	char *pg_dbuser;
	/** The password for the user. */
	char *pg_dbpass;

	/*
	 * Options for the dynamic backend.
	 */
	/** Name of the DB backend we're using */
	char *db_backend;
	/** Directory where backend .so files can be found */
	char *backends_dir;

	/** Pointer to the function table for our loaded DB backend */
	struct dbfuncs *dbbackend;

	/** Should we verify signature hashes match? */
	bool check_sighash;
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
 * @brief clean up the config when we're shutting down.
 */
void cleanupconfig(void);

#endif /* __ONAK_CONF_H_ */
