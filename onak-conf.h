/*
 * onak-conf.h - Routines related to runtime config.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __ONAK_CONF_H_
#define __ONAK_CONF_H_

#include "keydb.h"

/*
 *	struct onak_config - Runtime configuration for onak.
 *	@maxkeys: The maximum number of keys a query should return.
 *	@thissite: Our email address that servers sync with.
 *	@adminemail: The email address of the server admin.
 *	@mta: The mta to invoke to send sync mails.
 *	@syncsites: A linked list of sites we sync with.
 *
 * 	@db_dir: The path to the directory containing the database files.
 * 
 *	@pg_dbhost: The host that Postgres is running on.
 *	@pg_dbname: The database name.
 *	@pg_dbuser: The user we should connect as.
 *	@pg_dbpass: The password for the user.
 *
 *	This structure holds various runtime configuration options for onak. It
 *	will eventually be populated from the config file.
 */
struct onak_config {
	/*
	 * Generic options.
	 */
	int maxkeys;
	char *thissite;
	char *adminemail;
	char *mta;
	struct ll *syncsites;
	char *logfile;

	/*
	 * Options for any database backend that needs a directory, be it the
	 * file, db2 or db3 options.
	 */
	char *db_dir;
	
	/*
	 * Options for the Postgres backend.
	 */
	char *pg_dbhost;
	char *pg_dbname;
	char *pg_dbuser;
	char *pg_dbpass;

	/*
	 * Options for the dynamic backend.
	 */
	char *db_backend;
	char *backends_dir;

	struct dbfuncs *dbbackend;
};

/*
 *	config - The variable containing our runtime config.
 */
extern struct onak_config config;

/*
 *	readconfig - read the onak config.
 *	@configfile - the config file to read.
 *
 *	Read in our config file. If config file is NULL read in the compile
 *	time default.
 */
void readconfig(const char *configfile);

/*
 *	cleanupconfig - clean up the config when we're shutting down.
 */
void cleanupconfig(void);

#endif /* __ONAK_CONF_H_ */
