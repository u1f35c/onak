/*
 * onak-conf.h - Routines related to runtime config.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#ifndef __ONAK_CONF_H_
#define __ONAK_CONF_H_

#define VERSION "0.0.3"

/*
 *	struct onak_config - Runtime configuration for onak.
 *	@maxkeys: The maximum number of keys a query should return.
 *
 * 	@db2_dbpath: The path to the directory containing the db2 files.
 * 
 *	@file_dbpath: The path to the flat file DB directory.
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
	int maxkeys;

	/*
	 * Options for the db2 file backend.
	 */
	char *db2_dbpath;

	/*
	 * Options for the file backend.
	 */
	char *file_dbpath;
	
	/*
	 * Options for the Postgres backend.
	 */
	char *pg_dbhost;
	char *pg_dbname;
	char *pg_dbuser;
	char *pg_dbpass;
};

/*
 *	config - The variable containing our runtime config.
 */
extern struct onak_config config;

#endif /* __ONAK_CONF_H_ */
