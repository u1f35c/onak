/*
 * onak-conf.c - Routines related to runtime config.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <stdlib.h>

#include "onak-conf.h"

/*
 *	config - Runtime configuration for onak.
 *
 *	Currently this is all hardcoded, but only needs changed here. In future
 *	it'll be read from a config file.
 */
struct onak_config config = {
	128,			/* maxkeys */

	/*
	 * Options for the db2 file backend.
	 */
	"/home/noodles/onak-db",	/* db2_dbpath */

	/*
	 * Options for the file backend.
	 */
	"/home/noodles/projects/onak/db",	/* file_dbpath */
	
	/*
	 * Options for the Postgres backend.
	 */
	NULL,			/* pg_dbhost */
	"noodles",		/* pg_dbname */
	NULL,			/* pg_dbuser */
	NULL,			/* pg_dbpass */
};
