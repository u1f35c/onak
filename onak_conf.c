/*
 * onak_conf.c - Routines related to runtime config.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 2002 Project Purple
 */

#include <stdlib.h>

#include "onak_conf.h"

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
	NULL,			/* db2_dbpath */

	/*
	 * Options for the file backend.
	 */
	NULL,			/* file_dbpath */
	
	/*
	 * Options for the Postgres backend.
	 */
	NULL,			/* pg_dbhost */
	NULL,			/* pg_dbname */
	"noodles",		/* pg_dbuser */
	NULL,			/* pg_dbpass */
};
