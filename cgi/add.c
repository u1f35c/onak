/*
 * add.c - CGI to add keys.
 *
 * Copyright 2002-2004,2007-2008 Jonathan McDowell <noodles@earth.li>
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
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armor.h"
#include "cleankey.h"
#include "cleanup.h"
#include "charfuncs.h"
#include "getcgi.h"
#include "keydb.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"

int main(int argc, char *argv[])
{
	struct openpgp_packet_list  *packets = NULL;
	struct openpgp_publickey    *keys = NULL;
	char                       **params = NULL;
	struct buffer_ctx            ctx;
	int                          count = 0;
	int                          i;
	struct onak_dbctx           *dbctx;

	memset(&ctx, 0, sizeof(ctx));

	params = getcgivars(argc, argv);
	for (i = 0; params != NULL && params[i] != NULL; i += 2) {
		if (!strcmp(params[i], "keytext")) {
			ctx.buffer = params[i+1];
			ctx.size = strlen(ctx.buffer);
		} else {
			free(params[i+1]);
		}
		params[i+1] = NULL;
		free(params[i]);
		params[i] = NULL;
	}
	if (params != NULL) {
		free(params);
		params = NULL;
	}

	start_html("onak : Add");
	if (ctx.buffer == NULL) {
		puts("Error: No keytext to add supplied.");
		end_html();
	} else {
		readconfig(NULL);
		initlogthing("add", config.logfile);
		dearmor_openpgp_stream(buffer_fetchchar,
					&ctx,
					&packets);
		if (packets != NULL) {
			count = parse_keys(packets, &keys);
			logthing(LOGTHING_NOTICE, "Received %d keys.",
				count);
			printf("Key block added to key server database.\n");
			printf("  New public keys added: %d\n", count);
			end_html();
			if (stdout != NULL && fileno(stdout) != -1) {
				fclose(stdout);
			}
			if (stderr != NULL && stderr != stdout &&
					fileno(stderr) != -1) {
				fclose(stderr);
			}
			catchsignals();
			dbctx = config.dbinit(config.backend, false);
			
			count = cleankeys(dbctx, &keys, config.clean_policies);
			logthing(LOGTHING_INFO, "%d keys cleaned.",
					count);

			count = dbctx->update_keys(dbctx, &keys,
				&config.blacklist,
				config.clean_policies & ONAK_CLEAN_UPDATE_ONLY,
				true);
			logthing(LOGTHING_NOTICE, "Got %d new keys.",
				count);

			if (keys != NULL) {
				free_publickey(keys);
				keys = NULL;
			}
			
			dbctx->cleanupdb(dbctx);
		} else {
			puts("No OpenPGP packets found in input.");
			end_html();
		}
		cleanuplogthing();
		cleanupconfig();
	}
	return (EXIT_SUCCESS);
}
