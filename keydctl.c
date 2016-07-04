/*
 * keydctl.c - A simple program to control a running keyd instance
 *
 * Copyright 2011 Jonathan McDowell <noodles@earth.li>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "keyd.h"
#include "onak-conf.h"
#include "version.h"

/* HACK: We need to stop onak-conf.o requiring this. */
void *DBINIT = NULL;

static int keyd_fd = -1;
static int verbose = 0;

static int keyd_do_command(enum keyd_ops cmd, void *buf, size_t len)
{
	uint32_t tmp;

	if (keyd_fd < 0) {
		return -1;
	}

	tmp = cmd;
	if (write(keyd_fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
		if (verbose >= 0) {
			fprintf(stderr,
				"Couldn't write keyd command %d: %s (%d)\n",
				cmd, strerror(errno), errno);
		}
		exit(EXIT_FAILURE);
	} else if (read(keyd_fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
		if (verbose >= 0) {
			fprintf(stderr,
				"Couldn't read keyd command %d reply: "
				"%s (%d)\n",
				cmd, strerror(errno), errno);
			}
		exit(EXIT_FAILURE);
	} else if (tmp != KEYD_REPLY_OK) {
		return -1;
	} else if (buf == NULL) {
		return 0;
	} else if (read(keyd_fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
		if (verbose >= 0) {
			fprintf(stderr,
				"Couldn't read keyd command %d reply length: "
				"%s (%d)\n",
				cmd, strerror(errno), errno);
		}
		exit(EXIT_FAILURE);
	} else if (tmp > len) {
		/* TODO: Read what we can into buf and skip the rest */
		return -1;
	} else {
		return read(keyd_fd, buf, tmp);
	}
}

static void keyd_connect(void)
{
	struct sockaddr_un sock;
	uint32_t	   reply = KEYD_REPLY_UNKNOWN_CMD;

	keyd_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (keyd_fd < 0) {
		if (verbose >= 0) {
			fprintf(stderr,
				"Couldn't open socket: %s (%d)\n",
				strerror(errno),
				errno);
		}
		exit(EXIT_FAILURE);
	}

	sock.sun_family = AF_UNIX;
	snprintf(sock.sun_path, sizeof(sock.sun_path) - 1, "%s/%s",
			config.sock_dir,
			KEYD_SOCKET);
	if (connect(keyd_fd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		if (verbose >= 0) {
			fprintf(stderr,
				"Couldn't connect to socket %s: %s (%d)\n",
				sock.sun_path,
				strerror(errno),
				errno);
		}
		exit(EXIT_FAILURE);
	}

	keyd_do_command(KEYD_CMD_VERSION, &reply, sizeof(reply));
	if (reply != keyd_version) {
		if (verbose >= 0) {
			fprintf(stderr, "Error! keyd protocol version "
				"mismatch. (us = %d, it = %d)\n",
				keyd_version, reply);
		}
		exit(EXIT_FAILURE);
	}

	return;
}

static void keyd_close(void)
{
	uint32_t cmd = KEYD_CMD_CLOSE;

	if (write(keyd_fd, &cmd, sizeof(cmd)) != sizeof(cmd) && verbose >= 0) {
		fprintf(stderr, "Couldn't send close cmd: %s (%d)\n",
				strerror(errno),
				errno);
	}

	if (shutdown(keyd_fd, SHUT_RDWR) < 0 && verbose >= 0) {
		fprintf(stderr, "Error shutting down socket: %d\n",
				errno);
	}
	if (close(keyd_fd) < 0 && verbose >= 0) {
		fprintf(stderr, "Error closing down socket: %d\n",
				errno);
	}
	keyd_fd = -1;

	return;

}

static void keyd_status(void)
{
	uint32_t reply;
	struct keyd_stats stats;

	if (keyd_do_command(KEYD_CMD_VERSION, &reply, sizeof(reply)) == -1) {
		printf("Got failure asking for keyd version.\n");
		return;
	}
	printf("Using keyd protocol version %d.\n", reply);

	if (keyd_do_command(KEYD_CMD_STATS, &stats, sizeof(stats)) == -1) {
		printf("Got failure asking for keyd statistics.\n");
		return;
	}

	printf("keyd running since %s", ctime(&stats.started));
	printf("%d client connections received\n", stats.connects);

	printf("Command statistics:\n");
	printf("  Version:          %d\n",
		stats.command_stats[KEYD_CMD_VERSION]);
	printf("  Get key by ID:    %d\n",
		stats.command_stats[KEYD_CMD_GET_ID]);
	printf("  Get key by FP:    %d\n",
		stats.command_stats[KEYD_CMD_GET_FP]);
	printf("  Get key by hash:  %d\n",
		stats.command_stats[KEYD_CMD_GET_SKSHASH]);
	printf("  Store key:        %d\n",
		stats.command_stats[KEYD_CMD_STORE]);
	printf("  Delete key:       %d\n",
		stats.command_stats[KEYD_CMD_DELETE]);
	printf("  Update key:       %d\n",
		stats.command_stats[KEYD_CMD_UPDATE]);
	printf("  Search key:       %d\n",
		stats.command_stats[KEYD_CMD_GET_TEXT]);
	printf("  Get full keyid:   %d\n",
		stats.command_stats[KEYD_CMD_GETFULLKEYID]);
	printf("  Iterate all keys: %d\n",
		stats.command_stats[KEYD_CMD_KEYITER]);
	printf("  Close:            %d\n",
		stats.command_stats[KEYD_CMD_CLOSE]);
	printf("  Quit:             %d\n", stats.command_stats[KEYD_CMD_QUIT]);
	printf("  Get statistics:   %d\n",
		stats.command_stats[KEYD_CMD_STATS]);
	printf("  Unknown:          %d\n",
		stats.command_stats[KEYD_CMD_UNKNOWN]);

	return;
}

static void usage(void)
{
	puts("keydctl " ONAK_VERSION " - control an onak keyd instance.\n");
	puts("Usage:\n");
	puts("\tkeydctl [options] <command> <parameters>\n");
	puts("\tCommands:\n");
	puts("\tcheck    - check if keyd is running");
	puts("\tquit     - request that keyd cleanly shuts down");
	puts("\tstatus   - display running keyd status");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int	 optchar;
	char	*configfile = NULL;

	while ((optchar = getopt(argc, argv, "c:h")) != -1 ) {
		switch (optchar) {
		case 'c':
			configfile = strdup(optarg);
			break;
		case 'h':
		default:
			usage();
			break;
		}
	}

	readconfig(configfile);
	free(configfile);
	configfile = NULL;

	if ((argc - optind) < 1) {
		cleanupconfig();
		usage();
	} else if (!strcmp("check", argv[optind])) {
		/* Just do the connect and close quietly */
		verbose = -1;
		keyd_connect();
		keyd_close();
	} else if (!strcmp("status", argv[optind])) {
		keyd_connect();
		keyd_status();
		keyd_close();
	} else if (!strcmp("quit", argv[optind])) {
		keyd_connect();
		keyd_do_command(KEYD_CMD_QUIT, NULL, 0);
		keyd_close();
	} else {
		cleanupconfig();
		usage();
	}

	cleanupconfig();

	exit(EXIT_SUCCESS);
}
