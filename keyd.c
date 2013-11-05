/*
 * keyd.c - key retrieval daemon
 *
 * Copyright 2004,2011 Jonathan McDowell <noodles@earth.li>
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
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "charfuncs.h"
#include "cleanup.h"
#include "keyd.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "version.h"

/* Maximum number of clients we're prepared to accept at once */
#define MAX_CLIENTS 16

static struct keyd_stats *stats;

void daemonize(void)
{
	pid_t pid;

	pid = fork();

	if (pid < 0) {
		logthing(LOGTHING_CRITICAL,
			"Failed to fork into background: %d (%s)",
			errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		logthing(LOGTHING_INFO, "Backgrounded as pid %d.", pid);
		exit(EXIT_SUCCESS);
	}

	pid = setsid();

	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);

	return;
}

void iteratefunc(void *ctx, struct openpgp_publickey *key)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct buffer_ctx           storebuf;
	int                         ret = 0;
	int                         *fd = (int *) ctx;
	uint64_t                    keyid;

	if (key != NULL) {
		storebuf.offset = 0;
		storebuf.size = 8192;
		storebuf.buffer = malloc(8192);

		get_keyid(key, &keyid);
		logthing(LOGTHING_TRACE,
				"Iterating over 0x%016" PRIX64 ".",
				keyid);

		flatten_publickey(key,
				&packets,
				&list_end);
		write_openpgp_stream(buffer_putchar,
				&storebuf,
				packets);
		logthing(LOGTHING_TRACE,
				"Sending %d bytes.",
				storebuf.offset);
		ret = write(*fd, &storebuf.offset,
			sizeof(storebuf.offset));
		if (ret != 0) {
			write(*fd, storebuf.buffer,
				storebuf.offset);
		}

		free(storebuf.buffer);
		storebuf.buffer = NULL;
		storebuf.size = storebuf.offset = 0;
		free_packet_list(packets);
		packets = list_end = NULL;
	}

	return;
}

int sock_init(const char *sockname)
{
	struct sockaddr_un sock;
	int                fd = -1;
	int                ret = -1;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd != -1) {
		ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	}

	if (ret != -1) {
		sock.sun_family = AF_UNIX;
		strncpy(sock.sun_path, sockname, sizeof(sock.sun_path) - 1);
		unlink(sockname);
		ret = bind(fd, (struct sockaddr *) &sock, sizeof(sock));
	}

	if (ret != -1) {
		ret = listen(fd, 5);
	}
	
	return fd;
}

int sock_do(int fd)
{
	uint32_t cmd = KEYD_CMD_UNKNOWN;
	ssize_t  bytes = 0;
	ssize_t  count = 0;
	int	 ret = 0;
	uint64_t keyid = 0;
	uint8_t  fp[MAX_FINGERPRINT_LEN];
	char     *search = NULL;
	struct openpgp_publickey *key = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct buffer_ctx storebuf;
	struct skshash hash;

	/*
	 * Get the command from the client.
	 */
	bytes = read(fd, &cmd, sizeof(cmd));

	logthing(LOGTHING_DEBUG, "Read %d bytes, command: %d", bytes, cmd);

	if (bytes != sizeof(cmd)) {
		ret = 1;
	}
	
	if (ret == 0) {
		if (cmd < KEYD_CMD_LAST) {
			stats->command_stats[cmd]++;
		} else {
			stats->command_stats[KEYD_CMD_UNKNOWN]++;
		}
		switch (cmd) {
		case KEYD_CMD_VERSION:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			cmd = sizeof(keyd_version);
			write(fd, &cmd, sizeof(cmd));
			write(fd, &keyd_version, sizeof(keyd_version));
			break;
		case KEYD_CMD_GET_ID:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			bytes = read(fd, &keyid, sizeof(keyid));
			if (bytes != sizeof(keyid)) {
				ret = 1;
			}
			storebuf.offset = 0;
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching 0x%" PRIX64
						", result: %d",
						keyid,
						config.dbbackend->
						fetch_key_id(keyid,
							&key, false));
				if (key != NULL) {
					storebuf.size = 8192;
					storebuf.buffer = malloc(8192);

					flatten_publickey(key,
							&packets,
							&list_end);
					write_openpgp_stream(buffer_putchar,
							&storebuf,
							packets);
					logthing(LOGTHING_TRACE,
							"Sending %d bytes.",
							storebuf.offset);
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
					write(fd, storebuf.buffer,
						storebuf.offset);

					free(storebuf.buffer);
					storebuf.buffer = NULL;
					storebuf.size = storebuf.offset = 0;
					free_packet_list(packets);
					packets = list_end = NULL;
					free_publickey(key);
					key = NULL;
				} else {
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
				}
			}
			break;
		case KEYD_CMD_GET_FP:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			read(fd, &bytes, 1);
			if (bytes > MAX_FINGERPRINT_LEN) {
				ret = 1;
			} else {
				read(fd, fp, bytes);
			}
			storebuf.offset = 0;
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching by fingerprint"
						", result: %d",
						config.dbbackend->
						fetch_key_fp(fp, bytes,
							&key, false));
				if (key != NULL) {
					storebuf.size = 8192;
					storebuf.buffer = malloc(8192);

					flatten_publickey(key,
							&packets,
							&list_end);
					write_openpgp_stream(buffer_putchar,
							&storebuf,
							packets);
					logthing(LOGTHING_TRACE,
							"Sending %d bytes.",
							storebuf.offset);
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
					write(fd, storebuf.buffer,
						storebuf.offset);

					free(storebuf.buffer);
					storebuf.buffer = NULL;
					storebuf.size = storebuf.offset = 0;
					free_packet_list(packets);
					packets = list_end = NULL;
					free_publickey(key);
					key = NULL;
				} else {
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
				}
			}
			break;

		case KEYD_CMD_GET_TEXT:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			bytes = read(fd, &count, sizeof(count));
			if (bytes != sizeof(count)) {
				ret = 1;
			}
			storebuf.offset = 0;
			if (ret == 0) {
				search = malloc(count+1);
				read(fd, search, count);
				search[count] = 0;
				logthing(LOGTHING_INFO,
						"Fetching %s, result: %d",
						search,
						config.dbbackend->
						fetch_key_text(search, &key));
				if (key != NULL) {
					storebuf.size = 8192;
					storebuf.buffer = malloc(8192);

					flatten_publickey(key,
							&packets,
							&list_end);
					write_openpgp_stream(buffer_putchar,
							&storebuf,
							packets);
					logthing(LOGTHING_TRACE,
							"Sending %d bytes.",
							storebuf.offset);
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
					write(fd, storebuf.buffer,
						storebuf.offset);

					free(storebuf.buffer);
					storebuf.buffer = NULL;
					storebuf.size = storebuf.offset = 0;
					free_packet_list(packets);
					packets = list_end = NULL;
					free_publickey(key);
					key = NULL;
				} else {
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
				}
				free(search);
			}
			break;
		case KEYD_CMD_STORE:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			storebuf.offset = 0;
			bytes = read(fd, &storebuf.size,
					sizeof(storebuf.size));
			logthing(LOGTHING_TRACE, "Reading %d bytes.",
					storebuf.size);
			if (bytes != sizeof(storebuf.size)) {
				ret = 1;
			}
			if (ret == 0 && storebuf.size > 0) {
				storebuf.buffer = malloc(storebuf.size);
				bytes = count = 0;
				while (bytes >= 0 && count < storebuf.size) {
					bytes = read(fd,
						&storebuf.buffer[count],
						storebuf.size - count);
					logthing(LOGTHING_TRACE,
							"Read %d bytes.",
							bytes);
					count += bytes;
				}
				read_openpgp_stream(buffer_fetchchar,
						&storebuf,
						&packets,
						0);
				parse_keys(packets, &key);
				config.dbbackend->store_key(key, false, false);
				free_packet_list(packets);
				packets = NULL;
				free_publickey(key);
				key = NULL;
				free(storebuf.buffer);
				storebuf.buffer = NULL;
				storebuf.size = storebuf.offset = 0;
			}
			break;
		case KEYD_CMD_DELETE:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			bytes = read(fd, &keyid, sizeof(keyid));
			if (bytes != sizeof(keyid)) {
				ret = 1;
			}
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Deleting 0x%" PRIX64
						", result: %d",
						keyid,
						config.dbbackend->delete_key(
							keyid, false));
			}
			break;
		case KEYD_CMD_GETFULLKEYID:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			bytes = read(fd, &keyid, sizeof(keyid));
			if (bytes != sizeof(keyid)) {
				ret = 1;
			}
			if (ret == 0) {
				keyid = config.dbbackend->getfullkeyid(keyid);
				cmd = sizeof(keyid);
				write(fd, &cmd, sizeof(cmd));
				write(fd, &keyid, sizeof(keyid));
			}
			break;
		case KEYD_CMD_KEYITER:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			config.dbbackend->iterate_keys(iteratefunc,
					&fd);
			bytes = 0;
			write(fd, &bytes, sizeof(bytes));
			break;
		case KEYD_CMD_CLOSE:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			ret = 1;
			break;
		case KEYD_CMD_QUIT:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			logthing(LOGTHING_NOTICE,
				"Exiting due to quit request.");
			ret = 1;
			trytocleanup();
			break;
		case KEYD_CMD_STATS:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			cmd = sizeof(*stats);
			write(fd, &cmd, sizeof(cmd));
			write(fd, stats,
				sizeof(*stats));
			break;
		case KEYD_CMD_GET_SKSHASH:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			bytes = read(fd, hash.hash, sizeof(hash.hash));
			if (bytes != sizeof(hash.hash)) {
				ret = 1;
			}
			storebuf.offset = 0;
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching by hash"
						", result: %d",
						config.dbbackend->
						fetch_key_skshash(&hash,
							&key));
				if (key != NULL) {
					storebuf.size = 8192;
					storebuf.buffer = malloc(8192);

					flatten_publickey(key,
							&packets,
							&list_end);
					write_openpgp_stream(buffer_putchar,
							&storebuf,
							packets);
					logthing(LOGTHING_TRACE,
							"Sending %d bytes.",
							storebuf.offset);
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
					write(fd, storebuf.buffer,
						storebuf.offset);

					free(storebuf.buffer);
					storebuf.buffer = NULL;
					storebuf.size = storebuf.offset = 0;
					free_packet_list(packets);
					packets = list_end = NULL;
					free_publickey(key);
					key = NULL;
				} else {
					write(fd, &storebuf.offset,
						sizeof(storebuf.offset));
				}
			}
			break;

		default:
			logthing(LOGTHING_ERROR, "Got unknown command: %d",
					cmd);
			cmd = KEYD_REPLY_UNKNOWN_CMD;
			write(fd, &cmd, sizeof(cmd));
		}
	}

	return(ret);
}

int sock_close(int fd)
{
	shutdown(fd, SHUT_RDWR);
	return close(fd);
}

int sock_accept(int fd)
{
	struct sockaddr_un sock;
	socklen_t          socklen;
	int    srv = -1;
	int    ret = -1;

	socklen = sizeof(sock);
	srv = accept(fd, (struct sockaddr *) &sock, &socklen);
	if (srv != -1) {
		ret = fcntl(srv, F_SETFD, FD_CLOEXEC);
	}

	if (ret != -1) {
		stats->connects++;
	}

	return (srv);
}

static void usage(void)
{
	puts("keyd " ONAK_VERSION " - backend key serving daemon for the "
		"onak PGP keyserver.\n");
	puts("Usage:\n");
	puts("\tkeyd [options]\n");
	puts("\tOptions:\n:");
	puts("-c <file> - use <file> as the config file");
	puts("-f        - run in the foreground");
	puts("-h        - show this help text");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int fd = -1, maxfd, i, clients[MAX_CLIENTS];
	fd_set rfds;
	char sockname[1024];
	char *configfile = NULL;
	bool foreground = false;
	int optchar;

	while ((optchar = getopt(argc, argv, "c:fh")) != -1 ) {
		switch (optchar) {
		case 'c':
			configfile = strdup(optarg);
			break;
		case 'f':
			foreground = true;
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
	initlogthing("keyd", config.logfile);
	config.use_keyd = false;

	if (!foreground) {
		daemonize();
	}

	catchsignals();
	signal(SIGPIPE, SIG_IGN);


	stats = calloc(1, sizeof(*stats));
	if (!stats) {
		logthing(LOGTHING_ERROR,
			"Couldn't allocate memory for stats structure.");
		exit(EXIT_FAILURE);
	}
	stats->started = time(NULL);

	snprintf(sockname, 1023, "%s/%s", config.db_dir, KEYD_SOCKET);
	fd = sock_init(sockname);

	if (fd != -1) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		maxfd = fd;
		memset(clients, -1, sizeof (clients));

		config.dbbackend->initdb(false);

		logthing(LOGTHING_NOTICE, "Accepting connections.");
		while (!cleanup() && select(maxfd + 1, &rfds, NULL, NULL, NULL) != -1) {
			/*
			 * Deal with existing clients first; if we're at our
			 * connection limit then processing them might free
			 * things up and let us accept the next client below.
			 */
			for (i = 0; i < MAX_CLIENTS; i++) {
				if (clients[i] != -1 &&
						FD_ISSET(clients[i], &rfds)) {
					logthing(LOGTHING_DEBUG,
						"Handling connection for client %d.", i);
					if (sock_do(clients[i])) {
						sock_close(clients[i]);
						clients[i] = -1;
						logthing(LOGTHING_DEBUG,
							"Closed connection for client %d.", i);
					}
				}
			}
			/*
			 * Check if we have a new incoming connection to accept.
			 */
			if (FD_ISSET(fd, &rfds)) {
				for (i = 0; i < MAX_CLIENTS; i++) {
					if (clients[i] == -1) {
						break;
					}
				}
				if (i < MAX_CLIENTS) {
					logthing(LOGTHING_INFO,
						"Accepted connection %d.", i);
					clients[i] = sock_accept(fd);
				}
			}
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			maxfd = fd;
			for (i = 0; i < MAX_CLIENTS; i++) {
				if (clients[i] != -1) {
					FD_SET(clients[i], &rfds);
					maxfd = (maxfd > clients[i]) ?
							maxfd : clients[i];
				}
			}
		}
		config.dbbackend->cleanupdb();
		sock_close(fd);
		unlink(sockname);
	}

	free(stats);

	cleanuplogthing();
	cleanupconfig();

	return(EXIT_SUCCESS);
}
