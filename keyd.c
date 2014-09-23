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

#include "config.h"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

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

#ifdef HAVE_SYSTEMD
static bool using_socket_activation = false;
#endif

static struct keyd_stats *stats;

static void daemonize(void)
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

	if (setsid() == -1) {
		logthing(LOGTHING_CRITICAL,
			"Couldn't set process group leader: %d (%s)",
			errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!freopen("/dev/null", "r", stdin)) {
		logthing(LOGTHING_CRITICAL,
			"Couldn't reopen stdin to NULL: %d (%s)",
			errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!freopen("/dev/null", "w", stdout)) {
		logthing(LOGTHING_CRITICAL,
			"Couldn't reopen stdout to NULL: %d (%s)",
			errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!freopen("/dev/null", "w", stderr)) {
		logthing(LOGTHING_CRITICAL,
			"Couldn't reopen stderr to NULL: %d (%s)",
			errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

static bool keyd_write_key(int fd, struct openpgp_publickey *key)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct buffer_ctx           storebuf;
	ssize_t written;
	bool    ok = true;

	storebuf.offset = 0;
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
	written = write(fd, &storebuf.offset,
			sizeof(storebuf.offset));
	if (written == 0) {
		ok = false;
	} else {
		written = write(fd, storebuf.buffer,
			storebuf.offset);
		if (written != storebuf.offset) {
			ok = false;
		}
	}

	free(storebuf.buffer);
	storebuf.buffer = NULL;
	storebuf.size = storebuf.offset = 0;
	free_packet_list(packets);
	packets = list_end = NULL;

	return (ok);
}

static bool keyd_write_reply(int fd, enum keyd_reply _reply)
{
	uint32_t reply = _reply;
	ssize_t written;
	bool ok = true;

	written = write(fd, &reply, sizeof(reply));
	if (written != sizeof(reply)) {
		ok = false;
	}

	return (ok);
}

static bool keyd_write_size(int fd, size_t size)
{
	ssize_t written;
	bool ok = true;

	written = write(fd, &size, sizeof(size));
	if (written != sizeof(size)) {
		ok = false;
	}

	return (ok);
}

static void iteratefunc(void *ctx, struct openpgp_publickey *key)
{
	int      *fd = (int *) ctx;
	uint64_t  keyid;

	if (key != NULL) {
		get_keyid(key, &keyid);
		logthing(LOGTHING_TRACE,
				"Iterating over 0x%016" PRIX64 ".",
				keyid);

		keyd_write_key(*fd, key);
	}

	return;
}

static int sock_init(const char *sockname)
{
	struct sockaddr_un sock;
	int                fd = -1;
	int                ret = -1;
#ifdef HAVE_SYSTEMD
	int                n;

	n = sd_listen_fds(0);
	if (n > 1) {
		logthing(LOGTHING_ERROR,
			"Too many file descriptors received from systemd.");
	} else if (n == 1) {
		fd = SD_LISTEN_FDS_START + 0;
		if (sd_is_socket_unix(fd, SOCK_STREAM, 1, NULL, 0) <= 0) {
			logthing(LOGTHING_ERROR,
				"systemd passed an invalid socket.");
			fd = -1;
		}
		using_socket_activation = true;
	} else {
#endif
		fd = socket(PF_UNIX, SOCK_STREAM, 0);
		if (fd != -1) {
			ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
		}

		if (ret != -1) {
			sock.sun_family = AF_UNIX;
			strncpy(sock.sun_path, sockname,
					sizeof(sock.sun_path) - 1);
			unlink(sockname);
			ret = bind(fd, (struct sockaddr *) &sock,
					sizeof(sock));
		}

		if (ret != -1) {
			ret = listen(fd, 5);
			if (ret == -1) {
				close(fd);
				fd = -1;
			}
		}
#ifdef HAVE_SYSTEMD
	}
#endif

	return fd;
}

static int sock_do(struct onak_dbctx *dbctx, int fd)
{
	uint32_t cmd = KEYD_CMD_UNKNOWN;
	ssize_t  bytes = 0;
	ssize_t  count = 0;
	int	 ret = 0;
	uint64_t keyid = 0;
	char     *search = NULL;
	struct openpgp_publickey *key = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct buffer_ctx storebuf;
	struct skshash hash;
	struct openpgp_fingerprint fingerprint;

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
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				cmd = sizeof(keyd_version);
				bytes = write(fd, &cmd, sizeof(cmd));
				if (bytes != sizeof(cmd)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				bytes = write(fd, &keyd_version,
					sizeof(keyd_version));
				if (bytes != sizeof(keyd_version)) {
					ret = 1;
				}
			}
			break;
		case KEYD_CMD_GET_ID:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				bytes = read(fd, &keyid, sizeof(keyid));
				if (bytes != sizeof(keyid)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching 0x%" PRIX64
						", result: %d",
						keyid,
						dbctx->fetch_key_id(dbctx,
							keyid,
							&key, false));
				if (key != NULL) {
					keyd_write_key(fd, key);
					free_publickey(key);
					key = NULL;
				} else {
					if (!keyd_write_size(fd, 0)) {
						ret = 1;
					}
				}
			}
			break;
		case KEYD_CMD_GET_FP:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				if ((read(fd, &bytes, 1) != 1) ||
						(bytes > MAX_FINGERPRINT_LEN)) {
					ret = 1;
				} else {
					fingerprint.length = bytes;
					bytes = read(fd, fingerprint.fp,
						fingerprint.length);
					if (bytes != fingerprint.length) {
						ret = 1;
					}
				}
			}
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching by fingerprint"
						", result: %d",
						dbctx->fetch_key_fp(dbctx,
							&fingerprint,
							&key, false));
				if (key != NULL) {
					keyd_write_key(fd, key);
					free_publickey(key);
					key = NULL;
				} else {
					if (!keyd_write_size(fd, 0)) {
						ret = 1;
					}
				}
			}
			break;

		case KEYD_CMD_GET_TEXT:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				bytes = read(fd, &count, sizeof(count));
				if (bytes != sizeof(count)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				search = malloc(count+1);
				bytes = read(fd, search, count);
				if (bytes != count) {
					ret = 1;
					free(search);
					break;
				}
				search[count] = 0;
				logthing(LOGTHING_INFO,
						"Fetching %s, result: %d",
						search,
						dbctx->fetch_key_text(dbctx,
							search, &key));
				if (key != NULL) {
					keyd_write_key(fd, key);
					free_publickey(key);
					key = NULL;
				} else {
					if (!keyd_write_size(fd, 0)) {
						ret = 1;
					}
				}
				free(search);
			}
			break;
		case KEYD_CMD_STORE:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				bytes = read(fd, &storebuf.size,
					sizeof(storebuf.size));
				logthing(LOGTHING_TRACE, "Reading %d bytes.",
					storebuf.size);
				if (bytes != sizeof(storebuf.size)) {
					ret = 1;
				}
			}
			if (ret == 0 && storebuf.size > 0) {
				storebuf.buffer = malloc(storebuf.size);
				storebuf.offset = 0;
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
				dbctx->store_key(dbctx, key, false, false);
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
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				bytes = read(fd, &keyid, sizeof(keyid));
				if (bytes != sizeof(keyid)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Deleting 0x%" PRIX64
						", result: %d",
						keyid,
						dbctx->delete_key(dbctx,
							keyid, false));
			}
			break;
		case KEYD_CMD_GETFULLKEYID:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				bytes = read(fd, &keyid, sizeof(keyid));
				if (bytes != sizeof(keyid)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				keyid = dbctx->getfullkeyid(dbctx, keyid);
				cmd = sizeof(keyid);
				bytes = write(fd, &cmd, sizeof(cmd));
				if (bytes != sizeof(cmd)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				bytes = write(fd, &keyid, sizeof(keyid));
				if (bytes != sizeof(keyid)) {
					ret = 1;
				}
			}
			break;
		case KEYD_CMD_KEYITER:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				dbctx->iterate_keys(dbctx, iteratefunc,
					&fd);
				if (!keyd_write_size(fd, 0)) {
					ret = 1;
				}
			}
			break;
		case KEYD_CMD_CLOSE:
			/* We're going to close the FD even if this fails */
			(void) keyd_write_reply(fd, KEYD_REPLY_OK);
			ret = 1;
			break;
		case KEYD_CMD_QUIT:
			/* We're going to quit even if this fails */
			(void) keyd_write_reply(fd, KEYD_REPLY_OK);
			logthing(LOGTHING_NOTICE,
				"Exiting due to quit request.");
			ret = 1;
			trytocleanup();
			break;
		case KEYD_CMD_STATS:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				cmd = sizeof(*stats);
				bytes = write(fd, &cmd, sizeof(cmd));
				if (bytes != sizeof(cmd)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				bytes = write(fd, stats, sizeof(*stats));
				if (bytes != sizeof(*stats)) {
					ret = 1;
				}
			}
			break;
		case KEYD_CMD_GET_SKSHASH:
			if (!keyd_write_reply(fd, KEYD_REPLY_OK)) {
				ret = 1;
			}
			if (ret == 0) {
				bytes = read(fd, hash.hash, sizeof(hash.hash));
				if (bytes != sizeof(hash.hash)) {
					ret = 1;
				}
			}
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching by hash"
						", result: %d",
						dbctx->fetch_key_skshash(dbctx,
							&hash, &key));
				if (key != NULL) {
					keyd_write_key(fd, key);
					free_publickey(key);
					key = NULL;
				} else {
					if (!keyd_write_size(fd, 0)) {
						ret = 1;
					}
				}
			}
			break;

		default:
			logthing(LOGTHING_ERROR, "Got unknown command: %d",
					cmd);
			if (!keyd_write_reply(fd, KEYD_REPLY_UNKNOWN_CMD)) {
				ret = 1;
			}
		}
	}

	return(ret);
}

static int sock_close(int fd)
{
	shutdown(fd, SHUT_RDWR);
	return close(fd);
}

static int sock_accept(int fd)
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
	struct onak_dbctx *dbctx;

	while ((optchar = getopt(argc, argv, "c:fh")) != -1 ) {
		switch (optchar) {
		case 'c':
			if (configfile != NULL) {
				free(configfile);
			}
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

		dbctx = config.dbinit(false);

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
					if (sock_do(dbctx, clients[i])) {
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
		dbctx->cleanupdb(dbctx);
#ifdef HAVE_SYSTEMD
		if (!using_socket_activation) {
#endif
			sock_close(fd);
			unlink(sockname);
#ifdef HAVE_SYSTEMD
		}
#endif
	}

	free(stats);

	cleanuplogthing();
	cleanupconfig();

	return(EXIT_SUCCESS);
}
