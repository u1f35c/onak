/*
 * keyd.c - key retrieval daemon
 *
 * Jonathan McDowell <noodles@earth.li>
 * 
 * Copyright 2004 Project Purple
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
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

void iteratefunc(void *ctx, struct openpgp_publickey *key)
{
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct buffer_ctx           storebuf;
	int                         ret = 0;
	int                         fd = (int) ctx;

	if (key != NULL) {
		storebuf.offset = 0;
		storebuf.size = 8192;
		storebuf.buffer = malloc(8192);

		logthing(LOGTHING_TRACE,
				"Iterating over 0x%016llX.",
				get_keyid(key));

		flatten_publickey(key,
				&packets,
				&list_end);
		write_openpgp_stream(buffer_putchar,
				&storebuf,
				packets);
		logthing(LOGTHING_TRACE,
				"Sending %d bytes.",
				storebuf.offset);
		ret = write(fd, &storebuf.offset,
			sizeof(storebuf.offset));
		if (ret != 0) {
			write(fd, storebuf.buffer,
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
		ret = fcntl(fd, F_SETFD, 1);
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
	int      cmd = KEYD_CMD_UNKNOWN;
	ssize_t  bytes = 0;
	ssize_t  count = 0;
	int	 ret = 0;
	uint64_t keyid = 0;
	char     *search = NULL;
	struct openpgp_publickey *key = NULL;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct buffer_ctx storebuf;

	/*
	 * Get the command from the client.
	 */
	bytes = read(fd, &cmd, sizeof(cmd));

	logthing(LOGTHING_DEBUG, "Read %d bytes, command: %d", bytes, cmd);

	if (bytes != sizeof(cmd)) {
		ret = 1;
	}
	
	if (ret == 0) {
		switch (cmd) {
		case KEYD_CMD_VERSION:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			write(fd, &keyd_version, sizeof(keyd_version));
			break;
		case KEYD_CMD_GET:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			bytes = read(fd, &keyid, sizeof(keyid));
			if (bytes != sizeof(keyid)) {
				ret = 1;
			}
			storebuf.offset = 0;
			if (ret == 0) {
				logthing(LOGTHING_INFO,
						"Fetching 0x%llX, result: %d",
						keyid,
						fetch_key(keyid, &key, false));
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
		case KEYD_CMD_GETTEXT:
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
				store_key(key, false, false);
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
						"Deleting 0x%llX, result: %d",
						keyid,
						delete_key(keyid, false));
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
				keyid = getfullkeyid(keyid);
				write(fd, &keyid, sizeof(keyid));
			}
			break;
		case KEYD_CMD_KEYITER:
			cmd = KEYD_REPLY_OK;
			write(fd, &cmd, sizeof(cmd));
			iterate_keys(iteratefunc, (void *) fd);
			bytes = 0;
			write(fd, &bytes, sizeof(bytes));
			break;
		case KEYD_CMD_CLOSE:
			ret = 1;
			break;
		case KEYD_CMD_QUIT:
			trytocleanup();
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
	return shutdown(fd, SHUT_RDWR);
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
		ret = fcntl(srv, F_SETFD, 1);
	}

	if (ret != -1) {
		while (!sock_do(srv)) ;
		sock_close(srv);
	}

	return 1;
}

int main(int argc, char *argv[])
{
	int fd = -1;
	fd_set rfds;
	char sockname[1024];

	readconfig(NULL);
	initlogthing("keyd", config.logfile);

	catchsignals();
	
	snprintf(sockname, 1023, "%s/%s", config.db_dir, KEYD_SOCKET);
	fd = sock_init(sockname);

	if (fd != -1) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		initdb(false);

		logthing(LOGTHING_NOTICE, "Accepting connections.");
		while (!cleanup() && select(fd + 1, &rfds, NULL, NULL, NULL) != -1) {
			logthing(LOGTHING_INFO, "Accepted connection.");
			sock_accept(fd);
			FD_SET(fd, &rfds);
		}
		cleanupdb();
		sock_close(fd);
		unlink(sockname);
	}

	cleanuplogthing();
	cleanupconfig();
	
	return(EXIT_SUCCESS);
}
