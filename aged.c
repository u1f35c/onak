/*
 * aged.c - Helpers and command drivers for the aged / dump-aged /
 *          clean-aged onak subcommands.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mneme (u5=001777236237.945e_43.30_005.38) <mneme@foopgp.org>
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aged.h"
#include "armor.h"
#include "charfuncs.h"
#include "keydb.h"
#include "keyid.h"
#include "keystructs.h"
#include "log.h"
#include "marshal.h"
#include "mem.h"
#include "openpgp.h"
#include "parsekey.h"

time_t parse_age_string(const char *s)
{
	char *end;
	long val;

	if (s == NULL || *s == '\0') {
		return 0;
	}
	val = strtol(s, &end, 10);
	if (val <= 0 || end == s) {
		return 0;
	}
	switch (*end) {
	case 'y': case 'Y':
	case '\0':
		return (time_t) val * 365 * 86400;
	case 'd': case 'D':
		return (time_t) val * 86400;
	case 'h': case 'H':
		return (time_t) val * 3600;
	case 's': case 'S':
		return (time_t) val;
	default:
		return 0;
	}
}

time_t key_creation_time(struct openpgp_publickey *key)
{
	if (key == NULL || key->publickey == NULL ||
			key->publickey->length < 5) {
		return 0;
	}
	return ((time_t) key->publickey->data[1] << 24) +
		((time_t) key->publickey->data[2] << 16) +
		((time_t) key->publickey->data[3] << 8) +
		(time_t) key->publickey->data[4];
}

/*
 * For a v4+ signature, walk the hashed subpacket area looking for the
 * KEYEXPIRY subpacket. Returns the 4-octet offset value if found, 0
 * otherwise. See RFC 9580 §5.2.3.7 for the subpacket length encoding.
 */
static uint32_t find_keyexpiry_in_sig(struct openpgp_packet *sig)
{
	unsigned char *data;
	size_t data_len, sub_len, offset, packet_len;

	if (sig == NULL || sig->length < 6) {
		return 0;
	}
	if (sig->data[0] != 4 && sig->data[0] != 5) {
		return 0;
	}
	data = &sig->data[4];
	data_len = sig->length - 4;
	if (data_len < 2) {
		return 0;
	}
	sub_len = ((size_t) data[0] << 8) + data[1] + 2;
	if (sub_len > data_len) {
		return 0;
	}
	offset = 2;
	while (offset + 2 < sub_len) {
		packet_len = data[offset++];
		if (packet_len > 191 && packet_len < 255) {
			packet_len = ((packet_len - 192) << 8) +
				data[offset++] + 192;
		} else if (packet_len == 255) {
			if (offset + 4 > sub_len) {
				return 0;
			}
			packet_len = ((uint32_t) data[offset] << 24) +
				((uint32_t) data[offset + 1] << 16) +
				((uint32_t) data[offset + 2] << 8) +
				data[offset + 3];
			offset += 4;
		}
		if (packet_len == 0 || packet_len > sub_len - offset) {
			return 0;
		}
		if ((data[offset] & 0x7f) == OPENPGP_SIGSUB_KEYEXPIRY &&
				packet_len >= 5) {
			return ((uint32_t) data[offset + 1] << 24) +
				((uint32_t) data[offset + 2] << 16) +
				((uint32_t) data[offset + 3] << 8) +
				data[offset + 4];
		}
		offset += packet_len;
	}
	return 0;
}

time_t key_expiration_time(struct openpgp_publickey *key)
{
	struct openpgp_signedpacket_list *uid;
	struct openpgp_packet_list *sig;
	time_t creation, candidate, latest = 0;
	uint16_t days;
	uint32_t expiry_offset;

	if (key == NULL || key->publickey == NULL ||
			key->publickey->length < 5) {
		return 0;
	}
	creation = key_creation_time(key);
	if (creation == 0) {
		return 0;
	}

	if (key->publickey->data[0] == 2 || key->publickey->data[0] == 3) {
		if (key->publickey->length < 7) {
			return 0;
		}
		days = (key->publickey->data[5] << 8) +
			key->publickey->data[6];
		if (days == 0) {
			return 0;
		}
		return creation + (time_t) days * 86400;
	}

	for (uid = key->uids; uid != NULL; uid = uid->next) {
		for (sig = uid->sigs; sig != NULL; sig = sig->next) {
			expiry_offset = find_keyexpiry_in_sig(sig->packet);
			if (expiry_offset == 0) {
				continue;
			}
			candidate = creation + (time_t) expiry_offset;
			if (candidate > latest) {
				latest = candidate;
			}
		}
	}
	return latest;
}

bool key_is_aged_or_expired(struct openpgp_publickey *key,
		time_t now, time_t max_age)
{
	time_t creation, expiration;

	if (key == NULL) {
		return false;
	}
	creation = key_creation_time(key);
	if (creation == 0) {
		return false;
	}
	if (max_age > 0 && (creation + max_age) < now) {
		return true;
	}
	expiration = key_expiration_time(key);
	if (expiration != 0 && expiration < now) {
		return true;
	}
	return false;
}

struct aged_walk_ctx {
	time_t now;
	time_t max_age;
	int count;
	int errors;
};

struct aged_list_ctx {
	struct aged_walk_ctx base;
};

struct aged_dump_ctx {
	struct aged_walk_ctx base;
	bool binary;
};

struct aged_collect_ctx {
	struct aged_walk_ctx base;
	struct openpgp_fingerprint *fps;
	size_t capacity;
};

static void print_fingerprint(struct openpgp_fingerprint *fp)
{
	size_t i;

	for (i = 0; i < fp->length; i++) {
		printf("%02X", fp->fp[i]);
	}
	putchar('\n');
}

static void aged_list_cb(void *ctx, struct openpgp_publickey *key)
{
	struct aged_list_ctx *state = ctx;
	struct openpgp_fingerprint fp;

	if (!key_is_aged_or_expired(key, state->base.now,
			state->base.max_age)) {
		return;
	}
	if (get_fingerprint(key->publickey, &fp) != ONAK_E_OK) {
		state->base.errors++;
		return;
	}
	print_fingerprint(&fp);
	state->base.count++;
}

static void aged_dump_cb(void *ctx, struct openpgp_publickey *key)
{
	struct aged_dump_ctx *state = ctx;
	struct openpgp_packet_list *packets = NULL;
	struct openpgp_packet_list *list_end = NULL;

	if (!key_is_aged_or_expired(key, state->base.now,
			state->base.max_age)) {
		return;
	}
	flatten_publickey(key, &packets, &list_end);
	if (state->binary) {
		write_openpgp_stream(stdout_putchar, NULL, packets);
	} else {
		armor_openpgp_stream(stdout_putchar, NULL, packets);
	}
	free_packet_list(packets);
	state->base.count++;
}

static void aged_collect_cb(void *ctx, struct openpgp_publickey *key)
{
	struct aged_collect_ctx *state = ctx;
	struct openpgp_fingerprint fp;
	struct openpgp_fingerprint *grown;
	size_t new_cap;

	if (!key_is_aged_or_expired(key, state->base.now,
			state->base.max_age)) {
		return;
	}
	if (get_fingerprint(key->publickey, &fp) != ONAK_E_OK) {
		state->base.errors++;
		return;
	}
	if ((size_t) state->base.count >= state->capacity) {
		new_cap = state->capacity ? state->capacity * 2 : 32;
		grown = realloc(state->fps,
			new_cap * sizeof(struct openpgp_fingerprint));
		if (grown == NULL) {
			state->base.errors++;
			return;
		}
		state->fps = grown;
		state->capacity = new_cap;
	}
	state->fps[state->base.count++] = fp;
}

int onak_cmd_aged(struct onak_dbctx *dbctx, time_t max_age)
{
	struct aged_list_ctx ctx = {{ time(NULL), max_age, 0, 0 }};

	if (dbctx == NULL || dbctx->iterate_keys == NULL) {
		logthing(LOGTHING_ERROR,
			"Backend does not support iterate_keys; "
			"aged listing is unavailable.");
		return 0;
	}
	dbctx->iterate_keys(dbctx, aged_list_cb, &ctx);
	if (ctx.base.errors) {
		logthing(LOGTHING_INFO,
			"%d key(s) skipped due to fingerprint errors",
			ctx.base.errors);
	}
	return ctx.base.count;
}

int onak_cmd_dump_aged(struct onak_dbctx *dbctx, time_t max_age, bool binary)
{
	struct aged_dump_ctx ctx = {{ time(NULL), max_age, 0, 0 }, binary};

	if (dbctx == NULL || dbctx->iterate_keys == NULL) {
		logthing(LOGTHING_ERROR,
			"Backend does not support iterate_keys; "
			"aged dump is unavailable.");
		return 0;
	}
	dbctx->iterate_keys(dbctx, aged_dump_cb, &ctx);
	return ctx.base.count;
}

int onak_cmd_clean_aged(struct onak_dbctx *dbctx, time_t max_age)
{
	struct aged_collect_ctx ctx = {{ time(NULL), max_age, 0, 0 },
		NULL, 0};
	int deleted = 0, i, rc;

	if (dbctx == NULL || dbctx->iterate_keys == NULL ||
			dbctx->delete_key == NULL) {
		logthing(LOGTHING_ERROR,
			"Backend does not support iterate_keys or "
			"delete_key; aged cleanup is unavailable.");
		return 0;
	}
	dbctx->iterate_keys(dbctx, aged_collect_cb, &ctx);
	for (i = 0; i < ctx.base.count; i++) {
		rc = dbctx->delete_key(dbctx, &ctx.fps[i], false);
		if (rc == 0) {
			deleted++;
		} else {
			logthing(LOGTHING_INFO,
				"delete_key returned %d for an aged key; "
				"the backend may not support deletion.",
				rc);
		}
	}
	if (deleted < ctx.base.count) {
		logthing(LOGTHING_INFO,
			"clean-aged: matched %d key(s), deleted %d. "
			"Check the backend supports delete_key.",
			ctx.base.count, deleted);
	}
	free(ctx.fps);
	return deleted;
}
