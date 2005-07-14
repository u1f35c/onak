/*
 * keydb_dynamic.h - declarations for the dynamic backend
 *
 * Brett Parker <iDunno@sommitrealweird.co.uk>
 *
 * Copyright 2005 Project Purple
 */
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <inttypes.h>

#include "charfuncs.h"
#include "onak-conf.h"
#include "keystructs.h"
#include "ll.h"
#include "log.h"

#ifndef __KEYDB_DYNAMIC_H__
#define __KEYDB_DYNAMIC_H__

/*
 * Hide the ugly function definitions in typedefs that we use elsewhere
 */
typedef void (*initdbfunc_t)(bool);
typedef void (*cleanupdbfunc_t)(void);
typedef bool (*starttransfunc_t)(void);
typedef bool (*endtransfunc_t)(void);
typedef int (*fetch_keyfunc_t)(uint64_t keyid,
		struct openpgp_publickey **publickey, bool intrans);
typedef int (*store_keyfunc_t)(struct openpgp_publickey *publickey,
		bool intrans, bool update);
typedef int (*delete_keyfunc_t)(uint64_t keyid, bool intrans);
typedef int (*fetch_key_textfunc_t)(const char *search,
		struct openpgp_publickey **publickey);
typedef int (*update_keysfunc_t)(struct openpgp_publickey **keys,
		bool sendsync);
typedef char *(*keyid2uidfunc_t)(uint64_t keyid);
typedef struct ll *(*getkeysigsfunc_t)(uint64_t keyid, bool *revoked);
typedef struct ll *(*cached_getkeysigsfunc_t)(uint64_t keyid);
typedef uint64_t (*getfullkeyidfunc_t)(uint64_t keyid);
typedef int (*iterate_keysfunc_t)(
		void (*iterfunc) (void *ctx, struct openpgp_publickey *key),
		void *ctx);


/*
 * Define a nice struct to hold pointers to the functions, once the backend
 * is loaded
 */
struct dynamic_backend {
	initdbfunc_t initdb;
	cleanupdbfunc_t cleanupdb;
	starttransfunc_t starttrans;
	endtransfunc_t endtrans;
	fetch_keyfunc_t fetch_key;
	store_keyfunc_t store_key;
	delete_keyfunc_t delete_key;
	fetch_key_textfunc_t fetch_key_text;
	update_keysfunc_t update_keys;
	keyid2uidfunc_t keyid2uid;
	getkeysigsfunc_t getkeysigs;
	cached_getkeysigsfunc_t cached_getkeysigs;
	getfullkeyidfunc_t getfullkeyid;
	iterate_keysfunc_t iterate_keys;
	char *backendsoname;
	void *handle;
	bool loaded;
};

struct dynamic_backend __dynamicdb_backend__ = {
	NULL,	/* initdb */
	NULL,	/* cleanupdb */
	NULL,	/* starttrans */
	NULL,	/* endtrans */
	NULL,	/* fetch_key */
	NULL,	/* store_key */
	NULL,	/* delete_key */
	NULL,	/* fetch_key_text */
	NULL,	/* update_keys */
	NULL,	/* keyid2uid */
	NULL,	/* getkeysigs */
	NULL,	/* cached_getkeysigs */
	NULL,	/* getfullkeyid */
	NULL,	/* iteratekeys */
	NULL,	/* backendsoname */
	NULL,	/* handle */
	0	/* loaded */
};

bool load_backend(void);
bool close_backend(void);
bool backend_loaded(void);
struct dynamic_backend *get_backend(void);

#endif /* __KEYDB_DYNAMIC_H__ */
