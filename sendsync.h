/*
 * sendsync.c - Routines to send a key sync mail.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * Copyright 1999, 2002 Project Purple
 *
 * $Id: sendsync.h,v 1.2 2003/06/04 20:57:12 noodles Exp $
 */

#ifndef __SENDSYNC_H_
#define __SENDSYNC_H_

#include "keystructs.h"

/**
 *	sendkeysync - Send a key sync mail to our peers.
 *	keys: The list of keys to send.
 *
 *	Takes a list of keys and sends out a keysync mail to all our peers.
 */
int sendkeysync(struct openpgp_publickey *keys);

#endif /* __SENDSYNC_H */
