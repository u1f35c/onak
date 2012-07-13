#ifndef __SIGCHECK_H__
#define __SIGCHECK_H__
#include "keystructs.h"

int check_packet_sighash(struct openpgp_publickey *key,
			struct openpgp_packet *packet,
			struct openpgp_packet *sig);

#endif /* __SIGCHECK_H__ */
