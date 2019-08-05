#ifndef __SIGCHECK_H__
#define __SIGCHECK_H__
#include "keystructs.h"

onak_status_t calculate_packet_sighash(struct openpgp_publickey *key,
			struct openpgp_packet *packet,
			struct openpgp_packet *sig,
			uint8_t *hashtype,
			uint8_t *hash,
			uint8_t **sighash);

#endif /* __SIGCHECK_H__ */
