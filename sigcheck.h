#ifndef __SIGCHECK_H__
#define __SIGCHECK_H__
#include "keystructs.h"

onak_status_t calculate_packet_sighash(struct openpgp_publickey *key,
			struct openpgp_packet *packet,
			struct openpgp_packet *sig,
			uint8_t *hashtype,
			uint8_t *hash,
			uint8_t **sighash);

/**
 * onak_check_hash_sig - check the signature on a hash is valid
 * @sigkey: The public key that made the signature
 * @sig: The signature packet
 * @hash: Hash digest the signature is over
 * @hashtype: Type of hash (OPENPGP_HASH_*)
 */
onak_status_t onak_check_hash_sig(struct openpgp_publickey *sigkey,
		struct openpgp_packet *sig,
		uint8_t *hash,
		uint8_t hashtype);

#endif /* __SIGCHECK_H__ */
