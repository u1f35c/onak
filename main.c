#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "armor.h"
#include "charfuncs.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "parsekey.h"

int main(int argc, char *argv[])
{
	struct openpgp_packet_list *packets = NULL; 
/*
	, *newpackets = NULL;
	struct openpgp_packet_list *list_end = NULL;
	struct openpgp_publickey *keys = NULL;
	struct openpgp_publickey *newkeys = NULL;
	void *ctx = NULL;

	fputs("Doing read_openpgp_stream():\n", stderr);
	read_openpgp_stream(getnextchar, ctx, &packets, 0);
*/
	fputs("Doing dearmor_openpgp_stream():\n", stderr);
	dearmor_openpgp_stream(stdin_getchar, NULL, &packets);
	fputs("Doing armor_openpgp_stream():\n", stderr);
	armor_openpgp_stream(stdout_putchar, NULL, packets);

/*
	fputs("Doing parse_keys():\n", stderr);
	parse_keys(packets, &keys);

	printf("Key id is 0x%llX\n", get_keyid(keys));

	key_index(keys, true, false, false);

	initdb(true);
	fetch_key(get_keyid(keys), &newkeys);
	cleanupdb();

	printf("New key id is 0x%llX\n", get_keyid(newkeys));

	fputs("Doing flatten_publickey():\n", stderr);
	flatten_publickey(keys, &newpackets, &list_end);

	fputs("Doing write_openpgp_stream():\n", stderr);
	write_openpgp_stream(putnextchar, ctx, newpackets);
*/
	return 0;
}
