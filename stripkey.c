#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "armor.h"
#include "charfuncs.h"
#include "cleankey.h"
#include "keydb.h"
#include "keyid.h"
#include "keyindex.h"
#include "keystructs.h"
#include "log.h"
#include "mem.h"
#include "merge.h"
#include "onak-conf.h"
#include "parsekey.h"
#include "photoid.h"
#include "decodekey.h"

int main(int argc, char** argv) {
  struct openpgp_packet_list *packets = NULL;
  struct openpgp_packet_list *list_end = NULL;
  struct openpgp_publickey   *keys = NULL;
  struct openpgp_publickey   *key = NULL;
  struct openpgp_signedpacket_list *uid = NULL;
  struct openpgp_packet_list *sig = NULL;
  struct openpgp_packet_list *prevsig = NULL;
  int result = 0;
  uint64_t my_key = 0;

  if( argc > 1 )
     my_key = strtoull( argv[1], NULL, 16 );
   
  /* expect a stream of openpgp packets on stdin comprising some keys */
  /* strip each key of everything but its pubkey component, uids and
   * selfsigs and revsigs on those selfsigs */

  result = read_openpgp_stream( stdin_getchar, NULL, &packets, 0 );
  result = parse_keys( packets, &keys );
  free_packet_list(packets);
  packets = NULL;
  result = cleankeys( keys );
  /* Iterate over the keys... */
  for( key = keys; key; key = key->next ) {
    uint64_t keyid = get_keyid( key );
    for( uid = key->uids; uid; uid = uid->next ) {
      REPEATTHISUID: 
      for( sig = uid->sigs, prevsig = NULL; 
           sig; 
           prevsig = sig, sig = sig->next ) {
        uint64_t thissig = sig_keyid( sig->packet );
        if( thissig != keyid && thissig != my_key ) {
          /* Don't care about this packet... */
          if( prevsig ) {
            prevsig->next = sig->next;
          } else {
            uid->sigs = sig->next;
          }
          sig->next = NULL;
          free_packet_list( sig );
          goto REPEATTHISUID;
        }
      }
    }
    flatten_publickey( key, &packets, &list_end );
  }
  write_openpgp_stream( stdout_putchar, NULL, packets );
  return 0;
}
