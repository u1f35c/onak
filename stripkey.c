/*
 * stripkey.c - Strip a key of all signatures except self-sigs.
 *
 * Copyright 2004 Daniel Silverstone <dsilvers@digital-scurf.org>
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "charfuncs.h"
#include "cleankey.h"
#include "keyid.h"
#include "keystructs.h"
#include "mem.h"
#include "parsekey.h"
#include "decodekey.h"

int main(int argc, char** argv) {
  struct openpgp_packet_list *packets = NULL;
  struct openpgp_packet_list *list_end = NULL;
  struct openpgp_publickey   *keys = NULL;
  struct openpgp_publickey   *key = NULL;
  struct openpgp_signedpacket_list *uid = NULL;
  struct openpgp_packet_list *sig = NULL;
  struct openpgp_packet_list *prevsig = NULL;
  uint64_t my_key = 0;

  if( argc > 1 )
     my_key = strtoull( argv[1], NULL, 16 );
   
  /* expect a stream of openpgp packets on stdin comprising some keys */
  /* strip each key of everything but its pubkey component, uids and
   * selfsigs and revsigs on those selfsigs */

  read_openpgp_stream( stdin_getchar, NULL, &packets, 0 );
  parse_keys( packets, &keys );
  free_packet_list(packets);
  packets = NULL;
  cleankeys( keys );
  /* Iterate over the keys... */
  for( key = keys; key; key = key->next ) {
    uint64_t keyid;
    get_keyid( key, &keyid );
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
  }
  flatten_publickey( keys, &packets, &list_end );
  write_openpgp_stream( stdout_putchar, NULL, packets );
  return 0;
}
