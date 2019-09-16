# onak

onak is an OpenPGP compatible keyserver. It was originally written
concentrating on providing real time path finding between 2 keys, but
over time has moved to concentrating on providing standard keyserver
storage and retrieval functionality.

Features include:

 * Multiple backend key storage options (DB4, PostgreSQL, flat file,
   read-only PGP keyring)
 * Command-line tool for interacting with key store
 * Forwarding capability to other key servers
 * Experimental full verification of signatures
 * Experimental OpenPGP v5 support

It does not (yet) support the SKS Gossip keyserver synchronisation
protocol.

See the doc/ subdirectory for more complete documentation.

### License

onak is released under the GPLv2.

### Requirements

onak is written in C and has no hard external dependencies. The
recommended backend key-store requires Berkeley DB (tested with versions
4 + 5). [Nettle](https://www.lysator.liu.se/~nisse/nettle/) is
recommended for full cryptographic functionality. onak can also make use
of [curl](https://curl.haxx.se/) if available.

### Downloads

onak can always be found at
[https://the.earth.li/gitweb/?p=onak.git;a=summary](http://the.earth.li/gitweb/?p=onak.git;a=summary)
and there is a [GitHub](https://github.com/) mirror at
[https://github.com/u1f35c/onak](https://github.com/u1f35c/onak)

Contributions are welcome via emailed patches to
[noodles@earth.li](noodles@earth.li) or pull requests on GitHub.
