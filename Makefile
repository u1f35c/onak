# Makefile for onak.

CC = gcc
LINK = gcc
CFLAGS += -Wall -pedantic -g -I/usr/local/include
#LDFLAGS += -pg
# Can be "pg" for Postgresql, "file" for flat files or "db2" for pksd db2 style.
DBTYPE = db3
# If using DBTYPE of "file" then comment the following line out.
#LIBS = -L/usr/local/lib -lpq
LIBS = -L/usr/local/lib -ldb3

PROGS = add lookup gpgwww onak
CORE_OBJS = armor.o charfuncs.o decodekey.o getcgi.o hash.o keydb_$(DBTYPE).o \
	keyid.o keyindex.o ll.o mem.o onak-conf.o parsekey.o sha.o md5.o log.o
OBJS = merge.o stats.o sendsync.o $(CORE_OBJS)
SRCS = armor.c parsekey.c merge.c keyid.c md5.c sha.c main.c getcgi.c stats.c \
	keyindex.c mem.c lookup.c add.c keydb_$(DBTYPE).c ll.c hash.c \
	gpgwww.c onak-conf.c charfuncs.c sendsync.c log.c

all: .depend $(PROGS) testparse maxpath sixdegrees

testparse: main.o $(OBJS)
	$(LINK) -o testparse main.o $(OBJS) $(LIBS)

maxpath: maxpath.o $(OBJS)
	$(LINK) -o maxpath maxpath.o $(OBJS) $(LIBS)

sixdegrees: sixdegrees.o $(OBJS)
	$(LINK) -o sixdegrees sixdegrees.o $(OBJS) $(LIBS)

gpgwww: gpgwww.o $(OBJS)
	$(LINK) -o gpgwww gpgwww.o $(OBJS) $(LIBS)

lookup: lookup.o $(CORE_OBJS)
	$(LINK) -o lookup lookup.o $(CORE_OBJS) $(LIBS)

add: add.o merge.o sendsync.o $(CORE_OBJS)
	$(LINK) -o add add.o merge.o sendsync.o $(CORE_OBJS) $(LIBS)

onak: onak.o merge.o $(CORE_OBJS)
	$(LINK) $(LDFLAGS) -o onak onak.o merge.o $(CORE_OBJS) $(LIBS)

clean:
	rm -f $(PROGS) $(OBJS) Makefile.bak testparse maxpath *.core core \
		gpgwww.o add.o lookup.o main.o maxpath.o onak.o sixdegrees \
		sixdegrees.o

.depend: $(SRCS)
	rm .depend
	makedepend -f- -- $(CFLAGS) -- $(SRCS) > .depend

include .depend

.PHONY: all clean
