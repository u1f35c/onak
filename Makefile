# Makefile for onak.

CC = gcc
CFLAGS += -Wall -pedantic -g -I/usr/local/include
#LDFLAGS += -pg
# Can be "pg" for Postgresql, "file" for flat files or "db2" for pksd db2 style.
DBTYPE = db3
# If using DBTYPE of "file" then comment the following line out.
#LIBS = -L/usr/local/lib -lpq
LIBS = -L/usr/local/lib -ldb3

PROGS = add lookup gpgwww onak
OBJS = armor.o parsekey.o keydb_$(DBTYPE).o merge.o keyid.o md5.o sha.o \
	getcgi.o keyindex.o mem.o stats.o ll.o hash.o onak-conf.o
SRCS = armor.c parsekey.c merge.c keyid.c md5.c sha.c main.c getcgi.c stats.c \
	keyindex.c mem.c lookup.c add.c keydb_$(DBTYPE).c ll.c hash.c \
	gpgwww.c onak-conf.c

all: $(PROGS) testparse maxpath

testparse: main.o $(OBJS)
	$(CC) -o testparse main.o $(OBJS) $(LIBS)

maxpath: maxpath.o $(OBJS)
	$(CC) -o maxpath maxpath.o $(OBJS) $(LIBS)

gpgwww: gpgwww.o $(OBJS)
	$(CC) -o gpgwww gpgwww.o $(OBJS) $(LIBS)

lookup: lookup.o getcgi.o keyindex.o keydb_$(DBTYPE).o keyid.o sha.o \
		parsekey.o mem.o armor.o ll.o hash.o onak-conf.o
	$(CC) -o lookup lookup.o getcgi.o keyindex.o keydb_$(DBTYPE).o keyid.o \
		sha.o parsekey.o mem.o armor.o ll.o hash.o onak-conf.o $(LIBS)

add: add.o getcgi.o armor.o parsekey.o keydb_$(DBTYPE).o keyid.o sha.o mem.o \
		keyindex.o ll.o hash.o merge.o onak-conf.o
	$(CC) -o add add.o getcgi.o armor.o parsekey.o keydb_$(DBTYPE).o \
		keyid.o sha.o mem.o keyindex.o ll.o hash.o merge.o onak-conf.o \
		$(LIBS)

onak: onak.o merge.o keyid.o sha.o armor.o parsekey.o ll.o \
		keydb_$(DBTYPE).o mem.o keyindex.o hash.o getcgi.o onak-conf.o
	$(CC) $(LDFLAGS) -o onak onak.o merge.o keyid.o sha.o armor.o parsekey.o \
		keydb_$(DBTYPE).o mem.o keyindex.o ll.o hash.o getcgi.o \
		onak-conf.o $(LIBS)


clean:
	rm -f $(PROGS) $(OBJS) Makefile.bak testparse maxpath *.core core \
		gpgwww.o add.o lookup.o main.o maxpath.o onak.o

depend:
	makedepend $(SRCS)

# DO NOT DELETE
