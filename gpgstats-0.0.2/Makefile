# Makefile for gpgstats.

CC = gcc
OBJS = gpgstats.o hash.o ll.o parse.o graphstuff.o
CFLAGS += -Wall -pedantic -g -I..
# -DUSEREADLINE

all:	gpgstats

gpgstats: $(OBJS)
	gcc -g -o gpgstats $(OBJS)
# -lreadline -lhistory

dotrees: $(OBJS) dotrees.o
	gcc -g -o dotrees dotrees.o hash.o ll.o parse.o 
	
clean:
	rm -f $(OBJS) gpgctl.o dotrees.o gpgstats *.core core
