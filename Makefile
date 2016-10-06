#
# Makefile for ampr-ripd
#

BASEDIR = /usr
SBINDIR = $(BASEDIR)/sbin
MANDIR = $(BASEDIR)/man/man1
SCACHEDIR = /var/lib/ampr-ripd

# no need to run ampr-ripd as root
OWN = daemon
GRP = daemon

CC = gcc

#
# Choose one of the followinf DOPTs if you need debug
#

# Full debug including Netlink
#DOPT = -Wall -O2 -D HAVE_DEBUG -D NL_DEBUG

# Full debug
#DOPT = -Wall -O2 -D HAVE_DEBUG

CFLAGS ?= -Wall -O2
LDFLAGS ?=
ampr-ripd:	ampr-ripd.c
	$(CC) $(CFLAGS) $(DOPT) $(LDFLAGS) $(CPPFLAGS) -o ampr-ripd ampr-ripd.c

all:	ampr-ripd

clean:
	rm -f ampr-ripd

install:	ampr-ripd
	strip ampr-ripd
	install -m 755 -o $(OWN) -g $(GRP) -d          $(SCACHEDIR)
	install -m 755 -o $(OWN) -g $(GRP) ampr-ripd   $(SBINDIR)
	install -m 644 -o $(OWN) -g $(GRP) ampr-ripd.1 $(MANDIR)
