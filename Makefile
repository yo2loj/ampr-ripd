#
# Makefile for ampr-ripd
#

BASEDIR = /usr
SBINDIR = $(BASEDIR)/sbin
SCACHEDIR = /var/lib/ampr-ripd

# no need to run dx-broadcast as root
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

COPT = -Wall -O2
LOPT =

ampr-ripd:	ampr-ripd.c
	$(CC) $(COPT) $(DOPT) $(LOPT) -o ampr-ripd ampr-ripd.c

all:	ampr-ripd

clean:
	rm -f ampr-ripd

install:	ampr-ripd
	strip ampr-ripd
	install -m 755 -o $(OWN) -g $(GRP) -d        $(SCACHEDIR)
	install -m 755 -o $(OWN) -g $(GRP) ampr-ripd $(SBINDIR)
