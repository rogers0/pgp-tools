LDLIBS=-lpthread
CFLAGS=-O2 -W -Wall -g

all: keyanalyze process_keys pgpring/pgpring

keyanalyze: keyanalyze.o
process_keys: process_keys.o

pgpring/pgpring:
	cd pgpring && CFLAGS="${CFLAGS}" ./configure && make pgpring

install:
	install pgpring/pgpring $(DESTDIR)/usr/bin
	install keyanalyze $(DESTDIR)/usr/bin
	install process_keys $(DESTDIR)/usr/bin

clean:
	-(cd pgpring && make distclean)
	-rm -f *.o core *~ keyanalyze process_keys
	-rm -f test.pre preprocess.keys keyanalyze.out all.keys
	-rm -rf output
