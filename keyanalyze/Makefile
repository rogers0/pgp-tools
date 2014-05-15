LDLIBS=-lpthread
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)

all: keyanalyze process_keys pgpring/pgpring

keyanalyze: keyanalyze.o
process_keys: process_keys.o

pgpring/pgpring:
	cd pgpring && touch AUTHORS ChangeLog INSTALL NEWS README && automake-1.11 --add-missing && automake-1.11
	cd pgpring && autoconf && CFLAGS="${CFLAGS}" ./configure
	make -C pgpring pgpring

install:
	install pgpring/pgpring $(DESTDIR)/usr/bin
	install keyanalyze $(DESTDIR)/usr/bin
	install process_keys $(DESTDIR)/usr/bin

clean:
	-(cd pgpring && make distclean)
	-rm -f *.o core *~ keyanalyze process_keys
	-rm -f test.pre preprocess.keys keyanalyze.out all.keys
	-rm -rf output
