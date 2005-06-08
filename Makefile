DIRS=caff gpg-key2ps gpg-mailkeys gpgsigs
VERSION=$(shell dpkg-parsechangelog 2>&1 | perl -ne 'print $$1 if /^Version: ([^-]*)/')
TGZ=../signing-party_$(VERSION).orig.tar.gz

all:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir || exit 1 ; fi ; done

clean:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir clean || exit 1 ; fi ; done

dist:
	[ ! -f $(TGZ) ]
	tar cvz -f $(TGZ) --exclude .svn --exclude debian .
