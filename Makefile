DIRS=caff gpg-key2ps gpg-mailkeys gpgsigs gpglist
VERSION=$(shell dpkg-parsechangelog 2>&1 | perl -ne 'print $$1 if /^Version: ([^-]*)/')
TGZ=../signing-party_$(VERSION).orig.tar.gz
TGZ_DIR=signing-party-$(VERSION)

all:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir || exit 1 ; fi ; done

clean:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir clean || exit 1 ; fi ; done

dist:
	[ ! -f $(TGZ) ]
	mkdir $(TGZ_DIR)
	for dir in $(DIRS) ; do cp -a $$dir $(TGZ_DIR); done
	cp -a README TODO Makefile $(TGZ_DIR)
	tar cvz -f $(TGZ) --exclude .svn $(TGZ_DIR)
	rm -rf $(TGZ_DIR)
