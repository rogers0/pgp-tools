DIRS=caff gpg-key2ps gpg-mailkeys gpgsigs gpglist gpgparticipants keylookup \
     sig2dot springgraph
VERSION=$(shell dpkg-parsechangelog 2>&1 | perl -ne 'print $$1 if /^Version: ([^-]*)/')
DEBVERSION=$(shell dpkg-parsechangelog 2>&1 | perl -ne 'print $$1 if /^Version: (.*)/')
TGZ=../signing-party_$(VERSION).orig.tar.gz
TGZ_DIR=signing-party-$(VERSION)

all:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir || exit 1 ; fi ; done

install:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir install || exit 1 ; fi ; done

clean:
	for dir in $(DIRS) ; do if [ -f $$dir/Makefile ] ; then $(MAKE) -C $$dir clean || exit 1 ; fi ; done

dist:
	[ ! -f $(TGZ) ]
	mkdir $(TGZ_DIR)
	for dir in $(DIRS) ; do cp -a $$dir $(TGZ_DIR); done
	cp -a README Makefile $(TGZ_DIR)
	GZIP=--best tar cvz -f $(TGZ) --exclude .svn $(TGZ_DIR)
	rm -rf $(TGZ_DIR)

tag-release:
	if svn ls svn+ssh://svn.debian.org/svn/pgp-tools/tags/release-$(VERSION) >/dev/null 2>&1; then \
		echo "Already exists." >&2; exit 1; \
	fi
	svn cp -m 'tagging release $(VERSION)' svn+ssh://svn.debian.org/svn/pgp-tools/trunk svn+ssh://svn.debian.org/svn/pgp-tools/tags/release-$(VERSION)

tag-debian-version:
	if svn ls svn+ssh://svn.debian.org/svn/pgp-tools/tags/debian-version-$(DEBVERSION) >/dev/null 2>&1; then \
		echo "Already exists." >&2; exit 1; \
	fi
	svn cp -m 'tagging debian version $(DEBVERSION)' svn+ssh://svn.debian.org/svn/pgp-tools/trunk svn+ssh://svn.debian.org/svn/pgp-tools/tags/debian-version-$(DEBVERSION)
