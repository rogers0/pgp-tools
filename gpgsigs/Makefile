all: gpgsigs.1

gpgsigs.1: gpgsigs
	pod2man $< > $@

install:
	install -D gpgsigs $(DESTDIR)/usr/bin/gpgsigs
	install -D gpgsigs-helper \
		$(DESTDIR)/usr/share/signing-party/gpgsigs-helper
	install -d $(DESTDIR)/usr/share/doc/signing-party/examples/gpgsigs
	install -m644 gpgsigs-lt2k5*.txt \
		$(DESTDIR)/usr/share/doc/signing-party/examples/gpgsigs

clean:
	rm -f gpgsigs.1
