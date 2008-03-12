all:

install:
	install -D sig2dot $(DESTDIR)/usr/bin/sig2dot
	install -D -m644 sig2dot.1 $(DESTDIR)/usr/share/man/man1/sig2dot.1
	install -d $(DESTDIR)/usr/share/doc/signing-party/sig2dot
	install -m644 README.sig2dot changelog.sig2dot \
		$(DESTDIR)/usr/share/doc/signing-party/sig2dot

clean:
