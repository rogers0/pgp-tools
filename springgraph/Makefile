all:

install:
	install -D springgraph $(DESTDIR)/usr/bin/springgraph
	install -D -m644 springgraph.1 $(DESTDIR)/usr/share/man/man1/springgraph.1
	install -d $(DESTDIR)/usr/share/doc/signing-party/springgraph
	install -m644 README.springgraph changelog.springgraph \
		$(DESTDIR)/usr/share/doc/signing-party/springgraph

clean:
