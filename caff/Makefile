MAN = caff.1 pgp-clean.1 pgp-fixkey.1

all: $(MAN)

%.1: %
	pod2man $< > $@

clean:
	rm -f $(MAN)
