MAN = gpglist.1

all: $(MAN)

%.1: %
	pod2man $< > $@

clean:
	rm -f $(MAN)
