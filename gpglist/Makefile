MAN = gpglist.1

all: $(MAN)

%.1: %
	pod2man $< > $@

install:

clean:
	rm -f $(MAN)
