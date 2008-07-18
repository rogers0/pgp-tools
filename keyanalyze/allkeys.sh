#!/bin/bash --
# usage ./analyze.sh path/to/pubring.pgp
set -e
make

# comment these next lines out if you are working with an existing
# preprocess.keys file
pgpring/pgpring -S -k $1							\
	| grep "\(pub\|sig\|rev\|uid\)"					\
	| sed -e "s/^\([a-z]*\).*:\([0-9A-F]\{16\}\):.*/\1 \2/g"	\
		-e "s/^uid:.*/uid/"	> all.keys
