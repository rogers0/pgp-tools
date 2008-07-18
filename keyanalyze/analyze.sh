#!/bin/bash --
# usage ./analyze.sh path/to/pubring.pgp
set -e
make

# comment these next lines out if you are working with an existing
# preprocess.keys file
pgpring -S -k $1							\
	| grep "\(pub\|sig\|rev\|uid\)"					\
	| sed -e "s/^\([a-z]*\).*:\([0-9A-F]\{16\}\):.*/\1 \2/g"	\
		-e "s/^uid:.*/uid/"	> all.keys
cat all.keys | process_keys $2 > preprocess.keys

# the actual processing of the main report
keyanalyze

# html beautification and reports and such
# comment this out if you don't want all the stuff in the report
# at http://dtype.org/keyanalyze/
cat output/msd.txt | sort -n -k 3 | nl -s ' ' > output/msd-sorted.txt
head -n 50 output/msd-sorted.txt | scripts/top50.pl > output/top50table.html
cat scripts/report_top.php output/top50table.html \
	scripts/report_bottom.php > output/report.php
head -n 1000 output/msd-sorted.txt | scripts/top50.pl > output/top1000table.html
cat scripts/1000_top.php output/top1000table.html \
	scripts/1000_bottom.php > output/report_1000.php
