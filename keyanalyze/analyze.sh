#!/bin/bash --
# usage ./analyze.sh path/to/pubring.pgp
set -e
make

# comment these next lines out if you are working with an existing
# preprocess.keys file
pgpring -S -k "$1" | process_keys $2 > preprocess.keys

# the actual processing of the main report
keyanalyze

# html beautification and reports and such
# comment this out if you don't want all the stuff in the report
# at http://dtype.org/keyanalyze/
cat output/msd.txt | sort -k 3 | nl -s ' ' > output/msd-sorted.txt
cat output/msd.txt | scripts/top50.pl > output/top50table.html
cat scripts/report_top.php output/top50table.html \
	scripts/report_bottom.php > output/report.php
cat output/msd.txt | scripts/top50.pl -n 1000 > output/top1000table.html
cat scripts/1000_top.php output/top1000table.html \
	scripts/1000_bottom.php > output/report_1000.php
