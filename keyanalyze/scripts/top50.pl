#!/usr/bin/perl
# this short script is for making the HTML for the top50 report monthly
# Copyright (c)2001 M. Drew Streib
# This code is released under the GPL version 2 or later.

# NOTE: this is designed to be run one directory up, from analyze.sh

while ($line = <STDIN>) {
	$line =~ /\s+(\d+)\s+((\w|\d)+)\s+((\w|\d)+)\s+((\d|\.)+)/;
	$rank = $1;
	$key0 = $2;
	$key = $4;
	$msd = $6;
	$command = 'wget -O - -q "http://pgp.dtype.org:11371/pks/lookup?search=0x'
		.$key.'&op=index"';
	$wget = `$command`;
	$command = 'grep "'.$key.'" scripts/top50comments.txt';
	$rawcomments = `$command`;
	if (!($wget =~ /\d\d\d\d\/\d\d\/\d\d (.*)( \&lt.*)\n/)) { 
			$wget =~ /\d\d\d\d\/\d\d\/\d\d (.*)/;
			$name = $1;
		}
	else {
		$name = $1;
	}
	if ($rawcomments) {
		$rawcomments =~ /(\w|\d)+\s(.*)/;
		$comments = $2;
	} else {
		$comments = '';
	}
	print "<TR><TD>$rank</TD><TD><A href=\"http://pgp.dtype.org:11371/pks/lookup?search=0x$key\&op=vindex\">$key</A></TD><TD>$name</TD><TD><I>$comments</I></TD><TD align=\"right\">$msd</TD></TR>\n";
}
