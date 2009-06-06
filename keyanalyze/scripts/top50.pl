#!/usr/bin/perl -w
# this short script is for making the HTML for the top50 report monthly
# Copyright (c)2001 M. Drew Streib
# This code is released under the GPL version 2 or later.

# 2004-09-14: modifications by Christoph Berg <cb@df7cb.de>:
#  * use perl to read top50comments.txt
#  * use gpg --list-key instead of wget
#  * use strict & warnings

# 2008-07-18: modifications by Christoph Berg <cb@df7cb.de>:
#  * directly read msd.txt instead of a -sorted variant

use strict;
use Getopt::Std;

#my $keyserver = "http://pks.gpg.cz:11371/pks/lookup?op=vindex&fingerprint=on&search=0x";
#my $keyserver = "http://keyserver.noreply.org/pks/lookup?op=index&fingerprint=on&search=0x";
my $keyserver = "http://pool.sks-keyservers.net:11371/pks/lookup?op=index&fingerprint=on&search=0x";
my %options;
getopts('c:k:n:', \%options);
my $comments = $options{c} || "top50comments.txt";
my $keyring = $options{k} ? "--no-default-keyring --keyring=$options{k}" : "";
my $top = $options{n} || 50;

my %comment;
if (open F, $comments) {
	while(<F>) {
		die "$comments.$.: syntax error" unless /([\dA-F]+)\b ?(.*)/;
		$comment{$1} = $2;
	}
	close F;
}

my %msd;
while (my $line = <>) {
	$line =~ /^\w+\s+(\w+)\s+([\d\.]+)/ or die "cannot parse line $.: $line";
	$msd{$1} = $2;
}

print "<table>\n";
print "<tr><th>#</th><th>Id</th><th></th><th>Name</th><th>MSD</th></tr>\n";

my $oldmsd = 0;
my $i = 1;
foreach my $key (sort { $msd{$a} <=> $msd{$b} } keys %msd) {
	my $rank = "";
	if($oldmsd != $msd{$key}) {
		$rank = $i++;
	}
	last if $rank and $rank > $top;
	$oldmsd = $msd{$key};
	my $name = "";
	open G, "gpg --list-key --fixed-list-mode --with-colon --trust-model always $keyring $key |" or die "gpg: $!";
	while(<G>) {
		#uid:u::::1082202576::1DC0BEA2AC64671CC902D50B8121F6E4E6336E15::Christoph Berg <cb@df7cb.de>:
		next unless /^uid:[-qmfue]::::\d*::[\dA-F]*::(.+):$/;
		$name = $1;
		$name =~ s/</&lt;/g;
		$name =~ s/>/&gt;/g;
		$name =~ s/\@/&#64;/g;
		last;
	}
	close G;
	my $comment = $comment{$key} || "";
	$key =~ /^([\dA-F]{2})/;
	#my $prefix = $1;
	#print "<TR><TD align=\"right\">$rank</TD><TD><a href=\"$prefix/$key.html\">$key</a> <small><A href=\"$keyserver$key\">keyserver</A></small></TD><TD>$name</TD><TD><I>$comment</I></TD><TD align=\"right\">$msd</TD></TR>\n";
	print "<TR><TD align=\"right\">$rank</TD><TD><a href=\"$key.html\">$key</a></TD><TD><small><A href=\"$keyserver$key\">keyserver</A></small></TD><TD>$name <I>$comment</I></TD><TD align=\"right\">$msd{$key}</TD></TR>\n";
}

print "</table>\n";
