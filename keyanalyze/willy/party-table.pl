#!/usr/bin/perl

# Version: 1.0
# Date:    2001.01.07
# Author:  V. Alex Brennen <vab@cryptnet.net>
#          http://www.cryptnet.net/people/vab/
# License: GPL
# Description:
#          This script was written as part of the gpg keysigning
#          party howto.  It generates a checklist for individuals
#          participating in a keysigning party. The keysigning
#          howto lives at:
#               http://www.cryptnet.net/fdp/crypto/gpg-party.html

if($ARGV[0] eq "")
{
        print "\nUsage: party-table.pl <keyring> > out_file.html\n";
        print "\nThe keyring should be the keyring where the public keys for the\n";
        print "party participants are stored.\n\n";
        exit;
}

@fps = `gpg --fingerprint --no-default-keyring --keyring $ARGV[0]`;

my @parsed;

while($line = shift(@fps))
{
        if($line =~ /^pub/)
        {
                $key_info = substr($line,5,14);
                ($size_type,$id) = split(/\//,$key_info);
                $size = substr($size_type,0,4);
                $type = substr($size_type,-1,1);
                $owner = substr($line,31,-1);
                $fp_line = shift(@fps);
                ($trash,$fp) = split(/ = /,$fp_line);
                chomp $fp;
                ($fp1,$fp2) = split(/  /,$fp);
                $fp1 =~ s/ /&nbsp;/g;
                $fp2 =~ s/ /&nbsp;/g;
                if($type eq "D"){$type = "DSA";}
                elsif($type eq "R"){$type = "RSA";}
		elsif($type eq "G"){$type = "ElG";}
                $owner =~ s/</&lt\;/;
                $owner =~ s/>/&gt\;/;
                $owner =~ s/@/-at-/;
                push @parsed, {
                    id    => $id,
                    owner => $owner,
                    fp1   => $fp1,
                    fp2   => $fp2,
                    size  => $size,
                    type  => $type,
                };
        }
}

print "<HTML>\n";
print "<TABLE BORDER=1>\n";
print "<TR><TD>Key ID</TD><TD>Key Owner</TD><TD>Key Fingerprint</TD><TD>Key Size</TD><TD>Key Type</TD><TD>Key Info Matches?</TD><TD>Owner ID Matches?</TD></TR>\n";

foreach my $f (sort {uc($a->{owner}) cmp uc($b->{owner})} @parsed)
{
    $id = $f->{id};
    $owner = $f->{owner};
    $fp1 = $f->{fp1};
    $fp2 = $f->{fp2};
    $size = $f->{size};
    $type = $f->{type};

    print "<TR><TD>$id</TD><TD>$owner</TD><TD><tt>$fp1  $fp2</tt></TD><TD>$size</TD>";
    print "<TD>$type</TD><TD>&nbsp;</TD><TD>&nbsp;</TD></TR>\n";
}

print "</TABLE>\n";
print "</HTML>";
