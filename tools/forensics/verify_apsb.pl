#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0
# Verify every APSB (volume superblock) hit reported by apfs_scan.pl:
# check the Fletcher63 checksum and print xid/volname/root_tree_oid,
# newest first.  Use this to pick which volume superblock is intact.
#
# Usage: ./verify_apsb.pl <image> <apfs_magic_scan.txt output>
use strict;

my $f = shift or die "usage: $0 <image> <scan_output>\n";
open my $fh, "<", $f or die "$f: $!"; binmode($fh);
sub rd { my ($o, $n) = @_; return "" unless sysseek($fh, $o, 0); my $b = ""; sysread($fh, $b, $n); return $b; }

# Fletcher63 over bytes [8..end) of the block (standard APFS checksum).
sub fletcher64 {
    my ($d) = @_;
    my @w = unpack("V*", substr($d, 8, length($d) - 8));
    my ($s1, $s2) = (0, 0);
    for my $x (@w) { $s1 += $x; $s2 += $s1; }
    my $c1 = 0xFFFFFFFF - ($s1 + $s2) % 0xFFFFFFFF;
    my $c2 = 0xFFFFFFFF - ($s1 + $c1) % 0xFFFFFFFF;
    return ($c2 << 32) | $c1;
}

my $scan = shift or die "usage: $0 <image> <scan_output>\n";
open my $g, "<", $scan or die "$scan: $!";
my @hits;
while (<$g>) {
    # apfs_scan.pl prints: APSB magic@0x..... sb@0x..... objtype=... xid=...
    next unless /^APSB magic\@0x([0-9a-f]+) sb\@0x([0-9a-f]+)/;
    push @hits, hex($2);
}
close $g;

my @rows;
for my $sb (@hits) {
    my $d = rd($sb, 4096);
    next unless substr($d, 0x20, 4) eq "APSB";
    my $ok   = (unpack("Q<", substr($d, 0, 8)))[0] == fletcher64($d);
    my $xid  = (unpack("Q<", substr($d, 0x10, 8)))[0];
    my $n    = substr($d, 0x2C0, 64); $n =~ s/\x00.*//s;
    my ($nf, $nd) = unpack("Q< Q<", substr($d, 0xB8, 16));
    my $rt   = (unpack("Q<", substr($d, 0x88, 8)))[0];
    push @rows, [$xid, $sb, $ok, $n, $nf, $nd, $rt];
}
for my $r (sort { $b->[0] <=> $a->[0] } @rows) {
    printf "%s xid=%-7d sb\@0x%012x vol=[%s] files=%d dirs=%d root_tree_oid=0x%x\n",
        ($r->[2] ? "VALID" : "bad  "), $r->[0], $r->[1], $r->[3], $r->[4], $r->[5], $r->[6];
}
