#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0
# Read-only scan of a raw disk image for APFS superblock magics
# (NXSB container / APSB volume).  Output is the input for verify_apsb.pl,
# boot_sb.pl and find_vsb.pl.
#
# Usage: ./apfs_scan.pl <image> > apfs_magic_scan.txt
use strict;

my $f = shift or die "usage: $0 <image>\n";
open my $fh, "<", $f or die "$f: $!"; binmode($fh);
my ($pos, $carry) = (0, "");
my (%cnt, %maxxid, $detail_budget);
$detail_budget = 300;
while (sysread($fh, my $buf, 64 * 1024 * 1024)) {
    my $ws = $pos - length($carry);
    my $w  = $carry . $buf;
    for my $pat ("NXSB", "APSB") {
        while ($w =~ /\Q$pat\E/g) {
            my $i  = pos($w) - 4;          # magic index in window
            my $sb = $ws + $i - 0x20;      # absolute superblock start
            next if $sb < 0 || ($sb % 4096) != 0;
            $cnt{$pat}++;
            my $lsb = $i - 0x20;           # local index of sb in window
            my $xid = length($w) >= $lsb + 0x18 ? (unpack("Q<", substr($w, $lsb + 0x10, 8)))[0] : -1;
            $maxxid{$pat} = $xid if $xid > ($maxxid{$pat} // -1);
            if ($detail_budget-- > 0) {
                my $ot = unpack("V", substr($w, $lsb + 0x18, 4));
                printf "%s magic\@0x%012x sb\@0x%012x objtype=0x%x xid=%d\n", $pat, $ws + $i, $sb, $ot, $xid;
                if ($pat eq "APSB" && length($w) >= $lsb + 0x350) {
                    my $name = substr($w, $lsb + 0x2C0, 64);
                    $name =~ s/\x00.*//s;
                    my ($nf, $nd) = unpack("Q< Q<", substr($w, $lsb + 0xB8, 16));
                    my $flags = (unpack("Q<", substr($w, $lsb + 0x68, 8)))[0];
                    printf "   volname=[%s] files=%d dirs=%d flags=0x%x\n", $name, $nf, $nd, $flags;
                }
                if ($pat eq "NXSB" && length($w) >= $lsb + 0x68) {
                    my ($bsz, $bcnt) = unpack("V Q<", substr($w, $lsb + 0x24, 12));
                    printf "   block_size=%d block_count=%d\n", $bsz, $bcnt;
                }
            }
        }
    }
    $pos += length($buf);
    $carry = substr($buf, -8192);
}
printf "\n=== SUMMARY ===\n";
for my $pat ("NXSB", "APSB") {
    printf "%s aligned candidates: %d  max_xid=%s\n", $pat, $cnt{$pat} // 0, defined $maxxid{$pat} ? $maxxid{$pat} : "-";
}
