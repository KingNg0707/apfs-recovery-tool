#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0
# Walk container superblock copies newest-first, parse each transaction's
# checkpoint maps (40-byte entries), and collect every ephemeral
# volume-superblock copy (checkpoint type 0xd) the ring still references.
# Complements boot_sb.pl: this one stops as soon as it has >=2 vsb copies.
#
# Usage: ./find_vsb.pl <image> <scan_output> [ring_start_hex ring_end_hex]
#        scan_output = apfs_scan.pl output; ring range optional, in bytes
use strict;

my $f = shift or die "usage: $0 <image> <scan_output> [ring_start ring_end]\n";
open my $fh, "<", $f or die "$f: $!"; binmode($fh);
sub rd { my ($o, $n) = @_; return "" unless sysseek($fh, $o, 0); my $b = ""; sysread($fh, $b, $n); return $b; }

# Fletcher63 over bytes [8..end).
sub fletcher64 {
    my ($blk) = @_;
    my @w = unpack("V*", substr($blk, 8, length($blk) - 8));
    my ($s1, $s2) = (0, 0);
    for my $x (@w) { $s1 += $x; $s2 += $s1; }
    my $c1 = 0xFFFFFFFF - ($s1 + $s2) % 0xFFFFFFFF;
    my $c2 = 0xFFFFFFFF - ($s1 + $c1) % 0xFFFFFFFF;
    return ($c2 << 32) | $c1;
}
sub csum_ok { my ($d) = @_; return (unpack("Q<", substr($d, 0, 8)))[0] == fletcher64($d); }

my $scan = shift or die "usage: $0 <image> <scan_output> [ring_start ring_end]\n";
my ($ring_lo, $ring_hi) = (0, ~0);
if (@ARGV >= 2) { ($ring_lo, $ring_hi) = (hex($ARGV[0]), hex($ARGV[1])); }

# collect candidate NXSBs from scan log (optionally range-restricted), newest first
my @sbs;
open my $g, "<", $scan or die "$scan: $!";
while (<$g>) {
    # apfs_scan.pl prints: NXSB magic@0x..... sb@0x..... objtype=... xid=...
    next unless /^NXSB magic\@0x([0-9a-f]+) sb\@0x([0-9a-f]+)/;
    my $sb = hex($2);
    push @sbs, $sb if $sb >= $ring_lo && $sb <= $ring_hi;
}
close $g;
@sbs = sort { $b <=> $a } @sbs;

my %seen_vsb;   # paddr -> highest xid seen
for my $sb (@sbs) {
    my $d = rd($sb, 4096);
    next unless substr($d, 0x20, 4) eq "NXSB" && csum_ok($d);
    my $xid = (unpack("Q<", substr($d, 0x10, 8)))[0];
    # walk back over map blocks
    my @maps;
    for (my $b = $sb - 4096; ; $b -= 4096) {
        my $m = rd($b, 4096);
        last unless length($m) == 4096 && csum_ok($m);
        my $ot = unpack("V", substr($m, 0x18, 4)) & 0xffff;
        last unless $ot == 0xc;
        push @maps, $m;
        my $flags = unpack("V", substr($m, 0x20, 4));
        last if ($flags & 1) == $flags;
    }
    for my $m (@maps) {
        my $count = unpack("V", substr($m, 0x24, 4));
        for my $i (0 .. $count - 1) {
            my $e = substr($m, 0x28 + $i * 40, 40);
            my ($type, $subtype) = unpack("V V", substr($e, 0, 8));
            my ($fsoid, $oid, $paddr) = unpack("Q< Q< Q<", substr($e, 16, 24));
            next unless ($type & 0xffff) == 0xd;   # FS superblock copy
            printf "tx=%d: FS_SB copy fs_oid=%d oid=%d paddr_block=%d (byte 0x%x)\n", $xid, $fsoid, $oid, $paddr, $paddr * 4096;
            $seen_vsb{$paddr} = $xid unless exists $seen_vsb{$paddr};
        }
    }
    last if %seen_vsb >= 2;   # enough: we have copies for newest txs that touched fs sb
}

# verify each vsb copy and dump
for my $blk (sort { $seen_vsb{$b} <=> $seen_vsb{$a} } keys %seen_vsb) {
    my $v = rd($blk * 4096, 4096);
    printf "\n--- volSB copy block %d (byte 0x%x) [last seen in tx %d] ---\n", $blk, $blk * 4096, $seen_vsb{$blk};
    next unless substr($v, 0x20, 4) eq "APSB";
    printf "checksum: %s\n", (csum_ok($v) ? "VALID" : "INVALID");
    my $vxid   = (unpack("Q<", substr($v, 0x10, 8)))[0];
    my $name   = substr($v, 0x2C0, 64); $name =~ s/\x00.*//s;
    my ($nf, $nd, $nl, $no, $ns) = unpack("Q<5", substr($v, 0xB8, 40));
    my $rt_oid = (unpack("Q<", substr($v, 0x88, 8)))[0];
    my $rt_type = unpack("V", substr($v, 0x74, 4));
    my $lmt  = (unpack("Q<", substr($v, 0x100, 8)))[0];
    my $vf   = (unpack("Q<", substr($v, 0x28, 8)))[0];
    my $vinc = (unpack("Q<", substr($v, 0x38, 8)))[0];
    my $role = unpack("v", substr($v, 0x3C2, 2));
    printf "xid=%d vol=[%s] role=0x%x files=%d dirs=%d symlinks=%d other=%d snaps=%d\n", $vxid, $name, $role, $nf, $nd, $nl, $no, $ns;
    printf "root_tree_oid=0x%x type=0x%x last_mod=%s\n", $rt_oid, $rt_type, scalar(localtime($lmt + 978307200));
    printf "features=0x%x incompat=0x%x UNENCRYPTED: %s\n", $vf, $vinc, ($vf & 1) ? "yes" : "no";
}
