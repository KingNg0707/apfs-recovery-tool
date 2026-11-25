#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0
# When the standard container superblock is destroyed, find the newest
# checksum-valid NXSB in the transaction ring, then walk its checkpoint-map
# blocks backwards to locate (and verify) every volume-superblock copy.
#
# Usage: ./boot_sb.pl <image> <scan_output> [ring_start_hex ring_end_hex]
#        scan_output = apfs_scan.pl output; ring range optional, in bytes
#
# Checkpoint-map entry layout follows struct apfs_checkpoint_mapping
# (40-byte entries at offset 0x28: type/subtype/size/pad, fs_oid, oid, paddr).
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

my $scan = shift or die "usage: $0 <image> <scan_output> [ring_start ring_end]\n";
my ($ring_lo, $ring_hi) = (0, ~0);
if (@ARGV >= 2) { ($ring_lo, $ring_hi) = (hex($ARGV[0]), hex($ARGV[1])); }

# --- Step 1: NXSBs from scan output (optionally restricted to a range), verify checksums, find newest ---
my @ringA;
open my $g, "<", $scan or die "$scan: $!";
while (<$g>) {
    # apfs_scan.pl prints: NXSB magic@0x..... sb@0x..... objtype=... xid=...
    next unless /^NXSB magic\@0x([0-9a-f]+) sb\@0x([0-9a-f]+)/;
    my $sb = hex($2);
    push @ringA, $sb if $sb >= $ring_lo && $sb <= $ring_hi;
}
close $g;
my (@ok, $best);
for my $sb (sort { $a <=> $b } @ringA) {
    my $d = rd($sb, 4096);
    next unless substr($d, 0x20, 4) eq "NXSB";
    my $stored = (unpack("Q<", substr($d, 0, 8)))[0];
    my $xid    = (unpack("Q<", substr($d, 0x10, 8)))[0];
    if ($stored == fletcher64($d)) { push @ok, [$sb, $xid]; $best = [$sb, $xid] if !$best || $xid > $best->[1]; }
}
die "no checksum-valid NXSB found\n" unless $best;
printf "candidates: %d, checksum-valid: %d; best sb\@0x%x xid=%d\n", scalar(@ringA), scalar(@ok), $best->[0], $best->[1];

# --- Step 2: walk backwards from best SB collecting checkpoint-map blocks (objtype 0xc) ---
my @maps;
for (my $b = $best->[0] - 4096; ; $b -= 4096) {
    my $d = rd($b, 4096);
    last unless length($d) == 4096;
    my $ot = unpack("V", substr($d, 0x18, 4));
    $ot &= 0xffff;
    last unless $ot == 0xc;
    push @maps, $b;
    my $flags = unpack("V", substr($d, 0x20, 4));
    last if ($flags & 1) == $flags;   # LAST flag set -> first map block of the transaction
}
printf "checkpoint-map blocks for tx %d: %s\n", $best->[1], join(", ", map { sprintf "0x%x", $_ } @maps);

# --- Step 3: parse entries, find volume-superblock copies (type 0xd) ---
my @vsb;
for my $mb (@maps) {
    my $d = rd($mb, 4096);
    my $count = unpack("V", substr($d, 0x24, 4));
    for my $i (0 .. $count - 1) {
        my $e = substr($d, 0x28 + $i * 40, 40);
        my ($type, $subtype, $size, $pad) = unpack("V V V V", substr($e, 0, 16));
        my ($fs_oid, $oid, $paddr) = unpack("Q< Q< Q<", substr($e, 16, 24));
        if (($type & 0xffff) == 0xd) {
            printf "  FS entry: fs_oid=%d oid=%d paddr_block=%d (byte 0x%x)\n", $fs_oid, $oid, $paddr, $paddr * 4096;
            push @vsb, $paddr;
        }
    }
}

# --- Step 4: read each volume superblock copy, verify, dump fields ---
for my $blk (@vsb) {
    my $v = rd($blk * 4096, 4096);
    printf "\n--- volSB candidate at block %d (byte 0x%x) ---\n", $blk, $blk * 4096;
    next unless substr($v, 0x20, 4) eq "APSB";
    my $stored = (unpack("Q<", substr($v, 0, 8)))[0];
    printf "checksum: %s\n", ($stored == fletcher64($v) ? "VALID" : "INVALID");
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
    printf "features=0x%x incompat=0x%x (UNENCRYPTED flag set: %s)\n", $vf, $vinc, ($vf & 1) ? "yes" : "no";
}
