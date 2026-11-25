#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0
# Parse container superblocks (NXSB) at given byte offsets and dump their
# checkpoint-map locations plus all volume-superblock (APSB) references.
#
# Usage: ./parse_sb.pl <image> <sb_byte_offset> [more offsets...]
#        (offsets may be hex with 0x prefix; find them with apfs_scan.pl)
use strict;

my $f = shift or die "usage: $0 <image> <sb_offset...>\n";
open my $fh, "<", $f or die "$f: $!"; binmode($fh);
sub rd { my ($o, $n) = @_; sysseek($fh, $o, 0); my $b = ""; sysread($fh, $b, $n); return $b; }

for my $sb (@_) {
    my $d = rd(hex($sb), 4096);
    next unless length($d) == 4096;
    my ($bsz, $bcnt) = unpack("V Q<", substr($d, 0x24, 12));
    my ($nxid)       = unpack("Q<", substr($d, 0x60, 8));
    my ($xpb, $xpdb)     = unpack("V V", substr($d, 0x68, 8));
    my ($xpb_base, $xpdb_base) = unpack("Q< Q<", substr($d, 0x70, 16));
    my ($xdi, $xdlen)    = unpack("V V", substr($d, 0x88, 8));
    printf "=== NXSB \@$sb ===\n";
    printf " bs=%d blocks=%d next_xid=%d\n", $bsz, $bcnt, $nxid;
    printf " xp_desc: base_block=%d (byte 0x%x) blocks=%d index=%d len=%d range=0x%x..0x%x\n",
        $xpb_base, $xpb_base * $bsz, $xpb, $xdi, $xdlen,
        $xpb_base * $bsz, ($xpb_base + $xpb) * $bsz;
    printf " xp_data: base_block=%d blocks=%d\n", $xpdb_base, $xpdb;
    my @oids = unpack("Q<16", substr($d, 0xB8, 128));
    for my $i (0 .. 15) {
        my $oid = $oids[$i];
        next unless $oid;
        my $v     = rd($oid * $bsz, $bsz);
        my $magic = substr($v, 0x20, 4);
        my ($nf, $nd) = unpack("Q< Q<", substr($v, 0xB8, 16));
        my $name = substr($v, 0x2C0, 64); $name =~ s/\x00.*//s;
        my $rt_oid = (unpack("Q<", substr($v, 0x88, 8)))[0];
        my $rt_type = unpack("V", substr($v, 0x74, 4));
        my $lmt  = (unpack("Q<", substr($v, 0x100, 8)))[0];
        my $vf   = (unpack("Q<", substr($v, 0x28, 8)))[0];
        my $vinc = (unpack("Q<", substr($v, 0x38, 8)))[0];
        my $vxid = (unpack("Q<", substr($v, 0x10, 8)))[0];
        printf "  fs_oid[%d]=%d -> APSB\@0x%x magic=%s vol=[%s] files=%d dirs=%d\n",
            $i, $oid, $oid * $bsz, $magic, $name, $nf, $nd;
        printf "   root_tree_oid=0x%x type=0x%x last_mod=%s features=0x%x incompat=0x%x xid=%d\n",
            $rt_oid, $rt_type, scalar(localtime($lmt + 978307200)), $vf, $vinc, $vxid;
    }
}
