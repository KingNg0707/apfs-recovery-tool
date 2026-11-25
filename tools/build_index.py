#!/usr/bin/env python3
"""Build a SQLite tree index from an apfsck catalog dump (I/D/E TSV).

Input lines produced by the patched apfsck (see patches/):
  I<TAB>cnid<TAB>mode<TAB>size<TAB>btime<TAB>mtime        (inode; size often 0 -> use extents)
  D<TAB>parent_cnid<TAB>child_cnid<TAB>drec_flags<TAB>name(escaped)
  E<TAB>cnid<TAB>logical_offset<TAB>length<TAB>flags<TAB>phys_block_num

File sizes come from extent sums (authoritative on damaged images, where the
inode uncompressed_size field is frequently 0); the extents table feeds the
GUI extractor. Output: SQLite with tables `nodes` + `extents`.

Usage: python3 build_index.py cat_dump.tsv recovery.db

SPDX-License-Identifier: GPL-2.0
"""
import argparse
import os
import sqlite3
import time

ROOT = 2  # APFS_ROOT_DIR_INO_NUM


def unescape(s):
    """Decode the C-side escape format: \\t \\n \\r \\\\ \\uXXXX."""
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            n2 = s[i + 1]
            if n2 == "t":
                out.append("\t"); i += 2; continue
            if n2 == "n":
                out.append("\n"); i += 2; continue
            if n2 == "r":
                out.append("\r"); i += 2; continue
            if n2 == "\\":
                out.append("\\"); i += 2; continue
            if n2 == "u" and i + 5 < n:
                try:
                    out.append(chr(int(s[i + 2:i + 6], 16))); i += 6; continue
                except ValueError:
                    pass
        out.append(c); i += 1
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("tsv", help="catalog dump produced by patched apfsck")
    ap.add_argument("db", help="output SQLite database")
    args = ap.parse_args()
    tsv, db = args.tsv, args.db

    t0 = time.time()
    inodes = {}   # cnid -> [mode, size, btime, mtime]
    edges  = []   # (parent, child, name)
    ext_sum = {}  # cnid -> total length
    n_i = n_d = n_e = bad = 0
    with open(tsv, "r", encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            if not line.endswith("\n"):
                continue
            p = line.rstrip("\n").split("\t")
            try:
                if p[0] == "I":
                    cnid = int(p[1])
                    inodes[cnid] = [int(p[2]), int(p[3]), int(p[4]), int(p[5])]
                    n_i += 1
                elif p[0] == "D":
                    name = unescape(p[4]).rstrip("\0")
                    edges.append((int(p[1]), int(p[2]), name))
                    n_d += 1
                elif p[0] == "E":
                    cnid = int(p[1])
                    ln = int(p[3])
                    ext_sum[cnid] = ext_sum.get(cnid, 0) + ln
                    n_e += 1
            except (IndexError, ValueError):
                bad += 1
    print(f"parsed: inodes={n_i} drecs={n_d} extents={n_e} bad={bad}  {time.time()-t0:.1f}s")

    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("""CREATE TABLE nodes(
        cnid INTEGER PRIMARY KEY, parent INTEGER, name TEXT,
        type TEXT, mode INTEGER, size INTEGER, btime INTEGER, mtime INTEGER,
        children_count INTEGER DEFAULT 0, subtree_size INTEGER DEFAULT 0,
        subtree_files INTEGER DEFAULT 0, depth INTEGER DEFAULT -1)""")
    cur.execute("""CREATE TABLE extents(
        cnid INTEGER, off INTEGER, len INTEGER, flags INTEGER, pblock INTEGER)""")
    cur.execute("CREATE INDEX idx_ext_cnid ON extents(cnid)")

    def ftype(mode):
        fmt = mode & 0o170000
        return {0o40000: "dir", 0o100000: "file", 0o120000: "symlink"}.get(fmt, "other")

    # extents table (batch insert)
    with open(tsv, "r", encoding="utf-8", errors="surrogateescape") as f:
        buf = []
        for line in f:
            if not line.startswith("E\t"):
                continue
            p = line.rstrip("\n").split("\t")
            try:
                buf.append((int(p[1]), int(p[2]), int(p[3]), int(p[4]), int(p[5])))
            except (IndexError, ValueError):
                continue
            if len(buf) >= 200000:
                cur.executemany("INSERT INTO extents VALUES(?,?,?,?,?)", buf); buf = []
        if buf:
            cur.executemany("INSERT INTO extents VALUES(?,?,?,?,?)", buf)
    con.commit()
    print(f"extents table done  {time.time()-t0:.1f}s")

    # dedupe edges: same (parent,name) keep first occurrence
    seen_edge = set()
    rows = []
    for parent, child, name in edges:
        key = (parent, name)
        if key in seen_edge:
            continue
        seen_edge.add(key)
        rows.append((child, parent, name))

    ins = []
    for child, parent, name in rows:
        m = inodes.get(child)
        if m is None:
            continue
        size = ext_sum.get(child, m[1])
        ins.append((child, parent, name, ftype(m[0]), m[0], size, m[2], m[3]))
    cur.executemany("INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?,?, ?,0,0,0,-1)", ins)
    con.commit()
    print(f"inserted {len(ins)} linked nodes  {time.time()-t0:.1f}s")

    cnt = dict(cur.execute("SELECT parent, COUNT(*) FROM nodes WHERE parent IS NOT NULL GROUP BY parent"))
    # NOTE: executemany binds left-to-right — feed (count, cnid), not cnt.items()
    cur.executemany("UPDATE nodes SET children_count=? WHERE cnid=?",
                    [(c, p) for p, c in cnt.items()])

    kids = {}
    for child, parent, _ in rows:
        if child != ROOT:
            kids.setdefault(parent, []).append(child)

    order = []
    cur_depth = {ROOT: 0}
    frontier = [ROOT]
    while frontier:
        nxt = []
        for p in frontier:
            order.append(p)
            for c in kids.get(p, ()):
                if c not in cur_depth:
                    cur_depth[c] = cur_depth[p] + 1
                    nxt.append(c)
        frontier = nxt

    sub_size = {}
    sub_files = {}
    for cnid in reversed(order):
        m = inodes.get(cnid)
        is_file = bool(m) and ftype(m[0]) == "file"
        s = ext_sum.get(cnid, 0) if is_file else 0
        n = 1 if is_file else 0
        for c in kids.get(cnid, ()):
            s += sub_size.get(c, 0)
            n += sub_files.get(c, 0)
        sub_size[cnid] = s
        sub_files[cnid] = n

    batch = [(sub_size[c], sub_files[c], cur_depth[c], c) for c in order]
    cur.executemany("UPDATE nodes SET subtree_size=?, subtree_files=?, depth=? WHERE cnid=?", batch)
    con.commit()
    tot = cur.execute("SELECT COUNT(*), SUM(subtree_size) FROM nodes").fetchone()
    print(f"db rows={tot[0]} total_bytes={tot[1]}  done {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
