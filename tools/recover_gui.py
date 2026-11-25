#!/usr/bin/env python3
"""Lightweight APFS recovery GUI (local web app).

Browse the recovered directory tree from a SQLite index built by
build_index.py, select files/dirs, and export them to one or more target
volumes with capacity caps + crash-resume. The source image is opened
read-only; nothing is ever written to it.

Usage:
  python3 recover_gui.py --db recovery.db --image disk.img [--port 8642]
                         [--blocksize 4096] [--forbid /path/never/write ...]

The server binds to 127.0.0.1 only; it has no authentication, so do not
expose the port beyond localhost.

SPDX-License-Identifier: GPL-2.0
"""
import argparse
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

CHUNK = 8 << 20   # streaming chunk size for extraction (keep RAM footprint tiny)


def sanitize_rel(name_parts):
    """Refuse path components that could escape the output directory.

    Names come from a damaged foreign filesystem; they may contain NULs,
    leading slashes or '..' segments. Returns None when unsafe.
    """
    out = []
    for part in name_parts:
        if part in (".", "..") or "/" in part or "\0" in part:
            return None
        out.append(part)
    return "/".join(out)


# ---------------------------------------------------------------- engine
class Engine:
    def __init__(self, db, image, blocksize=4096, forbidden=()):
        if not os.path.exists(db):
            sys.exit(f"index database not found: {db} (run build_index.py first)")
        self.db = db
        self.image = image
        self.blocksize = blocksize
        # The volume hosting the source image is always write-forbidden;
        # --forbid adds further path prefixes.
        self.forbidden = [os.path.realpath(p) for p in forbidden]
        try:
            self.img_dev = os.stat(image).st_dev
        except OSError:
            self.img_dev = None
        self.con = sqlite3.connect(db, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        # nodes has no index on parent -> every /api/children would be a
        # full multi-million-row scan; create it on first run.
        try:
            self.con.execute("CREATE INDEX IF NOT EXISTS idx_nodes_parent ON nodes(parent)")
            self.con.commit()
        except sqlite3.Error as e:
            print(f"[warn] parent index not created: {e}")
        self.lock = threading.Lock()
        self.img_fd = None
        self.status = {"running": False, "done": 0, "bytes_done": 0,
                       "total_files": 0, "total_bytes": 0, "log": [],
                       "targets": {}, "started": 0}

    # ---------- tree queries
    def children(self, cnid):
        # IMPORTANT: nodes.children_count from the raw APFS inode nchildren
        # field is unreliable on recovered images (snapshot counts leak into
        # it; e.g. a .DS_Store once claimed millions of children).
        # Expandability must come from real parent links instead.
        q = self.con.execute(
            """SELECT n.cnid,n.parent,n.name,n.type,n.size,n.subtree_size,n.subtree_files,
                      n.mtime,
                      CASE WHEN n.type='dir'
                           THEN (SELECT COUNT(*) FROM nodes c WHERE c.parent=n.cnid)
                           ELSE 0 END AS real_children
               FROM nodes n WHERE n.parent=?
               ORDER BY (n.type='dir') DESC, n.subtree_size DESC, n.name ASC""", (cnid,))
        out = []
        for r in q:
            d = dict(r)
            d["children_count"] = d["real_children"]   # authoritative item count for the '+' arrow
            out.append(d)
        return out

    def node(self, cnid):
        r = self.con.execute("SELECT * FROM nodes WHERE cnid=?", (cnid,)).fetchone()
        return dict(r) if r else None

    def path_parts(self, cnid):
        """Name components from root down to cnid; guards against cycles."""
        parts = []
        seen = set()
        cur = cnid
        while True:
            if cur in seen or len(parts) > 1024:
                return None          # corrupted parent chain
            seen.add(cur)
            r = self.con.execute("SELECT parent,name,type FROM nodes WHERE cnid=?", (cur,)).fetchone()
            if not r or cur == 2:
                break
            parts.append(r["name"])
            cur = r["parent"]
        return list(reversed(parts))

    def expand(self, cnids):
        """Yield files under selected cnids (dedup) as rows with extents."""
        seen = set()
        for c in cnids:
            q = self.con.execute(
                """WITH RECURSIVE t(c) AS (SELECT ? UNION ALL
                     SELECT n.cnid FROM nodes n JOIN t ON n.parent=t.c)
                   SELECT n.cnid,n.name,n.size,n.type FROM nodes n
                   WHERE n.cnid IN t AND n.type='file'""", (c,))
            for r in q:
                if r["cnid"] in seen:
                    continue
                seen.add(r["cnid"])
                yield dict(r)

    # ---------- volumes / capacity
    def volumes(self):
        out = []
        base = "/Volumes"          # macOS mount point; adjust for your OS
        try:
            for name in sorted(os.listdir(base)):
                p = os.path.join(base, name)
                if not os.path.isdir(p) or os.path.islink(p):
                    continue
                sv = os.statvfs(p)
                free = sv.f_bavail * sv.f_frsize
                total = sv.f_blocks * sv.f_frsize
                out.append({"path": p, "free": free, "total": total})
        except OSError as e:
            self.log(f"volumes scan error: {e}")
        return out

    def forbidden_reason(self, rp):
        """Return a human-readable reason why rp must not receive output."""
        for fp in self.forbidden:
            if rp == fp or rp.startswith(fp.rstrip("/") + "/"):
                return f"forbidden output location: {rp}"
        # Same filesystem as the source image is never a valid target — a
        # device check, not path-prefix, so other volumes mounted under /
        # (macOS firmlinks) are judged correctly.
        if self.img_dev is not None:
            a = rp
            while not os.path.exists(a):
                a = os.path.dirname(a)
            try:
                if os.stat(a).st_dev == self.img_dev:
                    return f"same filesystem as source image: {rp}"
            except OSError:
                pass
        return None

    # ---------- extraction
    def log(self, msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        with self.lock:
            self.status["log"].append(line)
            if len(self.status["log"]) > 500:
                self.status["log"] = self.status["log"][-500:]

    def ensure_image(self):
        if self.img_fd is None:
            self.img_fd = os.open(self.image, os.O_RDONLY)

    def iter_at(self, abs_off, length):
        # Stream <= CHUNK bytes at a time. NEVER buffer a whole extent:
        # recovered images routinely contain single extents of 100+ GB; an
        # 8 GB RAM machine died with SIGBUS (KERN_MEMORY_ERROR) when the
        # first version did bytearray(length).
        self.ensure_image()
        remaining = length
        off = abs_off
        while remaining > 0:
            want = min(CHUNK, remaining)
            data = os.pread(self.img_fd, want, off)
            if not data:
                raise OSError(f"image EOF at byte {off}")
            yield data
            off += len(data)
            remaining -= len(data)

    def extract_file(self, cnid, relpath, resume_from=0):
        """Stream all extents to relpath; resume_from = bytes already present to keep.
        Returns (bytes_written_this_run, final_size)."""
        rows = self.con.execute(
            "SELECT off,len,pblock FROM extents WHERE cnid=? ORDER BY off", (cnid,)).fetchall()
        if not rows:
            # inline-extent files have no E records; size in inode is authoritative then
            return 0, 0
        final = max(r["off"] + r["len"] for r in rows)
        written_now = 0
        total = resume_from
        next_log_at = resume_from
        with open(relpath, "r+b" if resume_from else "wb") as f:
            for r in rows:
                off, ln, pblock = r["off"], r["len"], r["pblock"]
                if off + ln <= resume_from:      # extent fully written before a crash
                    continue
                data_off = 0
                if off < resume_from:            # resume point falls inside this extent
                    data_off = resume_from - off
                    ln -= data_off
                f.seek(off + data_off)
                for chunk in self.iter_at(pblock * self.blocksize + data_off, ln):
                    f.write(chunk)
                    written_now += len(chunk)
                    total += len(chunk)
                    if total >= next_log_at:     # per-file progress (huge files take hours)
                        self.log(f"progress {relpath}: {total/1e9:.1f}/{final/1e9:.1f} GB")
                        next_log_at = total + max(2e9, final * 0.05)
            f.flush()
            if final >= (2 << 30):               # keep statvfs-based capacity math honest
                os.fsync(f.fileno())
        return written_now, final

    def start(self, cnids, targets):
        # targets: list of {"path":..., "cap": int}
        with self.lock:
            if self.status["running"]:
                return False, "already running"
        for t in targets:
            rp = os.path.realpath(t["path"])
            why = self.forbidden_reason(rp)
            if why:
                return False, why
            try:
                os.makedirs(rp, exist_ok=True)
            except OSError as e:
                return False, f"target {t['path']}: {e}"
        files = list(self.expand(cnids))
        files.sort(key=lambda x: -x["size"])
        total_bytes = sum(f["size"] for f in files)
        with self.lock:
            st = self.status
            st.update({"running": True, "done": 0, "bytes_done": 0,
                       "total_files": len(files), "total_bytes": total_bytes,
                       "log": [], "targets": {t["path"]: {"bytes": 0, "files": 0} for t in targets},
                       "started": time.time()})
        threading.Thread(target=self._worker, args=(files, targets), daemon=True).start()
        return True, ""

    def _pick_target(self, targets, size):
        for t in targets:
            path = t["path"]
            cap = t.get("cap", 0)
            sv = os.statvfs(path)
            free = (sv.f_bavail - 16) * sv.f_frsize   # keep a little headroom
            used = self.status["targets"][path]["bytes"]
            if size <= free and (cap == 0 or used + size <= cap):
                return path
        return None

    def _worker(self, files, targets):
        st = self.status
        manifest_dir_cache = {}
        for f in files:
            if not st["running"]:
                self.log("stopped by user")
                break
            parts = self.path_parts(f["cnid"])
            rel = sanitize_rel(parts) if parts else None
            if rel is None:
                self.log(f"SKIP (unsafe path) {f['cnid']}")
                continue
            tgt = self._pick_target(targets, max(f["size"], 1))
            if tgt is None:
                self.log(f"SKIP (no space) {rel}")
                continue
            outpath = os.path.join(tgt, rel)
            mdir = os.path.dirname(outpath)
            if mdir not in manifest_dir_cache:
                try:
                    os.makedirs(mdir, exist_ok=True)
                except OSError as e:
                    self.log(f"MKDIR FAIL {mdir}: {e}")
                    continue
                manifest_dir_cache[mdir] = True
            # resume: exact-size match = done; otherwise continue a partial file from its
            # existing bytes (extraction is deterministic, so byte-offset resume is safe)
            have = os.path.getsize(outpath) if os.path.exists(outpath) else 0
            if f["size"] > 0 and have == f["size"]:
                st["done"] += 1; st["bytes_done"] += f["size"]
                continue
            try:
                n, final = self.extract_file(f["cnid"], outpath, resume_from=have)
                st["done"] += 1
                st["bytes_done"] += n
                st["targets"][tgt]["bytes"] += n
                st["targets"][tgt]["files"] += 1
                if st["done"] % 200 == 0:
                    self.log(f"{st['done']}/{st['total_files']} files, {st['bytes_done']/1e9:.1f} GB")
            except Exception as e:
                self.log(f"FAIL {rel}: {e}")
        st["running"] = False
        self.log(f"finished: {st['done']} files, {st['bytes_done']/1e9:.2f} GB")

ENGINE = None  # built in main()

# ---------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self.send_error(404); return
        self.send_response(200)
        ctype = "text/html; charset=utf-8" if path.endswith(".html") else \
                "text/css" if path.endswith(".css") else "application/javascript"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            return self._html(os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui", "index.html"))
        if u.path == "/api/config":
            forb = list(ENGINE.forbidden)
            if ENGINE.img_dev is not None:   # show the auto-forbidden image volume too
                for v in ENGINE.volumes():
                    try:
                        if os.stat(v["path"]).st_dev == ENGINE.img_dev and v["path"] not in forb:
                            forb.append(v["path"])
                    except OSError:
                        pass
            return self._json({"image": ENGINE.image, "db": ENGINE.db,
                               "blocksize": ENGINE.blocksize,
                               "forbidden": forb})
        if u.path == "/api/children":
            cnid = int(qs.get("cnid", ["2"])[0])
            return self._json(ENGINE.children(cnid))
        if u.path == "/api/volumes":
            return self._json(ENGINE.volumes())
        if u.path == "/api/status":
            st = dict(ENGINE.status)
            st.pop("log", None)
            st["log"] = ENGINE.status["log"][-40:]
            return self._json(st)
        if u.path == "/api/node":
            return self._json(ENGINE.node(int(qs.get("cnid", ["2"])[0])))
        self.send_error(404)

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if u.path == "/api/extract":
            ok, err = ENGINE.start(body.get("cnids", []), body.get("targets", []))
            return self._json({"ok": ok, "error": err})
        if u.path == "/api/stop":
            ENGINE.status["running"] = False
            return self._json({"ok": True})
        self.send_error(404)

    def log_message(self, *a):  # quiet
        pass


def main():
    global ENGINE
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", required=True, help="SQLite index built by build_index.py")
    ap.add_argument("--image", required=True, help="raw disk image (opened read-only)")
    ap.add_argument("--port", type=int, default=8642)
    ap.add_argument("--blocksize", type=int, default=4096,
                    help="APFS block size used when converting extent pblock offsets")
    ap.add_argument("--forbid", action="append", default=[],
                    help="path prefix that must never receive output (repeatable)")
    a = ap.parse_args()
    ENGINE = Engine(a.db, a.image, a.blocksize, a.forbid)
    print(f"recovery GUI on http://127.0.0.1:{a.port}")
    HTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
