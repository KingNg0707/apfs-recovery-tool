# apfs-recovery-tool

A pipeline for recovering files from a **damaged APFS container** when normal
mounting tools fail — the worst case being the primary container superblock
overwritten by another filesystem's quick-format (e.g. NTFS). Instead of
repairing the filesystem, it reads the raw disk image, locates a surviving
superblock in the transaction ring, dumps the volume's catalog B-tree with a
patched `apfsck`, indexes the dump into SQLite, and serves a small web GUI for
selecting and streaming files back out to target disks.

**Everything here is read-only.** No tool in this repo writes to the source
image. You should still work on a copy of the image whenever feasible.

## 中文说明见下方（本 README 中英双语）。

## Layout

```
patches/apfsck-catalog-dump.patch   Patch against apfsprogs b9c4cb4 (recovery knobs + catalog dumper)
tools/build_index.py                TSV catalog dump -> SQLite index
tools/recover_gui.py                Local HTTP server: browse index, stream files to targets
tools/webui/index.html              GUI front-end (served by recover_gui.py)
tools/forensics/*.pl                Perl helpers for superblock discovery/verification
```

## Requirements

- macOS or Linux with `cc`, `make`, `perl`, Python 3 (`sqlite3` stdlib).
- [apfsprogs](https://github.com/linux-apfs/apfsprogs) at upstream commit
  `b9c4cb4` (GNU GPL-2.0). The patch also works on nearby commits if you fix
  context conflicts.

## Build the patched apfsck

```sh
git clone https://github.com/linux-apfs/apfsprogs && cd apfsprogs
git checkout b9c4cb4
git apply /path/to/patches/apfsck-catalog-dump.patch

# macOS: build with the mmap shim (see patch header — READ-ONLY use!)
cd apfsck && make CFLAGS='-include ../compat/mmap_shim.h -I../compat'
```

With no `APFS_*` environment variables set, this binary behaves like upstream.

## Recovery pipeline

1. **Image the disk** to a raw file (e.g. `dd if=/dev/rdiskN of=backup.img bs=4m`) or use an existing raw image.
2. **Find superblock candidates:**
   ```sh
   tools/forensics/apfs_scan.pl backup.img > apfs_magic_scan.txt
   tools/forensics/verify_apsb.pl backup.img apfs_magic_scan.txt   # newest valid APSB copies
   ```
3. **If the container superblock is gone**, locate one still referenced by the transaction ring:
   ```sh
   tools/forensics/boot_sb.pl  backup.img apfs_magic_scan.txt [ring_start ring_end]
   tools/forensics/find_vsb.pl backup.img apfs_magic_scan.txt
   tools/forensics/parse_sb.pl backup.img <sb_byte_offset>...
   ```
   Note the **block number** of a checksum-valid NXSB — that becomes `APFS_SB_BLOCK`.
4. **Dump the catalog** (opt-in knobs; ~13 min per 3.5 TB image):
   ```sh
   APFS_SB_BLOCK=<block> APFS_ALLOW_TRUNCATED=1 APFS_RECOVERY=1 \
     APFS_DUMP=/path/dump.tsv ./apfsck /path/backup.img
   ```
   Do **not** pass `-v` together with `APFS_DUMP` (it falls through to usage).
5. **Build the index:**
   ```sh
   python3 tools/build_index.py dump.tsv recovery_index.db
   ```
6. **Run the GUI** and stream selected files to your destination disks:
   ```sh
   python3 tools/recover_gui.py --db recovery_index.db --image backup.img \
       [--port 8642] [--blocksize 4096] [--forbid /path/never/write ...]
   ```
   Open http://127.0.0.1:8642 — the browser UI lets you browse the tree, select
   subtrees, add output volumes with capacity caps, and watch progress. The
   server refuses to write into the image's own volume or any `--forbid` prefix.

## Environment knobs (patched apfsck)

| Variable | Effect |
|---|---|
| `APFS_SOFT=1` | `report()` prints problems but does not exit |
| `APFS_RECOVERY=1` | Lenient key/inode/object checks |
| `APFS_ALLOW_TRUNCATED=1` | Clamp `s_block_count` to the real device size |
| `APFS_SB_BLOCK=<n>` | Read container NXSB from block `n` (dec or `0x` hex) |
| `APFS_DUMP=<file>` | Stream catalog B-tree to TSV and exit before fsck passes |
| `APFS_DUMP_XID=<xid>` | Dump a specific snapshot xid instead of the newest |

Dump line types: `I` inode, `D` directory entry, `E` extent. **File sizes come
from `E` extents** — on damaged images the inode `uncompressed_size` field is
often 0; `build_index.py` already computes sizes from extents.

## Forensics helper notes

- Checkpoint-map entries are 40 bytes (`struct apfs_checkpoint_mapping`).
  `boot_sb.pl`'s stride was fixed from an earlier buggy 32 in this repo.
- `verify_apsb.pl`, `boot_sb.pl` and `find_vsb.pl` parse the exact output
  format of `apfs_scan.pl` (`NXSB magic@0x... sb@0x...`). Older scan logs
  produced by an earlier version of `apfs_scan.pl` used a broken printf that
  emitted `magicx000012345678` instead; regenerate them with the current script.

## Limitations

- The GUI assumes an APFS block size matching `--blocksize` (4096 default) for
  extent→byte offset conversion.
- Hard links appear once per catalog entry; the dedup during extraction is by
  cnid, not content hash.
- Recovery mode disables integrity checks — expect some garbage entries in the
  dump; `build_index.py` skips obviously invalid rows.

## License

This repository is licensed under the **GNU GPL-2.0** (see `LICENSE`).
`patches/apfsck-catalog-dump.patch` is a derivative work of
[apfsprogs](https://github.com/linux-apfs/apfsprogs) (GPL-2.0, base commit
b9c4cb4); upstream copyright notices apply. The Python/Perl/web tools ship
under the same terms.

---

# 中文说明

这是一套从**损坏的 APFS 容器**恢复文件的流水线，适用于常规挂载工具都失效的最坏情况——例如容器主超级块被 NTFS 快速格式化覆盖。思路是不修复文件系统，而是直接读原始镜像：在事务环里找到幸存的超级块，用打过补丁的 `apfsck` 把目录 B 树整个导出成 TSV，再用 SQLite 建索引，最后通过本地网页 GUI 勾选文件、流式写回目标盘。

**全程只读**：仓库内没有任何工具会写源镜像；即便如此也建议在镜像副本上操作。

- 先 `apfs_scan.pl` 扫魔数 → `verify_apsb.pl` 校验卷超级块 →（主超级块被毁时）`boot_sb.pl` / `find_vsb.pl` 在事务环里找容器超级块，记下其**块号**。
- 用补丁版 apfsck 导出目录树：`APFS_SB_BLOCK=<块号> APFS_ALLOW_TRUNCATED=1 APFS_RECOVERY=1 APFS_DUMP=out.tsv ./apfsck 镜像`（约 13 分钟 / 3.5TB；**不要**带 `-v`）。
- `build_index.py` 建索引，`recover_gui.py` 起 GUI。文件大小以 extent（E 行）为准——损坏镜像上 inode 的 size 字段大多为 0，脚本已处理。
- GUI 会拒绝写入源镜像所在卷以及所有 `--forbid` 前缀；目标盘可按顺序填充并设容量上限。
- 本仓库整体采用 **GNU GPL-2.0**（见 `LICENSE`）。补丁为 [apfsprogs](https://github.com/linux-apfs/apfsprogs)（GPL-2.0，基线提交 b9c4cb4）的衍生作品，保留上游版权声明；Python/Perl/GUI 工具同样按 GPL-2.0 分发。
