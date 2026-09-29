"""一次性修复：T3 期间产生的备份记录，local_path 记的是不带序号前缀的错误文件名。

背景（真因）：backup.py 把远程备份命名成 `{seq:02d}-{base}`，scp 拉回管理机后落盘也是这个名字，
但旧代码把 local_path 记成 `{local_dir}/{base}` —— 于是记录指向一个不存在的文件。
代码已在 T4 修正；这个脚本只用来**修复历史记录**，让"记录里的路径 = 磁盘上的文件"重新成立。

用法：
  python tools\\fix_backup_local_path.py          # 干跑（默认，只报告不改）
  python tools\\fix_backup_local_path.py --apply  # 真改
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "var" / "ops.db"
APPLY = "--apply" in sys.argv


def main() -> int:
    if not DB.exists():
        print(f"❌ 找不到数据库：{DB}")
        return 1
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    rows = list(conn.execute(
        "SELECT id, task_id, seq, orig_path, local_path FROM backups "
        "WHERE local_path IS NOT NULL AND local_path != '' ORDER BY id"
    ))
    print(f"数据库：{DB}")
    print(f"待检查记录：{len(rows)} 条\n")

    fixed = ok = missing = 0
    updates: list[tuple[str, int]] = []
    for r in rows:
        cur = Path(r["local_path"])
        if cur.exists():
            ok += 1
            print(f"  [无需改] #{r['id']} 原样存在：{cur.name}")
            continue
        # 候选：同一目录下带序号前缀的那个文件（就是 scp 真正落盘的名字）
        cand = cur.parent / f"{int(r['seq']):02d}-{cur.name}"
        if cand.exists():
            fixed += 1
            updates.append((str(cand), r["id"]))
            print(f"  [需修复] #{r['id']} {cur.name}  →  {cand.name}   （{cand.stat().st_size} B）")
        else:
            missing += 1
            print(f"  [查不到] #{r['id']} 记录={cur.name}，目录里也没有 {cand.name}"
                  f"　→ 原始路径 {r['orig_path']}（可能是当时回拉失败）")

    print(f"\n小结：无需改 {ok} · 需修复 {fixed} · 真找不到 {missing}")
    if not updates:
        print("没有需要改的记录。")
        return 0
    if not APPLY:
        print("\n（干跑模式，未改动数据库；加 --apply 执行）")
        return 0
    with conn:
        for new_path, bid in updates:
            conn.execute("UPDATE backups SET local_path = ? WHERE id = ?", (new_path, bid))
    print(f"\n✅ 已更新 {len(updates)} 条记录")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
