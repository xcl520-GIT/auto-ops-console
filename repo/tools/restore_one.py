"""恢复演练工具（T3）：把一条备份恢复回原路径，并做逐字节自证。

用法（在 repo/ 下）：
    python tools/restore_one.py              # 列出最近的备份记录（只看，不恢复）
    python tools/restore_one.py <记录id>     # 恢复该记录（自动带正确确认词）
    python tools/restore_one.py <记录id> wrong   # 反面验证：故意用错的确认词

为什么要它：规范 §9.2 说"备份 ≠ 可恢复"。护栏的价值只有在**真恢复过一次**之后才算成立，
所以这个演练是 T3 的验收项之一，不能靠"看代码觉得没问题"。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.catalog import load_actions  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.errors import OpsError  # noqa: E402
from app.store import Store  # noqa: E402


def main() -> int:
    cfg = load_config(Path("."))
    store = Store(cfg)
    store.init()
    engine = Engine(cfg, load_actions(cfg.paths.actions), store)

    if len(sys.argv) < 2:
        rows = store.list_backups(limit=12)
        if not rows:
            print("还没有任何备份记录。先跑一个带 backup: 段的变更动作（如 cron.remove）。")
            return 0
        print(f"{'id':>4}  {'状态':<8} {'原路径':<40} {'指纹':<18} 恢复于")
        for r in rows:
            print(
                f"{r['id']:>4}  {r['status']:<8} {str(r['orig_path'])[:40]:<40} "
                f"{str(r['sha256'] or '')[:16]:<18} {r['restored_at'] or '—'}"
            )
        return 0

    arg = str(sys.argv[1])
    if arg == "latest":
        rows = [r for r in store.list_backups(limit=50) if r["status"] == "ok"]
        if not rows:
            print("没有状态为 ok 的备份可恢复。")
            return 1
        backup_id = int(rows[0]["id"])
    else:
        backup_id = int(arg)
    wrong = len(sys.argv) > 2 and sys.argv[2] == "wrong"
    confirm_text = "随便写点什么" if wrong else "确认恢复"

    rec = store.get_backup(backup_id)
    print(f"=== 恢复演练 #{backup_id} @ {rec['host_name']} ===")
    print(f"原路径   : {rec['orig_path']}")
    print(f"备份路径 : {rec['remote_path']}")
    print(f"记录指纹 : {str(rec['sha256'] or '')[:32]}…")
    print(f"确认词   : {confirm_text}" + ("（★ 故意写错，应当被拦下）" if wrong else ""))
    try:
        out = engine.restore_backup(backup_id, confirm_text)
    except OpsError as exc:
        print(f"[被拦下] {exc.code}: {exc.reason}")
        print(f"         建议：{exc.advice}")
        return 1 if wrong else 1

    print(f"恢复任务 : {out['task_id']}")
    print(f"结果     : {'✅ 成功' if out['ok'] else '❌ 失败'}")
    for s in out["steps"]:
        print(f"  · {s['title']}  rc={s['exit_code']}")
        if s.get("stdout"):
            print(f"      {s['stdout'].strip().splitlines()[0][:90]}")
    print("结论     :", out["conclusion"] or out.get("error") or "（无）")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
