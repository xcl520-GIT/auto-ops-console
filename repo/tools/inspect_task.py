"""查看某个任务的步骤留证（临时排查用，跑完即删）。"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

db = ROOT / "var" / "ops.db"
con = sqlite3.connect(db)
con.row_factory = sqlite3.Row
task_id = sys.argv[1]
for r in con.execute(
    "SELECT seq, name, status, exit_code, duration_ms, argv_quoted, stderr, error_reason "
    "FROM task_steps WHERE task_id=? ORDER BY seq", (task_id,)
):
    print(f"[{r['seq']:02d}] {r['name']:<12} {r['status']:<8} rc={r['exit_code']} {r['duration_ms']}ms")
    print(f"     命令: {r['argv_quoted']}")
    if r["error_reason"]:
        print(f"     错误: {r['error_reason']}")
    if r["stderr"]:
        print(f"     stderr: {r['stderr'][:300]!r}")
print()
print("表结构：", [d[0] for d in con.execute("SELECT * FROM task_steps LIMIT 1").description])
