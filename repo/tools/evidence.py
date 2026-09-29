"""诊断：对每个动作取最近一次任务，把「原始 stdout」与「解析结果」「结论」并排打出来。

用途：验证"界面结论 vs 手工执行输出"是否逐字对得上（T1 验收标准 #1 的核心手段）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from app.config import load as load_config  # noqa: E402
from app.store import Store  # noqa: E402

cfg = load_config(ROOT)
store = Store(cfg)

WATCH = {
    "host.overview": ["os_release", "cpu", "mem", "uptime_sec", "loadavg"],
    "svc.list": ["health", "running", "failed", "failed_state", "failed_log"],
    "log.view": ["tz", "unit_check", "hit_count", "logs"],
    "demo.confirm-gate": ["datetime", "chrony"],
}

# 每个动作取最近一次成功任务
latest: dict[str, str] = {}
for t in store.list_tasks(limit=60):
    if t["action_id"] in WATCH and t["action_id"] not in latest:
        latest[t["action_id"]] = t["id"]

for aid, tid in latest.items():
    data = store.get_task(tid)
    t = data["task"]
    print("=" * 74)
    print(f"### {aid}   任务 {tid}   状态 {t['status']}   自证 {t['verify_result']}   {t['duration_ms']}ms")
    print("=" * 74)
    print("\n【结论】")
    print(t["conclusion"])
    print("\n【关键步骤：原始 stdout vs 解析结果】")
    for s in data["steps"]:
        if s["name"] not in WATCH[aid]:
            continue
        print(f"\n  [{s['name']}] exit={s['exit_code']} status={s['status']}")
        print(f"    命令: {s['argv_quoted']}")
        raw = (s["stdout"] or "").strip()
        print(f"    原始 stdout: {raw[:300]!r}{' …' if len(raw) > 300 else ''}")
        print(f"    解析结果   : {s['parsed']!r}")
    print()
