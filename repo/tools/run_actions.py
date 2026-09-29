"""T2 批量跑动作的临时运行器（跑完即删）。

用法：python var\_t2_run_batch.py host.datetime disk.usage ...   （不给 id 则跑全部 green 动作）
每个动作：默认参数 + 真实执行 → 打印状态/步骤/结论，并落库留证。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from app.catalog import load_actions          # noqa: E402
from app.config import load as load_config    # noqa: E402
from app.engine import Engine                 # noqa: E402
from app.errors import OpsError               # noqa: E402
from app.store import Store                   # noqa: E402

cfg = load_config(ROOT)
actions = load_actions(cfg.paths.actions)
store = Store(cfg)
store.init()
engine = Engine(cfg, actions, store)
host_id = cfg.hosts[0].id

ids = sys.argv[1:] or sorted(a.id for a in actions.values() if a.risk == "green")

for aid in ids:
    print("=" * 72)
    try:
        res = engine.run(aid, host_id, {}, confirm=True)
    except OpsError as exc:
        print(f"{aid}: ❌ {exc.code} {exc.reason} | {exc.advice}")
        continue
    pub = res.to_public(raw=False)
    t = pub["task"]
    print(f"{aid}  status={t['status']}  verify={t['verify_result']}  "
          f"steps={t['step_total']}（失败 {t['step_failed']}）  {t['duration_ms']}ms  task={t['id']}")
    for s in pub["steps"]:
        flag = {"ok": "OK  ", "skipped": "SKIP"}.get(s["status"], s["status"].upper())
        line = f"   [{flag}] {s['name']:<14} rc={s['exit_code']} {s['duration_ms']}ms"
        if s["error"]:
            line += f"  ⚠ {s['error']['code']}: {s['error']['reason']}"
        print(line)
    if t["error"]:
        print(f"   ★ 任务级错误 {t['error']['code']}: {t['error']['reason']}")
        print(f"     建议：{t['error']['advice']}")
    print("   --- 结论 ---")
    for ln in (t["conclusion"] or "（空）").splitlines():
        print("   " + ln)
