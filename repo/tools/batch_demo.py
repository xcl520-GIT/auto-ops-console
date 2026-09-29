"""批量演练（T3）：把同一个动作铺到多台，验证失败隔离与横向对比。

用法（在 repo/ 下）：
    python tools/batch_demo.py svc.start unit=aoc-lab.service
    python tools/batch_demo.py disk.usage          # 只读动作也能批量（green 不需要确认）

设计要点：
  · 每台是**独立任务**（独立 ID、独立留证、可单独回放），批次只做汇总
  · 失败隔离：一台失败不阻断其他（这里靠"只有某台缺这个服务"来制造差异）
  · 横向对比：把"各台结论是否一致"标出来 —— **差异才是重点**
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

HOSTS = ["node-01", "node-02", "node-03", "docker-01"]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    action_id = sys.argv[1]
    params: dict[str, str] = {}
    for kv in sys.argv[2:]:
        key, _, value = kv.partition("=")
        params[key] = value

    cfg = load_config(Path("."))
    store = Store(cfg)
    store.init()
    engine = Engine(cfg, load_actions(cfg.paths.actions), store)

    print(f"=== 批量：{action_id} × {len(HOSTS)} 台  params={params} ===")
    try:
        out = engine.batch_run(action_id, HOSTS, params, confirm=True)
    except OpsError as exc:
        print(f"[被拦下] {exc.code}: {exc.reason}")
        print(f"         建议：{exc.advice}")
        return 1

    print(f"批次   = {out['batch_id']}")
    print(f"状态   = {out['status']}（{len([r for r in out['results'] if r['status'] == 'ok'])}/{len(out['results'])} 成功）")
    print("--- 各机结果 ---")
    for r in out["results"]:
        head = str(r.get("conclusion") or "").strip().splitlines()
        brief = head[0][:46] if head else ""
        print(f"  {r['host_name'][:28]:<30} {r['status']:<8} {r['duration_ms']:>6}ms  {brief}")
        if r.get("error"):
            print(f"      错误：{r['error']['reason'][:90]}")
    print("--- 横向对比 ---")
    if out["diff"]["consistent"]:
        print("  各台结论一致（无差异列需要高亮）")
    else:
        for d in out["diff"]["differences"]:
            print(f"  ⚠ {d['count']}/{len(out['results'])} 台：{'、'.join(d['hosts'])}")
            print(f"      → {str(d['conclusion'])[:100]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
