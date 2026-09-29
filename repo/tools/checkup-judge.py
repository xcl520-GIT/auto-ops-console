# -*- coding: utf-8 -*-
"""T17·S8 取证：把平台**自己的**体检判定层（`app.checkup.judge`）对某个体检任务跑一遍并打出来。

★ 为什么要有这一步：`host.checkup` 是**采集器**（只交原始事实），
  「12 项逐项给什么结论」是**判定层**算出来的（§10.2）。验收 #7 要看的正是**判定层**，
  尤其是"命令不在 ⇒ 无法判定（⚠️）"这一档 —— 不许被写成"通过"。
★ 这里**不重新实现**任何判据：直接调平台那一份 `judge()`。
用法：python var/_t17_judge.py <体检任务号>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.catalog import load_actions  # noqa: E402
from app.checkup import judge  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.store import Store  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    task_id = sys.argv[1]
    cfg = load_config(ROOT)
    store = Store(cfg)
    actions = load_actions(cfg.paths.actions)
    j = judge(cfg, store, task_id, actions)

    print("=== 判定层输出（app.checkup.judge） ===")
    print("任务号：%s" % task_id)
    print("总判：%s %s ｜ %s" % (j.get("overall_icon", ""), j.get("overall_label", ""),
                                j.get("overall") or ""))
    print("")
    print("%-4s %-6s %-18s %s" % ("#", "判定", "项", "结论（verdict）"))
    for it in j.get("items") or []:
        print("%-4s %-6s %-18s %s" % (it.get("no"), it.get("icon", "") + (it.get("label") or ""),
                                      it.get("title"), (it.get("verdict") or "")[:150]))
        if it.get("advice"):
            print("      建议：%s" % str(it["advice"])[:150])
    print("")
    print("按档位统计：%s" % json.dumps(j.get("counts") or {}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
