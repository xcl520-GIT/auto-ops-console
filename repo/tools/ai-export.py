"""重新生成 AI 工具面生成物：`catalog/ai-tools.json`（规范 §12.75.2）。

用法（在 repo/ 下）：
    python tools/ai-export.py

★ 为什么要有这个脚本：**对账要有一个不依赖"我记得改过"的落点**（§12.68）。
  改了动作（加/删/改 risk）之后不重新生成，自检断言 ⑶ 就会红 —— 那是**设计意图**。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ai.tools import (  # noqa: E402
    COST_NOTES,
    ToolFace,
    _require_note,
    function_spec,
    write_json,
)
from app.catalog import load_actions  # noqa: E402
from app.config import load as load_config  # noqa: E402


def main() -> int:
    cfg = load_config(Path("."))
    actions = load_actions(cfg.paths.actions)
    if not isinstance(actions, dict):
        actions = {a.id: a for a in actions}

    face = ToolFace(cfg, actions)
    out = Path("catalog/ai-tools.json")
    payload = write_json(out, face)

    specs = face.function_specs()
    bad = [s["function"]["name"] for s in specs if "confirm" in json.dumps(s, ensure_ascii=False)]
    print(f"动作总数      = {len(actions)}")
    print(f"工具面（green）= {payload['tool_total']}")
    print(f"域数          = {len(payload and face.l1_index()['domains'])}")
    print(f"带代价说明的   = {len([a for a in payload['tools'] if a['cost_note']])}")
    print(f"带依赖说明的   = {len([a for a in payload['tools'] if a['require_note']])}")
    print(f"必填参数合计   = {sum(len(a['required']) for a in payload['tools'])}")
    print(f"函数 schema 数 = {len(specs)}")
    # ★ 结构自检（断言 🄋 的离线那一半）
    non_green = [a["id"] for a in payload["tools"] if a["risk"] != "green"]
    confirm_hits = [a for a in bad]
    print(f"★ 非 green 混入 = {non_green or '无'}")
    print(f"★ schema 里出现 confirm 字样 = {confirm_hits or '无'}")
    print(f"★ 生成物 = {out}（{out.stat().st_size} 字节）")
    print("★ 域索引预览 =", json.dumps(face.l1_index()["domains"], ensure_ascii=False))
    print("★ L2 预览（J 域前 3 条）= ",
          json.dumps(face.l2_domain("J")[:3], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
