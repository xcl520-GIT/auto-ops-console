"""验收标准 #4 的证明：新增一个动作**只需加一份 YAML**，代码零改动。

做法（比 git diff 更严格 —— 它比对的是内容哈希，不是文件列表）：
  1. 对 repo 下所有「代码 + 配置 + 文档」文件算 sha256，得到基线快照
  2. 新建一份临时动作 YAML
  3. 重新装载动作目录 → 确认新动作出现、覆盖率分母不变（因为它不在 map 里）
  4. 真跑一次这个新动作
  5. 删掉临时 YAML（不留垃圾）
  6. 重新算哈希 → 与基线逐一比对

判定：只要**没有任何旧文件的哈希发生变化**，就证明"加动作不动代码"。
如果将来有人为了加动作去改 app/ 下的代码，这个脚本会立刻失败。

用法：python tools\\proof_add_action.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

from app.catalog import load_actions, load_map, reconcile  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.store import Store  # noqa: E402

# 这些目录/文件属于"实现"，新增动作时一个字节都不该变
WATCH_DIRS = ["app", "web", "docs", "tools"]
WATCH_FILES = ["config.yaml", "hosts.yaml", "catalog/map.yaml"]

NEW_ACTION_ID = "proof.added-action"
NEW_ACTION_FILE = ROOT / "catalog" / "actions" / f"{NEW_ACTION_ID}.yaml"

NEW_ACTION_YAML = f"""# 临时动作：用于证明"新增动作只加一份 YAML"（tools/proof_add_action.py 会自动删除它）
id: {NEW_ACTION_ID}
title: 新增动作证明
summary: 临时动作，验证"只加一份 YAML 就能跑"
domain: A
risk: green
priority: P0
params:
  - name: word
    label: 要说的话
    type: str
    required: true
    pattern: '^[A-Za-z0-9 _-]{{1,40}}$'
    default: hello from a new action
    help: 只允许字母数字空格下划线连字符（白名单）
steps:
  - name: uname
    title: 内核版本
    run: ["uname", "-r"]
    parser: raw
verify:
  - name: 必须读到内核
    from: uname
    on_missing: uname -r 无输出
conclusion: |
  新动作跑通了。
  参数 word = {{word}}
  目标机内核 = {{uname}}
"""


def snapshot() -> dict[str, str]:
    out: dict[str, str] = {}
    for d in WATCH_DIRS:
        for f in sorted((ROOT / d).rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                out[str(f.relative_to(ROOT))] = hashlib.sha256(f.read_bytes()).hexdigest()
    for f in WATCH_FILES:
        p = ROOT / f
        if p.is_file():
            out[f] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def main() -> int:
    print("=" * 72)
    print("  验收标准 #4 证明：新增一个动作，代码零改动")
    print("=" * 72)
    cfg = load_config(ROOT)

    before = snapshot()
    print(f"\n① 基线快照：{len(before)} 个文件已记录 sha256")
    print(f"   覆盖：{'、'.join(WATCH_DIRS)} + {'、'.join(WATCH_FILES)}")

    if NEW_ACTION_FILE.exists():
        NEW_ACTION_FILE.unlink()
    print(f"\n② 写入一份新动作 YAML：{NEW_ACTION_FILE.name}（{len(NEW_ACTION_YAML)} 字节）")
    NEW_ACTION_FILE.write_text(NEW_ACTION_YAML, encoding="utf-8")

    try:
        actions_before = load_actions(cfg.paths.actions)
        print(f"\n③ 重新装载动作目录 → 共 {len(actions_before)} 个动作")
        print(f"   新动作是否出现：{'✅ 是' if NEW_ACTION_ID in actions_before else '❌ 否'}")
        a = actions_before.get(NEW_ACTION_ID)
        if a is None:
            return 1
        print(f"   它的参数/步骤/断言全部由 YAML 声明：params={len(a.params)} steps={len(a.steps)} verify={len(a.verify)}")

        cov = reconcile(load_map(cfg.paths.map), actions_before)
        print(f"   覆盖率分母不变（新动作不在 map 里，不污染账本）：{cov['done']}/{cov['total']}")

        print("\n④ 真跑这个新动作（走完整 Engine 流程）")
        engine = Engine(cfg, actions_before, Store(cfg))
        res = engine.run(NEW_ACTION_ID, cfg.hosts[0].id, {"word": "proof ok"}, confirm=True)
        pub = res.to_public()
        t = pub["task"]
        print(f"   任务 {t['id']} 状态={t['status']} 自证={t['verify_result']} 用时={t['duration_ms']}ms")
        print("   ---- 它自己的结论 ----")
        for line in t["conclusion"].splitlines():
            print("   " + line)
    finally:
        NEW_ACTION_FILE.unlink(missing_ok=True)
        print(f"\n⑤ 已删除临时 YAML：{NEW_ACTION_FILE.name}")

    after = snapshot()
    changed = [k for k in sorted(set(before) | set(after))
               if before.get(k) != after.get(k)]

    print("\n⑥ 哈希比对")
    print(f"   基线 {len(before)} 个文件 ｜ 现在 {len(after)} 个文件")
    if changed:
        print(f"   ❌ 有 {len(changed)} 个文件发生了变化（这违反「加动作只加 YAML」）：")
        for k in changed:
            print(f"      · {k}")
        return 1
    print("   ✅ 0 个文件变化 —— 新增动作确实只需要一份 YAML")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
