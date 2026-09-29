"""跑一个配方（T17·S5）—— 补上 T16 结题回执 §4 #6 留下的那个缺口。

★ 为什么要有它：T16 的 A 级真跑只做到**动作级**；配方的**整体真跑**当时跑不了，
  因为 `tools\\` 下没有跑配方的命令行入口（只有 `recipe-check.py` 那样的静态体检）。
  ⇒ T17 的"一句话造机"就是一条配方，**必须**能整链真跑，所以先把它补上。

用法（在 repo/ 下）：
    python tools/run_recipe.py <配方id> <目标机id> [参数=值 ...] [confirm_text=xxx] [mode=deploy]
    python tools/run_recipe.py vm-provision aoc-tpl-01 mother=node-03 new_id=aoc-tpl-01 ...
    python tools/run_recipe.py vm-provision aoc-tpl-01 --plan      # ★ 只做计划（不执行）

★ 与界面走的是**同一条路**（`RecipeRunner.run` / `.plan`）—— 这里不是"另一套执行"，
  只是"给命令行一个入口"，免得为了跑一次整链去开浏览器。
★ 闸门照旧：配方含 red 步骤 ⇒ 必须 `confirm_text=` 手输配方声明的那个词（规范 §12.6.1 / 铁律 9）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.catalog import load_actions  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.errors import OpsError  # noqa: E402
from app.recipe import RecipeRunner, load_recipes  # noqa: E402
from app.store import Store  # noqa: E402


try:  # ★★ T17（规范 §12.134）：工具自己的 stdout 也要 pin 编码（同 run_one.py 的理由）
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    recipe_id, host_id = sys.argv[1], sys.argv[2]
    rest = sys.argv[3:]
    plan_only = "--plan" in rest
    rest = [x for x in rest if x != "--plan"]

    params: dict[str, str] = {}
    confirm_text = ""
    mode = "deploy"
    for kv in rest:
        key, _, value = kv.partition("=")
        if key == "confirm_text":
            confirm_text = value
        elif key == "mode":
            mode = value
        else:
            params[key] = value

    cfg = load_config(Path("."))
    actions = load_actions(cfg.paths.actions)
    recipes, report = load_recipes(cfg.paths.catalog / "recipes", actions)
    store = Store(cfg)
    store.init()
    engine = Engine(cfg, actions)
    runner = RecipeRunner(cfg, actions, engine, store, recipes, report)

    bad = [p for p in getattr(report, "problems", []) or [] if "vm-provision" in str(p)]
    if bad:
        print("★ 装载期就报错（这就不该往下走）：")
        for b in bad:
            print(f"  {b}")
        return 2

    print(f"=== 配方 {recipe_id} @ {host_id}  mode={mode}  params={params} ===")

    if plan_only:
        try:
            plan = runner.plan(recipe_id, host_id, params)
        except OpsError as exc:
            print(f"[被拦下] {exc.code}: {exc.reason}")
            print(f"         建议：{exc.advice}")
            return 1
        keep = {k: plan.get(k) for k in ("recipe_id", "host_id", "risk", "blocked", "reason",
                                         "steps", "uninstall", "health", "params")}
        print(json.dumps(keep, ensure_ascii=False, indent=2, default=str)[:4000])
        return 0

    try:
        run = runner.run(recipe_id, host_id, params, mode=mode, confirm=True,
                         confirm_text=confirm_text)
    except OpsError as exc:
        print(f"[被拦下] {exc.code}: {exc.reason}")
        print(f"         建议：{exc.advice}")
        return 1

    print(f"run     = {getattr(run, 'id', '?')}")
    print(f"status  = {getattr(run, 'status', '?')}")
    steps = (getattr(run, "steps", None) or getattr(run, "records", None)
             or getattr(run, "results", None) or [])
    print("--- 步骤 ---")
    for s in steps:
        seq = getattr(s, "seq", getattr(s, "index", ""))
        print(f"  {seq} {getattr(s, 'name', '?'):<16} {getattr(s, 'status', '?'):<9} "
              f"task={getattr(s, 'task_id', '') or getattr(s, 'task', '')}")
    print("--- 结论 ---")
    print(getattr(run, "conclusion", "") or "（无）")
    err = getattr(run, "error", None)
    if err:
        print(f"--- 错误 ---\n  {getattr(err, 'code', '')}: {getattr(err, 'reason', err)}")
    return 0 if getattr(run, "status", "") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
