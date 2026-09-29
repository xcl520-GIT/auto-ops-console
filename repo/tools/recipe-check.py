"""配方体检 · 命令行入口（T7 · 规范 §12.21 的"写配方时随手可跑"那一半）。

为什么要有这个入口（而不是只用界面上的那个按钮）：
  体检的设计目标是"**写配方的过程中**每改一处就点一下"。而写配方的人**不一定开着控制台** ——
  跑一条命令就能得到同样的结论，门槛才真的低。★ 两条路走的是**同一套** `lint_recipe`
  （与 `/api/recipes/<id>/lint` 共用实现）—— **不养第二套判定**，否则两边结论迟早漂移。

用法：
  python tools\\recipe-check.py                     # 体检 catalog/recipes 下全部配方
  python tools\\recipe-check.py --id nginx          # 只看一份
  python tools\\recipe-check.py --recipes <目录>     # 体检别处的配方（例如 var\\lab\\recipes-bad）
  python tools\\recipe-check.py -v                  # 连"每一项为什么"一起打印

退出码：
  0 = 全部 ok / warn（warn 是"能跑，但有条边界要知道"）
  1 = 有 fail（**别拿去跑**）
  2 = 装载期就跑不起来（会把"哪一份、错在哪"打出来 —— 那是装载期校验在说话）
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # Windows 控制台默认 cp936
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

from app.catalog import load_actions  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.recipe import lint_recipe, lint_summary, load_recipes  # noqa: E402
from app.store import now_iso  # noqa: E402


def _arg(name: str, default: str = "") -> str:
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def main() -> int:
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    cfg = load_config(ROOT)
    actions = load_actions(cfg.paths.actions)

    recipes_dir = Path(_arg("--recipes") or (cfg.paths.catalog / "recipes"))
    if not recipes_dir.is_absolute():
        recipes_dir = (ROOT / recipes_dir).resolve()

    recipes, report = load_recipes(recipes_dir, actions, now=now_iso(cfg))
    print(f"配方目录：{recipes_dir}")
    print(f"装载：成功 {len(report.loaded)} 份"
          f"{'（' + '、'.join(report.loaded) + '）' if report.loaded else ''}")
    if not report.ok:
        print(f"★ 有 {len(report.failed)} 份**没装进来**（装载期校验拦下）：")
        for f in report.failed:
            print(f"  · {f['file']}")
            for e in (f.get("errors") or []):
                print(f"      {e}")
        # ★ 装载不过就不体检 —— 体检的是"写得全不全"，不是"能不能装载"（两件事，别混）
        return 2

    want = _arg("--id")
    targets = [want] if want else sorted(recipes)
    missing = [t for t in targets if t not in recipes]
    if missing:
        print(f"没有这个配方：{'、'.join(missing)}")
        return 2

    worst = "ok"
    for rid in targets:
        res = lint_summary(lint_recipe(recipes[rid], actions))
        mark = {"ok": "✅", "warn": "⚠️", "fail": "❌"}.get(res["overall"], "?")
        print(f"\n{mark} {rid}（{recipes[rid].name}）总判：{res['overall']}"
              f" ｜ ok {res['ok']} · warn {res['warn']} · fail {res['fail']}")
        for item in res["items"]:
            if item["level"] == "ok" and not verbose:
                continue
            print(f"    [{item['level']}] {item['name']}：{item['detail']}")
        if res["overall"] == "fail":
            worst = "fail"
        elif res["overall"] == "warn" and worst == "ok":
            worst = "warn"

    print(f"\n一共体检 {len(targets)} 份 ｜ 最差的一档：{worst}")
    print("★ 体检**不连目标机**（静态检查）；连机器的探测属于「探针 / 计划预览」，是另一件事。")
    return 1 if worst == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
