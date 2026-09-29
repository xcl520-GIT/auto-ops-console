# -*- coding: utf-8 -*-
"""规模复算器（★ README / 工程方法 里那些数字的**出处**）。

★ 为什么要有它：T11 定下的「交付物的数字纪律」要求**每个数字都能照复算命令跑一遍**。
  而"行数 / 文件数"这种东西最容易被口径搞混 ——
    · `splitlines()` 与"文件以换行结尾时多算一行"的差别；
    · 递归范围（`app/` 还是 `app/ + tools/`；含不含 `var/` 下的一次性脚本）；
    · 一份文档写的 `20026 行`，另一份写的 `20356 行` —— **两个真相**。
  ⇒ 把**口径写在代码里**：行数一律 = 每个文件 `.splitlines()` 之和（含空行）。

用法（两个位置都能跑）：
    python 工具\\size-report.py
    cd repo && python tools\\size-report.py

★ 与 `工具\\check-deliverables.py` 的分工：
  那个管"交付物齐不齐 / 引用点不点得开"；这个只回答"有多大"。
"""
from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent


def find_repo() -> Path:
    """找到 `repo/`（本脚本可能在 项目根\\工具\\ 下，也可能在 repo\\tools\\ 下）。"""
    for cand in (HERE, HERE.parent, HERE / "repo", HERE.parent / "repo", HERE.parent.parent / "repo"):
        if (cand / "app" / "__init__.py").is_file():
            return cand
    raise SystemExit("★ 没找到 repo/（本脚本要放在 项目根\\工具\\ 或 repo\\tools\\ 下跑）")


REPO = find_repo()
ROOT = REPO.parent


def stat(patterns: list[str], base: Path | None = None) -> tuple[int, int]:
    base = base or REPO
    files: list[Path] = []
    for pat in patterns:
        files += [p for p in base.glob(pat) if p.is_file()]
    files = sorted(set(files))
    lines = sum(len(p.read_text(encoding="utf-8", errors="replace").splitlines()) for p in files)
    return len(files), lines


def main() -> int:
    print("=" * 68)
    print("  auto-ops-console · 规模复算（口径：splitlines() 求和，含空行）")
    print(f"  repo = {REPO}")
    print("=" * 68)
    checks = [
        ("后端（app/**/*.py）", ["app/**/*.py"]),
        ("前端（web/* 全部文件）", ["web/*"]),
        ("动作 YAML（catalog/actions）", ["catalog/actions/*.yaml"]),
        ("配方 YAML（catalog/recipes）", ["catalog/recipes/*.yaml"]),
        ("动作规范（docs/动作规范.md）", ["docs/动作规范.md"]),
        ("自检（tools/selftest.py）", ["tools/selftest.py"]),
        ("代码合计（app + tools 的 .py）", ["app/**/*.py", "tools/*.py"]),
    ]
    for name, pats in checks:
        n, ln = stat(pats)
        print(f"  {name:30s} {n:4d} 个 / {ln:6d} 行")
    shots = sorted((ROOT / "docs" / "screenshots").glob("*.png"))
    print(f"  {'截图（docs/screenshots/*.png）':30s} {len(shots):4d} 张")
    print("\n★ 这份输出就是 README「规模」那一行的出处；改文档时先跑它，别凭印象写。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
