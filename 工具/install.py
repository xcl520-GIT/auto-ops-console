"""auto-ops-console · 首次使用安装（由 `工具\\首次使用-安装.cmd` 调起）

★ 为什么分成两个文件：
  `cmd.exe` **按 OEM 代码页读 `.cmd`**（不是 UTF-8）⇒ `.cmd` 里的中文会被切碎、脚本解析不了。
  所以那个 `.cmd` 是**纯 ASCII 的引导**（找解释器 + 版本校验），**真正的活由本文件干** ——
  Python 处理 UTF-8 天经地义，中文提示也就能写清楚。

★ 它做什么（★ 每一件都**只做一次**，重复跑是幂等的）：
  1. 备好 `repo\\config.yaml`（缺 ⇒ 从 `config.example.yaml` 复制）
  2. 备好 `repo\\hosts.yaml`（缺 ⇒ 从 `hosts.example.yaml` 复制，并**明确告诉你还差什么**）
  3. 备好 `工具\\AutoOpsConsole.exe`（缺 ⇒ 调 `工具\\build-launcher.cmd` 用系统自带 csc 编一遍）
  4. 问一句要不要建快捷方式（桌面 + 开始菜单）
  5. 打印「下一步做什么」

★ 它**不装任何东西**：不用 pip / 不用 .NET SDK / 不下载任何二进制。
  本项目的运行期依赖只有"一个 Python 3.10+ 解释器"＋"系统自带的 ssh 客户端"。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

TOOLS = Path(__file__).resolve().parent
PROJ = TOOLS.parent
REPO = PROJ / "repo"

OK = "[OK]"
WARN = "[!]"
BAD = "[X]"


def say(s: str = "") -> None:
    print(s)


def step(n: int, total: int, title: str) -> None:
    say()
    say("── %d/%d %s " % (n, total, title) + "─" * max(0, 52 - len(title)))


def main() -> int:
    say("=" * 72)
    say("  auto-ops-console · 首次使用安装")
    say("  项目：%s" % PROJ)
    say("  解释器：%s（Python %d.%d.%d）" % (sys.executable, *sys.version_info[:3]))
    say("=" * 72)

    todo: list[str] = []          # 留给用户做的事
    problems: list[str] = []      # 需要修的问题

    # ── 1. config.yaml ───────────────────────────────────────────
    step(1, 5, "运行配置 repo\\config.yaml")
    cfg, ex_cfg = REPO / "config.yaml", REPO / "config.example.yaml"
    if cfg.is_file():
        say("  %s 已在（不动它）" % OK)
    elif ex_cfg.is_file():
        shutil.copyfile(ex_cfg, cfg)
        say("  %s 从模板生成了一份 —— ★ 你若不用 VMware，**什么都不用改**" % OK)
    else:
        problems.append("repo\\config.example.yaml 不见了（仓库不完整？）")
        say("  %s 模板不在，生成不了" % BAD)

    # ── 2. hosts.yaml ────────────────────────────────────────────
    step(2, 5, "主机清单 repo\\hosts.yaml")
    hosts, ex_hosts = REPO / "hosts.yaml", REPO / "hosts.example.yaml"
    if hosts.is_file():
        say("  %s 已在（不动它）" % OK)
        todo.append("看一眼 `repo\\hosts.yaml`：里面那几台机器是不是**你自己的**")
    elif ex_hosts.is_file():
        shutil.copyfile(ex_hosts, hosts)
        say("  %s 从模板生成了一份 —— ★★ **它现在填的是示例地址（192.0.2.x），要改成你的机器**" % WARN)
        todo.append("★ 改 `repo\\hosts.yaml`：把 id / address / user 换成你自己的 3 台（或更多）")
    else:
        problems.append("repo\\hosts.example.yaml 不见了（仓库不完整？）")
        say("  %s 模板不在，生成不了" % BAD)

    # ── 3. 交付物 AutoOpsConsole.exe ─────────────────────────────
    step(3, 5, "一键启动器 工具\\AutoOpsConsole.exe")
    exe, build = TOOLS / "AutoOpsConsole.exe", TOOLS / "build-launcher.cmd"
    if exe.is_file():
        say("  %s 已在（%d 字节）" % (OK, exe.stat().st_size))
    elif build.is_file():
        say("  不在 ⇒ 调 `工具\\build-launcher.cmd` 用**系统自带**的 C# 编译器编一遍…")
        cp = subprocess.run(["cmd", "/c", str(build)], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", cwd=str(TOOLS))
        if exe.is_file():
            say("  %s 编好了（%d 字节）" % (OK, exe.stat().st_size))
        else:
            problems.append("编不出来 —— 看 `工具\\build-launcher.cmd` 的输出（需要 .NET Framework 的 csc.exe）")
            say("  %s 没编出来" % BAD)
            say("      " + (cp.stdout or cp.stderr or "")[-400:])
    else:
        problems.append("`工具\\build-launcher.cmd` 不见了（仓库不完整？）")
        say("  %s 构建脚本不在" % BAD)

    # ── 4. 快捷方式（问一句，不擅自建）──────────────────────────
    step(4, 5, "桌面快捷方式 / 开始菜单项（可选）")
    if not exe.is_file():
        say("  %s 启动器还没编出来 ⇒ 这一步跳过" % WARN)
    else:
        say("  要不要在**桌面**和**开始菜单**各建一个入口？（只建这两个位置，可一键撤）")
        try:
            ans = input("  建吗？[y/N] ").strip().lower()
        except EOFError:
            ans = "n"
        if ans in ("y", "yes"):
            cp = subprocess.run([str(exe), "shortcut", "add"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
            say("  %s rc=%d" % (OK if cp.returncode == 0 else WARN, cp.returncode))
            for ln in (cp.stdout or "").splitlines():
                say("      " + ln)
        else:
            say("  好，跳过（以后随时可以：`工具\\AutoOpsConsole.exe shortcut add`）")

    # ── 5. 下一步 ───────────────────────────────────────────────
    step(5, 5, "下一步做什么")
    say("  ① 双击 **%s** —— 它会自己在 127.0.0.1:8787 上把控制台起起来，" % (TOOLS / "AutoOpsConsole.exe"))
    say("     并把浏览器打开（★ 只绑本机，不对外暴露）")
    say("  ② 第一次打开会让你**设一个口令**（本平台不用密码登录目标机，只做本机界面的门）")
    say("  ③ 想确认「它到底起没起来」：")
    say("        工具\\AutoOpsConsole.exe status          ← 人话")
    say("        工具\\AutoOpsConsole.exe status --json   ← 一行 JSON（给脚本读）")
    say()
    say("  ★ 换台机器要改的两处：`repo\\config.yaml` 里的 vmrun 路径 与 允许的虚拟机目录")
    say("  ★ 本平台**不改目标机**做任何安装：它只用 ssh，目标机侧零依赖")

    if todo:
        say()
        say("─" * 72)
        say("  还要你做这几件：")
        for t in todo:
            say("    · " + t)
    if problems:
        say()
        say("─" * 72)
        say("  有几处**没做成**（安装没完成，别往下用）：")
        for p in problems:
            say("    · " + p)
        say("=" * 72)
        return 1
    say()
    say("=" * 72)
    say("  安装完成。★ 上面「还要你做这几件」做完，才算真的能用。")
    say("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
