"""T18 · 证伪演示：注入 ⇒ 对应断言**真红** ⇒ **逐字节**还原 ⇒ 复核回绿。

★ 为什么每条断言都要有这一份：本项目口径「**能证伪才算判据**」。
  一条"永远绿"（或"永远红"）的判据，与没有判据是同义的（§12.114）——
  它会被人关掉，或者在关键时刻给出一个没有信息量的绿。
★ 本文件**只做注入与还原**：判据本身**一行都不另写**，跑的还是 `tools\\selftest.py`。
  （T15 那条教训：判据不能判自己。这里注入的是"**被测物**"，复核的是"**原来那条判据**"。）

★★ 本文件自己踩过的坑（T18·S6 第一次跑就照出来了，留档）：
  第一版用**文本模式**读、`write_text(newline="")` 写回 —— 那**不叫逐字节还原**。
  它当场给出了两条「还原**不逐字节一致**」的报错。改成 `read_bytes / write_bytes`
  之后才对。★ 教训与 §12.142 同源：**"看起来一样"与"逐字节一样"是两件事**；
  而"还原"必须是后者 —— 否则你还原的是"我以为的原文"，不是原文。

用法：  python tools\\proof_t18.py                  # 输出到控制台
        python tools\\proof_t18.py --log <路径>      # 同时自己写一份日志
退出码：0 = 每一处注入都**真红**（且**只红该红的那几条**）＋ 还原**逐字节一致** ＋ 复核回绿
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import time
from pathlib import Path

try:                                     # ★ 规范 §12.134：工具自己 pin 住 stdout 编码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]           # repo/
PROJ = ROOT.parent                                   # 项目根
SELFTEST = ROOT / "tools" / "selftest.py"
PROBE = ROOT / "tools" / "launcher_probe.py"
BUILD = PROJ / "工具" / "build-launcher.cmd"
DOC = PROJ / "工具" / "启动器-说明.md"
RREADME = ROOT / "README.md"

# ★★ 交付物源码的 sha256 —— **现算**，不许写死。
#   ★ 为什么要有这一行（T18 收尾真踩过）：Ⓩg-5 那处注入原来把**旧的**哈希前 8 位
#     （`d76df49c`）写成字面量；而 S9 改了 `AutoOpsConsole.cs`（六层解释器探测）之后
#     说明文档里的记录值换成了 `c8dc71f1…` ⇒ 注入**命中 0 次** ⇒ 那一条**"没验到"**，
#     而整个演示只报"有 1 处不符合预期"，**看起来像被测物坏了**。
#   ⇒ 规矩：注入串**不许是会漂的字面量** —— 能从现场算出来的，就现算。
_CSSHA8 = hashlib.sha256(
    (PROJ / "工具" / "launcher" / "AutoOpsConsole.cs").read_bytes()).hexdigest()[:8]
_CSSHA8_ALT = ("d" if _CSSHA8[0] != "d" else "e") + _CSSHA8[1:]

# (标签, 目标文件, 原文, 换成, 期望变红的符号**集合**, 用哪条通道)
#   ★ 通道 t18     = `selftest.py --t18`（只跑 T18 那一节，快）
#   ★ 通道 offline = `selftest.py --offline`（Ⓩi 算的是"这次一共多少条"，
#     快通道里那个数字**毫无意义** ⇒ 刻意不跑它，只能用完整离线跑）
#   ★★ 「期望变红的集合」是**集合**而不是"恰好一条"：
#      把 `repo\README.md` 的数字改掉，**同时**会踩响 `㊿b`（它管"文档**之间**不许打架"）
#      —— 那是对的，不是噪音。两条断言的分工本来就不同（§12.146 写得明明白白）。
CASES = [
    ("Ⓩe 可注入：把探针里「注入之后人话里不许再出现 8787」那条**删掉**",
     PROBE, '"①-c ★ 注入之后人话里不许再出现 8787"', '"①c-已删 ★ 注入之后"',
     {"Ⓩe"}, "t18"),
    ("Ⓩf 认人：把探针里「`restart` 之后那个程序**也还活着**」那条**删掉**",
     PROBE, '"③-i ★★★', '"③i-已删 ★★★',
     {"Ⓩf"}, "t18"),
    ("Ⓩg-1 构建脚本必须是纯 ASCII：往里塞一个非 ASCII 字节",
     BUILD, "@echo off", "@echo off\nrem 中",
     {"Ⓩg-1"}, "t18"),
    ("Ⓩg-2 判据必须是「大小一致」：把它写反成「大小不一致」",
     SELFTEST, "sizes[0] is not None and sizes[0] == sizes[1]",
     "sizes[0] is not None and sizes[0] != sizes[1]",
     {"Ⓩg-2"}, "t18"),
    ("Ⓩg-5 源码 sha256 对账：把说明里记的那个 hash 改掉一位（★ 串是**现算**的，不写死）",
     DOC, _CSSHA8, _CSSHA8_ALT,
     {"Ⓩg-5"}, "t18"),
    ("Ⓩj 结论的收口：把探针里「`start` **不攥着调用者的管道**」那条**删掉**"
     "（★ 这条是 S8 那条真缺陷的回归哨兵）",
     PROBE, '"⑥-c2 ★★★', '"⑥c2-已删 ★★★',
     {"Ⓩj"}, "t18"),
    ("Ⓩk 拉起服务的护栏：把探针里「第一个**还在跑**时第二个实例照样起得来」那条**删掉**"
     "（★ 这条是 S8 第二条真缺陷的回归哨兵：两个实例抢同一个日志文件）",
     PROBE, '"⑦-b ★★★', '"⑦b-已删 ★★★',
     {"Ⓩk"}, "t18"),
    ("Ⓩm 可移植性：把探针里「第一个候选**不是 python** ⇒ 跳过并继续找」那条**删掉**"
     "（★ 这条是「自动找解释器」**真的自动**的哨兵）",
     PROBE, '"⑧-b ★★★', '"⑧b-已删 ★★★',
     {"Ⓩm"}, "t18"),
    ("Ⓩi 门禁条数 文档↔实测：把 `repo\\README.md` 的数字改掉一个"
     "（★ 同时应当踩响 `㊿b`：它管「文档之间」，两条分工不同）",
     RREADME, "离线 752/752 · 完整 834/834", "离线 751/751 · 完整 834/834",
     {"Ⓩi", "㊿b"}, "offline"),
    ("Ⓩn 离线门不许碰生产库：把那条判据的比较**写反**（★ 与 Ⓩg-2 同一个风格："
     "判据写反了必须红。★ Ⓩn 的**强证据**不在这里 —— 见 T18 残尾的写入追踪："
     "隔离前一次门往生产库写了 3 笔，隔离后 0 笔）",
     SELFTEST, "now == _REAL_DB_SHA_AT_START,", "now != _REAL_DB_SHA_AT_START,",
     {"Ⓩn"}, "offline"),
]


def _run(argv: list[str], timeout: int = 900):
    t0 = time.time()
    p = subprocess.run([sys.executable] + argv, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=str(ROOT), timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or ""), time.time() - t0


def _reds(out: str) -> set:
    """只取汇总段里那些 `    ❌ <符号> ...` 的**符号**（前几个字符）。"""
    got = set()
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("❌ "):
            body = s[2:].strip()
            got.add(body.split(" ")[0])
    return got


class _Tee:
    """★★ 把输出**同时**写到控制台和一份日志文件。

    ★ 为什么需要它（S6′ 的现场）：本演示一轮要跑 ~250 秒，而 shell 对这条长命令的捕获
      反复给出 **0 字节**（纯重定向 / `Tee-Object` / `python -u` 各试一次）。
      ⇒ 证据**不能依赖管道的可靠性** —— 让脚本**自己把证据写下来**。
      （与 T17 §一.4「工具自己 pin stdout」同一条纪律：**留证这件事本身要自己扛**。）
    """

    def __init__(self, console, log):
        self.console = console
        self.log = log

    def write(self, s):
        # ★★ **先写文件，再写控制台** —— 这个类的全部意义就是"证据不依赖管道的可靠性"
        #   （见类注释），顺序反了就等于把这件事交给管道。
        #   ★ T18 收尾实测到过反面：控制台那头是一个**已经没人读的管道**（调用方窗口到期），
        #   写到缓冲区满就**阻塞** ⇒ 进程卡死、而日志**一个字节都没写**（因为先写的是控制台）。
        #   ⇒ 两件事：① 顺序反过来；② 两边都 try —— **留证这件事谁也不许把谁拖死**。
        try:
            self.log.write(s)
            self.log.flush()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.console.write(s)
        except Exception:  # noqa: BLE001
            pass
        return len(s)

    def flush(self):
        try:
            self.console.flush()
        except Exception:  # noqa: BLE001
            pass
        self.log.flush()

    def isatty(self):
        return False


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    logpath = None
    if "--log" in argv:
        i = argv.index("--log")
        if i + 1 >= len(argv):
            print("❌ --log 需要一个路径")
            return 2
        logpath = argv[i + 1]
    if logpath:
        lp = Path(logpath)
        lp.parent.mkdir(parents=True, exist_ok=True)
        _fh = open(lp, "w", encoding="utf-8", newline="")   # noqa: SIM115
        sys.stdout = _Tee(sys.__stdout__, _fh)
        sys.stderr = sys.stdout

    print("=" * 74)
    print("  T18 · 证伪演示：注入 ⇒ 真红 ⇒ **逐字节**还原 ⇒ 复核回绿")
    print(f"  仓库 {ROOT}")
    print("=" * 74)

    bad = []
    for label, target, old, new, want, channel in CASES:
        # ★★ 按**字节**读、按**字节**还原 —— 见文件头「本文件自己踩过的坑」。
        raw = target.read_bytes()
        before = hashlib.sha256(raw).hexdigest()
        old_b, new_b = old.encode("utf-8"), new.encode("utf-8")
        n = raw.count(old_b)
        if n != 1:
            print(f"\n❌ {label}\n     注入点不唯一（命中 {n} 次）—— 这一条**没验到**")
            bad.append(label + "（注入点不唯一）")
            continue
        target.write_bytes(raw.replace(old_b, new_b))
        try:
            argv = ["tools\\selftest.py", "--t18"] if channel == "t18" else \
                   ["tools\\selftest.py", "--offline"]
            rc, out, err, dt = _run(argv)
            reds = _reds(out)
            got = ("通过 " + out.split("结果：通过 ")[-1].split("\n")[0]) if "结果：通过 " in out \
                else (err.strip().splitlines()[-1] if err.strip() else "（没有汇总行）")
            print(f"\n▶ {label}\n     通道 {argv[1]} ｜ {dt:.0f}s ｜ {got}")
            print(f"     期望变红：{sorted(want)}　实际红的：{sorted(reds) or '（一个都没有）'}")
            if reds != want:
                print("     ★ 不符合预期")
                bad.append(label)
            else:
                print("     ✅ 符合预期（红的**正是**该红的那几条）")
        finally:
            target.write_bytes(raw)          # ★ 逐字节还原
        after = hashlib.sha256(target.read_bytes()).hexdigest()
        if after != before:
            print(f"     ❌ 还原**不逐字节一致**！{before[:16]}… → {after[:16]}…")
            bad.append(label + "（还原）")
        else:
            print(f"     ✅ 还原逐字节一致 sha256={after[:16]}…")

    print("\n" + "-" * 74)
    print("  复核：还原之后，两道门应当回绿")
    rc, out, _err, dt = _run(["tools\\selftest.py", "--offline"])
    tail = out.split("结果：")[-1].split("\n")[0] if "结果：" in out else "（没有汇总行）"
    print(f"  --offline ｜ {dt:.0f}s ｜ 结果：{tail}")
    if rc != 0:
        bad.append("复核：--offline 没有回绿")
    rc2, out2, _e2, dt2 = _run(["tools\\selftest.py", "--t18"])
    tail2 = out2.split("结果：")[-1].split("\n")[0] if "结果：" in out2 else "（没有汇总行）"
    print(f"  --t18     ｜ {dt2:.0f}s ｜ 结果：{tail2}")
    if rc2 != 0:
        bad.append("复核：--t18 没有回绿")

    print("\n" + "=" * 74)
    if bad:
        print("  结论：**有 %d 处不符合预期**" % len(bad))
        for b in bad:
            print("    · " + b)
        print("=" * 74)
        return 1
    print("  结论：全部 %d 处注入**都真红**，且红的正是该红的那几条；"
          "还原**逐字节一致**；复核回绿 ✅" % len(CASES))
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())