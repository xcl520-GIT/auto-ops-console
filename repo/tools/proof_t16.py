"""★★ T16 验收 #10 的证明：**注入一处破坏 ⇒ 对应的那条断言真的红**（含「red 结构上不可请求」）。

做法（比"看一眼源码"硬 —— 它比的是**判据的实测行为**与**字节级还原**）：
    ① 记录目标文件原文的 sha256（**按字节**读，连行尾一起保住）
    ② 注入一处**破坏**（真实的代码改动，不是注释）
    ③ 立刻跑 `python tools\\selftest.py --t16`（**快通道**：只跑 T16 那一节，同一个 `check_t16`）
       ⇒ 期望：**指定那一条**必须出现 `❌`
    ④ 还原原文 ⇒ **逐字节**核对 sha256 一致
    ⑤ **再跑一遍** ⇒ 期望同一条**回绿**
       ★ 这一步 T15 没做：只验"注入会红"不验"还原会绿"，就分不清
         "判据真的在盯着这件事"与"这条判据本来就在红（空转）"。

为什么要有它：断言最容易得的病是「**绿着但不管用**」—— 写的时候瞄一眼源码就算过，
    改坏了却没人发现。这种断言在出事那天一定会站在错误的一边。**能证伪，才算判据。**

用法（在 repo/ 下）：python tools\\proof_t16.py
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

SELFTEST = ROOT / "tools" / "selftest.py"

#: 每一处注入：`(序号, 一句人话, 目标文件, 原文, 换成什么, 换法, 期望红的断言里的一段独特文字)`
#:   ★ `原文` 必须**恰好命中一次**（命中 0 次或多次 ⇒ 立刻算演示失败：说明注入点已经漂了）
#:   ★ 换法：`apply` 替换 · `drop` 删掉 · `suffix` 追加到文件末尾
INJECTIONS = [
    (
        "①",
        "本地通道偷偷加回 `env LC_ALL=C`（本地通道**不该有 shell 语义**）",
        ROOT / "app" / "transport_local.py",
        "        self.cfg = cfg\n",
        '        self.cfg = cfg\n        LC_ALL_MUT = ["env", "LC_ALL=C"]\n',
        "apply",
        "本地通道 **argv 直传**",
    ),
    (
        "②",
        "在 `vmware.py` 里开一处**裸子进程**（绕过 `hostexec.run_child` 这个唯一出口）",
        ROOT / "app" / "vmware.py",
        "",
        '\n\nimport subprocess  # 证伪注入：裸调用\n\n\n'
        'def _proof_bad() -> object:\n'
        '    return subprocess.run(["echo", "x"], capture_output=True)\n',
        "suffix",
        "只有一个出口",
    ),
    (
        "③",
        "把 VM 归属闸门那一段**删掉**（不再走 `resolve_vm` ⇒ 未登记的也能操作）",
        ROOT / "app" / "vmware.py",
        "    info = resolve_vm(cfg, token)",
        '    info = {"name": "injected", "vmx": token, "host_id": "", "managed_by": "injected"}',
        "apply",
        "未登记的 VM ⇒ 闸门拒绝",
    ),
    (
        "④",
        "把 🔴 `vm.stop-hard` 塞进 `APPROVED_YELLOW`（**red 结构上不可请求**那一条）",
        ROOT / "app" / "ai" / "requests.py",
        '    "file.push",\n',
        '    "file.push",\n    "vm.stop-hard",   # 证伪注入：red 混进被批准表\n',
        "apply",
        "M 域的 `red`",
    ),
    (
        "⑤",
        "把走查表里的 `vm` 那一行**删掉**（新页签从此永远没人看过）",
        ROOT.parent / "工具" / "capture-screenshots.py",
        '    ("vm", "12-虚拟机.png", "虚拟机：清单 / 状态 / 地址 / 快照链 / 等就绪'
        '（★ 执行面是宿主机，不是顶栏那台）"),\n',
        "",
        "drop",
        "逐个同序",
    ),
    (
        "⑥",
        "把体检里对 `no_uninstall` 的**认账去掉**（复现 S6 那条真缺陷）",
        ROOT / "app" / "recipe.py",
        "    if no_un or un.stop or un.disable:",
        "    if un.stop or un.disable:   # 证伪注入：开口不认账",
        "apply",
        "体检对「反向操作",
    ),
]


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _run_t16() -> tuple[int, str]:
    env = dict(os.environ)
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    proc = subprocess.run(
        [sys.executable, str(SELFTEST), "--t16"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=env, cwd=str(ROOT), stdin=subprocess.DEVNULL, timeout=900,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _parse(stdout: str) -> dict[str, bool]:
    """把子进程输出解析成 `{断言名: 绿没绿}`（`⏭` 记 False —— 跳过**不算通过**）。"""
    out: dict[str, bool] = {}
    for line in stdout.splitlines():
        s = line.strip()
        if s[:1] in ("✅", "❌", "⏭") and len(s) > 2:
            out[s[1:].strip()] = s.startswith("✅")
    return out


def _named(stdout: str, marker: str, want_ok: bool) -> list[str]:
    return [n for n, ok in _parse(stdout).items() if ok is want_ok and marker in n]


def _detail_of(stdout: str, name: str) -> str:
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(("❌", "✅")) and name in line:
            tail = [ln.strip() for ln in lines[i + 1:i + 3] if ln.strip()]
            return " ｜ ".join(tail)[:200]
    return ""


def _mutated_text(raw: bytes, old: str, new: str, how: str) -> str:
    text = raw.decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    old_n = old.replace("\n", nl)
    new_n = new.replace("\n", nl)
    if how == "suffix":
        return text + new_n
    if text.count(old_n) != 1:
        raise AssertionError("注入点命中 %d 次（应为 1）" % text.count(old_n))
    return text.replace(old_n, new_n, 1) if how == "apply" else text.replace(old_n, "", 1)


def main() -> int:
    print("=" * 78)
    print("  T16 · S9 证伪演示：注入一处 ⇒ 对应断言**真的红**（注入后立刻还原，并复核回绿）")
    print("=" * 78)

    start_sha = {str(p): _sha_bytes(p.read_bytes())
                 for _s, _t, p, _o, _n, _h, _m in INJECTIONS}

    print("\n⓪ 先确认「没注入时它是绿的」—— 否则后面的「红」可能本来就在红（空转）")
    rc0, out0 = _run_t16()
    base_red = [n for n, ok in _parse(out0).items() if not ok]
    print(f"   基线：退出码 {rc0} ｜ 红 {len(base_red)} 条 {base_red or '（无）'}")
    if base_red:
        print("   ❌ 基线就有红的 —— 先修绿，证伪演示才有意义")
        return 1

    ok_all = True
    for seq, title, path, old, new, how, marker in INJECTIONS:
        rel = path.relative_to(ROOT.parent) if ROOT.parent in path.parents else path
        print("\n" + "-" * 78)
        print(f"{seq} {title}")
        print(f"   目标：{rel}")
        raw = path.read_bytes()
        try:
            mutated = _mutated_text(raw, old, new, how)
            path.write_bytes(mutated.encode("utf-8"))
            rc, out = _run_t16()
            reds = _named(out, marker, False)
            greens = _named(out, marker, True)
            print(f"   期望红的断言含：{marker!r}")
            if reds:
                print(f"   ✅ 实际跳红 {len(reds)} 条 —— 期望那一条真的红了：")
                print(f"      {reds[0][:100]}")
                detail = _detail_of(out, reds[0])
                if detail:
                    print(f"      它给的理由：{detail}")
            else:
                print(f"   ❌ 没红！（还绿着的是 {len(greens)} 条：{greens[:2]}）⇒ 这条判据在空转")
                ok_all = False
        finally:
            path.write_bytes(raw)                      # ★ 按**字节**还原：连行尾一起还原
        print(f"   还原后 sha256 = {_sha_bytes(path.read_bytes())[:16]}…")
        rc2, out2 = _run_t16()
        reds2 = _named(out2, marker, False)
        greens2 = _named(out2, marker, True)
        if reds2:
            print(f"   ❌ 还原之后**还在红**：{[r[:60] for r in reds2[:1]]} —— 没还原干净？")
            ok_all = False
        elif not greens2:
            print("   ❌ 还原之后这条**既没红也没绿**（名字对不上？）")
            ok_all = False
        else:
            print(f"   ✅ 还原后同一条**回绿**（{len(greens2)} 条）· 退出码 {rc2}")

    print("\n" + "=" * 78)
    print("  逐字节还原核对：六个文件与演示开始时的 sha256 逐个比对")
    bad: list[str] = []
    for seq, _title, path, _old, _new, _how, _marker in INJECTIONS:
        now = _sha_bytes(path.read_bytes())
        want = start_sha[str(path)]
        if now != want:
            bad.append(seq)
        print(f"   {'✅' if now == want else '❌'} {seq} {path.name}  {now[:16]}…  "
              f"{'一致' if now == want else '★ 不一致！want ' + want[:16] + '…'}")
    verdict = "全部符合预期" if (ok_all and not bad) else "有不符预期的地方"
    print(f"\n  ★ 证伪演示总判：{verdict}")
    print("=" * 78)
    return 0 if (ok_all and not bad) else 1


if __name__ == "__main__":
    raise SystemExit(main())
