"""★★ T17 验收 #11 的证明：**注入一处破坏 ⇒ 对应的那条断言真的红**（含"克隆必须人点头"那一条）。

做法（与 T16 同规矩 —— 它比的是**判据的实测行为**与**字节级还原**）：
    ① 记录目标文件原文的 sha256（**按字节**读，连行尾一起保住）
    ② 注入一处**破坏**（真实的代码 / YAML 改动，不是注释）
    ③ 立刻跑 `python tools\\selftest.py --t17`（**快通道**：只跑 T17 那一节，同一个 `check_t17`）
       ⇒ 期望：**指定那一条**必须出现 `❌`
    ④ 还原原文 ⇒ **逐字节**核对 sha256 一致
    ⑤ **再跑一遍** ⇒ 期望同一条**回绿**
       ★ 只验"注入会红"不验"还原会绿"，就分不清"判据真的在盯着这件事"
         与"这条判据本来就在红（空转）"。

六处注入对应 T17 的六条断言（一断言一处，谁也不替谁说话）：

    Ⓥ  克隆是 red 且 AI 结构上不可请求   ⇒ 把 `vm.clone` 塞进被批准表
    Ⓦ  目标已存在 ⇒ 预检拒绝（不覆盖）   ⇒ 把 `target_free`（vmx-absent）那一步删掉
    Ⓧ  五项身份各有判据 / 判据步非 optional ⇒ 把 `host.static-ip-set` 的判据步设成 optional
    Ⓨ  `hosts.yaml` 可逐字节回退         ⇒ 让写前备份**写成空文件**
    Ⓩ  工具自己 pin stdout 编码          ⇒ 把 `run_one.py` 的 pin 编码两行删掉
    Ⓩa 同一作用域不许有重复函数定义      ⇒ 往 `changed.py` 末尾再插一份同名函数

用法（在 repo/ 下）：python tools\\proof_t17.py
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

#: `(序号, 一句人话, 目标文件, 原文, 换成什么, 换法, 期望红的断言里的一段独特文字)`
#:   ★ `原文` 必须**恰好命中一次**（0 次或多次 ⇒ 立刻算演示失败：注入点已经漂了）
#:   ★ 换法：`apply` 替换 · `drop` 删掉 · `suffix` 追加到文件末尾
INJECTIONS = [
    (
        "①",
        "把 🔴 `vm.clone` 塞进 `APPROVED_YELLOW`（「克隆必须人点头」那一条）",
        ROOT / "app" / "ai" / "requests.py",
        '    "file.push",\n',
        '    "file.push",\n    "vm.clone",   # 证伪注入：red 混进被批准表\n',
        "apply",
        "AI 侧结构上不可请求",
    ),
    (
        "②",
        "把克隆预检里「目标已存在 ⇒ 拒绝」那一步**删掉**（不覆盖从此没人看住）",
        ROOT / "catalog" / "actions" / "vm.clone.yaml",
        "  - name: target_free\n"
        '    title: ★★ 前置：新机落盘位置必须**还不存在**（"不覆盖"是硬规矩，规范 §12.130 第 4 条）\n'
        '    run: ["{{ vm_probe_py }}", "{{ vm_probe_script }}", "--mode", "expect",\n'
        '          "--vmx", "{{ vm_new_vmx }}", "--expect", "vmx-absent"]\n'
        "    parser: json\n"
        "    ok_exit_codes: [0]\n"
        "    timeout: 60\n\n",
        "",
        "drop",
        "克隆的**预检**里有「目标已存在 ⇒ 拒绝」那一条",
    ),
    (
        "③",
        "把 `host.static-ip-set` 的**判据步**设成 `optional`（= 把判据取下来）",
        ROOT / "catalog" / "actions" / "host.static-ip-set.yaml",
        "    ok_exit_codes: [0]\n    note: |\n      ★ 0 = 网卡上出现了这个地址",
        "    ok_exit_codes: [0]\n    optional: true   # 证伪注入：把判据取下来\n"
        "    note: |\n      ★ 0 = 网卡上出现了这个地址",
        "apply",
        "四个重置动作的判据步都**在**",
    ),
    (
        "④",
        "让 `hosts.yaml` 的**写前备份写成空文件**（「逐字节可回退」从此是句空话）",
        ROOT / "tools" / "host_register.py",
        "    backup = BACKUP_DIR / f\"hosts.yaml.{stamp}.bak\"\n"
        "    backup.write_bytes(raw)\n\n"
        "    block = build_block(a)\n",
        "    backup = BACKUP_DIR / f\"hosts.yaml.{stamp}.bak\"\n"
        "    backup.write_bytes(raw[:0])   # 证伪注入：备份写成空文件\n\n"
        "    block = build_block(a)\n",
        "apply",
        "登记**可逐字节回退**",
    ),
    (
        "⑤",
        "把 `run_one.py` 的 **pin 编码**两行删掉（GBK 管道下 `⇒` 又编不出来）",
        ROOT / "tools" / "run_one.py",
        '    sys.stdout.reconfigure(encoding="utf-8", errors="replace")\n'
        '    sys.stderr.reconfigure(encoding="utf-8", errors="replace")\n',
        "    pass  # 证伪注入：不再 pin 编码\n",
        "apply",
        "命令行工具**自己 pin 住 stdout 编码**",
    ),
    (
        "⑥",
        "往 `app/changed.py` 末尾**再插一份同名函数**（补丁重复插入那个真缺陷）",
        ROOT / "app" / "changed.py",
        "",
        "\n\n# 证伪注入：同名函数写两遍（后者会静默覆盖前者）\n"
        "def _r_vm_clone(action, result):\n"
        "    return None\n",
        "suffix",
        "同一个作用域里不许有重复的函数定义",
    ),
    (
        "⑦",
        "把身份脚本那行「问到几个文件」的结论**删掉**（判据又只能靠猜）",
        ROOT / "var" / "uploads" / "aoc-identity.sh",
        '            say "kind=ssh-hostkey count=$_n files=$_nfiles priv=$_npriv pub=$_npub"\n',
        "",
        "drop",
        "必须把「问到什么」摆出来",
    ),
    (
        "⑧",
        "让「接受新指纹」的**写前备份写成空文件**（撤旧记录不再可回退）"
        "★ 第一版注入写的是「把备份那一步删掉」—— 那种注入会让平台**当场抛异常**"
        "（后面还要读那个备份文件），于是新报出来的是 `自检脚本异常` 而不是那条判据红；"
        "**判据有没有在盯着这件事**就说不清了 ⇒ 改成「备份了、但备份是错的」这种更贴的破坏。",
        ROOT / "app" / "transport.py",
        '        backup.write_bytes(raw)                          # ★ 逐字节：连行尾一起保住\n',
        "        backup.write_bytes(raw[:0])   # 证伪注入：备份写成空文件\n",
        "apply",
        "「指纹变了」有人点过的台阶",
    ),
    (
        "⑨",
        "把 `run_one.py` 里「本机通道必须点名 `vm=`」那道拦截**删掉**"
        "（★ 注入后这次调用会真的执行 —— 所以判据用的是**只读动作**）",
        ROOT / "tools" / "run_one.py",
        '    if act is not None and getattr(act, "channel", "ssh") == "local" \\\n'
        '            and _has_vm_param and "vm" not in params:\n',
        "    if False:   # 证伪注入：拦截不生效了\n",
        "apply",
        "本机通道的动作必须点名",
    ),
]


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _run_t17() -> tuple[int, str]:
    env = dict(os.environ)
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    proc = subprocess.run(
        [sys.executable, str(SELFTEST), "--t17"],
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
    print("  T17 · S9 证伪演示：注入一处 ⇒ 对应断言**真的红**（注入后立刻还原，并复核回绿）")
    print("=" * 78)

    print("\n⓪ 先确认「没注入时它是绿的」—— 否则后面的「红」可能本来就在红（空转）")
    rc0, out0 = _run_t17()
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
            rc, out = _run_t17()
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
        except AssertionError as exc:
            print(f"   ❌ 注入没做进去：{exc}")
            ok_all = False
        finally:
            path.write_bytes(raw)                      # ★ 按**字节**还原：连行尾一起还原
        after = _sha_bytes(path.read_bytes())
        print(f"   还原后 sha256 = {after[:16]}…（原文 {_sha_bytes(raw)[:16]}…）")
        if after != _sha_bytes(raw):
            print("   ❌ 还原后**与原文不一致** —— 演示必须逐字节还原！")
            ok_all = False
            continue
        rc2, out2 = _run_t17()
        reds2 = _named(out2, marker, False)
        greens2 = _named(out2, marker, True)
        if reds2:
            print(f"   ❌ 还原之后**还在红**：{reds2[0][:70]} —— 没还原干净？")
            ok_all = False
        elif not greens2:
            print("   ❌ 还原之后这条**既没红也没绿**（名字对不上？）")
            ok_all = False
        else:
            print("   ✅ 还原后**回绿**（说明这条判据不是「本来就在红」）")

    # ★ 收尾复核：所有注入点都还原了、且门禁整体回绿
    print("\n" + "=" * 78)
    rc3, out3 = _run_t17()
    tail = [ln for ln in out3.splitlines() if "结果：" in ln]
    print(f"★ 收尾复核：退出码 {rc3} ｜ {tail[-1].strip() if tail else '（没读到汇总行）'}")
    if rc3 != 0:
        print("   ❌ 收尾复核不是绿的 —— 有文件没还原干净")
        ok_all = False
        print(out3[-2000:])
    print("=" * 78)
    print(f"✅ {len(INJECTIONS)} 处注入：全部符合预期（注入⇒真红 · 逐字节还原⇒回绿）" if ok_all
          else "❌ 证伪演示**没通过** —— 见上面逐条")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
