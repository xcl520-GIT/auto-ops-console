"""单动作真跑工具（T3）：验证一个变更动作在真机上是否按预期工作。

用法（在 repo/ 下）：
    python tools/run_one.py <动作id> [主机id] [参数=值 ...] [confirm_text=xxx]

例：
    python tools/run_one.py svc.start node-01 unit=aoc-lab.service
    python tools/run_one.py svc.stop  node-01 unit=aoc-lab.service confirm_text=我已确认要停止

为什么单独做一个工具：
  T2 的 tools/run_actions.py 是"批量跑一批只读动作"，它不知道确认词；
  T3 的变更动作有 yellow/red 闸门，需要能单独喂一个动作 + 参数 + 确认词，
  并且要看到**每一步的退出码**（写变更动作时，退出码是最容易搞错的东西）。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.catalog import load_actions  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.errors import OpsError  # noqa: E402
from app.store import Store  # noqa: E402


def _default_vm(action: Any) -> str:
    """把 `vm` 参数的**默认值**取出来 —— 只为在报错里如实告诉人"它差点动了谁"。"""
    for p in getattr(action, "params", []) or []:
        if getattr(p, "name", "") == "vm":
            return str(getattr(p, "default", "") or "")
    return ""


try:  # ★★ T17（规范 §12.134）：**工具自己的 stdout 也要 pin 编码**。
    #   否则输出被管道 / 重定向捕获时，Python 按**系统代码页**（中文 Windows 上是 cp936/GBK）编码，
    #   而结论里那些 `⇒ ★ 「」` 编不出来 ⇒ `UnicodeEncodeError` ⇒ **退出码 1、结论被截断**。
    #   ★ T17·S0 真缺陷的现场：一个**只读**动作，因为"打印"而失败 —— 崩的偏偏是**留证**那一步。
    #   ★ 与 §12.115.4「本地通道双向 pin 编码」同源：**编码是通道的属性**，不是控制台的性质。
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001  （老解释器没有 reconfigure ⇒ 退回默认，不因此崩掉）
    pass


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    action_id = sys.argv[1]
    host_id = sys.argv[2] if len(sys.argv) > 2 and "=" not in sys.argv[2] else "node-01"
    rest = sys.argv[3:] if (len(sys.argv) > 2 and "=" not in sys.argv[2]) else sys.argv[2:]

    params: dict[str, str] = {}
    confirm_text = ""
    for kv in rest:
        key, _, value = kv.partition("=")
        if key == "confirm_text":
            confirm_text = value
        else:
            params[key] = value

    cfg = load_config(Path("."))
    actions = load_actions(cfg.paths.actions)
    Store(cfg).init()
    engine = Engine(cfg, actions)

    # ★★★ T17·S8 真缺陷（规范 §12.140）：**本机通道的动作，目标机必须点名，不许吃默认值。**
    #   现场：`vm.stop aoc-tpl-01` —— 第一个位置参数是 **host_id**（这台是 ssh 通道的目标），
    #   而 `vm.*` 的目标是 **`vm` 参数**，它的默认值偏偏是 `node-03`（一台真集群节点）
    #   ⇒ 于是这次"关掉靶机"**真的把 node-03 关了**，随后"开回 docker-01"又把它开回来。
    #   ★ 平台的结论**没有说假话**（抬头写的就是【node-03】），是**脚本化调用**把目标搞错了：
    #     界面上那个默认值**人看得见**，脚本里那个默认值**没人看得见**。
    #   ⇒ 规矩：`channel: local` 的动作，**命令行里必须显式给 `vm=`**（缺了就当场拒），
    #     且把"你到底动的是哪台"**回显**出来（第二只眼睛）。
    act = actions.get(action_id)
    _has_vm_param = any(getattr(p, "name", "") == "vm"
                        for p in (getattr(act, "params", []) or [])) if act else False
    if act is not None and getattr(act, "channel", "ssh") == "local" \
            and _has_vm_param and "vm" not in params:
        print("[被拦下] VM_TARGET_NOT_NAMED: 本机通道的动作**必须显式点名 `vm=`**，"
              "不许吃参数默认值")
        print("         为什么：`vm.*` 动的是**宿主机上的某一台虚拟机**，而 `vm` 参数的默认值"
              f"（{_default_vm(act)!r}）是给**界面表单**用的 —— 脚本里看不见它，"
              "照着默认值跑就会**动错机器**（规范 §12.140 的现场）。")
        print(f"         正确写法：python tools\\run_one.py {action_id} {host_id} "
              f'"vm=<要动的那台>" …')
        return 2

    print(f"=== {action_id} @ {host_id} params={params} ===")
    if act is not None and getattr(act, "channel", "ssh") == "local" and _has_vm_param:
        print(f"★★ 本机通道：本次**真正要动的虚拟机** = {params.get('vm')!r}"
              f"（不是上面那个 host_id —— 那个只是记账用的目标机）")
    try:
        result = engine.run(action_id, host_id, params, confirm=True, confirm_text=confirm_text)
    except OpsError as exc:
        print(f"[被拦下] {exc.code}: {exc.reason}")
        print(f"         建议：{exc.advice}")
        return 1

    print(f"task    = {result.id}")
    print(f"status  = {result.status}")
    print(f"verify  = {result.verify_result}")
    print(f"耗时    = {result.duration_ms} ms")
    if result.backups:
        print("--- 改动前备份 ---")
        for b in result.backups:
            print(f"  [{b.status}] {b.label}  ->  {b.remote_path or '(未备份)'}")
            if b.sha256:
                print(f"        sha256={b.sha256[:16]}…  大小={b.size}B")
            if b.error:
                print(f"        备注：{b.error}")
    print("--- 步骤 ---")
    for s in result.steps:
        out = (s.stdout or "").replace("\n", " | ")[:80]
        print(f"  {s.seq:>2} {s.name:<14} {s.status:<9} rc={s.exit_code}  {out}")
    print("--- 结论 ---")
    print(result.conclusion or "（无）")
    if result.error:
        print("--- 错误 ---")
        print(f"  {result.error.code}: {result.error.reason}")
        print(f"  建议：{result.error.advice}")
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
