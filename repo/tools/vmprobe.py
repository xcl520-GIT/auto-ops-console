"""本通道的**自证探针**（规范 §12.115 落点表）—— 把"状态"变成**退出码**。

退出码语义（★ 与 `systemctl is-active` 的 0/3 同一套）：

    0  = **期望成立**
    3  = **期望不成立**（含"等超时了还没到"）
    2  = **读不到**（vmrun 不在 / 参数不对 / VMware 说了别的话）

为什么要有它：动作层的 `ok_exit_codes` 只能表达"这条命令的退出码等于几"，
而 `vmrun list` **永远返回 0**（它只是把清单打出来）。
"这台 VM 现在不该在运行"这种事，**没有任何一条原生命令的退出码能表达** ——
所以就写这一条**小的、只读的**探针，让判据仍然是"退出码"，
而不是把判定塞进解析器里（那样在留证里看不出来）。

★★ 本脚本**只读**：`list` / `listSnapshots` / `getGuestIPAddress` 三件事，
   外加读 `inventory.vmls`；**一个字都不写**（红线 13/14）。

用法（动作 YAML 里的形态）：

    [python, tools\\vmprobe.py, --mode, state,    --vmx, {{ vm_vmx }}]
    [python, tools\\vmprobe.py, --mode, expect,   --vmx, {{ vm_vmx }}, --expect, running, --wait, 60]
    [python, tools\\vmprobe.py, --mode, expect,   --vmx, {{ vm_vmx }}, --expect, snapshot, --snapshot, NAME]
    [python, tools\\vmprobe.py, --mode, list]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import vmware  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.errors import OpsError  # noqa: E402


try:  # ★★ T17（规范 §12.134）：工具自己的 stdout 也要 pin 编码（同 run_one.py 的理由）
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="VMware 只读探针：把状态变成退出码")
    ap.add_argument("--mode", required=True,
                    choices=["list", "state", "snapshots", "expect", "vmx", "mkdir", "disk"],
                    help="list=全部虚拟机盘面 · state=一台的状态 · snapshots=快照链 · "
                         "expect=期望判断 · vmx=只读读 .vmx 的身份字段（UUID/MAC） · "
                         "mkdir=建一个空目录（新机落盘位置）· disk=宿主机磁盘余量")
    ap.add_argument("--vmx", default="", help="vmx 全路径（expect/state/snapshots 需要）")
    ap.add_argument("--expect", default="",
                    help="running | stopped | guest-ready | snapshot | vmx-exists | vmx-absent | dir-absent")
    ap.add_argument("--snapshot", default="", help="快照名（--expect snapshot 时用，逐字匹配）")
    ap.add_argument("--path", default="", help="mkdir / disk 模式用的路径")
    ap.add_argument("--min-free-mb", type=int, default=2048, help="disk 模式：至少留多少 MB 余量")
    ap.add_argument("--wait", type=int, default=0, help="最多等多少秒（0 = 只问一次）")
    ap.add_argument("--interval", type=int, default=3, help="轮询间隔（秒）")
    ap.add_argument("--root", default=str(ROOT), help="repo 根目录（默认 = 本脚本的上一级）")
    a = ap.parse_args(argv)

    try:
        cfg = load_config(a.root)
        code, payload = vmware.probe(
            cfg, a.mode, vmx=a.vmx, want=a.expect, snapshot=a.snapshot,
            wait_sec=a.wait, interval=a.interval,
            path=(a.path or a.vmx), min_free_mb=a.min_free_mb,
        )
    except OpsError as exc:
        code, payload = 2, {
            "checked": "装载配置 / 解析 vmrun 路径",
            "error": exc.code, "reason": exc.reason, "advice": exc.advice,
        }
    except Exception as exc:  # noqa: BLE001 —— 探针自己崩了也要留下一条可读的结论
        code, payload = 2, {"checked": "探针自身", "error": type(exc).__name__,
                            "reason": str(exc)[:400]}

    payload["probe_exit_code"] = code
    payload["probe_exit_meaning"] = {0: "期望成立", 3: "期望不成立", 2: "读不到"}.get(code, "未知")
    print(vmware.dump(payload))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
