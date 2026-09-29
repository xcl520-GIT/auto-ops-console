"""非 ssh 执行面：**本机进程**（规范 §12.115）。

它与 `SshTransport` **方法面一致**，这样 `engine.py` 那 15 处调用一行都不用改——
只把"用哪个通道"这一个决定挪到引擎里（`channel: local` 的动作走这里）。

★ 三处**刻意的不同**（都是规范 §12.115 的规矩，不是遗漏）：
  · `build_remote_cmd()` **不加** `env LC_ALL=C LANG=C` 前缀、**不追加** `< /dev/null`
    —— 那是 ssh 侧为了让远端字段名稳定、且不许交互；本通道没有 shell（规矩 3）。
  · `scp_put` / `scp_get` / `trust_host` **明确抛"本通道不支持"** ——
    ★ 不许静默返回成功（那会变成一条**假绿**）。
  · 多一个 `classify_failure()`：ssh 靠 255 认传输层失败，本通道靠**退出码 + 本地化话术**翻译。
"""
from __future__ import annotations

from typing import Any

from app.config import AppConfig, Host
from app.errors import OpsError
from app.hostexec import LocalRun, quote_windows, run_child
from app.transport import ExecResult
from app.vmware import translate, vm_conf, vmrun_path


def _to_exec(res: LocalRun) -> ExecResult:
    return ExecResult(
        argv=list(res.argv),
        quoted=res.quoted,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
        duration_ms=res.duration_ms,
        timed_out=res.timed_out,
        truncated=False,
        warnings=list(res.warnings),
    )


class LocalTransport:
    """本机（Windows / 宿主机）执行面。"""

    kind = "local"

    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg

    # -- 与 SshTransport 同名的方法 ------------------------------------

    def binary(self) -> str:
        """这个通道"用什么东西执行" —— 对留证/自检来说，答案是 `vmrun.exe`。"""
        return vmrun_path(self.cfg)

    def run(self, host: Host, argv: list[str], *, timeout: int | None = None,
            connect_timeout: int | None = None) -> ExecResult:
        """跑一条本机命令。★ argv 直传 `CreateProcess`，**不经过 shell**。"""
        t = int(timeout or self.cfg.default_timeout)
        return _to_exec(run_child([str(a) for a in argv], timeout=t))

    def build_remote_cmd(self, argv: list[str], host: Host | None = None) -> str:
        """留证/预览用的"命令原文"。

        ★ 与 ssh 侧的关键差别：**不加 `env` 前缀、不追加 `< /dev/null`、不做 shlex 转义**
          —— 这里没有远端 shell，转义反而是误导（规范 §12.115 规矩 3）。
        """
        return quote_windows([str(a) for a in argv])

    def check_connectivity(self, host: Host) -> tuple[bool, OpsError | None, ExecResult | None]:
        """本通道的"连得上吗" = **`vmrun.exe` 找得到，且能问出运行清单**。

        ★ 这条检查对每个动作都会跑（引擎的既有流程）：对本通道来说，
          "vmrun 不在"就等价于 ssh 侧的"机器连不上"——都是"这条路走不通"，
          都要在**动手之前**给出干净的原因 + 建议。
        """
        try:
            binary = vmrun_path(self.cfg)
        except OpsError as exc:
            return False, exc, None
        t = str(vm_conf(self.cfg).get("type") or "ws")
        res = run_child([binary, "-T", t, "list"], timeout=30)
        if res.exit_code != 0:
            return False, translate(res, what="自检：读取运行中的虚拟机清单"), _to_exec(res)
        return True, None, _to_exec(res)

    def classify_failure(self, host: Host, res: ExecResult) -> OpsError | None:
        """★ 判定看**退出码**，话术只用来翻译（规范 §12.115 规矩 6）。"""
        if res.exit_code == 0:
            return None
        return translate(
            LocalRun(
                argv=list(res.argv), quoted=res.quoted, exit_code=res.exit_code,
                stdout=res.stdout, stderr=res.stderr, duration_ms=res.duration_ms,
                timed_out=res.timed_out, warnings=list(res.warnings),
            ),
            what="执行命令",
        )

    # -- 明确的"不支持"（★ 不许静默成功）--------------------------------

    def scp_put(self, host: Host, local_path: str, remote_path: str) -> tuple[bool, str]:
        raise OpsError(
            code="EXEC_UNSUPPORTED",
            reason="本通道（宿主机执行面）**不支持传文件**",
            advice=(
                "传文件是 ssh 通道的能力（scp + 原子 mv）。"
                "若确要在宿主机与本机之间搬文件，请用 `file.push` 面向目标 Linux 机，"
                "或把需求写成一条动作步骤（argv 直传）。"
            ),
        )

    def scp_get(self, host: Host, remote_path: str, local_dir: str,
                *, recursive: bool = False) -> tuple[bool, str]:
        raise OpsError(
            code="EXEC_UNSUPPORTED",
            reason="本通道（宿主机执行面）**不支持回拉文件**",
            advice="回拉文件是 ssh 通道的能力；本通道只跑本机命令（规范 §12.115）。",
        )

    def trust_host(self, host: Host) -> dict[str, Any]:
        """★ 本通道没有"主机指纹"这回事 —— 返回**明说的**空结果，不是静默成功。"""
        return {"ok": True, "trusted": False,
                "note": "本通道不走 ssh，没有主机指纹需要信任（规范 §12.115）"}
