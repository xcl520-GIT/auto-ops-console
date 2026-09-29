"""本机（Windows / 宿主机）子进程的**唯一出口** —— 规范 §12.115 规矩 4~5。

为什么必须只有这一个出口
------------------------
T15·S9 的现场（规范 §12.111）：门禁里 4 处 `subprocess.run` **没给 `errors`**，
而本机代码页是 936 ⇒ 子进程按 cp936 写中文 ⇒ `UnicodeDecodeError` **抛在 subprocess 的读取线程里**
⇒ 那个管道的值变成 `None` ⇒ 调用处 `stderr + stdout` 抛 `TypeError` ⇒ 后面 360 多项一条没跑，
却照样打印一份"看起来像结论"的汇总。

虚拟化层（T16）跑的是**本机 Windows 进程**（`vmrun.exe`），会遇到同一类事：
读取期的解码、超时、`returncode` 的形态。⇒ **第一版就把它钉住**：

  · 写侧：`PYTHONUTF8=1` ＋ `PYTHONIOENCODING=utf-8`（不让子进程随控制台代码页走）
  · 读侧：`errors="replace"` ＋ `None` 兜底（**返回的 stdout/stderr 永远是 str**）
  · ★ 退出码**归一化**：Windows 上 `-1` 会以 **4294967295** 出现（T16·S0 实测）

★ 本模块**不认识** engine / transport / ssh —— 它只会"跑一个进程、把结果说清楚"。
"""
from __future__ import annotations

import os
import subprocess as _sp
import time
from dataclasses import dataclass, field

from app.errors import OpsError

#: ★★ T16·S0 实测：`vmrun` 报错时 Python 拿到的 `returncode` 是 **-1 的无符号形态**。
#: 判据里写 `rc == -1` **永远不成立** ⇒ 在出口处归一（规范 §12.115 规矩 5）。
UNSIGNED_NEG_ONE = 4294967295

#: 编码一律按 utf-8 读。★ 实测依据：`vmrun listSnapshots` 的快照名在字节层面就是 UTF-8
#: （`k8s\\xe9\\x9b\\x86…`），按 GBK 解会直接 `UnicodeDecodeError`（T16·S0）。
DEFAULT_ENCODING = "utf-8"


@dataclass
class LocalRun:
    """本机子进程的一次执行结果。字段与 `ExecResult` 对齐，便于走同一条留证路。"""

    argv: list[str]
    quoted: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _norm_rc(rc: int | None) -> int | None:
    """把 Windows 的"无符号化"退出码折回有符号。

    ★ 4294967295 → -1；其它大于 2**31 的值同理折成负数。
    """
    if rc is None:
        return None
    if rc == UNSIGNED_NEG_ONE:
        return -1
    if rc > 2**31:
        return rc - 2**32
    return rc


def to_text(raw: bytes | str | None, encoding: str = DEFAULT_ENCODING) -> str:
    """字节 → str。★ **永远返回 str**：`None` 兜底 ""、坏字节替换（绝不在读取期抛）。"""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return raw.decode(encoding, errors="replace")
    except (LookupError, UnicodeDecodeError):  # 编码名写错也不许崩
        return raw.decode("utf-8", errors="replace")


def quote_windows(argv: list[str]) -> str:
    """把 argv 拼成"人能读、可回放"的一行（**留证用**，不是拿去执行的）。

    ★ 与 ssh 侧 `build_remote_cmd` 的差别：这里**不加** `env LC_ALL=C` 前缀、
      **不追加** `< /dev/null` —— 那是 ssh 的语义，本通道没有 shell（规范 §12.115 规矩 3）。
    """
    out: list[str] = []
    for a in argv:
        s = str(a)
        if s == "" or any(c in s for c in ' \t"'):
            out.append('"' + s.replace('"', '\\"') + '"')
        else:
            out.append(s)
    return " ".join(out)


def run_child(
    argv: list[str] | tuple[str, ...],
    *,
    timeout: int = 60,
    cwd: str | None = None,
    env_extra: dict[str, str] | None = None,
) -> LocalRun:
    """跑一个**本机**子进程，双向钉住编码；退出码归一；**绝不抛解码异常**。

    ★ `argv` 只接受数组：本项目禁止把命令拼成字符串（规范 §12.115 规矩 3）。
    """
    if isinstance(argv, str):
        raise OpsError(
            code="EXEC_INVALID",
            reason="本地执行只接受 argv 数组，不接受命令行字符串",
            advice="把命令拆成数组元素（本项目禁止 shell 拼串；见规范 §12.115 规矩 3）。",
        )
    args = [str(a) for a in argv]
    if not args:
        raise OpsError(code="EXEC_INVALID", reason="本地执行的 argv 是空的")

    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    for k, v in (env_extra or {}).items():
        env[str(k)] = str(v)

    t0 = time.monotonic()
    warned: list[str] = []
    raw_out: bytes = b""
    raw_err: bytes = b""
    rc: int | None = None
    timed_out = False
    try:
        proc = _sp.run(
            args,
            capture_output=True,
            timeout=max(1, int(timeout)),
            cwd=cwd,
            env=env,
            shell=False,          # ★ 规矩 3：本通道没有 shell
            stdin=_sp.DEVNULL,    # 不读任何交互输入（与 ssh 侧同源的纪律）
            check=False,
        )
        rc = _norm_rc(proc.returncode)
        raw_out = proc.stdout or b""
        raw_err = proc.stderr or b""
    except _sp.TimeoutExpired as exc:
        timed_out = True
        raw_out = exc.stdout if isinstance(exc.stdout, bytes) else b""
        raw_err = exc.stderr if isinstance(exc.stderr, bytes) else b""
        warned.append(f"命令在 {timeout}s 内没有返回，已终止：{args[0]}")
    except OSError as exc:
        # 可执行文件不存在 / 权限不足 —— 这是一条**结论**，不是崩溃
        raw_err = str(exc).encode("utf-8", errors="replace")
        warned.append(f"无法启动 {args[0]}：{exc}")

    return LocalRun(
        argv=args,
        quoted=quote_windows(args),
        exit_code=rc,
        stdout=to_text(raw_out),
        stderr=to_text(raw_err),
        duration_ms=int((time.monotonic() - t0) * 1000),
        timed_out=timed_out,
        warnings=warned,
    )
