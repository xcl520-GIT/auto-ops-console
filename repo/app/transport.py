"""执行层：通过系统 ssh 在目标机上执行命令。

★ 设计要点

1. 数组传参，不拼字符串
   argv 是 list[str]；绝不把用户输入拼进命令行文本。

2. shlex.quote() 是防注入的**真正兜底**（安全契约第三层）
   OpenSSH 会把 `ssh host <cmd>` 的 <cmd> 交给目标机的 shell 执行。
   所以每个 argv 元素都用 shlex.quote() 单独转义后再拼成那一个 <cmd> 字符串，
   目标机 shell 看到的是被单引号包裹的字面量，无法逃逸。

3. 强制远端 locale 为 C（★ 写代码时发现的真实隐患）
   如果目标机 LANG=zh_CN.UTF-8，`timedatectl status` 的字段名会变成「本地时间」，
   我们按 "Local time" 做的 colon_kv 解析会**静默取空**，动作看起来"成功"但结论全空。
   因此在命令前加 `env LC_ALL=C LANG=C`（用 env 而不是 shell 变量前缀，更明确）。
   这也让 free/lscpu 等所有按字段名解析的输出保持稳定。

4. 退出码语义
   ssh 自身出错返回 255（连接失败/认证失败/主机指纹不认）；其余退出码来自远端命令本身。
   两者必须区分：255 → 归类为传输层错误并给「原因 + 建议」；
   其它非零 → 归类为「这一步失败」，把远端 stderr 原样留证。

5. 超时
   subprocess 超时会杀掉本地 ssh 进程；**远端命令可能仍在跑**（agentless 的固有代价，
   在 T1 只读动作里无影响，将来做变更类动作时要正视这一点）。
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.config import AppConfig, Host
from app.errors import OpsError


@dataclass
class ExecResult:
    argv: list[str]              # 远端 argv（未加 env 前缀、未转义）
    quoted: str                  # 实际交给 ssh 的那个远端命令字符串（留证：命令原文）
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def classify_ssh_failure(stderr: str, host: Host) -> OpsError:
    """把 ssh 自己的报错翻译成「原因 + 建议」。这是验收标准 #5 的核心。"""
    low = stderr.lower()
    if "host key verification failed" in low or "remote host identification has changed" in low:
        return OpsError(
            code="SSH_HOSTKEY_UNKNOWN",
            reason=f"目标机 {host.address} 的主机指纹未被信任，或与已记录的不一致",
            advice=(
                "首次连接：在界面「主机」区点击「信任此主机」后重试。"
                "若提示指纹已变化（可能是重装或克隆了虚拟机），"
                "请先确认这确实是你的机器，再删除 ~/.ssh/known_hosts 里的旧记录。"
            ),
        )
    if "permission denied" in low:
        return OpsError(
            code="SSH_AUTH_FAILED",
            reason=f"登录 {host.target} 被拒绝（密钥认证未通过）",
            advice=(
                "① 确认 hosts.yaml 里 user 正确；"
                "② 确认公钥已写入目标机 ~/.ssh/authorized_keys（文件 600、.ssh 目录 700）；"
                "③ 确认目标机 sshd 未禁用 PubkeyAuthentication。"
            ),
        )
    if "connection refused" in low:
        return OpsError(
            code="HOST_UNREACHABLE",
            reason=f"{host.address}:{host.port} 拒绝连接（机器在，但没人监听该端口）",
            advice="确认目标机上 sshd 已启动：systemctl status sshd；必要时 systemctl enable --now sshd。",
        )
    if "no route to host" in low or "network is unreachable" in low:
        return OpsError(
            code="HOST_UNREACHABLE",
            reason=f"到 {host.address} 没有可达路由",
            advice="确认宿主机与目标机在同一 VMnet8 网段（192.0.2.0/24），且目标机网卡是 NAT 模式。",
        )
    if "connection timed out" in low or "operation timed out" in low:
        return OpsError(
            code="HOST_UNREACHABLE",
            reason=f"连接 {host.address} 超时",
            advice="确认目标机已开机联网；在宿主机 ping 一下；检查是否有防火墙拦截。",
        )
    if "could not resolve hostname" in low:
        return OpsError(
            code="HOST_UNREACHABLE",
            reason=f"无法解析主机名：{host.address}",
            advice="hosts.yaml 里请填 IP 地址，不要填主机名。",
        )
    return OpsError(
        code="HOST_UNREACHABLE",
        reason=f"连接 {host.address} 失败",
        advice="确认目标机已开机、IP 正确、sshd 在运行，且两台机在同一网段。",
        detail=stderr.strip(),
    )


class SshTransport:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self._control_enabled, self.control_note = cfg.ssh.effective_control_master()
        self._control_dir: Path | None = None
        if self._control_enabled:
            self._control_dir = (cfg.paths.root / cfg.ssh.control_dir).resolve()
            self._control_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ 命令组装

    def binary(self) -> str:
        binary = self.cfg.ssh.binary
        found = shutil.which(binary)
        if not found:
            raise OpsError(
                code="CONFIG_INVALID",
                reason=f"找不到 ssh 客户端：{binary}",
                advice=(
                    "Windows：确认已启用「OpenSSH 客户端」功能（设置 → 应用 → 可选功能）。"
                    "Linux：dnf install -y openssh-clients。"
                ),
            )
        return found

    def build_ssh_argv(self, host: Host, remote_cmd: str, *, connect_timeout: int | None = None) -> list[str]:
        s = self.cfg.ssh
        argv = [self.binary(), "-T"]

        if s.batch_mode:
            argv += ["-o", "BatchMode=yes"]
        argv += ["-o", f"ConnectTimeout={connect_timeout or s.connect_timeout}"]
        argv += ["-o", f"StrictHostKeyChecking={s.strict_host_key}"]
        argv += [
            "-o", f"ServerAliveInterval={s.server_alive_interval}",
            "-o", f"ServerAliveCountMax={s.server_alive_count_max}",
        ]
        if self._control_enabled and self._control_dir:
            argv += ["-o", "ControlMaster=auto"]
            argv += ["-o", f"ControlPath={self._control_dir / '%r@%h-%p'}"]
            argv += ["-o", f"ControlPersist={s.control_persist}"]
        if s.strict_host_key in ("yes", "accept-new"):
            argv += ["-o", "UpdateHostKeys=yes"]

        if host.identity_file:
            argv += ["-i", os.path.expanduser(str(host.identity_file))]
        if host.port and host.port != 22:
            argv += ["-p", str(host.port)]

        argv += [host.target, remote_cmd]
        return argv

    def build_remote_cmd(self, argv: list[str]) -> str:
        """把远端 argv 转成一个安全的命令字符串。

        先加 env 前缀强制 C locale（见模块头注释第 3 点），
        再对每个元素单独 shlex.quote 后拼接，
        最后**关掉远端的 stdin**（`< /dev/null`）。

        ★ 为什么必须显式关 stdin（T2 实测得出的结论）：
          `subprocess.run(stdin=DEVNULL)` 只在**本地**把 stdin 接到 NUL；
          Windows 版 OpenSSH 并不会因此把 EOF 传给远端 —— 远端命令的 stdin 依然是个「开着但不来数据」的通道。
          绝大多数命令不读 stdin 所以看不出来，但**会读 stdin 的命令会一直等 EOF 然后挂死**：
          T2 的 `ausearch`（它把 stdin 也当作输入来源）就是活证据 ——
          同一条 `ausearch -m avc -ts recent`，手工直跑 20ms 返回，
          经引擎链路跑却挂满 160 秒被杀。
          统一在远端重定向 `/dev/null` 后，行为与 ssh 客户端实现无关。
          （这条重定向由传输层添加，不属于动作 YAML 的 `run`，不违反规范 §4 对 `run` 的禁令。）
        """
        env_pairs = self.cfg.raw.get("ssh", {}).get("remote_env") if isinstance(self.cfg.raw, dict) else None
        if not env_pairs:
            env_pairs = {"LC_ALL": "C", "LANG": "C"}
        prefix = ["env"] + [f"{k}={v}" for k, v in env_pairs.items()]
        cmd = " ".join(shlex.quote(part) for part in (prefix + list(argv)))
        return cmd + " < /dev/null"

    # ------------------------------------------------------------------ 执行

    def run(
        self,
        host: Host,
        argv: list[str],
        *,
        timeout: int | None = None,
        connect_timeout: int | None = None,
    ) -> ExecResult:
        timeout = int(timeout or self.cfg.default_timeout)
        remote_cmd = self.build_remote_cmd(argv)
        full = self.build_ssh_argv(host, remote_cmd, connect_timeout=connect_timeout)

        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                full,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + self.cfg.ssh.connect_timeout + 2,
                shell=False,
            )
            code: int | None = proc.returncode
            out = proc.stdout.decode("utf-8", errors="replace")
            err = proc.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            code = None
            out = (exc.stdout or b"").decode("utf-8", errors="replace")
            err = (exc.stderr or b"").decode("utf-8", errors="replace")
            err += f"\n[控制台] 本地 ssh 进程在 {timeout + self.cfg.ssh.connect_timeout + 2} 秒后被强制终止。"
        duration_ms = int((time.monotonic() - started) * 1000)

        truncated = False
        limit = self.cfg.max_output_bytes
        if len(out.encode("utf-8", errors="replace")) > limit:
            out = out.encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="replace")
            out += f"\n\n[控制台] 输出超过 {limit} 字节，已截断。"
            truncated = True

        return ExecResult(
            argv=list(argv),
            quoted=remote_cmd,
            exit_code=code,
            stdout=out,
            stderr=err,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=truncated,
        )

    # ------------------------------------------------------------------ 文件回拉

    def build_scp_argv(
        self, host: Host, remote_path: str, local_path: Path, *, recursive: bool
    ) -> list[str]:
        """构造 scp 的 argv —— 与 ssh 复用同一套连接选项，避免出现两套信任策略。"""
        scp = shutil.which("scp")
        if not scp:
            raise OpsError(
                code="CONFIG_INVALID",
                reason="找不到 scp 客户端（备份回拉需要它）",
                advice="Windows：启用「OpenSSH 客户端」功能；Linux：dnf install -y openssh-clients。",
            )
        s = self.cfg.ssh
        argv = [scp, "-q"]
        if recursive:
            argv += ["-r"]
        if s.batch_mode:
            argv += ["-o", "BatchMode=yes"]
        argv += ["-o", f"ConnectTimeout={s.connect_timeout}"]
        argv += ["-o", f"StrictHostKeyChecking={s.strict_host_key}"]
        if host.identity_file:
            argv += ["-i", os.path.expanduser(str(host.identity_file))]
        if host.port and host.port != 22:
            argv += ["-P", str(host.port)]      # ★ scp 的端口是 -P（大写），不是 ssh 的 -p
        argv += [f"{host.target}:{remote_path}", str(local_path)]
        return argv

    def scp_get(
        self, host: Host, remote_path: str, local_dir: Path, *, recursive: bool = False
    ) -> tuple[bool, str]:
        """把目标机上的文件/目录拉回管理机。返回 (是否成功, 失败说明)。

        为什么用 scp 而不是"ssh 读文件内容再写本地"：
        二进制/大文件经 stdout 文本通道会经历 utf-8 decode 与 256KB 截断 ——
        那不是备份，那是残骸。scp 是二进制安全的独立通道。
        """
        try:
            argv = self.build_scp_argv(host, remote_path, local_dir, recursive=recursive)
        except OpsError as exc:
            return False, exc.reason
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=600,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return False, "scp 超时（600 秒）"
        except OSError as exc:
            return False, f"无法启动 scp：{exc}"
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            return False, (err[:300] or f"scp 退出码 {proc.returncode}")
        return True, ""

    def scp_put(self, host: Host, local_path: Path, remote_path: str) -> tuple[bool, str]:
        """把管理机上的文件推到目标机（T3 的文件上传用）。返回 (是否成功, 失败说明)。"""
        scp = shutil.which("scp")
        if not scp:
            return False, "找不到 scp 客户端"
        s = self.cfg.ssh
        argv = [scp, "-q"]
        if s.batch_mode:
            argv += ["-o", "BatchMode=yes"]
        argv += ["-o", f"ConnectTimeout={s.connect_timeout}"]
        argv += ["-o", f"StrictHostKeyChecking={s.strict_host_key}"]
        if host.identity_file:
            argv += ["-i", os.path.expanduser(str(host.identity_file))]
        if host.port and host.port != 22:
            argv += ["-P", str(host.port)]
        argv += [str(local_path), f"{host.target}:{remote_path}"]
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=600,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return False, "scp 超时（600 秒）"
        except OSError as exc:
            return False, f"无法启动 scp：{exc}"
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            return False, (err[:300] or f"scp 退出码 {proc.returncode}")
        return True, ""

    # ------------------------------------------------------------------ 专用

    def check_connectivity(self, host: Host) -> tuple[bool, OpsError | None, ExecResult | None]:
        """SSH 连通性自检（主机清单要求的能力）。"""
        try:
            res = self.run(host, ["true"], timeout=10, connect_timeout=self.cfg.ssh.connect_timeout)
        except OpsError as exc:
            return False, exc, None
        if res.timed_out:
            return False, OpsError(
                code="SSH_TIMEOUT",
                reason=f"连接 {host.target} 超时",
                advice="确认目标机已开机联网；必要时调大 config.yaml 的 ssh.connect_timeout。",
            ), res
        if res.exit_code == 255:
            return False, classify_ssh_failure(res.stderr, host), res
        if res.exit_code != 0:
            return False, OpsError(
                code="SSH_AUTH_FAILED",
                reason=f"连接 {host.target} 返回异常退出码 {res.exit_code}",
                advice="查看原始输出。",
                detail=res.stderr.strip(),
            ), res
        return True, None, res

    def trust_host(self, host: Host, *, force: bool = False) -> dict[str, object]:
        """显式「信任此主机」：用 accept-new 策略连一次，把指纹写进 known_hosts。

        说明（开题单技术要求 #2）：BatchMode 下遇到未知主机键会直接失败，
        所以必须有一条显式的信任路径，而不是让用户去猜。
        T1 走 TOFU（首次使用即信任）；把指纹展示给用户确认的流程放到 T2。

        ★★ T17·S8 补（规范 §12.139 第 2 条）：`force=True` = **「接受新指纹」**。
          为什么必须有这一条：`accept-new` **只认"没见过的主机"** ——
          对"**指纹变了**"（例如刚被我们重置过 host key 的那台克隆机）它**一样拒**，
          于是唯一出路变成了"请用户自己去改 `~/.ssh/known_hosts`"，
          而"让人去手改文件"正是本项目一直在消灭的东西。
          ⇒ `force` 先把该地址的旧记录**逐字节备份后撤掉**（`drop_known_hosts_entries`），
            再用 accept-new 连一次把**新指纹**收进来；★ 这是**人在界面点的那一下**，
            不是自动的（平台不会自己决定"接受一个新指纹"）。
        """
        before = self._known_hosts_entries(host)
        dropped: dict[str, object] | None = None
        if force:
            dropped = self.drop_known_hosts_entries(
                host.address, host.port, backup_dir=self.cfg.paths.var / "backups")
        s = self.cfg.ssh
        saved = s.strict_host_key
        try:
            s.strict_host_key = "accept-new"
            res = self.run(host, ["true"], timeout=10)
        finally:
            s.strict_host_key = saved
        after = self._known_hosts_entries(host)
        added = [e for e in after if e not in before]
        return {
            "connected": res.exit_code == 0,
            "force": bool(force),
            "dropped": dropped,
            "known_hosts_added": added,
            "known_hosts_count": len(after),
            "detail": (res.stderr or "").strip(),
        }

    @staticmethod
    def drop_known_hosts_entries(
        address: str,
        port: int,
        *,
        path: Path | None = None,
        backup_dir: Path | None = None,
    ) -> dict[str, object]:
        """把**某个地址**的已知主机记录：① **先逐字节备份** ② 再删掉。

        ★★ 它服务的是哪一件事（规范 §12.139 第 2 条）：**重置过 SSH host key 之后**，
          管理机自己那份 `known_hosts` 里还记着**旧指纹** ⇒ ssh **拒连**
          （`REMOTE HOST IDENTIFICATION HAS CHANGED`）；而 `accept-new` 对付"指纹变了"
          **一样拒**（它只认"没见过的主机"）⇒ 必须有这一步台阶。

        ★★ 三条硬规矩：
          ① **只删** `<address>` 与 `[<address>]:<port>` 这两把键 —— **别的机器一行都不许动**；
          ② 删之前**逐字节备份**（把 sha256 一起交出来，可回退 —— §12.131 同族）；
          ③ 文件不存在 / 本来就没有该地址的记录 ⇒ **如实回 0 条**（那不是错误，是结论）。
        """
        import hashlib
        from datetime import datetime

        p = path or Path(os.path.expanduser("~/.ssh/known_hosts"))
        keys = {address, f"[{address}]:{port}"}
        if not p.is_file():
            return {"path": str(p), "existed": False, "removed": 0, "kept": 0, "backup": None}
        raw = p.read_bytes()
        lines = raw.decode("utf-8", errors="replace").splitlines(keepends=True)
        kept = [ln for ln in lines
                if (ln.split(" ", 1)[0] if ln.strip() else "") not in keys]
        removed = len(lines) - len(kept)
        out: dict[str, object] = {
            "path": str(p), "existed": True, "removed": removed, "kept": len(kept),
            "sha256_before": hashlib.sha256(raw).hexdigest(), "backup": None,
        }
        if removed == 0:
            return out                                   # 没有它的记录 ⇒ 什么都不用做
        bdir = backup_dir or Path("var") / "backups"
        bdir.mkdir(parents=True, exist_ok=True)
        backup = bdir / f"known_hosts.{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
        backup.write_bytes(raw)                          # ★ 逐字节：连行尾一起保住
        p.write_text("".join(kept), encoding="utf-8", newline="")
        out.update(
            backup=str(backup),
            backup_sha256=hashlib.sha256(backup.read_bytes()).hexdigest(),
            sha256_after=hashlib.sha256(p.read_bytes()).hexdigest(),
        )
        return out

    @staticmethod
    def _known_hosts_entries(host: Host) -> list[str]:
        path = Path(os.path.expanduser("~/.ssh/known_hosts"))
        if not path.is_file():
            return []
        keys = {host.address, f"[{host.address}]:{host.port}"}
        out: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            first = line.split(" ", 1)[0] if line.strip() else ""
            if first in keys:
                out.append(line.strip())
        return out
