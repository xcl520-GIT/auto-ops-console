"""配置与主机清单加载。

负责：
  · 读 config.yaml / hosts.yaml
  · 解析并校验路径、SSH 参数、监听地址（★ 安全红线：拒绝 0.0.0.0）
  · 提供时区工具（Windows 上 zoneinfo 无系统 tzdata，需降级）
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta, tzinfo
from pathlib import Path
from typing import Any

from app.errors import OpsError
from app.yamlload import load_yaml

# ------------------------------------------------------------------ 时区

_TIMEZONE_CACHE: dict[str, tzinfo] = {}


def get_tz(name: str) -> tzinfo:
    """取得时区对象。

    优先用标准库 zoneinfo；Windows 没有系统 tz 数据库时会失败，
    此时降级为固定偏移（Asia/Shanghai = UTC+8，自 1991 年起无夏令时，降级是正确的）。
    """
    if name in _TIMEZONE_CACHE:
        return _TIMEZONE_CACHE[name]

    tz: tzinfo
    try:
        from zoneinfo import ZoneInfo

        tz = ZoneInfo(name)
    except Exception:
        fixed = {"Asia/Shanghai": 8, "UTC": 0}.get(name)
        if fixed is None:
            raise OpsError(
                code="CONFIG_INVALID",
                reason=f"不认识的时区名：{name}",
                advice="改用 'Asia/Shanghai' 或 'UTC'；其它时区需先安装 tzdata（Windows: pip install tzdata）。",
            )
        tz = _FIXED_OFFSETS.setdefault(name, _FixedOffset(fixed, name))

    _TIMEZONE_CACHE[name] = tz
    return tz


@dataclass(frozen=True)
class _FixedOffset(tzinfo):
    hours: int
    name: str

    def utcoffset(self, dt):  # type: ignore[no-untyped-def]
        return timedelta(hours=self.hours)

    def tzname(self, dt):  # type: ignore[no-untyped-def]
        return self.name

    def dst(self, dt):  # type: ignore[no-untyped-def]
        return timedelta(0)


_FIXED_OFFSETS: dict[str, tzinfo] = {}


# ------------------------------------------------------------------ 主机


@dataclass
class Host:
    id: str
    name: str
    address: str
    port: int = 22
    user: str = "root"
    auth: str = "key"
    identity_file: str | None = None
    role: str = "lab"
    tags: list[str] = field(default_factory=list)
    note: str = ""
    # ★★ T16（规范 §12.115）：这台机器走**哪条执行通道**。缺省 `ssh`；
    #    另一个取值是 `local`（宿主机上的本机进程）。★ 宿主机条目由 `app\vmware.py`
    #    **合成**（不进 hosts.yaml），免得一台 Windows 机器混进"目标机"的每个下游功能。
    transport: str = "ssh"
    # ★★ T16（规范 §12.116）：虚拟化登记 —— 「哪些 VM 归本项目管」的**唯一来源**。
    #    形如 {provider: vmware-workstation, vmx: D:\VMs\node-03\node-03.vmx}
    #    ★ 必须有它才能操作那台 VM（红线 12）；★★ 不许靠"id == 目录名"的巧合
    #      （实测 docker-01 的 vmx 叫 vm-docker-01.vmx —— 不同名）。
    vm: dict[str, Any] | None = None

    @property
    def target(self) -> str:
        return f"{self.user}@{self.address}"

    def to_public(self) -> dict[str, Any]:
        """给界面的表示（不暴露 identity_file 的绝对路径细节）。"""
        return {
            "id": self.id,
            "name": self.name,
            "address": self.address,
            "port": self.port,
            "user": self.user,
            "role": self.role,
            "tags": self.tags,
            "note": self.note,
            "auth": self.auth,
            # ★ T16：通道与虚拟化登记要让界面看得见（否则"为什么这台要走本机"说不清）
            "transport": self.transport,
            "vm": ({"provider": str((self.vm or {}).get("provider") or ""),
                    "vmx": str((self.vm or {}).get("vmx") or "")} if self.vm else None),
        }


# ------------------------------------------------------------------ 配置


@dataclass
class Paths:
    root: Path
    catalog: Path
    actions: Path
    map: Path
    hosts: Path
    var: Path
    artifacts: Path
    database: Path
    web: Path

    def ensure(self) -> None:
        for p in (self.var, self.artifacts, self.database.parent):
            p.mkdir(parents=True, exist_ok=True)


@dataclass
class SshConfig:
    binary: str = "ssh"
    connect_timeout: int = 8
    default_timeout: int = 20
    control_master: bool = True
    control_persist: int = 300
    control_dir: str = "var/ssh-ctl"
    strict_host_key: str = "accept-new"
    batch_mode: bool = True
    server_alive_interval: int = 15
    server_alive_count_max: int = 3

    def effective_control_master(self) -> tuple[bool, str]:
        """返回 (是否启用连接复用, 说明)。

        ★ Windows 的 OpenSSH 不支持 ControlMaster（依赖 Unix 域套接字），
          强行开启会带来无谓的告警。真实部署在 RHEL 10 管理机上是开启的。
        """
        if not self.control_master:
            return False, "配置里已关闭"
        if os.name == "nt":
            return False, "Windows 的 OpenSSH 不支持 ControlMaster（Unix 域套接字），本机自动关闭；部署到 RHEL 管理机时会自动启用"
        return True, "已启用（节省每次握手开销）"


@dataclass
class AppConfig:
    root: Path
    server: dict[str, Any]
    timezone: str
    paths: Paths
    ssh: SshConfig
    exec: dict[str, Any]
    log: dict[str, Any]
    hosts: list[Host]
    raw: dict[str, Any] = field(default_factory=dict)

    # -- 便捷访问
    @property
    def default_timeout(self) -> int:
        return int(self.exec.get("default_timeout", self.ssh.default_timeout))

    @property
    def max_output_bytes(self) -> int:
        return int(self.exec.get("max_output_bytes", 262144))

    @property
    def max_foreach_items(self) -> int:
        return int(self.exec.get("max_foreach_items", 50))

    def host(self, host_id: str) -> Host:
        for h in self.hosts:
            if h.id == host_id:
                return h
        # ★★ T16（规范 §12.115 规矩 2）：**宿主机**（执行面）由 app\vmware.py 合成，
        #    不进 hosts.yaml —— 但它必须能被 host() 找到，因为
        #    "按 id 取主机"是预览 / 任务 / 留证 / REST 的公共入口。
        #    ★ 局部导入：避免 config ⇄ vmware 循环导入。
        from app.vmware import vm_host

        vh = vm_host(self)
        if vh.id == host_id:
            return vh
        raise OpsError(
            code="HOST_NOT_FOUND",
            reason=f"主机清单里没有 id 为「{host_id}」的机器",
            advice="检查 hosts.yaml；或在界面上刷新主机列表。",
            context={"known_hosts_ids": [h.id for h in self.hosts] + [vh.id]},
        )


# ------------------------------------------------------------------ 监听地址校验


def validate_bind(
    host: str, port: int, allow_prefixes: list[str] | None = None
) -> tuple[str, int]:
    """★ 安全红线：只允许本机或内网监听，永远拒绝 0.0.0.0（开题单 §3-5）。"""
    prefixes = allow_prefixes or [
        "127.0.0.1", "localhost", "::1",
        "192.168.", "10.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.2", "172.30.", "172.31.",
    ]
    h = str(host).strip()
    if not h:
        raise OpsError(code="BIND_REJECTED", reason="监听地址为空", advice="设为 127.0.0.1。")
    if not any(h.startswith(p) for p in prefixes):
        raise OpsError(
            code="BIND_REJECTED",
            reason=f"拒绝监听「{h}」：它不在允许的本机/内网白名单内",
            advice=(
                "这是项目安全红线（本地单用户控制台，不做鉴权，绝不允许对外暴露）。"
                "改回 127.0.0.1，或在这台机器确实处于内网时填入该内网 IP。"
            ),
            context={"allow_prefixes": prefixes},
        )
    if not (1 <= int(port) <= 65535):
        raise OpsError(code="BIND_REJECTED", reason=f"端口号非法：{port}")
    return h, int(port)


# ------------------------------------------------------------------ 加载


def _req(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d or d[key] in (None, ""):
        raise OpsError(
            code="CONFIG_INVALID",
            reason=f"{where} 缺少必填项：{key}",
            advice="对照 repo/config.yaml 的模板补齐该字段。",
        )
    return d[key]


def _load_hosts(path: Path) -> list[Host]:
    data = load_yaml(path, what="主机清单 hosts.yaml")
    items = data.get("hosts") or []
    if not isinstance(items, list) or not items:
        raise OpsError(
            code="CONFIG_INVALID",
            reason="hosts.yaml 里没有任何主机",
            advice="至少填写一台可 SSH 的 Linux 目标机（id / name / address / user）。",
        )
    hosts: list[Host] = []
    for i, item in enumerate(items):
        where = f"hosts.yaml 第 {i + 1} 个主机"
        if not isinstance(item, dict):
            raise OpsError(code="CONFIG_INVALID", reason=f"{where} 不是一个映射（应缩进两层）")
        transport = str(item.get("transport") or "ssh").strip().lower()
        if transport not in ("ssh", "local"):
            raise OpsError(
                code="CONFIG_INVALID",
                reason=f"{where} 的 transport 取值非法：{transport}",
                advice="只允许 ssh（默认）或 local（宿主机上的本机进程，规范 §12.115）。",
            )
        vm_raw = item.get("vm")
        if vm_raw is not None and not isinstance(vm_raw, dict):
            raise OpsError(
                code="CONFIG_INVALID",
                reason=f"{where} 的 vm 段不是一个映射",
                advice="写法：vm: {provider: vmware-workstation, vmx: D:\\VMs\\<名字>\\<名字>.vmx}",
            )
        hosts.append(
            Host(
                id=str(_req(item, "id", where)),
                name=str(item.get("name") or item["id"]),
                address=str(_req(item, "address", where)),
                port=int(item.get("port", 22)),
                user=str(item.get("user", "root")),
                auth=str(item.get("auth", "key")),
                identity_file=item.get("identity_file"),
                role=str(item.get("role", "lab")),
                tags=list(item.get("tags") or []),
                note=str(item.get("note") or "").strip(),
                transport=transport,
                vm=dict(vm_raw) if isinstance(vm_raw, dict) else None,
            )
        )
    ids = [h.id for h in hosts]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise OpsError(
            code="CONFIG_INVALID",
            reason=f"hosts.yaml 里有重复的主机 id：{sorted(dup)}",
            advice="每个主机 id 必须唯一，任务与留证都靠它索引。",
        )
    return hosts


def load(root: str | Path) -> AppConfig:
    """从 repo 根目录加载全部配置。"""
    root = Path(root).resolve()
    cfg_file = root / "config.yaml"
    data = load_yaml(cfg_file, what="全局配置 config.yaml")

    srv = data.get("server") or {}
    paths_raw = data.get("paths") or {}
    ssh_raw = data.get("ssh") or {}

    def _p(key: str, default: str) -> Path:
        val = str(paths_raw.get(key, default))
        p = Path(val)
        return p if p.is_absolute() else (root / p)

    paths = Paths(
        root=root,
        catalog=_p("catalog", "catalog"),
        actions=_p("actions", "catalog/actions"),
        map=_p("map", "catalog/map.yaml"),
        hosts=_p("hosts", "hosts.yaml"),
        var=_p("var", "var"),
        artifacts=_p("artifacts", "var/artifacts"),
        database=_p("database", "var/ops.db"),
        web=_p("web", "web"),
    )
    paths.ensure()

    bind_host, bind_port = validate_bind(
        str(srv.get("host", "127.0.0.1")),
        int(srv.get("port", 8787)),
        srv.get("allow_bind_prefixes"),
    )

    ssh = SshConfig(
        binary=str(ssh_raw.get("binary", "ssh")),
        connect_timeout=int(ssh_raw.get("connect_timeout", 8)),
        default_timeout=int(ssh_raw.get("default_timeout", 20)),
        control_master=bool(ssh_raw.get("control_master", True)),
        control_persist=int(ssh_raw.get("control_persist", 300)),
        control_dir=str(ssh_raw.get("control_dir", "var/ssh-ctl")),
        strict_host_key=str(ssh_raw.get("strict_host_key", "accept-new")),
        batch_mode=bool(ssh_raw.get("batch_mode", True)),
        server_alive_interval=int(ssh_raw.get("server_alive_interval", 15)),
        server_alive_count_max=int(ssh_raw.get("server_alive_count_max", 3)),
    )

    cfg = AppConfig(
        root=root,
        server={"host": bind_host, "port": bind_port},
        timezone=str(data.get("timezone", "Asia/Shanghai")),
        paths=paths,
        ssh=ssh,
        exec=data.get("exec") or {},
        log=data.get("log") or {},
        hosts=_load_hosts(paths.hosts),
        raw=data,
    )
    get_tz(cfg.timezone)  # 提前校验时区可用
    return cfg
