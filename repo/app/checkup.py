"""一键体检的**判定层**（T4 · 规范 §10.2）。

为什么单独一层，而不是写进动作 YAML：
  · 结论模板**不能做运算**（规范 §8.7 #1）—— "根分区 92% > 95% 所以判红"这件事，模板表达不了；
  · 阈值必须能改而**不改代码**（规范 §10.2.2）—— 一律读 config.yaml 的 `checkup.thresholds`，
    并且**在报告里回显用的是哪一档阈值**（否则没人知道"红"是怎么来的）。

分工：
    catalog/actions/host.checkup.yaml   采集（只读命令，20 步）
    app/checkup.py                      判定（总判 + 每项判定 + 下一步指向）← 本文件

★ 本层只**读**三样东西：任务的步骤留证、hosts.yaml 的角色、config.yaml 的阈值。
  它不执行任何命令、不写任何文件、不碰目标机。
"""
from __future__ import annotations

from typing import Any

from app.errors import OpsError

# 体检的采集动作（id 见 catalog/actions/host.checkup.yaml）
CHECKUP_ACTION_ID = "host.checkup"

# 体检项的固定展示顺序
LEVELS = ("crit", "warn", "ok", "unknown")
LEVEL_ICON = {"crit": "🔴", "warn": "🟡", "ok": "🟢", "unknown": "⚠️"}
LEVEL_LABEL = {"crit": "要处理", "warn": "注意", "ok": "通过", "unknown": "无法判定"}

# ── 阈值默认值（config.yaml 的 checkup.thresholds 可覆盖）
_THRESHOLD_DEFAULTS: dict[str, float] = {
    "disk_pct_warn": 85,        # 挂载点容量使用率
    "disk_pct_crit": 95,
    "inode_pct_warn": 85,
    "inode_pct_crit": 95,
    "failed_service_warn": 1,   # is-failed 的服务个数
    "kernel_err_warn": 10,      # 内核错误条数（超过才判黄，免得几条无害告警就让整台机器变黄）
}

_DEFAULT_CORE_SERVICES = ["sshd"]
_DEFAULT_ORPHAN_PORTS = [8080, 9090, 9100]

# 这些文件系统的百分比没有运维意义（与 disk.usage 动作的判读口径一致）
_PSEUDO_FS = ("tmpfs", "devtmpfs", "efivarfs", "ramfs", "overlay", "squashfs", "autofs", "cgroup", "cgroup2")

# journalctl 无匹配时的占位行 —— 对"OOM 检索"来说它是**好结论**，必须过滤掉（§10.2 探针发现）
_NO_ENTRIES = "-- No entries --"


# ------------------------------------------------------------------ 配置读取


def _checkup_raw(cfg: Any) -> dict[str, Any]:
    raw = getattr(cfg, "raw", None) or {}
    section = raw.get("checkup") if isinstance(raw, dict) else None
    return section if isinstance(section, dict) else {}


def thresholds(cfg: Any) -> dict[str, float]:
    """取阈值；只接受已知键的数值，未知键忽略（防手滑写错键名后静默生效）。"""
    th = dict(_THRESHOLD_DEFAULTS)
    for k, v in (_checkup_raw(cfg).get("thresholds") or {}).items():
        if k in th and isinstance(v, (int, float)) and not isinstance(v, bool):
            th[k] = v
    return th


def core_services(cfg: Any) -> list[str]:
    vals = _checkup_raw(cfg).get("core_services")
    return [str(x) for x in vals] if isinstance(vals, list) and vals else list(_DEFAULT_CORE_SERVICES)


def orphan_port_candidates(cfg: Any) -> list[int]:
    vals = _checkup_raw(cfg).get("orphan_port_candidates")
    if isinstance(vals, list) and vals:
        out: list[int] = []
        for v in vals:
            try:
                out.append(int(v))
            except (TypeError, ValueError):
                continue
        if out:
            return out
    return list(_DEFAULT_ORPHAN_PORTS)


# ------------------------------------------------------------------ 小工具


def _pct(value: Any) -> float | None:
    """'30%' / 30 / '30' → 30.0；取不出 → None（不猜）。"""
    if value is None:
        return None
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def _is_pseudo(fs: str) -> bool:
    name = fs.strip().lower()
    return any(name.startswith(p) for p in _PSEUDO_FS)


def _item(
    no: int,
    iid: str,
    title: str,
    level: str,
    verdict: str,
    advice: str = "",
    evidence: list[str] | None = None,
    next_action: str | None = None,
    next_hint: str | None = None,
) -> dict[str, Any]:
    return {
        "no": no,
        "id": iid,
        "title": title,
        "level": level,
        "icon": LEVEL_ICON.get(level, ""),
        "verdict": verdict,
        "advice": advice,
        "evidence": [e for e in (evidence or []) if e],
        "next_action": next_action,
        "next_action_title": None,      # 由 api 层按 actions 字典补全（这层不依赖动作清单）
        "next_hint": next_hint,
    }


class _Collect:
    """把一次体检任务的步骤留证按**步骤名**索引起来。

    checkup 没有 foreach，所以步骤名唯一；仍按 iter_key 过滤一次以防将来加循环。
    """

    def __init__(self, detail: dict[str, Any]) -> None:
        self.task: dict[str, Any] = detail.get("task") or {}
        self._steps: dict[str, dict[str, Any]] = {}
        for s in detail.get("steps") or []:
            if s.get("iter_key") in (None, ""):
                self._steps.setdefault(str(s.get("name")), s)

    def step(self, name: str) -> dict[str, Any] | None:
        return self._steps.get(name)

    def parsed(self, name: str) -> Any:
        s = self.step(name)
        return s.get("parsed") if s else None

    def rc(self, name: str) -> int | None:
        s = self.step(name)
        return s.get("exit_code") if s else None

    def status(self, name: str) -> str:
        s = self.step(name)
        return str(s.get("status")) if s else "missing"

    def missing_tool(self, name: str) -> str | None:
        """该步是否因为"目标机没装这个命令"而失败（§8.2 的 TOOL_MISSING）。"""
        s = self.step(name)
        if s and s.get("error_code") == "TOOL_MISSING":
            return str(s.get("error_reason") or "命令不存在")
        return None

    def tool_advice(self, name: str) -> str:
        s = self.step(name)
        return str(s.get("error_advice") or "") if s else ""

    def failed(self, name: str) -> bool:
        return self.status(name) in ("failed", "timeout", "rejected")


# ------------------------------------------------------------------ 12 个体检项


def _t_time_sync(c: _Collect, th: dict[str, float]) -> dict[str, Any]:
    ntp = c.parsed("ntp")
    if not isinstance(ntp, dict) or not ntp:
        mt = c.missing_tool("ntp")
        return _item(
            1, "time_sync", "时间同步", "unknown",
            f"拿不到时间同步状态（{mt or 'timedatectl show 无输出'}）",
            advice="先用「时间与时区」动作手工看一眼；若 timedatectl 不存在，这台机器可能不是 systemd 系统。",
            next_action="host.datetime",
        )
    sync = str(ntp.get("NTPSynchronized", "")).lower()
    tz = str(ntp.get("Timezone") or "?")
    ev = [f"NTPSynchronized={ntp.get('NTPSynchronized')} ｜ NTP 服务开关={ntp.get('NTP')} ｜ 时区={tz}"]
    if sync == "yes":
        return _item(1, "time_sync", "时间同步", "ok", f"系统时钟已同步（时区 {tz}）", evidence=ev,
                     next_action="host.datetime")
    return _item(
        1, "time_sync", "时间同步", "warn",
        f"系统时钟**未同步**（NTPSynchronized={ntp.get('NTPSynchronized')}）",
        advice="时间不准会让日志、证书校验、集群心跳全部对不上。先看「时间与时区」的同步源与偏移。",
        evidence=ev, next_action="host.datetime",
    )


def _worst_mount(rows: Any, key: str) -> tuple[dict[str, Any] | None, float | None, list[dict[str, Any]]]:
    """挑出使用率最高的真实文件系统；顺便把"超过告警线的其它挂载点"一并返回。"""
    if not isinstance(rows, list) or not rows:
        return None, None, []
    best: dict[str, Any] | None = None
    best_val: float | None = None
    for r in rows:
        if not isinstance(r, dict):
            continue
        fs = str(r.get("fs") or "")
        if _is_pseudo(fs):
            continue
        val = _pct(r.get(key))
        if val is None:
            continue
        if best_val is None or val > best_val:
            best, best_val = r, val
    return best, best_val, [r for r in rows if isinstance(r, dict) and not _is_pseudo(str(r.get("fs") or "")) and (_pct(r.get(key)) or 0) >= 0]


def _t_disk(c: _Collect, th: dict[str, float]) -> dict[str, Any]:
    rows = c.parsed("disk")
    best, val, _ = _worst_mount(rows, "pcent")
    if best is None or val is None:
        return _item(2, "disk", "磁盘水位", "unknown", "解析不出任何挂载点（df -P 输出格式可能已变）",
                     advice="手工执行 df -P 对照。", next_action="disk.usage")
    mount = str(best.get("mount") or "?")
    ev = [f"最高水位：{mount} = {val}%（{best.get('used_mb')} / {best.get('size_mb')} MB，可用 {best.get('avail_mb')} MB）",
          f"判定阈值：≥{th['disk_pct_crit']:g}% 红 ｜ ≥{th['disk_pct_warn']:g}% 黄"]
    # ★ 根分区单独列一行：运维第一句问的就是"/ 还有多少"。
    #   它未必是"水位最高"的那个（/boot 常常反而更高），所以不能只给 max。
    root_row = next((r for r in (rows or [])
                     if isinstance(r, dict) and str(r.get("mount")) == "/" and not _is_pseudo(str(r.get("fs") or ""))), None)
    if root_row is not None and str(root_row.get("mount")) != mount:
        ev.insert(1, f"根分区 / = {_pct(root_row.get('pcent'))}%（{root_row.get('used_mb')} / {root_row.get('size_mb')} MB）")
    others = [f"{r.get('mount')} {_pct(r.get('pcent'))}%" for r in (rows or [])
              if isinstance(r, dict) and not _is_pseudo(str(r.get("fs") or ""))
              and (_pct(r.get("pcent")) or 0) >= th["disk_pct_warn"] and str(r.get("mount")) != mount]
    if others:
        ev.append("其它高水位挂载点：" + "、".join(others))
    if val >= th["disk_pct_crit"]:
        return _item(2, "disk", "磁盘水位", "crit", f"{mount} 已用 **{val}%**（超过红线 {th['disk_pct_crit']:g}%）",
                     advice="先用「目录体积排行」找大目录、再用「大文件查找」定位，确认无用后再清。",
                     evidence=ev, next_action="disk.topdir")
    if val >= th["disk_pct_warn"]:
        return _item(2, "disk", "磁盘水位", "warn", f"{mount} 已用 {val}%（超过黄线 {th['disk_pct_warn']:g}%）",
                     advice="先查「目录体积排行」看增长来源，别等写满再处理。",
                     evidence=ev, next_action="disk.topdir")
    return _item(2, "disk", "磁盘水位", "ok", f"最高 {mount} {val}%，未超黄线 {th['disk_pct_warn']:g}%",
                 evidence=ev, next_action="disk.usage")


def _t_inode(c: _Collect, th: dict[str, float]) -> dict[str, Any]:
    rows = c.parsed("inode")
    best, val, _ = _worst_mount(rows, "ipcent")
    if best is None or val is None:
        return _item(3, "inode", "inode 水位", "unknown", "解析不出任何 inode 信息（df -P -i 输出异常）",
                     advice="手工执行 df -P -i 对照。", next_action="disk.usage")
    mount = str(best.get("mount") or "?")
    ev = [f"最高水位：{mount} = {val}%（{best.get('iused')} / {best.get('inodes')}）",
          f"判定阈值：≥{th['inode_pct_crit']:g}% 红 ｜ ≥{th['inode_pct_warn']:g}% 黄"]
    if val >= th["inode_pct_crit"]:
        return _item(3, "inode", "inode 水位", "crit", f"{mount} inode 已用 **{val}%**（超过红线）",
                     advice="inode 满通常是海量小文件：看「目录体积排行」并留意日志/缓存/会话目录。",
                     evidence=ev, next_action="disk.usage")
    if val >= th["inode_pct_warn"]:
        return _item(3, "inode", "inode 水位", "warn", f"{mount} inode 已用 {val}%（超过黄线）",
                     advice="容量可能还有余量，但 inode 满了会直接导致无法创建文件。",
                     evidence=ev, next_action="disk.usage")
    return _item(3, "inode", "inode 水位", "ok", f"最高 {mount} {val}%，未超黄线 {th['inode_pct_warn']:g}%",
                 evidence=ev, next_action="disk.usage")


def _t_services(c: _Collect, th: dict[str, float], cores: list[str]) -> dict[str, Any]:
    failed_raw = c.parsed("failed_units")
    failed = [str(x) for x in failed_raw] if isinstance(failed_raw, list) else []
    sshd = c.parsed("core_sshd")
    sshd_state = str(sshd).strip() if sshd is not None else ""

    # 核心服务（sshd 等）不在 running → 红：登录通道本身出问题，其他结论都要打问号
    down_core = [name for name in cores if name == "sshd" and sshd_state and sshd_state != "active"]
    if down_core:
        return _item(4, "services", "服务失败项", "crit",
                     f"核心服务 {'、'.join(down_core)} 不是 active（当前 {sshd_state}）",
                     advice="先确认「服务总览」里它的失败原因（配置语法、端口占用、依赖服务）。",
                     evidence=[f"systemctl is-active sshd = {sshd_state}"],
                     next_action="svc.list")

    hit_cores = [ln for ln in failed if any(ln.strip().startswith(f"{name}.") or ln.strip().startswith(name) for name in cores)]
    if hit_cores:
        return _item(4, "services", "服务失败项", "crit",
                     f"核心服务出现在失败列表里：{len(hit_cores)} 个",
                     advice="核心服务失败优先处理。",
                     evidence=[f"失败服务：{ln.split()[0]}" for ln in failed[:8]],
                     next_action="svc.list")

    if len(failed) >= th["failed_service_warn"]:
        return _item(4, "services", "服务失败项", "warn",
                     f"有 {len(failed)} 个服务处于 failed 状态",
                     advice="逐个看「服务总览」的失败原因；确认无用后再决定停用或修复。",
                     evidence=[f"· {ln}" for ln in failed[:6]],
                     next_action="svc.list")

    return _item(4, "services", "服务失败项", "ok", "没有处于 failed 状态的服务",
                 evidence=[f"核心服务 sshd = {sshd_state or '（未取到）'}"],
                 next_action="svc.list")


def _t_kernel(c: _Collect, th: dict[str, float]) -> dict[str, Any]:
    oom_raw = c.parsed("oom")
    oom = [str(x) for x in oom_raw] if isinstance(oom_raw, list) else []
    # ★ 必须过滤 journalctl 的占位行（"没有 OOM" 不等于 "有 OOM"，探针实测过）
    oom = [x for x in oom if _NO_ENTRIES not in x and x.strip()]
    errs_raw = c.parsed("kernel_errs")
    errs = [str(x) for x in errs_raw] if isinstance(errs_raw, list) else []
    oom_unknown = c.failed("oom") and not c.missing_tool("oom")

    ev = [f"内核错误 {len(errs)} 条 ｜ OOM 命中 {len(oom)} 条",
          f"判定阈值：内核错误 ≥{th['kernel_err_warn']:g} 条判黄 ｜ 出现 OOM 直接判红"]
    if errs[:1]:
        ev.append("最近一条内核错误：" + errs[0][:120])

    if oom:
        return _item(5, "kernel", "内核报错与 OOM", "crit",
                     f"发现 {len(oom)} 条 OOM（内存不足杀进程）记录",
                     advice="进程「莫名消失」的常见真因。先看「进程总览」按内存排序，再看是否该限制服务内存。",
                     evidence=[f"· {x[:140]}" for x in oom[:4]] + ev[1:],
                     next_action="kernel.log")
    if oom_unknown:
        return _item(5, "kernel", "内核报错与 OOM", "unknown", "内核日志不可读，无法判断是否发生过 OOM",
                     advice="这台机器可能没持久化 journal。用「内核日志与 OOM」动作手工确认。",
                     evidence=ev, next_action="kernel.log")
    if len(errs) >= th["kernel_err_warn"]:
        return _item(5, "kernel", "内核报错与 OOM", "warn",
                     f"没有 OOM，但内核错误 {len(errs)} 条（≥{th['kernel_err_warn']:g}）",
                     advice="看「内核日志与 OOM」判断是硬件/驱动报错（nvme、I/O error、link down）还是软件问题。",
                     evidence=ev + [f"· {x[:120]}" for x in errs[:3]],
                     next_action="kernel.log")
    return _item(5, "kernel", "内核报错与 OOM", "ok",
                 f"没有 OOM；内核错误 {len(errs)} 条，未超阈值 {th['kernel_err_warn']:g}",
                 evidence=ev, next_action="kernel.log")


def _t_selinux(c: _Collect, _th: dict[str, float]) -> dict[str, Any]:
    mode = c.parsed("selinux")
    mode_s = str(mode).strip() if mode is not None else ""
    if not mode_s:
        mt = c.missing_tool("selinux")
        return _item(6, "selinux", "SELinux 模式", "unknown",
                     f"取不到 SELinux 状态（{mt or 'getenforce 无输出'}）",
                     advice="这台机器可能没启用 SELinux。用「SELinux 状态」动作确认。",
                     next_action="sec.selinux")
    ev = [f"getenforce = {mode_s}"]
    if mode_s.lower() == "enforcing":
        return _item(6, "selinux", "SELinux 模式", "ok", "Enforcing（策略在强制生效）",
                     evidence=ev, next_action="sec.selinux")
    return _item(6, "selinux", "SELinux 模式", "warn",
                 f"{mode_s}（不是强制模式）",
                 advice="生产环境不建议长期 Disabled/Permissive：变更会「看起来成功」但被安全面放过。"
                        "确认这是有意为之（例如容器宿主需要），否则考虑恢复 Enforcing 并用策略放行。",
                 evidence=ev, next_action="sec.selinux")


def _t_firewall(c: _Collect, candidates: list[int]) -> dict[str, Any]:
    rc = c.rc("firewalld")
    raw = c.parsed("firewalld")
    raw_s = str(raw).strip() if raw is not None else ""
    if rc is None:
        mt = c.missing_tool("firewalld")
        return _item(7, "firewall", "防火墙", "unknown",
                     f"取不到 firewalld 状态（{mt or 'firewall-cmd 无输出'}）",
                     advice="这台机器可能没装 firewalld（或用了 nftables/ufw）。",
                     next_action="net.firewall")
    running = rc == 0 and raw_s == "running"
    if not running:
        return _item(7, "firewall", "防火墙", "warn",
                     f"firewalld 未运行（firewall-cmd --state 返回 {rc}）",
                     advice="未运行时所有端口都是敞开的（只受上游网络与安全组限制）。"
                            "确认这是有意为之；要启就用「服务」类的动作，别用命令硬启。",
                     evidence=[f"rc={rc}（252 = FirewallD is not running，实测值）",
                               "★ 未运行时「放行的端口有没有人监听」无从判断 —— 本项只给这一条结论"],
                     next_action="net.firewall")

    ports_raw = c.parsed("fw_ports")
    opened = [p for p in str(ports_raw or "").replace(",", " ").split() if p]
    listeners = c.parsed("listeners")
    listening: set[str] = set()
    if isinstance(listeners, list):
        for r in listeners:
            if isinstance(r, dict) and r.get("port"):
                listening.add(str(r["port"]))
    orphans: list[str] = []
    for p in opened:
        num = str(p).split("/")[0].strip()
        try:
            if int(num) in candidates and num not in listening:
                orphans.append(p)
        except ValueError:
            continue
    ev = [f"已放行端口（{len(opened)} 个）：{'、'.join(opened[:10]) or '（无）'}",
          f"实际监听端口数：{len(listening)} ｜ 候选无主端口：{'、'.join(str(x) for x in candidates)}"]
    if orphans:
        return _item(7, "firewall", "防火墙", "warn",
                     f"发现 {len(orphans)} 条「有意放行但没有进程监听」的规则：{'、'.join(orphans)}",
                     advice="这类规则会让端口扫描看到「开着但无服务」，也容易掩盖误配置。确认后撤销。",
                     evidence=ev, next_action="net.port")
    return _item(7, "firewall", "防火墙", "ok", "firewalld 运行中，未发现无主放行规则",
                 evidence=ev, next_action="net.firewall")


def _t_certs(c: _Collect, _th: dict[str, float]) -> dict[str, Any]:
    mt = c.missing_tool("openssl")
    if mt:
        return _item(8, "certs", "证书工具链", "unknown",
                     f"目标机没装 openssl，证书到期无法判定",
                     advice=c.tool_advice("openssl") or "装 openssl 后重跑体检（或先用「证书到期」动作看它是否走同一个缺口）。",
                     evidence=[f"原因：{mt}"],
                     next_action="sec.cert")
    if c.failed("openssl"):
        return _item(8, "certs", "证书工具链", "unknown", "openssl 执行失败，无法判定",
                     evidence=[f"stderr：{(c.step('openssl') or {}).get('stderr', '')[:160]}"],
                     next_action="sec.cert")
    ver = str(c.parsed("openssl") or "").strip()
    ca_rc = c.rc("ca_certs")
    ca_out = str(c.parsed("ca_certs") or "").strip() or "（未装）"
    ev = [f"openssl：{ver}", f"ca-certificates：{ca_out}（rpm -q 退出码 {ca_rc}）",
          "★ 本项只判「工具链是否可用」；具体证书的到期日期由「证书到期」动作细查"]
    if ca_rc not in (0, None):
        return _item(8, "certs", "证书工具链", "warn", "openssl 可用，但系统 CA 证书包缺失",
                     advice="缺 CA 包会让 https 校验大面积失败。先用「已装软件」确认，再决定是否安装。",
                     evidence=ev, next_action="sec.cert")
    return _item(8, "certs", "证书工具链", "ok", "openssl 与系统 CA 证书包都可用",
                 evidence=ev, next_action="sec.cert")


def _t_pkg(c: _Collect, _th: dict[str, float]) -> dict[str, Any]:
    val = str(c.parsed("rpm_db") or "").strip()
    if not val:
        return _item(9, "pkg", "包管理可用性", "crit",
                     "rpm 数据库读不出来",
                     advice="整个工作台的诊断能力都建立在 rpm 上（装了什么包、哪个包提供某命令）。先修它。",
                     evidence=[f"rpm -q rpm 退出码 {c.rc('rpm_db')}"],
                     next_action="pkg.installed")
    return _item(9, "pkg", "包管理可用性", "ok", f"rpm 数据库可读（{val}）",
                 evidence=[f"rpm -q rpm → {val}"], next_action="pkg.installed")


def _t_container(c: _Collect, _th: dict[str, float]) -> dict[str, Any]:
    d = c.parsed("docker_state") if isinstance(c.parsed("docker_state"), dict) else {}
    k = c.parsed("containerd_state") if isinstance(c.parsed("containerd_state"), dict) else {}
    d_state = str((d or {}).get("ActiveState") or "?")
    k_state = str((k or {}).get("ActiveState") or "?")
    if d_state != "active" and k_state != "active":
        return _item(10, "container", "容器运行状态", "ok",
                     f"本机没有运行中的容器引擎（docker={d_state}、containerd={k_state}）",
                     evidence=[f"docker={d_state} ｜ containerd={k_state}"],
                     next_hint="容器总览（T6 提供）")
    lines = c.parsed("containers")
    statuses = [str(x) for x in lines] if isinstance(lines, list) else []
    bad = [s for s in statuses if s.startswith("Restarting") or s.startswith("Exited")]
    ev = [f"docker={d_state} ｜ containerd={k_state}",
          f"容器总数 {len(statuses)} ｜ 异常（Restarting/Exited）{len(bad)}"]
    if bad:
        return _item(10, "container", "容器运行状态", "warn",
                     f"有 {len(bad)} 个容器处于异常状态",
                     advice="先看容器日志确认是配置问题还是依赖没起来；本工作台暂不提供容器操作入口（T6）。",
                     evidence=ev + [f"· {s}" for s in bad[:5]],
                     next_hint="容器总览（T6 提供）")
    return _item(10, "container", "容器运行状态", "ok", f"{len(statuses)} 个容器，无 Restarting/Exited",
                 evidence=ev, next_hint="容器总览（T6 提供）")


def _t_k8s(c: _Collect, role: str) -> dict[str, Any]:
    if role not in ("k8s-control-plane", "k8s-worker"):
        return _item(11, "k8s", "K8s 节点状态", "ok",
                     f"不是 K8s 节点（role={role or '未标注'}），本项不适用",
                     next_hint="K8s 界面在 T9")
    kubelet = str(c.parsed("kubelet") or "").strip() or "（未取到）"
    nodes_raw = c.parsed("k8s_nodes")
    nodes = [str(x) for x in nodes_raw] if isinstance(nodes_raw, list) else []
    not_ready = [n for n in nodes if "NotReady" in n]
    ev = [f"kubelet = {kubelet}", f"节点清单 {len(nodes)} 条 ｜ NotReady {len(not_ready)} 条"]
    if nodes:
        ev.append("节点：" + "、".join(n.split()[0] for n in nodes[:6]))
    if kubelet != "active":
        return _item(11, "k8s", "K8s 节点状态", "warn",
                     f"kubelet = {kubelet}（不是 active）→ 这个节点现在不参与集群工作",
                     advice="★ 这是集群**既有状态**，不是本工作台造成的（本工作台对 K8s 全程只读）。"
                            "要修集群请用你原来的 k8s 运维流程。",
                     evidence=ev, next_hint="K8s 界面在 T9")
    if not_ready:
        return _item(11, "k8s", "K8s 节点状态", "warn",
                     f"{len(not_ready)} 个节点 NotReady",
                     advice="先看节点上的 kubelet / 容器运行时 / 磁盘压力。",
                     evidence=ev, next_hint="K8s 界面在 T9")
    if c.missing_tool("k8s_nodes"):
        return _item(11, "k8s", "K8s 节点状态", "warn",
                     "kubelet 在跑，但本机没有 kubectl，查不到节点清单",
                     advice="控制面上装 kubectl 后重跑体检。",
                     evidence=ev, next_hint="K8s 界面在 T9")
    if c.failed("k8s_nodes") or not nodes:
        return _item(11, "k8s", "K8s 节点状态", "warn",
                     "kubelet 在跑，但控制面 API 查不通（拿不到节点清单）",
                     advice="kubelet 活着不代表集群可用 —— 看控制面的 apiserver 与 etcd。",
                     evidence=ev, next_hint="K8s 界面在 T9")
    return _item(11, "k8s", "K8s 节点状态", "ok", f"{len(nodes)} 个节点全部 Ready",
                 evidence=ev, next_hint="K8s 界面在 T9")


def _t_backups(store: Any) -> dict[str, Any]:
    """第 12 项：**护栏本身也是被体检对象**（T3 交过学费，规范 §9.10）。"""
    hint = "界面「历史」页 → 任务详情 → 「改动前备份」里的恢复入口"
    try:
        rows = store.list_backups(limit=20)
    except Exception as exc:  # noqa: BLE001
        return _item(12, "backups", "最近备份可用性", "unknown", f"读不到备份记录：{type(exc).__name__}",
                     next_hint=hint)
    if not rows:
        return _item(12, "backups", "最近备份可用性", "ok",
                     "还没有任何备份记录（护栏尚未被用到）",
                     evidence=["变更类动作执行前会自动备份；跑过变更动作后再看这一项"],
                     next_hint=hint)
    from pathlib import Path  # 局部导入，避免本模块在无磁盘环境下被牵连

    broken: list[str] = []
    checked = 0
    for r in rows:
        lp = str(r.get("local_path") or "")
        if not lp:
            continue
        checked += 1
        if not Path(lp).exists():
            broken.append(f"{r.get('label') or r.get('orig_path')} → {lp}")
    ev = [f"最近 {len(rows)} 条备份记录 ｜ 抽查管理机副本 {checked} 条",
          f"管理机落点：{Path(str(rows[0].get('local_path') or '')).parent if rows[0].get('local_path') else '（无）'}"]
    if broken:
        return _item(12, "backups", "最近备份可用性", "warn",
                     f"{len(broken)} 条备份记录的副本在磁盘上找不到",
                     advice="记录指向不存在的文件 = 恢复时会踩空。用 tools/fix_backup_local_path.py 对账修复。",
                     evidence=ev + [f"· {b}" for b in broken[:5]],
                     next_hint="tools/fix_backup_local_path.py（幂等，默认干跑）")
    return _item(12, "backups", "最近备份可用性", "ok",
                 f"{checked} 条管理机副本都在磁盘上（护栏可用）", evidence=ev, next_hint=hint)


# ------------------------------------------------------------------ 总判


def judge(cfg: Any, store: Any, task_id: str, actions: dict[str, Any] | None = None) -> dict[str, Any]:
    """对一次 host.checkup 任务做判定，产出结论式报告。

    返回结构（界面直接渲染）：
        {task_id, host, overall, summary, counts, thresholds, items[], duration_ms}
    """
    detail = store.get_task(task_id)
    task = detail.get("task") or {}
    if str(task.get("action_id") or "") != CHECKUP_ACTION_ID:
        raise OpsError(
            code="PARAM_INVALID",
            reason=f"任务 {task_id} 不是体检任务（动作是 {task.get('action_id')}）",
            advice=f"体检报告只能由 {CHECKUP_ACTION_ID} 的任务生成。",
        )
    c = _Collect(detail)
    th = thresholds(cfg)
    cores = core_services(cfg)
    cands = orphan_port_candidates(cfg)
    role = ""
    try:
        role = cfg.host(str(task.get("host_id") or "")).role
    except OpsError:
        role = ""

    items = [
        _t_time_sync(c, th),
        _t_disk(c, th),
        _t_inode(c, th),
        _t_services(c, th, cores),
        _t_kernel(c, th),
        _t_selinux(c, th),
        _t_firewall(c, cands),
        _t_certs(c, th),
        _t_pkg(c, th),
        _t_container(c, th),
        _t_k8s(c, role),
        _t_backups(store),
    ]

    # 补全「先去查什么」的动作标题（本层不依赖动作清单，由调用方传入）
    if actions:
        for it in items:
            aid = it.get("next_action")
            if aid and aid in actions:
                a = actions[aid]
                it["next_action_title"] = getattr(a, "title", None) or str(aid)

    counts = {lv: sum(1 for i in items if i["level"] == lv) for lv in LEVELS}
    overall = "crit" if counts["crit"] else ("warn" if counts["warn"] else "ok")
    parts = [f"{LEVEL_ICON[lv]} {counts[lv]} 项{LEVEL_LABEL[lv]}" for lv in LEVELS if counts[lv]]
    summary = " · ".join(parts) if parts else "没有可判定的项"

    return {
        "task_id": task_id,
        "action_id": CHECKUP_ACTION_ID,
        "host": {
            "id": task.get("host_id"),
            "name": task.get("host_name"),
            "address": task.get("host_address"),
            "role": role,
        },
        "task_status": task.get("status"),
        "verify_result": task.get("verify_result"),
        "started_at": task.get("started_at"),
        "duration_ms": task.get("duration_ms"),
        "overall": overall,
        "overall_icon": LEVEL_ICON.get(overall, ""),
        "summary": summary,
        "counts": counts,
        # ★ 报告里必须回显用的是哪一档阈值（规范 §10.2.2：否则没人知道"红"是怎么来的）
        "thresholds": {
            "values": th,
            "core_services": cores,
            "orphan_port_candidates": cands,
            "source": "config.yaml → checkup.thresholds（未配置的键用内置默认值）",
        },
        "items": items,
    }
