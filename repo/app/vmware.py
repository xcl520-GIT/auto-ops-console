"""虚拟化层：`vmrun` 封装 ＋ 输出解析 ＋ 错误翻译 ＋ **VM 盘点/归属**（规范 §12.115~§12.117）。

本模块只做三件事
----------------
1. **问 VMware**：把 `vmrun` 的调用、输出解析、失败翻译收在一处（`vmrun` 的输出是裸文本，
   而且**错误话术会本地化** —— 实测「找不到该虚拟机」）；
2. **答"哪些 VM 能碰"**：唯一来源是 `hosts.yaml` 每台受管机的 `vm.vmx` 登记，
   外加 `config.yaml` 的 `vm.extra_allow`（**当次点名**，写进文件即留痕）——
   ★ 判据在**平台侧**，本模块只是把这份判据实现出来（红线 12）；
3. **把状态变成可断言的形状**：`probe()` 把"在跑吗/停了吗/快照在吗/guest 起来了吗"
   变成**退出码**（`0` 成立 · `3` 不成立 · `2` 读不到），与 `systemctl is-active` 的 `0/3` 同源。

★ 本模块**不 import** engine / transport / ssh：它不认识「任务 / 留证 / 闸门」，
  那些留在平台侧（`engine.py` 调 `vm_guard()` 做闸门，规范 §12.116）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from app.config import AppConfig, Host
from app.errors import OpsError
from app.hostexec import LocalRun, run_child

# ------------------------------------------------------------------ 配置

#: `config.yaml` 的 `vm:` 段默认值。★ 只有一个地方定义（改这里即全生效）。
VM_DEFAULTS: dict[str, Any] = {
    # `vmrun.exe` —— VMware Workstation 的**非默认安装路径**（本机实测在 C:\Program Files (x86)\VMware\VMware Workstation）
    "vmrun": r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    # `vmrun -T <type>` 的取值：ws = Workstation
    "type": "ws",
    # ★ 宿主机在**任务/留证**里的 host 身份（由本模块合成，**不塞进 hosts.yaml**，
    #   免得它出现在目标机下拉 / 批量 / 体检 / AI 工具面里被当成一台 Linux 机器）
    "host_id": "vmhost",
    "host_name": "宿主机（VMware Workstation · 本机）",
    # 单次 `vmrun` 调用的默认超时（秒）；开机/关机这种慢操作由动作自己声明更长的 timeout
    "default_timeout": 120,
    # ★ 纵深防御：只允许操作这些目录下的 .vmx（与 file.remove 的路径白名单同源）
    "allow_vmx_dirs": [r"D:\VMs"],
    # ★ 当次点名：用户显式允许操作的 VM（写进文件 = 留痕，不做"口令式"的临时开关）
    "extra_allow": [],
    # 只读枚举用：VMware 的虚拟机清单（红线 13：**只允许只读**）
    "inventory": r"%APPDATA%\VMware\inventory.vmls",
    # 跑 `tools\vmprobe.py` 的解释器；留空 = 当前解释器
    "python": "",
}


def vm_conf(cfg: AppConfig) -> dict[str, Any]:
    """取 `vm:` 段（缺项用默认值补）。★ 不缓存：改配置即生效，便于现场排查。"""
    raw = dict(VM_DEFAULTS)
    got = cfg.raw.get("vm") or {}
    if isinstance(got, dict):
        raw.update({k: v for k, v in got.items() if v is not None})
    return raw


def vm_host(cfg: AppConfig) -> Host:
    """合成"宿主机"这个执行面（规范 §12.115 规矩 2）。

    ★ 它不是 `hosts.yaml` 里的条目 —— 它是**执行面**，不是目标机。
      这么做是为了不让一台 Windows 机器混进"目标机"的每一个下游功能
      （主机下拉 / 批量 / 体检 / AI 工具面）。
    """
    conf = vm_conf(cfg)
    return Host(
        id=str(conf.get("host_id") or "vmhost"),
        name=str(conf.get("host_name") or "宿主机"),
        address="127.0.0.1",
        port=0,
        user="-",
        auth="none",
        identity_file=None,
        role="vmware-host",
        tags=["Workstation", "本机", "非 ssh 通道"],
        note="本机 Windows 执行面：用 vmrun.exe 管 VMware 虚拟机（不走 ssh，规范 §12.115）。",
        # ★★ 这一行是**必需**的，不是装饰：`engine._to_step_out` 靠 `host.transport`
        #    选失败分类器（本机通道看退出码 + 本地化话术，不看英文关键字；§12.115 规矩 6）。
        transport="local",
    )


def python_path(cfg: AppConfig) -> str:
    """跑探针脚本用的解释器。"""
    p = str(vm_conf(cfg).get("python") or "").strip()
    return p or sys.executable


def probe_extra(cfg: AppConfig) -> dict[str, str]:
    """本通道动作要用的**工具坐标**（唯一来源，规范 §12.115）。

    ★ 动作 YAML 里**不写死任何绝对路径** —— 写 `{{ vm_probe_py }}` / `{{ vm_probe_script }}` /
      `{{ vmrun }}` / `{{ vm_type }}`，由平台在渲染前注入。
      这样"VMware 装在哪儿"只有一处定义（`config.yaml` 的 `vm:` 段），换机器只改配置。
    """
    repo = Path(__file__).resolve().parents[1]
    return {
        "vm_probe_py": python_path(cfg),
        "vm_probe_script": str(repo / "tools" / "vmprobe.py"),
        # ★ T17·S4：登记那条动作（改的是**管理机自己**的 hosts.yaml）也走本通道的工具坐标
        "host_register_script": str(repo / "tools" / "host_register.py"),
        "vmrun": vmrun_path(cfg),
        "vm_type": str(vm_conf(cfg).get("type") or "ws"),
    }


def vmrun_path(cfg: AppConfig) -> str:
    """解析 `vmrun.exe` 路径：显式配置 → PATH → 报清楚的错（**不许静默**）。"""
    conf = vm_conf(cfg)
    explicit = str(conf.get("vmrun") or "").strip()
    cands: list[str] = []
    if explicit:
        cands.append(explicit)
    found = shutil.which("vmrun") or shutil.which("vmrun.exe")
    if found:
        cands.append(found)
    for c in cands:
        if Path(c).is_file():
            return c
    raise OpsError(
        code="VM_VMRUN_MISSING",
        reason=f"找不到 vmrun.exe（试过：{'、'.join(cands) or '（没有任何候选）'}）",
        advice=(
            "在 config.yaml 的 vm.vmrun 里写全路径（本机实测：C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe），"
            "或确认 VMware Workstation 已安装。★ 这一条是「环境事实」，不是故障。"
        ),
        context={"tried": cands},
    )


# ------------------------------------------------------------------ 基础工具


def normalize_path(p: str) -> str:
    """路径归一（比较用）：大小写折叠 ＋ 分隔符归一 ＋ 去尾部斜杠。

    ★ 为什么必须归一：`vmrun list` 回的是它自己记的路径，而 `hosts.yaml` 里是人写的 ——
      Windows 上大小写与 `/` `\\` 都可能不同，不归一会"看着像两台"。
    """
    s = str(p or "").strip().strip('"')
    s = s.replace("/", "\\")
    return os.path.normcase(os.path.normpath(s)) if s else ""


def basename_of(vmx: str) -> str:
    return Path(str(vmx).replace("/", "\\")).name


def stem_of(vmx: str) -> str:
    return Path(basename_of(vmx)).stem


def in_allowed_dirs(cfg: AppConfig, vmx: str) -> bool:
    """★ 纵深防御：vmx 必须在 `vm.allow_vmx_dirs` 之内（规范 §12.116）。"""
    dirs = [str(d) for d in (vm_conf(cfg).get("allow_vmx_dirs") or [])]
    if not dirs:
        return True  # 显式清空 = 不做目录限制（但要靠登记/点名兜底）
    target = normalize_path(vmx)
    for d in dirs:
        root = normalize_path(d)
        if target == root:
            continue
        if target.startswith(root.rstrip("\\") + "\\"):
            return True
    return False


def _first_vmx_line(text: str) -> str:
    """从 vmrun 的裸文本里挑出第一行"看起来像 vmx 路径"的内容。"""
    for line in text.splitlines():
        s = line.strip().strip('"')
        if s.lower().endswith(".vmx"):
            return s
    return ""


def looks_like_error(text: str) -> bool:
    """★ 只用于**翻译话术**，不用于判定成败（成败一律看退出码，规范 §12.115 规矩 6）。"""
    t = text.strip()
    return t.startswith("Error:") or t.startswith("错误")


# ------------------------------------------------------------------ 调用 vmrun


def vmrun_argv(cfg: AppConfig, args: list[str]) -> list[str]:
    return [vmrun_path(cfg), "-T", str(vm_conf(cfg).get("type") or "ws")] + [str(a) for a in args]


def call(cfg: AppConfig, args: list[str], *, timeout: int | None = None) -> LocalRun:
    """跑一次 `vmrun`。★ argv 直传（本通道没有 shell）。"""
    t = int(timeout or vm_conf(cfg).get("default_timeout") or 120)
    return run_child(vmrun_argv(cfg, args), timeout=t)


def _rc_text(res: LocalRun) -> str:
    return (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")


def translate(res: LocalRun, *, what: str, vmx: str = "") -> OpsError:
    """把一次失败的 `vmrun` 翻译成"原因 + 建议"。

    ★★ 规矩 6：**判定看退出码**，文本只用来**翻译**——
      因为话术会随系统语言变（实测：`Error: Cannot open VM: …, 找不到该虚拟机`），
      而且它**走在 stdout 上**（不是 stderr）。
    """
    text = _rc_text(res).strip()
    low = text.lower()
    vm = f"「{basename_of(vmx)}」" if vmx else "这台虚拟机"

    def _mk(code: str, reason: str, advice: str) -> OpsError:
        return OpsError(
            code=code,
            reason=reason,
            advice=advice,
            detail=text[:800] or None,
            context={"what": what, "vmx": vmx, "exit_code": res.exit_code},
        )

    if res.timed_out:
        return _mk(
            "VM_TIMEOUT",
            f"{what}：命令在超时时间内没有返回（{vm}）",
            "★ 这是「读不到」，不等于「没成功」：先问一次状态（vm.status），再决定要不要重试或加长超时。",
        )
    if "cannot open vm" in low or "找不到该虚拟机" in text or "打开虚拟机" in text:
        return _mk(
            "VM_NOT_FOUND",
            f"{what}：VMware 说找不到这台虚拟机（{vm}）",
            "核对 vmx 路径（hosts.yaml 的 vm.vmx）与文件是否还在；★ 路径换了要两处一起改。",
        )
    if "tools" in low and ("not running" in low or "未运行" in text or "not installed" in low):
        return _mk(
            "VM_TOOLS_MISSING",
            f"{what}：guest 里没有可用的 VMware Tools（{vm}）",
            "等 guest 起来（vm.wait-guest）再试；若一直读不到，去 guest 里确认 open-vm-tools 在跑。",
        )
    if "is not running" in low or "not powered on" in low or "未运行" in text or "尚未启动" in text:
        return _mk(
            "VM_NOT_RUNNING",
            f"{what}：{vm}当前**没有在运行**",
            "先 vm.start（yellow，需要人点头）再重试；★ 「没在跑」是一条结论，不是故障。",
        )
    if "already running" in low or "已经在运行" in text or "正在运行" in text:
        return _mk(
            "VM_ALREADY_RUNNING",
            f"{what}：{vm}已经在运行",
            "★ 这是幂等路径（已达终态），不是失败；用 vm.status 复核一次即可。",
        )
    if "in use" in low or "being used" in low or "正在使用" in text or "lock" in low:
        return _mk(
            "VM_LOCKED",
            f"{what}：{vm}被占用（可能是孤儿 .lck 锁，或它正被另一个窗口/进程持有）",
            "★ **不要自动删锁**（清锁 = 拿所有权，可能破坏正在跑的 VM）：先看 vmrun list 确认它没在跑，"
            "再由人按 开发记录\环境事件-20260926-靶机硬断电体检.md 的口径手工处理。",
        )
    if "snapshot" in low and ("not found" in low or "does not exist" in low or "找不到" in text):
        return _mk(
            "VM_SNAPSHOT_NOT_FOUND",
            f"{what}：快照不存在（{vm}）",
            "先用 vm.snapshot-list 看链上有哪些快照名（★ 名字是**逐字**匹配的，含空格与中文）。",
        )
    return _mk(
        "VM_COMMAND_FAILED",
        f"{what}：本机命令返回了非零退出码（{res.exit_code}）",
        ("看下面的原文；★ 退出码是判定依据，原文只是证据。"
         "★ 这句话**不写死工具名** —— 本地通道上跑的不止 `vmrun`"
         "（T17 的 `host.register` 也在同一条通道上，写死它会变成一句假话）。"),
    )


def call_or_fail(cfg: AppConfig, args: list[str], *, what: str, vmx: str = "",
                 timeout: int | None = None) -> LocalRun:
    res = call(cfg, args, timeout=timeout)
    if res.exit_code != 0:
        raise translate(res, what=what, vmx=vmx)
    return res


# ------------------------------------------------------------------ 解析


_RUNNING_NUM_RE = re.compile(r"^total running vms:\s*(\d+)\s*$", re.I)
_SNAP_NUM_RE = re.compile(r"^total snapshots:\s*(\d+)\s*$", re.I)


def parse_running(text: str) -> list[str]:
    """解析 `vmrun list` 的裸文本。

    实测原文（Windows）：
        Total running VMs: 4
        D:\\VMs\\vm-docker-01\\vm-docker-01.vmx
        …
    """
    out: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip().strip('"')
        if not s or _RUNNING_NUM_RE.match(s) or s.startswith("Error:"):
            continue
        if s.lower().endswith(".vmx"):
            out.append(s)
    return out


def parse_snapshots(text: str) -> list[str]:
    """解析 `vmrun listSnapshots` 的裸文本。

    实测原文：`Total snapshots: 4` ＋ 每行一个快照名（**可能是中文**，如 `k8s集群搭建完成`）。
    ★ 名字里的前后空白是它自己加的，逐字匹配前先 strip。
    """
    out: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or _SNAP_NUM_RE.match(s) or s.startswith("Error:"):
            continue
        out.append(s)
    return out


def read_inventory(cfg: AppConfig) -> list[dict[str, str]]:
    """**只读**读 `inventory.vmls`（红线 13：绝不允许写）。

    格式是 VMware 自己的 ini 味：`vmlist<N>.config = "…\\x.vmx"` ＋ `vmlist<N>.DisplayName`。
    ★ 读不出来（文件不在 / 格式变了）**不是错误** —— 返回空表，由目录扫描兜底。
    """
    path = os.path.expandvars(str(vm_conf(cfg).get("inventory") or ""))
    items: dict[int, dict[str, str]] = {}
    # ★ 编码：VMware 在中文 Windows 上写的清单**不保证是 UTF-8** ——
    #   实测：先按 utf-8 读会得到一堆替换字符，于是同一台 VM 会在盘面上**出现两次**
    #   （一次来自目录扫描的正确名字，一次来自清单的乱码名字）。⇒ 严格试 utf-8，失败再退到
    #   本机 ANSI 代码页（cp936）。★ 这一条也是「问不到 ≠ 不存在」的另一半：
    #   **读到了但读错了**，与"没读到"一样会误导人（规范 §12.122）。
    raw = b""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return []
    text = ""
    for enc in ("utf-8", "utf-8-sig", "cp936", "mbcs"):
        try:
            text = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if not text:
        text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        m = re.match(r'^\s*vmlist(\d+)\.(config|DisplayName)\s*=\s*"?(.*?)"?\s*$', line, re.I)
        if not m:
            continue
        idx, key, val = int(m.group(1)), m.group(2).lower(), m.group(3)
        items.setdefault(idx, {})[key] = val
    out: list[dict[str, str]] = []
    for idx in sorted(items):
        it = items[idx]
        if it.get("config"):
            out.append({"vmx": it["config"], "display_name": it.get("displayname", "")})
    return out


def scan_vmx_files(cfg: AppConfig, *, limit: int = 200) -> list[str]:
    """扫 `vm.allow_vmx_dirs` 下的 `.vmx`（**只读**；不算红线 12 的"操作"）。"""
    out: list[str] = []
    for d in (vm_conf(cfg).get("allow_vmx_dirs") or []):
        try:
            for p in sorted(Path(str(d)).rglob("*.vmx")):
                if p.is_file():
                    out.append(str(p))
                    if len(out) >= limit:
                        return out
        except OSError:
            continue
    return out


# ------------------------------------------------------------------ VM 归属（红线 12）


def registry(cfg: AppConfig) -> dict[str, dict[str, Any]]:
    """**唯一来源**：`hosts.yaml` 里每台受管机的 `vm.vmx` 登记。key = 归一后的 vmx。"""
    out: dict[str, dict[str, Any]] = {}
    for h in cfg.hosts:
        vm = getattr(h, "vm", None)
        if not isinstance(vm, dict):
            continue
        vmx = str(vm.get("vmx") or "").strip()
        if not vmx:
            continue
        out[normalize_path(vmx)] = {
            "vmx": vmx,
            "host_id": h.id,
            "host_name": h.name,
            "provider": str(vm.get("provider") or "vmware-workstation"),
            "managed_by": "hosts.yaml",
        }
    return out


def registered_but_vmless(cfg: AppConfig) -> list[str]:
    """列出"受管但没登记 vmx"的机器（给自检/交付物看，便于一眼发现漏登记）。"""
    return [h.id for h in cfg.hosts if not (isinstance(getattr(h, "vm", None), dict)
                                            and str((h.vm or {}).get("vmx") or "").strip())]


def resolve_vm(cfg: AppConfig, token: str) -> dict[str, Any]:
    """把一个"VM 说法"解析成 `{vmx, name, host_id, managed_by}`。

    接受三种写法（**都走同一份登记表**，不靠名字巧合）：
      ① **受管主机 id**（如 `node-03`）—— 最自然的那种；
      ② vmx 的**全路径或文件名**（如 `vm-docker-01.vmx`）；
      ③ `vm.extra_allow` 里的**当次点名**（同样接受 id / 路径 / 文件名）。
    ★ 解析不到 ⇒ 拒绝（`VM_NOT_MANAGED`），话术里说清"这是保护，不是故障"。
    """
    tok = str(token or "").strip().strip('"')
    if not tok:
        raise OpsError(
            code="PARAM_INVALID",
            reason="没有指定要操作哪台虚拟机",
            advice="填「虚拟机」参数：可以是 hosts.yaml 里的主机 id（如 node-03），也可以是 vmx 文件名。",
        )
    reg = registry(cfg)
    conf = vm_conf(cfg)
    extra = [str(x).strip() for x in (conf.get("extra_allow") or []) if str(x).strip()]

    def _hit(entry: dict[str, Any], how: str) -> dict[str, Any]:
        vmx = str(entry.get("vmx") or "")
        if not in_allowed_dirs(cfg, vmx):
            raise OpsError(
                code="VM_OUTSIDE_ALLOWED_DIRS",
                reason=f"「{tok}」的 vmx 不在允许的目录里：{vmx}",
                advice=(
                    "这是**纵深防御**（规范 §12.116）：只允许操作 vm.allow_vmx_dirs 之内的虚拟机。"
                    "确认这台机确实归本项目管之后，把它的目录加进 config.yaml 的 vm.allow_vmx_dirs。"
                ),
                context={"vmx": vmx, "allow_dirs": conf.get("allow_vmx_dirs")},
            )
        return {
            "vmx": vmx,
            "name": stem_of(vmx),
            "host_id": str(entry.get("host_id") or ""),
            "host_name": str(entry.get("host_name") or ""),
            "managed_by": how,
        }

    # ① 登记表：按 vmx 全路径 / 文件名 / 主机 id 三种方式命中
    for key, entry in reg.items():
        if tok == str(entry.get("host_id")) or normalize_path(tok) == key \
                or normalize_path(basename_of(tok)) == normalize_path(basename_of(str(entry["vmx"]))):
            return _hit(entry, "hosts.yaml")

    # ② 当次点名（config.yaml 的 vm.extra_allow）
    for cand in extra:
        if tok == cand or normalize_path(tok) == normalize_path(cand):
            for key, entry in reg.items():
                if normalize_path(str(entry["vmx"])) == normalize_path(cand) \
                        or normalize_path(basename_of(cand)) == normalize_path(basename_of(str(entry["vmx"]))):
                    return _hit(entry, "extra_allow")
            # 点名了一台没登记的机器：直接按它自己的路径算（仍要过目录白名单）
            vmx = cand
            if not str(cand).lower().endswith(".vmx"):
                # 点名的是"名字"：去白名单目录里找一个同名的
                hit = [p for p in scan_vmx_files(cfg) if stem_of(p).lower() == str(cand).lower()]
                if not hit:
                    continue
                vmx = hit[0]
            return _hit({"vmx": vmx, "host_id": "", "host_name": ""}, "extra_allow")

    raise OpsError(
        code="VM_NOT_MANAGED",
        reason=(
            f"拒绝操作「{tok}」：它**不是本项目登记的虚拟机**，也不在当次点名里"
        ),
        advice=(
            "★ **这是保护，不是故障**（红线 12：D:\\VMs 下 14 台里有 10 台与本项目无关）。\n"
            "两种正当做法：① 它本来就归本项目管 ⇒ 在 hosts.yaml 那台机器下补一段 "
            "`vm: {provider: vmware-workstation, vmx: <全路径>}`；"
            "② 只是这一次要用 ⇒ 把它的名字或 vmx 路径加进 config.yaml 的 `vm.extra_allow`（写进文件即留痕）。"
        ),
        context={
            "token": tok,
            "registered": sorted({str(v["host_id"] or basename_of(str(v["vmx"]))) for v in reg.values()}),
            "extra_allow": extra,
        },
    )


#: ★ T17（规范 §12.130 第 6 条）：新机 id 的合法形状。
#: 它**同时是目录名与文件名**（`<base>\<id>\<id>.vmx`）⇒ 只许保守字符集，
#: 免得"造机"顺手变成"路径穿越"。
NEW_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,38}$")


def new_vm_paths(cfg: AppConfig, new_id: str) -> dict[str, str]:
    """算出**新机的落盘位置** —— 唯一来源是 `vm.allow_vmx_dirs` 的第一项。

    ★ 为什么由平台算、不让动作 YAML 拼字符串：模板引擎**只做变量替换、没有拼接**
      （规范 §12.4），而"VM 放在哪"只该有**一处**定义（§12.116）。
      动作里写 `{{ vm_new_vmx }}` / `{{ vm_new_dir }}`，由这里注入。
    """
    nid = str(new_id or "").strip()
    if not NEW_ID_RE.match(nid):
        raise OpsError(
            code="PARAM_INVALID",
            reason=f"新机 id 不合法：{nid!r}",
            advice=("只许字母数字与 . _ -（首字符必须是字母或数字），长度 2~39 —— "
                    "★ 它同时是新机的**目录名**与**文件名**，所以不能有空格与路径分隔符。"),
        )
    dirs = [str(d).rstrip("\\") for d in (vm_conf(cfg).get("allow_vmx_dirs") or []) if str(d).strip()]
    if not dirs:
        raise OpsError(
            code="VM_OUTSIDE_ALLOWED_DIRS",
            reason="config.yaml 的 vm.allow_vmx_dirs 是空的 ⇒ 不知道该把新机放在哪",
            advice="先在 vm.allow_vmx_dirs 里写一个受控目录（本环境：D:\\VMs）。",
        )
    base = dirs[0]
    d = f"{base}\\{nid}"
    return {"id": nid, "base": base, "dir": d, "vmx": f"{d}\\{nid}.vmx"}


def vm_guard(cfg: AppConfig, action_has_vm_param: bool, params: dict[str, Any]) -> dict[str, str]:
    """**平台侧的 VM 闸门**（规范 §12.116）：给 engine 用。

    返回要注入 argv 渲染上下文的 `extra`（`{{ vm }}` / `{{ vm_name }}` / `{{ vm_vmx }}`）。
    ★ 动作没有 `vm` 参数（如 `vm.list`）⇒ 原样返回空（它不针对某一台）。
    """
    if not action_has_vm_param:
        # ★ T17·S4：**没有 `vm` 参数**的动作（如 `host.register`：它登记的是"这台机器"，
        #   不是"操作哪台 VM"）也**可能**要"新机的落盘位置" ⇒ 这一支不再直接返回空。
        return _inject_new_paths(cfg, params, {})
    pv = params.get("vm")
    token = "" if pv is None else str(getattr(pv, "value", pv))
    info = resolve_vm(cfg, token)
    out: dict[str, str] = {
        "vm": token,
        "vm_name": str(info["name"]),
        "vm_vmx": str(info["vmx"]),
        "vm_host_id": str(info["host_id"]),
        "vm_managed_by": str(info["managed_by"]),
    }
    # ★ T17（规范 §12.130 第 6 条）：克隆类动作 / 登记动作要"新机的落盘位置"。
    return _inject_new_paths(cfg, params, out)


def _inject_new_paths(cfg: AppConfig, params: dict[str, Any],
                      out: dict[str, str]) -> dict[str, str]:
    """把「新机的落盘位置」注入渲染上下文（唯一来源：`vm.allow_vmx_dirs` 的第一项）。

    ★ 只有**声明了 `new_id` 参数**的动作才会拿到它们（白名单在
      `app/catalog.py::ENGINE_EXTRA_NAMES` —— 加名字要有出处，规范 §12.115）。
    ★ 为什么连"没有 `vm` 参数"的动作（如 `host.register`）也要能拿到：
      登记那条动作要写 `vmx:`，而那个路径**不许**由人来敲（唯一来源在平台侧）。
    """
    pn = params.get("new_id")
    if pn is None:
        return out
    nid = str(getattr(pn, "value", pn) or "").strip()
    if not nid:
        return out
    paths = new_vm_paths(cfg, nid)
    out.update({
        "vm_new_id": paths["id"],
        "vm_new_dir": paths["dir"],
        "vm_new_vmx": paths["vmx"],
    })
    return out


# ------------------------------------------------------------------ 盘点与探针


def running_vmx(cfg: AppConfig) -> tuple[list[str], LocalRun]:
    """问 **VMware 自己**：现在哪些 VM 在跑（`vmrun list`）—— 这是电源状态的权威判据。"""
    res = call(cfg, ["list"], timeout=60)
    if res.exit_code != 0:
        raise translate(res, what="读取运行中的虚拟机清单")
    return parse_running(res.stdout), res


def snapshot_names(cfg: AppConfig, vmx: str) -> tuple[list[str], LocalRun]:
    res = call(cfg, ["listSnapshots", vmx], timeout=60)
    if res.exit_code != 0:
        raise translate(res, what="读取快照链", vmx=vmx)
    return parse_snapshots(res.stdout), res


def inventory_rows(cfg: AppConfig) -> dict[str, Any]:
    """全部虚拟机的盘面（**只读**）：跑的 + 白名单目录里能扫到的，合并成一张表。"""
    conf = vm_conf(cfg)
    run_list, res = running_vmx(cfg)
    running = {normalize_path(p): p for p in run_list}
    reg = registry(cfg)
    seen: dict[str, dict[str, Any]] = {}

    def _put(vmx: str) -> None:
        key = normalize_path(vmx)
        if key in seen:
            return
        entry = reg.get(key)
        seen[key] = {
            "vmx": vmx,
            "name": stem_of(vmx),
            "running": key in running,
            "managed": entry is not None,
            "managed_by": (entry or {}).get("managed_by", ""),
            "host_id": (entry or {}).get("host_id", ""),
        }

    for vmx in scan_vmx_files(cfg):
        _put(vmx)
    for vmx in run_list:                      # 在跑但不在白名单目录里的，也要看得见
        _put(vmx)
    for it in read_inventory(cfg):            # inventory 只做补充（它可能过期）
        _put(it["vmx"])

    rows = sorted(seen.values(), key=lambda r: (not r["managed"], not r["running"], r["name"].lower()))
    table = "\n".join(
        "  {mark} {name:<22} {state:<8} {own}".format(
            mark="●" if r["running"] else "○",
            name=r["name"],
            state="在运行" if r["running"] else "已关机",
            own=("本项目管（%s）" % r["host_id"]) if r["managed"] else "只读可见 · 不可操作",
        )
        for r in rows
    )
    return {
        # ★ 交代"查了哪些键/哪份清单"（规范 §12.122：「问不到」≠「不存在」）
        "checked": "vmrun list ＋ 扫 allow_vmx_dirs ＋ 只读 inventory.vmls",
        "vmrun": res.quoted,
        "count": len(rows),
        "running": sum(1 for r in rows if r["running"]),
        "managed": sum(1 for r in rows if r["managed"]),
        "allow_dirs": list(conf.get("allow_vmx_dirs") or []),
        "extra_allow": list(conf.get("extra_allow") or []),
        "table": table or "  （没有扫到任何虚拟机）",
        "vms": rows,
    }


def state_of(cfg: AppConfig, vmx: str) -> dict[str, Any]:
    """一台 VM 的状态（判据问 VMware）。

    ★ vmx **文件不在** ⇒ 这不是"已关机"，而是**读不到**（规范 §12.117 / §12.122）：
      两者都会让"在跑吗"答"否"，但一个是结论、一个是故障，**不许混成一个字**。
    """
    if not Path(str(vmx)).is_file():
        raise OpsError(
            code="VM_NOT_FOUND",
            reason=f"vmx 文件不在：{vmx}",
            advice=(
                "核对 hosts.yaml 里那台机器的 vm.vmx（★ 实测 docker-01 的 vmx 叫 vm-docker-01.vmx，"
                "**与主机 id 不同名** —— 别靠名字猜）。"
            ),
            context={"vmx": vmx},
        )
    run_list, res = running_vmx(cfg)
    key = normalize_path(vmx)
    running = any(normalize_path(p) == key for p in run_list)
    entry = registry(cfg).get(key)
    snaps: list[str] = []
    snap_note = ""
    try:
        snaps, _ = snapshot_names(cfg, vmx)
    except OpsError as exc:
        snap_note = f"（快照链读不到：{exc.code}）"
    return {
        "checked": "vmrun list（VMware 的运行清单） ＋ vmrun listSnapshots",
        "vmrun": res.quoted,
        "vmx": vmx,
        "name": stem_of(vmx),
        "running": running,
        "was_running": "yes" if running else "no",
        "state": "running" if running else "stopped",
        "managed": entry is not None,
        "managed_by": (entry or {}).get("managed_by", ""),
        "host_id": (entry or {}).get("host_id", ""),
        "snapshot_count": len(snaps),
        "snapshots": snaps,
        "snapshot_note": snap_note,
    }


def guest_ip(cfg: AppConfig, vmx: str, *, wait_sec: int = 0, interval: int = 3) -> dict[str, Any]:
    """问 **guest**：它自己的 IP 是多少（`getGuestIPAddress`；`-wait` 会等 guest 起来）。

    ★ 这正是"**起来了**"与"**能 ssh 进去**"两件事里的前者（规范 §12.117）：
      它只证明 VMware Tools 在 guest 里跑起来了并报出了地址，**不证明 ssh 通**。
    """
    deadline = time.monotonic() + max(0, int(wait_sec))
    last = ""
    while True:
        args = ["getGuestIPAddress", vmx] + (["-wait"] if wait_sec > 0 else [])
        res = call(cfg, args, timeout=max(30, int(wait_sec) + 60))
        ip = ""
        for _line in (res.stdout or "").splitlines():
            _s = _line.strip().strip('"')
            if _s and not _s.lower().startswith("error"):
                ip = _s
                break
        if res.exit_code == 0 and ip:
            return {
                "checked": "vmrun getGuestIPAddress" + (" -wait" if wait_sec > 0 else ""),
                "vmx": vmx,
                "name": stem_of(vmx),
                "state": "guest-ready",
                "ip": ip,
                "waited_sec": int(max(0, int(wait_sec) - max(0, deadline - time.monotonic()))),
            }
        last = _rc_text(res).strip()
        if time.monotonic() >= deadline:
            return {
                "checked": "vmrun getGuestIPAddress" + (" -wait" if wait_sec > 0 else ""),
                "vmx": vmx,
                "name": stem_of(vmx),
                "state": "guest-not-ready",
                "ip": "",
                "last_message": last[:400],
            }
        time.sleep(max(1, int(interval)))


def expect(cfg: AppConfig, vmx: str, want: str, *, wait_sec: int = 0, interval: int = 3,
           snapshot: str = "") -> tuple[int, dict[str, Any]]:
    """**把"期望"变成退出码**（规范 §12.115 落点表 / 与 `systemctl is-active` 的 0/3 同源）。

    `want`：
      · `running`     —— VMware 认为它在运行
      · `stopped`     —— VMware 认为它已关机
      · `guest-ready` —— guest 起来了（Tools 报出 IP）
      · `snapshot`    —— 快照链上有这个名字（配合 `snapshot=`）
    返回 `(退出码, 证据字典)`：`0` 成立 · `3` 不成立（含超时）· `2` 读不到。
    """
    deadline = time.monotonic() + max(0, int(wait_sec))
    payload: dict[str, Any] = {}
    while True:
        try:
            if want == "running":
                payload = state_of(cfg, vmx)
                ok = bool(payload.get("running"))
            elif want == "stopped":
                payload = state_of(cfg, vmx)
                ok = not bool(payload.get("running"))
            elif want == "guest-ready":
                payload = guest_ip(cfg, vmx, wait_sec=max(0, int(deadline - time.monotonic())),
                                   interval=interval)
                ok = payload.get("state") == "guest-ready"
            elif want in ("vmx-exists", "vmx-absent", "dir-absent"):
                # ★★ 这三种期望问的是**宿主机文件系统**，不是 VMware ——
                #   对"这个路径在不在"，VMware 根本不表态（规范 §12.117 / §12.122）。
                p = Path(str(vmx).replace("/", "\\"))
                exists = p.is_file()
                payload = {
                    "checked": "宿主机文件系统（Path.is_file / Path.is_dir）",
                    "vmx": vmx,
                    "name": stem_of(vmx),
                    "vmx_exists": exists,
                    "dir_exists": p.parent.is_dir(),
                    "size_bytes": (p.stat().st_size if exists else 0),
                }
                if want == "vmx-exists":
                    ok = exists
                elif want == "vmx-absent":
                    ok = not exists
                else:
                    ok = not p.parent.is_dir()
            elif want in ("vmx-exists", "vmx-absent", "dir-absent"):
                # ★★ 这三种期望问的是**宿主机文件系统**，不是 VMware ——
                #   对"这个路径在不在"，VMware 根本不表态（规范 §12.117 / §12.122）。
                p = Path(str(vmx).replace("/", "\\"))
                exists = p.is_file()
                payload = {
                    "checked": "宿主机文件系统（Path.is_file / Path.is_dir）",
                    "vmx": vmx,
                    "name": stem_of(vmx),
                    "vmx_exists": exists,
                    "dir_exists": p.parent.is_dir(),
                    "size_bytes": (p.stat().st_size if exists else 0),
                }
                if want == "vmx-exists":
                    ok = exists
                elif want == "vmx-absent":
                    ok = not exists
                else:
                    ok = not p.parent.is_dir()
            elif want == "snapshot":
                names, res = snapshot_names(cfg, vmx)
                payload = {
                    "checked": "vmrun listSnapshots",
                    "vmx": vmx,
                    "name": stem_of(vmx),
                    "snapshot": snapshot,
                    "snapshots": names,
                    "snapshot_count": len(names),
                    "vmrun": res.quoted,
                }
                ok = snapshot in names
            else:
                return 2, {"error": f"不认识的期望：{want}"}
        except OpsError as exc:
            payload = {"checked": "vmrun", "vmx": vmx, "error": exc.code,
                       "reason": exc.reason, "advice": exc.advice}
            ok = False

        payload["want"] = want
        payload["waited_sec"] = int(max(0, int(wait_sec) - max(0, deadline - time.monotonic())))
        if ok:
            payload["verdict"] = "ok"
            return 0, payload
        if time.monotonic() >= deadline:
            payload["verdict"] = "not-yet" if wait_sec else "no"
            return (2 if payload.get("error") else 3), payload
        if wait_sec <= 0:
            payload["verdict"] = "no"
            return 3, payload
        time.sleep(max(1, int(interval)))


def vmx_identity(cfg: AppConfig, vmx: str) -> dict[str, Any]:
    """**只读**读出 `.vmx` 里的"第 5 项身份"（红线 13：读得到，但**一个字都不改**）。

    为什么必须有它（规范 §12.133）：VMware 的 UUID / MAC 是**明文写在这个文件里**的，
    而"克隆到底换没换它们"是 T17 最大的未知数 —— 判据只能来自**读**（`vmrun` 没有换 UUID 的选项）。
    ★ 指纹 = `sha256(uuid.bios + ethernet0.generatedAddress)`：一句话就能比较两台机是不是"同一个人"。
    """
    p = Path(str(vmx).replace("/", "\\"))
    if not p.is_file():
        raise OpsError(
            code="VM_NOT_FOUND",
            reason=f"vmx 文件不在：{vmx}",
            advice=("核对 hosts.yaml 里那台机器的 vm.vmx"
                    "（★ docker-01 的 vmx 叫 vm-docker-01.vmx，与主机 id 不同名）。"),
            context={"vmx": vmx},
        )
    raw = p.read_bytes()
    text = ""
    for enc in ("utf-8", "utf-8-sig", "cp936", "mbcs"):
        try:
            text = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if not text:
        text = raw.decode("utf-8", errors="replace")
    vals: dict[str, str] = {}
    _keys = ("displayName", "guestOS", "uuid.bios", "uuid.location", "memsize",
             "numvcpus", "ethernet0.generatedAddress", "ethernet0.address",
             "ethernet0.addressType", "ethernet0.present", "virtualHW.version")
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k in _keys:
            vals[k] = v.strip().strip('"')
    uuid_bios = vals.get("uuid.bios", "")
    mac = vals.get("ethernet0.generatedAddress", "") or vals.get("ethernet0.address", "")
    fp = hashlib.sha256(f"{uuid_bios}|{mac}".encode("utf-8")).hexdigest()
    st = p.stat()
    return {
        "checked": "只读解析 .vmx（红线 13：读得到、改不动）；★ 不读磁盘、不读快照内容",
        "vmx": str(p),
        "name": stem_of(str(p)),
        "display_name": vals.get("displayName", ""),
        "guest_os": vals.get("guestOS", ""),
        "uuid_bios": uuid_bios,
        "uuid_location": vals.get("uuid.location", ""),
        "mac": mac,
        "memsize_mb": vals.get("memsize", ""),
        "numvcpus": vals.get("numvcpus", ""),
        "uuid_equals_location": uuid_bios == vals.get("uuid.location", ""),
        "identity_fingerprint": fp,
        "size_bytes": st.st_size,
        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
    }


def mkdir_path(path: str) -> tuple[int, dict[str, Any]]:
    """建一个**空目录**（新机的落盘位置）。★ 幂等：已存在 = 已达终态（不报错）。"""
    p = Path(str(path).replace("/", "\\"))
    existed = p.is_dir()
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return 2, {"checked": f"建目录 {p}", "error": "MKDIR_FAILED",
                   "reason": str(exc)[:300], "dir": str(p), "existed": existed}
    return 0, {"checked": f"建目录 {p}", "dir": str(p), "existed": existed,
               "created": not existed, "is_dir": p.is_dir()}


def disk_check(path: str, *, min_free_mb: int = 2048) -> tuple[int, dict[str, Any]]:
    """宿主机侧磁盘余量（**只读**）：够不够放一台新机（规范 §12.130 第 5 条）。"""
    p = Path(str(path).replace("/", "\\"))
    at = p if p.exists() else Path(p.anchor or "C:\\")
    try:
        u = shutil.disk_usage(str(at))
    except OSError as exc:
        return 2, {"checked": f"宿主机磁盘余量（{at}）", "error": "DISK_UNREADABLE",
                   "reason": str(exc)[:300]}
    free_mb = int(u.free // (1024 * 1024))
    ok = free_mb >= int(min_free_mb)
    return (0 if ok else 3), {
        "checked": f"宿主机磁盘余量（{at}）",
        "path": str(at),
        "free_mb": free_mb,
        "free_gb": round(free_mb / 1024, 1),
        "total_gb": round(u.total / (1024 ** 3), 1),
        "min_free_mb": int(min_free_mb),
        "verdict": "ok" if ok else "no",
        "note": "★ 精简置备：这只保证「不会写到一半没地方」，不是「够不够用」的精确预算。",
    }


def probe(cfg: AppConfig, mode: str, *, vmx: str = "", want: str = "", snapshot: str = "",
          path: str = "", min_free_mb: int = 2048,
          wait_sec: int = 0, interval: int = 3) -> tuple[int, dict[str, Any]]:
    """探针总入口（`tools\\vmprobe.py` 就是它的命令行壳）。"""
    if mode == "list":
        return 0, inventory_rows(cfg)
    if mode == "state":
        if not vmx:
            return 2, {"error": "state 模式需要 --vmx"}
        try:
            return 0, state_of(cfg, vmx)
        except OpsError as exc:
            return 2, {"checked": "vmrun list", "vmx": vmx, "error": exc.code,
                       "reason": exc.reason, "advice": exc.advice}
    if mode == "snapshots":
        if not vmx:
            return 2, {"error": "snapshots 模式需要 --vmx"}
        try:
            names, res = snapshot_names(cfg, vmx)
        except OpsError as exc:
            return 2, {"checked": "vmrun listSnapshots", "vmx": vmx, "error": exc.code,
                       "reason": exc.reason, "advice": exc.advice}
        return 0, {
            "checked": "vmrun listSnapshots", "vmx": vmx, "name": stem_of(vmx),
            "count": len(names), "snapshots": names, "vmrun": res.quoted,
            "table": "\n".join(f"  {i + 1}. {n}" for i, n in enumerate(names))
                     or "  （这台虚拟机还没有任何快照）",
        }
    if mode == "expect":
        return expect(cfg, vmx, want, wait_sec=wait_sec, interval=interval, snapshot=snapshot)
    if mode == "vmx":
        if not vmx:
            return 2, {"error": "vmx 模式需要 --vmx"}
        try:
            return 0, vmx_identity(cfg, vmx)
        except OpsError as exc:
            return 2, {"checked": "只读解析 .vmx", "vmx": vmx, "error": exc.code,
                       "reason": exc.reason, "advice": exc.advice}
    if mode == "mkdir":
        return mkdir_path(path)
    if mode == "disk":
        return disk_check(path, min_free_mb=min_free_mb)
    if mode == "mkdir":
        return mkdir_path(path)
    if mode == "disk":
        return disk_check(path, min_free_mb=min_free_mb)
    return 2, {"error": f"不认识的模式：{mode}"}


def dump(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
