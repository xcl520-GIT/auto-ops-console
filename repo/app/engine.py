"""执行引擎：预检 → 计划 → 执行 → 自证 → 留证。

动作与配方**共用同一个引擎**（总纲锁定），所以这里的流程刻意做成与"动作"这一概念解耦：
它只认「一批步骤 + 一批断言 + 一段结论模板」。

关键行为约定：

· 计划先行
  命令在**执行前**就全部渲染完成（命令预览）。执行阶段不再临时拼命令。

· 遇阻塞失败即中止
  某一步返回非零（且该步骤未标 optional）→ 动作中止，剩余步骤记为 skipped。
  理由：继续跑下去只会产出一条"看起来成功"的假结论。只读动作中止无副作用。

· optional 步骤
  失败不中止、不影响任务成败，但**照样留证**（这是 svc.list 里"失败服务明细"的关键：
  某些失败服务可能连日志都没有）。

· 自证（verify）不是装饰
  断言不成立 → verify_result=failed → 任务状态为 failed，即使所有命令都返回 0。
  这就是"执行完不能假定成功"。

· 每一步都留证
  命令原文（argv + 实际交给 ssh 的转义后字符串）、起止时间、退出码、stdout/stderr
  全部落库并归档原文（含 sha256）。
"""
from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import re
import shlex
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.backup import BackupRecord, BackupRunner
from app.catalog import (
    Action,
    ParamValue,
    render_argv,
    render_argv_element,
    render_text,
    validate_params,
)
from app.changed import changed_for_action
from app.config import AppConfig, Host
from app.errors import OpsError, classify_remote_failure
from app.parsers import apply_pick, parse_text
from app.store import Store, new_batch_id, new_task_id, now_iso
from app.transport import ExecResult, SshTransport, classify_ssh_failure
# ★★ T16（规范 §12.115）：第二条执行面 —— 本机（宿主机上的 Windows 进程）。
#    ★ 通道由**动作**声明（`channel: local`），不是由主机声明 ——
#      因为配方是"一个 host 到底"（`recipe.py`：`engine.run(aid, host.id, …)`），
#      而编排链必须同时跨"本机 vmrun"与"ssh 进 guest"两段、目标机还是同一台。
from app.transport_local import LocalTransport
from app import vmware

# 恢复备份的确认词（🔴 级操作：必须手输，点一下不算）
RESTORE_CONFIRM_TEXT = "确认恢复"

#: ★★ T8·S6（规范 §12.35）：**内联写盘**的命令行长度上限。
#: 为什么需要它 —— 真跑抓到的**真缺陷**：`write_remote_file` 把文件内容 base64 后
#: **内联进命令行**（`sh -c "printf %s <blob> | base64 -d > …"`）。而管理机是 Windows，
#: `CreateProcess` 的命令行上限约 **32K 字符** ⇒ 一份 238KB 的 Calico 官方清单会以
#: `FileNotFoundError: [WinError 206] 文件名或扩展名太长` 炸在**控制台自己**的进程里。
#: ★ 取 **16384**：留一倍余量给 `mkdir -p` / `chmod` 那些字与转义。
#: ★ 超过它就走 `transport.scp_put`（二进制安全的独立通道，与备份回拉同一条路）。
MAX_INLINE_CMD = 16384


@dataclass
class StepOut:
    seq: int
    name: str
    title: str
    iter_key: str | None
    argv: list[str]
    argv_quoted: str
    status: str                      # ok / failed / timeout / skipped / rejected
    optional: bool
    exit_code: int | None = None
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    parsed: Any = None
    truncated: bool = False
    error: OpsError | None = None
    # ── T5（规范 §12.3）：**这一步到底改了没有** ─────────────────────
    #   True = 变了 / False = 没变（幂等的正面证据）/ None = **无法判定**
    #   ★ 引擎只在"写盘类步骤"（write_file）直接填它；其余动作的变更判定在任务级汇总
    #     （app/changed.py 的规则表）。三态必须保住 —— 不许把"判不出来"降级成"没变"。
    changed: bool | None = None
    started_at: str = ""
    ended_at: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "name": self.name, "title": self.title,
            "iter_key": self.iter_key, "argv": self.argv, "argv_quoted": self.argv_quoted,
            "status": self.status, "optional": self.optional, "exit_code": self.exit_code,
            "duration_ms": self.duration_ms, "stdout": self.stdout, "stderr": self.stderr,
            "parsed": self.parsed, "truncated": self.truncated, "changed": self.changed,
            "error_code": self.error.code if self.error else None,
            "error_reason": self.error.reason if self.error else None,
            "error_advice": self.error.advice if self.error else None,
            "started_at": self.started_at, "ended_at": self.ended_at,
        }

    def to_public(self, *, raw: bool = True) -> dict[str, Any]:
        d = {
            "seq": self.seq, "name": self.name, "title": self.title,
            "iter": self.iter_key, "status": self.status, "optional": self.optional,
            "exit_code": self.exit_code, "duration_ms": self.duration_ms,
            "argv": self.argv, "command": self.argv_quoted,
            "parsed": self.parsed, "truncated": self.truncated, "changed": self.changed,
            "error": self.error.to_dict() if self.error else None,
            "started_at": self.started_at, "ended_at": self.ended_at,
        }
        if raw:
            d["stdout"] = self.stdout
            d["stderr"] = self.stderr
        return d


@dataclass
class TaskResult:
    id: str
    action: Action
    host: Host
    status: str
    steps: list[StepOut] = field(default_factory=list)
    conclusion: str = ""
    verify_result: str = "none"
    verify_detail: list[dict[str, Any]] = field(default_factory=list)
    backups: list[BackupRecord] = field(default_factory=list)
    command_preview: str = ""
    params_display: dict[str, Any] = field(default_factory=dict)
    params_machine: dict[str, Any] = field(default_factory=dict)
    batch_id: str | None = None
    error: OpsError | None = None
    # ── T5（规范 §12.3）：**本次动作到底改了没有** ────────────────────
    #   True / False / None(unknown)。由 app/changed.py 的规则表推导；
    #   ★ 未登记规则的变更类动作一律 None —— 不许默认 False（宪法 2）。
    changed: bool | None = None
    started_at: str = ""
    ended_at: str = ""
    duration_ms: int = 0
    t0: float = 0.0

    def to_public(self, *, raw: bool = True) -> dict[str, Any]:
        return {
            "ok": self.status == "ok",
            "task": {
                "id": self.id,
                "action_id": self.action.id,
                "action_title": self.action.title,
                "risk": self.action.risk,
                "host_id": self.host.id,
                "host_name": self.host.name,
                "host_address": self.host.address,
                "host_user": self.host.user,
                "status": self.status,
                "conclusion": self.conclusion,
                "command_preview": self.command_preview,
                "verify_result": self.verify_result,
                "verify_detail": self.verify_detail,
                "changed": self.changed,
                "step_total": len(self.steps),
                "step_failed": len([s for s in self.steps if s.status in ("failed", "timeout", "rejected")]),
                "exit_code": next((s.exit_code for s in self.steps if s.status == "failed"), 0),
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "duration_ms": self.duration_ms,
                "error": self.error.to_dict() if self.error else None,
            },
            "steps": [s.to_public(raw=raw) for s in self.steps],
            "backups": [b.to_public() for b in self.backups],
        }


def conclusion_with_failure_banner(result: Any) -> str:
    """失败 / 中止时，给结论加一顶"**否定横幅**"（规范 §9.13）。

    ★ 为什么这必须是**平台行为**，而不是"每个动作自己注意"：
      结论是**静态模板**，动作层没有分支 —— 所以**失败时它必然在说谎**。
      T6·S2 实况：把 MariaDB 配置写坏后跑 `svc.configtest`，任务确实 `failed`
      （rc=7，stderr 里 `NOT_A_NUMBER` / `unknown variable` 写得明明白白），
      而结论里仍印着「✅ 语法通过（退出码 0）」。这与 T5 教训 #7
      （"失败提示不许空口承诺"）同族 —— **报告不许骗人**。

    ★ 处置：**不删信息，只加帽子**。原文照旧保留（有些动作失败时，结论里仍有部分有用信息）。
    ★ 抽成模块级纯函数，是为了让自检**离线**就能断言它（不用连目标机）。
    """
    text = str(getattr(result, "conclusion", "") or "")
    status = str(getattr(result, "status", "") or "")
    if status in ("", "ok") or not text:
        return text
    err = getattr(result, "error", None)
    code = getattr(err, "code", "") or "FAILED"
    reason = getattr(err, "reason", "") or ""
    return (
        f"❌ 本次执行**未通过**（{code}：{reason}）\n"
        f"   ⚠️ 下面这段结论文本是按「成功」写的，**本次不成立** ——\n"
        f"      请以「错误详情 + 各步骤原始输出」为准。\n"
        f"{'-' * 46}\n"
        f"{text}"
    )


class Engine:
    def __init__(self, cfg: AppConfig, actions: dict[str, Action], store: Store | None = None) -> None:
        self.cfg = cfg
        self.actions = actions
        self.store = store or Store(cfg)
        self.transport = SshTransport(cfg)
        # ★★ T16（规范 §12.115）：第二条执行面 = 宿主机上的本机进程（`vmrun.exe`）。
        #    它与 ssh 通道**方法面一致**，所以 15 处调用点一行都不用改 ——
        #    变的只是"这一步该走哪条通道"这一个决定（见下面的 transport_for）。
        self.local_transport = LocalTransport(cfg)
        # T3：改动前自动备份的护栏（护栏地基，规范 §9.1）——
        #     变更动作执行**前**由它完成备份；备份失败则中止，不执行任何变更。
        self.backup_runner = BackupRunner(cfg, self.transport)

    # ------------------------------------------------------------------ 执行面

    def transport_for(self, action: Action, host: Host):  # type: ignore[no-untyped-def]
        """★ 通道由**动作**声明（规范 §12.115 规矩 1）。

        判据只有一句：**这条命令在哪台机器上跑**。
        """
        if getattr(action, "channel", "ssh") == "local":
            return self.local_transport
        return self.transport

    def exec_host_for(self, action: Action, host: Host) -> Host:
        """★ 执行面（规范 §12.115 规矩 2）。

        `channel: local` 的动作**一律落在宿主机上** —— 宿主机由 `app\\vmware.py`
        **合成**（不进 `hosts.yaml`），因为它是**执行面**，不是一台目标机：
        塞进去它就会出现在目标机下拉 / 批量 / 体检 / AI 工具面里。
        ★ 而任务/留证里记的就是这个执行面 host —— **真话**（这一步确实在本机跑的）。
        """
        if getattr(action, "channel", "ssh") == "local":
            return vmware.vm_host(self.cfg)
        return host

    # ------------------------------------------------------------------ 公共入口

    def action(self, action_id: str) -> Action:
        a = self.actions.get(action_id)
        if a is None:
            raise OpsError(
                code="ACTION_NOT_FOUND",
                reason=f"没有这个动作：{action_id}",
                advice="刷新页面重新加载动作列表。",
                context={"available": sorted(self.actions)},
            )
        return a

    def preview(self, action_id: str, host_id: str, raw_params: dict[str, Any] | None) -> dict[str, Any]:
        """命令预览：执行前就把要跑的命令摆出来，顺便把参数规范化结果显示给用户。"""
        action = self.action(action_id)
        host = self.cfg.host(host_id)
        params = validate_params(action, raw_params)
        # ★ T16（规范 §12.116）：预览也过**同一道** VM 闸门、走**同一条**通道 ——
        #   否则会变成"预览能过、执行被拒"（或反过来），那就是第二套判据。
        extra = vmware.vm_guard(self.cfg, action.param("vm") is not None, params)
        exec_host = self.exec_host_for(action, host)
        transport = self.transport_for(action, exec_host)
        if getattr(action, "channel", "ssh") == "local":
            extra.update(vmware.probe_extra(self.cfg))
        ctx = self._base_ctx(exec_host, params)
        for _k, _v in extra.items():
            ctx.setdefault(_k, _v)

        commands: list[dict[str, Any]] = []
        for s in action.steps:
            if s.foreach:
                commands.append({
                    "name": s.name, "title": s.title,
                    "argv": None, "command": None,
                    "note": f"循环步骤：按 {s.foreach} 的每一项展开（执行时才知道具体命令）",
                })
                continue
            argv = render_argv(s, params, extra)
            commands.append({
                "name": s.name, "title": s.title,
                "argv": argv,
                "command": transport.build_remote_cmd(argv),
                "note": s.note or "",
            })

        return {
            "action": action.to_public(),
            "host": host.to_public(),
            # ★ T16（规范 §12.115 规矩 2）：**意图面**（上面那个 host）与**执行面**都摆出来 ——
            #   本机通道的动作，真正跑在宿主机上；两处都真，界面上不合并。
            "exec_host": exec_host.to_public(),
            "extra": dict(extra),
            "params": {p.name: params[p.name].display for p in action.params},
            "params_raw": {p.name: params[p.name].value for p in action.params},
            "commands": commands,
            "needs_confirm": action.risk != "green",
            "confirm": {
                "title": (action.confirm or {}).get("title", "确认执行"),
                "body": render_text(str((action.confirm or {}).get("body", "")), ctx),
                "confirm_text": (action.confirm or {}).get("confirm_text", "我已确认"),
            } if action.risk != "green" else None,
            "verify": [
                {"name": v.name, "from": v.from_, "field": v.field, "severity": v.severity}
                for v in action.verify
            ],
        }

    def run(
        self,
        action_id: str,
        host_id: str,
        raw_params: dict[str, Any] | None,
        *,
        confirm: bool = False,
        confirm_text: str = "",
        batch_id: str | None = None,
    ) -> TaskResult:
        action = self.action(action_id)
        host = self.cfg.host(host_id)
        params = validate_params(action, raw_params)

        # ★ red 级 = 必须**手输确认词**，而且由**服务端**校验（不是前端点一下就算）。
        #   T3 验收 #3 的反面证据就在这里：输错、不输、只勾选，都必须被拦下。
        if action.risk == "red":
            expected = str((action.confirm or {}).get("confirm_text") or "").strip()
            if not expected:
                raise OpsError(
                    code="CONFIG_INVALID",
                    reason=f"动作「{action.title}」是 red 级但 confirm 段没有 confirm_text",
                    advice="在动作 YAML 里补上 confirm.confirm_text（要求用户手输的那句话）。",
                )
            if confirm_text.strip() != expected:
                raise OpsError(
                    code="CONFIRM_REQUIRED",
                    reason="red 级动作需要手输确认词，且必须与确认文案完全一致",
                    advice=f"请手工输入：「{expected}」",
                    context={"expect": expected},
                )

        # ★ 批量执行的硬规矩（规范 §9.3）：red 动作**禁止批量**。
        #   不提供配置开关 —— 理由：批量会把一次手误放大到 N 台，
        #   而 red 恰好是不可 undo 的那一类。
        if batch_id and action.risk == "red":
            raise OpsError(
                code="BATCH_FORBIDDEN",
                reason=f"动作「{action.title}」是 red 级，禁止批量执行",
                advice="red 动作必须逐台执行并手输确认词：一次只选一台机器。",
            )

        if action.risk != "green" and not confirm:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason=f"动作「{action.title}」的风险等级是 {action.risk}，需要二次确认",
                advice="在界面上阅读确认文案并勾选确认后再执行。",
                context={"risk": action.risk},
            )

        # ★★ T16（规范 §12.116）：**VM 闸门** —— 红线 12 的执行面。
        #   在**动手之前**判定"这台 VM 归不归本项目管"：既不在 hosts.yaml 的登记里、
        #   也不在 config.yaml 的 vm.extra_allow（当次点名）里 ⇒ **拒绝**。
        #   ★ 闸门放在**平台侧**（不是探针脚本里）：脚本只干活，**纪律不外包**。
        #   ★ 同时把解析出来的 vmx 注入 argv 渲染上下文（{{ vm }} / {{ vm_vmx }} …）——
        #     于是动作 YAML 里**不重复写一份 VM 清单**（唯一来源 = hosts.yaml 的登记）。
        extra = vmware.vm_guard(self.cfg, action.param("vm") is not None, params)
        exec_host = self.exec_host_for(action, host)
        transport = self.transport_for(action, exec_host)
        # ★ 本通道的"工具坐标"（vmrun 在哪、探针脚本在哪）也由平台注入 ——
        #   动作 YAML 里不写死绝对路径（换了机器只改 config.yaml 的 vm: 段）。
        if getattr(action, "channel", "ssh") == "local":
            extra.update(vmware.probe_extra(self.cfg))

        # ★ 本机通道没有"文件级备份"语义：backup_runner 做的是 df/stat/cp/scp（全都基于 ssh 上的
        #   目标机文件系统）。M 域的护栏是**整机快照**（规范 §12.118）⇒ 这里**明确拒绝**，
        #   而不是让它悄悄去 ssh 一台 Windows 宿主机（那会得到一堆看不懂的报错）。
        if action.backup and getattr(action, "channel", "ssh") == "local":
            raise OpsError(
                code="CONFIG_INVALID",
                reason=f"动作「{action.title}」声明了本机执行通道（channel: local），却又声明了 backup 段",
                advice=(
                    "文件级备份护栏是 ssh 侧的能力（df/stat/cp/scp 都作用在目标机的文件系统上）。"
                    "本机通道的护栏请用**整机快照**：vm.snapshot-create（规范 §12.118）。"
                ),
            )

        task_id = new_task_id(self.cfg)
        started = now_iso(self.cfg)
        ctx = self._base_ctx(exec_host, params)
        # ★ 本机通道：把那台 VM 的名字/路径也放进 ctx —— 结论（人话）里要能写出"是哪一台"。
        for _k, _v in extra.items():
            ctx.setdefault(_k, _v)
        result = TaskResult(id=task_id, action=action, host=exec_host, status="ok", started_at=started)
        result.batch_id = batch_id
        result.params_display = {p.name: params[p.name].display for p in action.params}
        result.params_machine = {p.name: params[p.name].value for p in action.params}
        result.t0 = time.monotonic()

        # ---------- 计划：执行前确定全部命令（留证 + 预览一致） ----------
        plan_lines: list[str] = []
        for s in action.steps:
            if s.foreach:
                plan_lines.append(f"[{s.name}] (循环 {s.foreach}) {s.title}")
            else:
                plan_lines.append(f"[{s.name}] {transport.build_remote_cmd(render_argv(s, params, extra))}")
        result.command_preview = "\n".join(plan_lines)

        # ---------- 预检 ----------
        for s in action.precheck:
            out = self._exec_one(s, exec_host, params, extra, seq=0)
            result.steps.append(out)
            ctx[s.name] = out.parsed
            if out.status != "ok" and not s.optional:
                result.status = "aborted"
                result.error = OpsError(
                    code="PRECHECK_FAILED",
                    reason=out.error.reason if out.error else f"预检未通过：{out.title}",
                    advice=out.error.advice if out.error else "按预检输出处理后再执行本动作。",
                )
                return self._finish(result)

        # ---------- 目标机连通性预检（让"机器连不上"给出干净的原因+建议） ----------
        ok, err, conn = transport.check_connectivity(exec_host)
        if not ok:
            if conn is not None:
                result.steps.append(
                    StepOut(
                        seq=0, name="_connect",
                        # ★ T16：名字要说清是**哪条**通道在自检 —— 否则"SSH 连通性自检"出现在
                        #   一个根本不过 ssh 的动作里，读起来就是假话（规范 §12.42 同源）。
                        title=("本机执行面自检（vmrun）" if getattr(action, "channel", "ssh") == "local"
                               else "SSH 连通性自检"),
                        iter_key=None, argv=["true"],
                        argv_quoted=conn.quoted, status="failed",
                        optional=False, exit_code=conn.exit_code,
                        duration_ms=conn.duration_ms, stdout=conn.stdout, stderr=conn.stderr,
                        error=err, started_at=started, ended_at=now_iso(self.cfg),
                    )
                )
            result.status = "aborted"
            result.error = err
            return self._finish(result)

        # ---------- 改动前自动备份（T3 · 规范 §9.1）----------
        # ★ 顺序不可调换：备份必须在**任何变更步骤之前**完成，且失败即中止。
        #   变更动作的底线是"能撤回"；备份没成功就动手，等于把它变成一句口号。
        if action.backup:
            try:
                records, bak_err = self.backup_runner.run(result.id, action, params, host)
            except OpsError as exc:
                records, bak_err = [], exc
            except Exception as exc:  # noqa: BLE001
                # ★ 备份阶段的**任何**未预期异常都必须降级成"备份失败"：
                #   宁可中止动作，也不能在"备份状态未知"的情况下继续做变更。
                records = []
                bak_err = OpsError(
                    code="BACKUP_FAILED",
                    reason=f"备份阶段出现未预期错误：{type(exc).__name__}: {exc}",
                    advice="这是控制台自身的缺陷，请记录详情；**本动作未执行任何变更**。",
                )
            result.backups = records
            if bak_err is not None:
                result.status = "aborted"
                result.error = OpsError(
                    code=bak_err.code,
                    reason=f"改动前备份未完成，已中止本动作：{bak_err.reason}",
                    advice=(bak_err.advice or "") + "（本动作未执行任何变更）",
                    detail=bak_err.detail,
                )
                return self._finish(result)

        # ---------- 执行 ----------
        seq = 0
        aborted = False
        for s in action.steps:
            if aborted:
                result.steps.append(self._skipped(s, seq, None, "前序步骤失败，未执行"))
                seq += 1
                continue

            if s.foreach:
                items = self._foreach_items(s, ctx)
                if not items:
                    result.steps.append(
                        StepOut(
                            seq=seq, name=s.name, title=s.title, iter_key=None,
                            argv=[], argv_quoted="", status="ok", optional=s.optional,
                            parsed=[], started_at=now_iso(self.cfg), ended_at=now_iso(self.cfg),
                        )
                    )
                    ctx[s.name] = []
                    seq += 1
                    continue

                collected: list[dict[str, Any]] = []
                for item in items:
                    if not self._item_ok(item, s):
                        collected.append({"iter": item, "rejected": "循环项未通过白名单校验，已跳过"})
                        continue
                    out = self._exec_one(s, exec_host, params, {**extra, (s.as_ or "item"): item}, seq=seq)
                    result.steps.append(out)
                    seq += 1
                    if out.parsed is not None:
                        collected.append({"iter": item, "value": out.parsed,
                                          "raw": out.parsed if isinstance(out.parsed, dict) else None})
                    if out.status != "ok" and not s.optional:
                        aborted = True
                        break
                ctx[s.name] = collected
                continue

            out = self._exec_one(s, exec_host, params, extra, seq=seq)
            result.steps.append(out)
            # ★ 把解析结果写回 ctx —— 结论模板与 verify 都靠它取值。
            #   （T1 期间这里漏过一次，导致"命令全部 exit 0、结论全是（无）"；
            #     正是 verify 断言把它拦下来的 —— 这就是自证存在的理由。）
            ctx[s.name] = out.parsed
            seq += 1

            if out.status != "ok":
                if not s.optional:
                    aborted = True
                    result.status = "failed"
                    result.error = out.error or OpsError(
                        code="STEP_FAILED",
                        reason=f"步骤「{s.title}」执行失败（退出码 {out.exit_code}）",
                        advice="查看该步骤的原始输出。",
                    )
                # optional 失败：不影响任务成败，但已在步骤里留证

        # ---------- 自证 ----------
        result.verify_result, result.verify_detail = self._verify(action, ctx)
        if result.verify_result == "failed" and result.status == "ok":
            result.status = "failed"
            first = next((d for d in result.verify_detail if not d["ok"] and d["severity"] == "fail"), None)
            result.error = OpsError(
                code="VERIFY_FAILED",
                reason=f"自证未通过：{first['name'] if first else '断言不成立'}",
                advice=(
                    "命令都返回了成功，但结果不符合预期 —— **这次结果不可信**。"
                    "请查看原始输出，并把这个情况记录为缺陷。"
                ),
                detail=str(first.get("detail", "")) if first else "",
            )

        # ---------- 结论 ----------
        result.conclusion = render_text(action.conclusion, ctx).strip() if action.conclusion else ""
        # ---------- 变更判定（T5 · 规范 §12.3）----------
        #   ★ "成功了"与"变了没有"是两件事：前者靠 verify，后者靠这里。
        #     规则表在 app/changed.py（按动作 id 登记），**配方侧一个字都不用写**。
        #     三态：True 变了 / False 没变（幂等的正面证据）/ None 无法判定（未登记规则）。
        result.changed = changed_for_action(action, result)
        return self._finish(result)

    # ------------------------------------------------------------------ 内部

    def _finish(self, result: TaskResult) -> TaskResult:
        result.ended_at = now_iso(self.cfg)
        if result.t0:
            result.duration_ms = int((time.monotonic() - result.t0) * 1000)
        # ★ v1.7（T6·S2 真跑抓到 · 规范 §9.13）：失败的执行**不许念"按成功写好的结论"**。
        result.conclusion = conclusion_with_failure_banner(result)
        try:
            self._persist(result)
        except OpsError as exc:
            if result.error is None:
                result.error = exc
                if result.status == "ok":
                    result.status = "failed"
        return result

    def _persist(self, result: TaskResult) -> None:
        arts: list[dict[str, Any]] = []
        for s in result.steps:
            label = f"{s.seq:02d}-{s.name}" + (f"-{s.iter_key}" if s.iter_key else "")
            for kind, content in (("stdout", s.stdout), ("stderr", s.stderr)):
                row = self.store.archive(result.id, kind, label, content)
                if row:
                    row["label"] = label
                    arts.append(row)
        for kind, label, content in (
            ("plan", "plan", result.command_preview),
            ("conclusion", "conclusion", result.conclusion),
        ):
            row = self.store.archive(result.id, kind, label, content)
            if row:
                row["label"] = label
                arts.append(row)

        task_row = {
            "id": result.id,
            "action_id": result.action.id,
            "action_title": result.action.title,
            "risk": result.action.risk,
            "host_id": result.host.id,
            "host_name": result.host.name,
            "host_address": result.host.address,
            "host_user": result.host.user,
            "status": result.status,
            "params": result.params_display,
            "command_preview": result.command_preview,
            "conclusion": result.conclusion,
            "error_code": result.error.code if result.error else None,
            "error_reason": result.error.reason if result.error else None,
            "error_advice": result.error.advice if result.error else None,
            "verify_result": result.verify_result,
            "verify_detail": result.verify_detail,
            "changed": result.changed,
            "step_total": len(result.steps),
            "step_failed": len([s for s in result.steps if s.status in ("failed", "timeout", "rejected")]),
            "exit_code": next((s.exit_code for s in result.steps if s.status == "failed"), 0),
            "started_at": result.started_at,
            "ended_at": result.ended_at,
            "duration_ms": result.duration_ms,
            "batch_id": result.batch_id,
        }
        self.store.save_task(task_row, [s.to_row() for s in result.steps])
        # T3：备份记录落库（在哪备份的、指纹多少、恢复状态）—— 界面据此提供「恢复」
        if result.backups:
            self.store.save_backups(
                [
                    {
                        **b.to_row(),
                        "host_id": result.host.id,
                        "host_name": result.host.name,
                        "action_id": result.action.id,
                    }
                    for b in result.backups
                ]
            )
        self.store.save_artifacts(result.id, arts)

    def _base_ctx(self, host: Host, params: dict[str, ParamValue]) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "host": {
                "id": host.id, "name": host.name, "address": host.address,
                "user": host.user, "port": host.port, "role": host.role,
            }
        }
        for p in params.values():
            ctx[p.name] = p.display
        return ctx

    def _item_ok(self, item: str, step) -> bool:
        if not step.item_pattern:
            return True
        return bool(re.fullmatch(step.item_pattern, item))

    def _foreach_items(self, step, ctx: dict[str, Any]) -> list[str]:
        head, _, field_name = str(step.foreach).partition(".")
        src = ctx.get(head)
        if src is None:
            return []
        items: list[str] = []
        if field_name:
            if isinstance(src, list):
                for it in src:
                    if isinstance(it, dict) and it.get(field_name) not in (None, ""):
                        items.append(str(it[field_name]))
        elif isinstance(src, list):
            items = [str(i) for i in src if i not in (None, "")]
        else:
            items = [str(src)]
        # ★ T2 新增：**循环项去重并保序**。
        #   理由：net.port 的「归属服务」是 foreach over ss 的 pid —— 同一个进程可能出现在
        #   多行 socket 里（IPv4/IPv6、多个端口），不去重就会对同一个 PID 反复跑同一条命令，
        #   既多花 SSH 往返，又让结论里出现 4 行一模一样的「905：rpcbind.service」。
        #   去重后语义更准（"有哪些 PID 需要反查"），也顺带把 11 次调用减到 4 次。
        items = list(dict.fromkeys(items))
        limit = self.cfg.max_foreach_items
        if len(items) > limit:
            items = items[:limit]
        return items

    def _skipped(self, step, seq: int, iter_key: str | None, why: str) -> StepOut:
        return StepOut(
            seq=seq, name=step.name, title=step.title, iter_key=iter_key,
            argv=[], argv_quoted="", status="skipped", optional=step.optional,
            error=OpsError(code="STEP_FAILED", reason=why, advice="处理前序失败后重新执行本动作。"),
            started_at=now_iso(self.cfg), ended_at=now_iso(self.cfg),
        )

    # ------------------------------------------------------------------ T3：非 run 步骤（规范 §9.5）

    def _rejected(self, step, seq: int, extra: dict[str, str], exc: OpsError, started: str) -> StepOut:
        return StepOut(
            seq=seq, name=step.name, title=step.title,
            iter_key=extra.get(step.as_ or "") if step.as_ else None,
            argv=[], argv_quoted="", status="rejected", optional=step.optional,
            error=exc, started_at=started, ended_at=now_iso(self.cfg),
        )

    def _resolve_local(self, src: str) -> Path:
        """把动作里的本地路径限制在**受控上传目录**内（规范 §9.5）。

        为什么必须限制：否则一个 file.push 动作就能把管理机上任意文件（含私钥）传到目标机。
        """
        base = (self.cfg.paths.var / "uploads").resolve()
        raw = Path(src)
        target = (raw if raw.is_absolute() else base / raw).resolve()
        try:
            target.relative_to(base)
        except ValueError:
            raise OpsError(
                code="PATH_FORBIDDEN",
                reason=f"源文件必须在受控目录内：{src}",
                advice="把要上传的文件放进 repo/var/uploads/，动作里只写它的文件名。",
            ) from None
        return target

    def _exec_write_file(self, step, host: Host, params, extra, seq: int, started: str) -> StepOut:
        """写远端文件（规范 §9.5）。

        实现：内容 base64 后经
        `sh -c 'printf %s <b64> | base64 -d > <path> && chmod <mode> <path>'`。

        ★ 这里出现了管道与重定向 —— 它们是**平台内部实现**，不是动作 YAML 的 `run`，
          所以不违反规范 §4（与"传输层统一加 < /dev/null"、"备份模块的目录计数"同一类做法）。
          内容走 base64（纯 ASCII、无 shell 元字符），路径过白名单校验后再 quote。
        """
        spec = step.write_file or {}
        try:
            path = render_argv_element(str(spec.get("path") or ""), params, extra)
            content = render_argv_element(str(spec.get("content") or ""), params, extra)
        except OpsError as exc:
            return self._rejected(step, seq, extra, exc, started)
        try:
            self.backup_runner.validate_path(path)
        except OpsError as exc:
            return self._rejected(step, seq, extra, exc, started)

        mode = str(spec.get("mode") or "0644")
        if not re.fullmatch(r"[0-7]{4}", mode):
            return self._rejected(step, seq, extra, OpsError(
                code="CATALOG_INVALID",
                reason=f"文件权限「{mode}」不合法（应为 4 位八进制，如 0644）",
                advice="在动作 YAML 的 write_file.mode 里改正。",
            ), started)

        res = self.write_remote_file(host, path, content, mode)
        return StepOut(
            seq=seq, name=step.name, title=step.title,
            iter_key=extra.get(step.as_ or "") if step.as_ else None,
            argv=[], argv_quoted=f"write_file {path}（幂等：内容相同则不写）",
            status="ok" if res["ok"] else "failed", optional=step.optional,
            exit_code=0 if res["ok"] else 1, duration_ms=0,
            stdout=res["stdout"],
            parsed={
                "path": path,
                "sha256": res["after_sha"] or res["before_sha"],
                "before_sha256": res["before_sha"],
                "changed": res["changed"],
            },
            changed=res["changed"], error=res["error"],
            started_at=started, ended_at=now_iso(self.cfg),
        )

    def write_remote_file(
        self, host: Host, path: str, content: str, mode: str = "0644",
        before_write: Any = None,
    ) -> dict[str, Any]:
        """★ 幂等地把内容写到目标机（T5 · 规范 §12.4）。

        幂等来源：**先比对 sha256，相同则不写**。
          · 目标机已有同内容文件 → 不写盘、`changed=False`、**mtime 不变**
          · 内容不同 / 文件不存在 → 走 base64 通道写盘、`changed=True`

        为什么必须有它：`write_file` 原来是"无条件写"，于是"重复部署零变更"
        在文件这一层根本没法断言（写完 mtime 就变了）。
        顺带把 `cron.upsert` / `cron.remove` 也变成幂等的（规范 §9.4 第 20 条）。

        ★ 配方引擎的 `template:` 步骤复用的就是本方法 —— 两条路径**同一套实现**，
          不会出现"动作写文件是幂等的、配方写文件不是"这种双标。

        参数 `before_write`：可选回调，入参是目标机**当前**的 sha256（文件不存在则为空串）。
        它在"内容确实不同、马上就要写盘"的那一刻被调用 ——
        配方引擎用它完成**改动前备份 + 登记检查点**（规范 §9.1 / §12.7）。
        ★ 内容相同的幂等分支在这之前就返回了，所以**"没变"的那一次既不产生备份、也不产生检查点** ——
          这正是我们要的：检查点只标记"真的改了盘"的那些时刻。
        回调抛 `OpsError` → 直接放弃写入（备份没成功就不许动手）。

        返回：`{ok, changed, before_sha, after_sha, stdout, error}`
        """
        # ★ 路径白名单（绝对路径 / 无 .. / 拒绝 /proc /sys 这类危险根）——
        #   动作的 write_file 步骤在调本方法前已校验过一次，这里再校验一次是**故意的**：
        #   本方法是写盘的**单一咽喉**，配方引擎的模板步骤也走它，
        #   于是"动作写文件"与"配方写文件"共用同一道门（不会出现一边严一边松）。
        self.backup_runner.validate_path(path)

        data = content.encode("utf-8")
        want = hashlib.sha256(data).hexdigest()

        # ① 先看目标机现在是什么（不存在 / 读不到 → before_sha 为空）
        cur = self.transport.run(host, ["sha256sum", path], timeout=30)
        before_sha = ""
        if cur.exit_code == 0 and (cur.stdout or "").strip():
            cand = cur.stdout.strip().split()[0]
            if re.fullmatch(r"[0-9a-f]{64}", cand):
                before_sha = cand
                if before_sha == want:
                    return {
                        "ok": True, "changed": False,
                        "before_sha": before_sha, "after_sha": want, "error": None,
                        "stdout": (
                            f"[未变更] {path}"
                            f"（内容与目标机现有文件逐字节相同，已跳过写入，文件时间戳未动）\n"
                            f"[指纹] sha256={want}"
                        ),
                    }

        # ①.5 ★ 变更前最后一刻的挂钩（规范 §9.1 / §12.7）——
        #     只有走到这里才是"真的会改盘"；内容相同的分支已经在上面返回了。
        if before_write is not None:
            before_write(before_sha)

        # ② 写盘（内容 base64 ⇒ 纯 ASCII 无 shell 元字符；路径过白名单后再 quote）
        blob = base64.b64encode(data).decode("ascii")
        # ★ 顺手补一步 `mkdir -p <父目录>`：`dest` 本身已经隐含"它的父目录应当存在"，
        #   否则第一次部署会因为"站点目录不存在"而写盘失败
        #   （T5 开题单 §8.2 坑 #10：`root_dir` 要由配方**主动创建**，不能假设它存在）。
        parent = posixpath.dirname(path) or "/"
        inner = (
            f"mkdir -p {shlex.quote(parent)}"
            f" && printf %s {blob} | base64 -d > {shlex.quote(path)}"
            f" && chmod {mode} {shlex.quote(path)}"
        )
        # ★★ T8·S6 真跑抓到的**真缺陷**（规范 §12.35）：**大文件不能走命令行**。
        #   上面那条 `sh -c <内联 base64>` 会把整份内容塞进**命令行**；而管理机是 Windows ⇒
        #   `CreateProcess` 的命令行上限约 32K 字符 ⇒ 一份 238KB 的清单（Calico 官方 `calico.yaml`）
        #   会以 `FileNotFoundError: [WinError 206] 文件名或扩展名太长` 炸在**控制台自己的进程里**
        #   —— 报出来长得像"控制台内部错误"，而它其实是"这条路走不了这么大的东西"。
        #   ⇒ 超过阈值改走 **scp**（`transport.scp_put`：与备份回拉同一条**二进制安全**的独立通道），
        #     先落到目标机的**临时路径**，再 `mv` 到位。
        #     ★ `mv` 是**同一文件系统内的原子改名** ⇒ 目标路径不会出现"写了一半"的中间态。
        if len(inner) > MAX_INLINE_CMD:
            res = self._write_remote_file_via_scp(host, path, data, mode, parent)
        else:
            res = self.transport.run(host, ["sh", "-c", inner], timeout=60)
        if res.exit_code != 0:
            return {
                "ok": False, "changed": None, "before_sha": before_sha, "after_sha": "",
                "stdout": "",
                "error": classify_remote_failure(
                    "sh -c base64 -d", res.exit_code, res.stdout or "", res.stderr or ""
                ) or OpsError(
                    code="STEP_FAILED",
                    reason=f"写入 {path} 失败（退出码 {res.exit_code}）",
                    advice="确认父目录存在、该路径可写、磁盘有空间。",
                    detail=(res.stderr or "").strip()[:2000],
                ),
            }

        # ③ 回读字节数 + **复核指纹** —— "写成功"要有证据，不能只看写入命令的退出码
        chk = self.transport.run(host, ["wc", "-c", path], timeout=30)
        size = (chk.stdout or "").strip().split()[0] if (chk.stdout or "").strip() else ""
        verify = self.transport.run(host, ["sha256sum", path], timeout=30)
        after_sha = ""
        if verify.exit_code == 0 and (verify.stdout or "").strip():
            after_sha = verify.stdout.strip().split()[0]
        matched = after_sha == want
        before_txt = (before_sha[:16] + "…") if before_sha else "（文件不存在）"
        after_txt = (after_sha[:16] + "…") if after_sha else "（读不到）"
        return {
            "ok": matched, "changed": True,
            "before_sha": before_sha, "after_sha": after_sha,
            "stdout": (
                f"[写入] {path}（{len(data)} 字节，mode {mode}）\n"
                f"[回读] wc -c -> {size or '(读不到)'}\n"
                f"[指纹] 写前 {before_txt} / 写后 {after_txt}"
                f"{'（一致）' if matched else '★ 不一致'}"
            ),
            "error": None if matched else OpsError(
                code="STEP_FAILED",
                reason=f"写入 {path} 后指纹对不上（文件可能被截断）",
                advice="检查目标机磁盘空间与文件系统状态后重试。",
                detail=f"期望 {want} / 实际 {after_sha or '（空）'}",
            ),
        }

    def _write_remote_file_via_scp(
        self, host: Host, path: str, data: bytes, mode: str, parent: str,
    ) -> ExecResult:
        """★★ 大文件写盘走 **scp**（规范 §12.35 · T8·S6 真跑抓到的真缺陷）。

        为什么要这条路：内联写盘（`sh -c "printf %s <base64> | base64 -d > …"`）
        把内容塞进**命令行**，而 Windows 的 `CreateProcess` 命令行上限约 32K 字符 ⇒
        一份 238KB 的清单根本递不过去（报出来是控制台内部的 `WinError 206`，
        看着像"平台坏了"，其实是"这条路走不了这么大的东西"）。

        顺序（每一步都为下一步留了退路）：
          ① 内容写进**管理机的临时文件**（二进制安全，不经 shell）；
          ② `scp` 推到目标机的**临时路径**（不进最终目录 ⇒ 不会有"写了一半"的现场）；
          ③ 远端 `mkdir -p 父目录 && mv -f 临时 → 目标 && chmod` ——
             ★ `mv` 在同一文件系统内是**原子改名**，目标路径要么是旧的、要么是完整的新内容；
          ④ 管理机的临时文件无论如何都删掉（`finally`）。
        """
        tmp_local: Path | None = None
        try:
            fd, name = tempfile.mkstemp(prefix="aoc-push-", suffix=".bin")
            tmp_local = Path(name)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            remote_tmp = f"/tmp/.aoc-push-{uuid.uuid4().hex[:12]}"
            ok, msg = self.transport.scp_put(host, tmp_local, remote_tmp)
            if not ok:
                return ExecResult(
                    argv=[], quoted=f"scp {tmp_local.name} -> {host.target}:{remote_tmp}",
                    exit_code=1, stdout="", stderr=msg, duration_ms=0,
                )
            inner = (
                f"mkdir -p {shlex.quote(parent)}"
                f" && mv -f {shlex.quote(remote_tmp)} {shlex.quote(path)}"
                f" && chmod {mode} {shlex.quote(path)}"
            )
            res = self.transport.run(host, ["sh", "-c", inner], timeout=60)
            res.stdout = (res.stdout or "") + (
                f"[落盘路径] scp → {remote_tmp} → mv → {path}"
                f"（内容 {len(data)} 字节，超过内联上限 {MAX_INLINE_CMD} 字符 ⇒ 走 scp）\n"
            )
            return res
        finally:
            if tmp_local is not None:
                try:
                    tmp_local.unlink()
                except OSError:
                    pass

    def _exec_transfer(self, step, host: Host, params, extra, seq: int, started: str) -> StepOut:
        """文件传输（规范 §9.5）：put = 本地→远端；get = 远端→本地。

        ★ 上传后**自动做 sha256 双向比对**（管理机算 + 目标机算），不一致即判失败 ——
          这是"上传成功"的真自证，而不是"scp 没报错"。
        """
        kind = str(step.transfer or "").lower()
        try:
            src = render_argv_element(str(step.src or ""), params, extra)
            dst = render_argv_element(str(step.dst or ""), params, extra)
        except OpsError as exc:
            return self._rejected(step, seq, extra, exc, started)

        if kind not in ("put", "get"):
            return self._rejected(step, seq, extra, OpsError(
                code="CATALOG_INVALID",
                reason=f"transfer 只能是 put 或 get，实际是「{kind}」",
                advice="在动作 YAML 里改正 transfer 的取值。",
            ), started)

        if kind == "put":
            try:
                local = self._resolve_local(src)
            except OpsError as exc:
                return self._rejected(step, seq, extra, exc, started)
            if not local.is_file():
                return self._rejected(step, seq, extra, OpsError(
                    code="LOCAL_FILE_MISSING",
                    reason=f"本地源文件不存在：{src}",
                    advice="把要上传的文件放进 repo/var/uploads/ 后重试。",
                ), started)
            try:
                self.backup_runner.validate_path(dst)
            except OpsError as exc:
                return self._rejected(step, seq, extra, exc, started)

            local_sha = hashlib.sha256(local.read_bytes()).hexdigest()
            # T5（规范 §12.3）：上传**之前**先取目标机现有文件的指纹 ——
            #   没有它，"这次到底改了没有"就只能靠猜（file.push 的 changed 规则靠它）。
            pre = self.transport.run(host, ["sha256sum", dst], timeout=30)
            remote_sha_before = ""
            if pre.exit_code == 0 and (pre.stdout or "").strip():
                cand = pre.stdout.strip().split()[0]
                if re.fullmatch(r"[0-9a-f]{64}", cand):
                    remote_sha_before = cand
            ok, msg = self.transport.scp_put(host, local, dst)
            if not ok:
                return self._rejected(step, seq, extra, OpsError(
                    code="TRANSFER_FAILED",
                    reason=f"上传 {src} → {dst} 失败",
                    advice="确认目标机路径可写、磁盘有空间、sshd 允许 scp。",
                    detail=msg,
                ), started)

            remote = self.transport.run(host, ["sha256sum", dst], timeout=60)
            remote_sha = (remote.stdout or "").strip().split()[0] if (remote.stdout or "").strip() else ""
            if remote_sha != local_sha:
                return self._rejected(step, seq, extra, OpsError(
                    code="TRANSFER_MISMATCH",
                    reason="上传后指纹与本地不一致（文件可能被截断）",
                    advice="重试一次；若反复出现，检查目标机磁盘空间与网络。",
                    detail=f"本地 {local_sha[:16]}… / 远端 {remote_sha[:16] or '（空）'}…",
                ), started)
            return StepOut(
                seq=seq, name=step.name, title=step.title,
                iter_key=extra.get(step.as_ or "") if step.as_ else None,
                argv=[], argv_quoted=f"scp {local} -> {host.target}:{dst}",
                status="ok", optional=step.optional, exit_code=0, duration_ms=0,
                stdout=(
                    f"[上传] {local.name} → {dst}\n"
                    f"[指纹] sha256={local_sha}（管理机与目标机一致，已逐字节校验）"
                ),
                parsed={
                    "local": str(local), "remote": dst,
                    "sha256": local_sha, "sha256_before": remote_sha_before,
                    "size": local.stat().st_size,
                },
                started_at=started, ended_at=now_iso(self.cfg),
            )

        # get：远端 → 管理机
        try:
            self.backup_runner.validate_path(src)
        except OpsError as exc:
            return self._rejected(step, seq, extra, exc, started)
        local_dir = self._resolve_local(dst) if dst else (self.cfg.paths.var / "downloads")
        local_dir.mkdir(parents=True, exist_ok=True)
        ok, msg = self.transport.scp_get(host, src, local_dir)
        if not ok:
            return self._rejected(step, seq, extra, OpsError(
                code="TRANSFER_FAILED",
                reason=f"下载 {src} 失败",
                advice="确认目标机上该文件存在且可读。",
                detail=msg,
            ), started)
        local_file = local_dir / Path(src).name
        size = local_file.stat().st_size if local_file.is_file() else 0
        return StepOut(
            seq=seq, name=step.name, title=step.title,
            iter_key=extra.get(step.as_ or "") if step.as_ else None,
            argv=[], argv_quoted=f"scp {host.target}:{src} -> {local_file}",
            status="ok", optional=step.optional, exit_code=0, duration_ms=0,
            stdout=f"[下载] {src} → {local_file}（{size} 字节）",
            parsed={"local": str(local_file), "remote": src, "size": size},
            started_at=started, ended_at=now_iso(self.cfg),
        )

    def _exec_one(self, step, host: Host, params: dict[str, ParamValue],
                  extra: dict[str, str], seq: int) -> StepOut:
        started = now_iso(self.cfg)
        # ── T3：两种"非 run"步骤（平台能力，规范 §9.5）────────────────
        # 为什么必须有它们：动作层的 `run` 禁止重定向（安全契约 §4），
        # 于是"写一个配置文件"“把本地文件传上去”这两件变更动作的刚需无处可放。
        if step.write_file:
            return self._exec_write_file(step, host, params, extra, seq, started)
        if step.transfer:
            return self._exec_transfer(step, host, params, extra, seq, started)
        try:
            argv = render_argv(step, params, extra)
        except OpsError as exc:
            return StepOut(
                seq=seq, name=step.name, title=step.title,
                iter_key=extra.get(step.as_ or "") if step.as_ else None,
                argv=[], argv_quoted="", status="rejected", optional=step.optional,
                error=exc, started_at=started, ended_at=now_iso(self.cfg),
            )

        if not argv:
            # ★ T2 新增：渲染出来是**空 argv** —— 说明该步骤的每个元素都被 `when` 判为"参数没填"，
            #   于是整步跳过。为什么需要它：`when` 只能**逐元素**判断，做不到"整条命令消失"；
            #   把所有元素都挂 when 就会渲染出空 argv，而此前空 argv 会被当成一条真命令去执行
            #   （远端只剩 env 前缀）—— 那是错的。
            #   语义定为「未提供参数 → 本步未执行」，**不是失败**（请在 YAML 里给这类步骤标 optional: true）。
            return StepOut(
                seq=seq, name=step.name, title=step.title,
                iter_key=extra.get(step.as_ or "") if step.as_ else None,
                argv=[], argv_quoted="", status="skipped", optional=step.optional,
                error=None, started_at=started, ended_at=now_iso(self.cfg),
            )

        timeout = step.timeout or self.cfg.default_timeout
        # ★★ T16（规范 §12.115）：**这里也要按通道分发** ——
        #   `run()` 里换过 transport 是不够的：真正执行的那一行在这个函数内部。
        #   ★ 判据用 `host.transport`：本机通道的动作，执行面 host 就是合成的宿主机
        #     （`exec_host_for` 换过），所以这一处是**结构可判**的，不靠"我记得传下来一个参数"。
        #   ★ T16·S3 真跑抓到的真缺陷：只改 run() 里那几处 ⇒ 连通性检查走本机、
        #     步骤却仍然去 ssh 127.0.0.1 ⇒ 255 + 「连接 127.0.0.1 失败」。
        transport = self.local_transport if getattr(host, "transport", "ssh") == "local" else self.transport
        res: ExecResult = transport.run(host, argv, timeout=timeout)
        # T4：解析器参数（排行/截断类的"取前几条"）。用 {{ 参数 }} 渲染；
        # 渲染失败不让整步失败 —— 它只影响"显示几行"，退回解析器默认 20 即可。
        parser_arg = ""
        if step.parser_arg:
            try:
                parser_arg = render_argv_element(step.parser_arg, params, extra)
            except OpsError:
                parser_arg = ""
        return self._to_step_out(step, host, seq, extra, res, started, parser_arg=parser_arg)
    def _to_step_out(self, step, host: Host, seq: int, extra: dict[str, str],
                     res: ExecResult, started: str, parser_arg: str = "") -> StepOut:
        parsed: Any = None
        error: OpsError | None = None
        status = "ok"

        if res.timed_out:
            status = "timeout"
            error = OpsError(
                code="STEP_TIMEOUT",
                reason=f"步骤「{step.title}」超过 {step.timeout or self.cfg.default_timeout} 秒未返回",
                advice="若命令本身耗时长，在该动作 YAML 里调大这一步的 timeout。",
            )
        elif res.exit_code == 255:
            status = "failed"
            error = classify_ssh_failure(res.stderr, host)
        elif host.transport == "local" and res.exit_code not in (None, 0):
            # ★★ T16（规范 §12.115 规矩 6）：本机通道的失败**不看英文关键字** ——
            #   `vmrun` 的话术会随系统语言变（实测「找不到该虚拟机」）而且走在 stdout 上。
            #   判定看**退出码**（已在 hostexec 里归一化），这里只把原文翻译成「原因 + 建议」。
            status = "failed"
            error = self.local_transport.classify_failure(host, res)
        elif res.exit_code is not None and res.exit_code not in (step.ok_exit_codes or [0]):
            # ★★ T8·S6 真跑抓到的**真缺陷**（规范 §12.36）：这里的判定条件原来是
            #   `res.exit_code not in (0, None) and res.exit_code not in (step.ok_exit_codes or [0])`
            #   —— 句首那半句 `not in (0, None)` 让 **0 永远算成功**，
            #   于是 `ok_exit_codes` **根本表达不了"这条命令必须失败"**。
            #   ★★ 而库里**有六个动作**早就那么写了，注释还写着"0 不在 ok_exit_codes 里，所以会红"：
            #     `svc.stop`（[3] · 服务没停掉时 is-active 返回 0）· `file.remove` / `cron.remove`（[2]）
            #     · `pkg.remove` / `svc.disable`（[1]）· `fw.port-close`（[1]）。
            #   ⇒ 它们**一直在假绿**："这个东西还在/服务还开着"被记成了成功。
            #   ⇒ 改成**以 `ok_exit_codes` 为唯一准绳**（省略 = 只认 0，与文档一致）。
            #      ★ `None` 仍然放行：那是"没拿到退出码"（本地没跑起来 / ssh 起不来），
            #        由上面 `== 255` 那条与连通性检查各自负责，不该在这里被当成业务失败。
            status = "failed"
            tool = str(res.argv[0]) if res.argv else ""
            # ★ T2 新增：把"目标机上没有这个命令"单独识别出来。
            #   理由：只读诊断动作大量依赖外部工具，而 RHEL 10 的最小安装**不装** dig /
            #   nslookup / traceroute / mtr（T2 探针实测）。若统一报 STEP_FAILED，
            #   用户看到的是"非零退出码 127"这种废话，违背验收标准 #3「失败时给原因 + 建议」。
            #   远端命令带 `env LC_ALL=C LANG=C` 前缀，命令不存在时 stderr 形如
            #   `env: 'dig': No such file or directory`，退出码 127。
            looks_missing = bool(tool) and (
                res.exit_code == 127
                or "command not found" in res.stderr
                or f"'{tool}': No such file or directory" in res.stderr
                or f"{tool}: not found" in res.stderr
            )
            if res.exit_code == 252 and "not running" in ((res.stderr or "") + (res.stdout or "")):
                # 探针实测：firewalld 未运行时 firewall-cmd 返回 **252** + "not running"。
                # 这种情况给"把服务起起来 / 先想清楚该不该起"的建议，
                # 比抛一句"非零退出码 252"有用得多（验收标准 #3 的落点之一）。
                error = OpsError(
                    code="SERVICE_NOT_RUNNING",
                    reason="目标机上的 firewalld 未运行（firewall-cmd 返回 252，输出 not running）",
                    advice=(
                        "① 启动它：systemctl enable --now firewalld；"
                        "② 先确认这台机器是否本来就用 firewalld 管防火墙（也有环境用 nftables 原生规则）；"
                        "③ 起 firewalld 前请确认默认策略不会切断你正在用的连接（尤其是远程 SSH 会话）。"
                    ),
                    detail=((res.stderr or "") + (res.stdout or "")).strip()[:500],
                )
            elif looks_missing:
                error = OpsError(
                    code="TOOL_MISSING",
                    reason=f"目标机上没有命令「{tool}」，这一步无法执行（退出码 {res.exit_code}）",
                    advice=(
                        f"① 用「包搜索」动作查哪个包提供它（dnf provides */{tool}）；"
                        f"② 装上后重试，例如 dnf install -y <包名>；"
                        "③ 或用目标机上已有的等价命令（见本动作的说明）。"
                    ),
                    detail=res.stderr.strip()[:2000],
                )
            else:
                # ★ T4 新增：先让"命令自己的失败"翻译一次（软件源不可达 / 装包冲突 / 磁盘满 / 只读 fs …）。
                #   这是真跑逼出来的：`pkg.install tree` 在 docker-01 上失败时，界面只给
                #   "命令返回非零退出码 1" —— 而真因是"源指向一个已不存在的本地 ISO 挂载点"。
                #   翻译不出来才退回通用 STEP_FAILED（宁可退回，也不要瞎猜）。
                error = classify_remote_failure(
                    tool, res.exit_code, res.stdout or "", res.stderr or ""
                ) or OpsError(
                    code="STEP_FAILED",
                    reason=f"命令返回非零退出码 {res.exit_code}",
                    advice="查看原始输出定位原因。",
                    detail=res.stderr.strip()[:2000],
                )

        if status == "ok" and res.stdout.strip():
            try:
                parsed = apply_pick(parse_text(step.parser, res.stdout, parser_arg), step.pick)
            except OpsError as exc:
                status = "failed"
                error = exc
        elif status == "ok" and step.parser == "line_count":
            # ★ T4 实测补的一条：**空输出对"数行数"来说是有意义的结论（0 行）**。
            #   实测 `journalctl -o cat` 无匹配时 rc=0 且 stdout 完全为空 ——
            #   不补这一条，结论里会渲染成（无），把"这段时间没有错误日志"说成"取不到数据"，
            #   正好把结论说反（与 T3 §9.12「验证自己会骗人」是同一类问题）。
            parsed = 0
        elif status != "ok" and res.stdout.strip():
            # ★ 退出码非 0，但 stdout 有内容 —— 照样解析。
            #   optional 步骤经常是"非零退出码 + 恰好是我们想要的输出"：
            #   例如 `systemctl is-system-running` 在 degraded 时退出码 1，
            #   而 stdout 就是 "degraded" 这个词本身。
            #   T1 期间这里因为"非零就不解析"，把这条结论整个丢成了（无）。
            #   注意：解析失败不覆盖原有的退出码错误信息。
            try:
                parsed = apply_pick(parse_text(step.parser, res.stdout, parser_arg), step.pick)
            except OpsError:
                parsed = None

        return StepOut(
            seq=seq, name=step.name, title=step.title,
            iter_key=extra.get(step.as_ or "") if step.as_ else None,
            argv=res.argv, argv_quoted=res.quoted, status=status,
            optional=step.optional, exit_code=res.exit_code, duration_ms=res.duration_ms,
            stdout="" if step.silent else res.stdout, stderr=res.stderr,
            parsed=parsed, truncated=res.truncated, error=error,
            started_at=started, ended_at=now_iso(self.cfg),
        )

    # ------------------------------------------------------------------ 恢复（T3 · 规范 §9.2）

    def restore_backup(self, backup_id: int, confirm_text: str) -> dict[str, Any]:
        """把一条备份恢复回原路径。

        ★ 恢复本身也是变更动作，而且是 🔴 级：要求**手输确认词**，全过程留证。
        ★ 明确不做自动回滚（规范 §9.2）：变更失败不会自动还原 ——
          自动还原可能把"其实没坏"的现场也覆盖掉。T3 只保证"人能一键回到变更前"。
        """
        if confirm_text.strip() != RESTORE_CONFIRM_TEXT:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason="恢复操作需要手输确认词",
                advice=f"请手工输入「{RESTORE_CONFIRM_TEXT}」后再提交（点一下不算）。",
            )
        rec = self.store.get_backup(backup_id)
        host = self.cfg.host(str(rec.get("host_id") or ""))
        task_id = new_task_id(self.cfg)
        started = now_iso(self.cfg)

        outcome = self.backup_runner.restore(host, rec, task_id)

        # 留证：恢复也写成一条任务（伪 action_id = system.restore），复用现有回放体系
        steps_rows = [
            {
                "seq": i + 1,
                "name": f"restore_{i + 1}",
                "title": s["title"],
                "iter_key": None,
                "argv": [],
                "argv_quoted": s["command"],
                "status": "ok" if s["exit_code"] == 0 else "failed",
                "optional": False,
                "exit_code": s["exit_code"],
                "duration_ms": 0,
                "stdout": s["stdout"],
                "stderr": s["stderr"],
                "parsed": None,
                "truncated": False,
                "error_code": None,
                "error_reason": None,
                "error_advice": None,
                "started_at": started,
                "ended_at": now_iso(self.cfg),
            }
            for i, s in enumerate(outcome["steps"])
        ]
        self.store.save_task(
            {
                "id": task_id,
                "action_id": "system.restore",
                "action_title": "恢复备份到原路径",
                "risk": "red",
                "host_id": host.id,
                "host_name": host.name,
                "host_address": host.address,
                "host_user": host.user,
                "status": "ok" if outcome["ok"] else "failed",
                "params": {"backup_id": backup_id, "orig_path": rec.get("orig_path")},
                "command_preview": "\n".join(f"[{s['title']}] {s['command']}" for s in outcome["steps"]),
                "conclusion": outcome.get("conclusion") or "",
                "error_code": None if outcome["ok"] else "RESTORE_FAILED",
                "error_reason": outcome.get("error"),
                "error_advice": (
                    None if outcome["ok"]
                    else "确认目标机上的备份仍在（可能被清理）、原路径可写、磁盘有空间。"
                ),
                "verify_result": "ok" if outcome["ok"] else "failed",
                "verify_detail": [{"name": "恢复后与备份逐字节一致", "ok": bool(outcome["ok"])}],
                "step_total": len(steps_rows),
                "step_failed": 0 if outcome["ok"] else 1,
                "exit_code": steps_rows[-1]["exit_code"] if steps_rows else None,
                "started_at": started,
                "ended_at": now_iso(self.cfg),
                "duration_ms": 0,
                "batch_id": None,
            },
            steps_rows,
        )
        if outcome["ok"]:
            self.store.mark_restored(backup_id, task_id)
        return {"task_id": task_id, **outcome}

    # ------------------------------------------------------------------ 批量执行（T3 · 规范 §9.3）

    def batch_preview(
        self, action_id: str, host_ids: list[str], raw_params: dict[str, Any] | None
    ) -> dict[str, Any]:
        """批量预检：**参数校验 + 全部主机连通性**。任一不通过 → 整体不开始。

        为什么要求"全部可达"才开跑：批量最坏的体验是"看起来跑了、其实两台没跑"。
        宁可让人先修连通性，也不要产出一张半真半假的对比表。
        """
        action = self.action(action_id)
        if action.risk == "red":
            raise OpsError(
                code="BATCH_FORBIDDEN",
                reason=f"动作「{action.title}」是 red 级，禁止批量执行",
                advice="red 动作必须逐台执行并手输确认词；请一次只选一台机器。",
            )
        if not host_ids:
            raise OpsError(
                code="PARAM_MISSING", reason="没有选择任何目标机", advice="至少勾选一台机器。"
            )
        if len(host_ids) > 8:
            raise OpsError(
                code="PARAM_INVALID",
                reason=f"一次最多 8 台（本次 {len(host_ids)} 台）",
                advice="分批执行；批量会把一次手误同时放大到所有选中机器。",
            )
        params = validate_params(action, raw_params)
        checks: list[dict[str, Any]] = []
        for hid in host_ids:
            h = self.cfg.host(hid)
            # ★ T16（规范 §12.115）：批量预览也要走**这条动作自己的通道** ——
            #   本机通道的"连得上吗"= vmrun 在不在，与 ssh 可达性是两件事，不能互相冒充。
            eh = self.exec_host_for(action, h)
            ok, err, _ = self.transport_for(action, eh).check_connectivity(eh)
            checks.append({"host": h.to_public(), "reachable": ok, "error": err.to_dict() if err else None})
        return {
            "action": action.to_public(),
            "params": {p.name: params[p.name].display for p in action.params},
            "hosts": checks,
            "all_reachable": all(c["reachable"] for c in checks),
            "risk_blocked": False,
        }

    def batch_run(
        self,
        action_id: str,
        host_ids: list[str],
        raw_params: dict[str, Any] | None,
        *,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """把「同一个动作 + 同一份参数」铺到 N 台。每台**独立任务**、失败隔离。"""
        preview = self.batch_preview(action_id, host_ids, raw_params)
        if not preview["all_reachable"]:
            bad = [c["host"]["name"] for c in preview["hosts"] if not c["reachable"]]
            raise OpsError(
                code="HOST_UNREACHABLE",
                reason=f"有 {len(bad)} 台机器不可达：{'、'.join(bad)}",
                advice="批量要求**全部可达**（否则会产出一张半真半假的对比表）。先修连通性再批量。",
            )
        action = self.action(action_id)
        if action.risk != "green" and not confirm:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason=f"动作「{action.title}」是 {action.risk} 级，批量需要二次确认",
                advice="在界面上阅读确认文案后再提交。",
            )

        batch_id = new_batch_id(self.cfg)
        started = now_iso(self.cfg)
        t0 = time.monotonic()
        workers = int(((self.cfg.raw.get("batch") or {}) if isinstance(self.cfg.raw, dict) else {}).get("max_workers") or 4)
        results: list[dict[str, Any]] = []
        lock = threading.Lock()

        def _one(hid: str) -> None:
            try:
                r = self.run(action_id, hid, raw_params, confirm=True, batch_id=batch_id)
                row = {
                    "host_id": hid, "host_name": r.host.name, "task_id": r.id,
                    "status": r.status, "conclusion": r.conclusion,
                    "verify_result": r.verify_result, "duration_ms": r.duration_ms,
                    "step_total": len(r.steps),
                    "step_failed": len([s for s in r.steps if s.status in ("failed", "timeout", "rejected")]),
                    "error": r.error.to_dict() if r.error else None,
                }
            except OpsError as exc:
                row = {
                    "host_id": hid, "host_name": hid, "task_id": None, "status": "failed",
                    "conclusion": "", "verify_result": "none", "duration_ms": 0,
                    "step_total": 0, "step_failed": 0, "error": exc.to_dict(),
                }
            except Exception as exc:  # noqa: BLE001  单台意外不得拖垮整批
                row = {
                    "host_id": hid, "host_name": hid, "task_id": None, "status": "failed",
                    "conclusion": "", "verify_result": "none", "duration_ms": 0,
                    "step_total": 0, "step_failed": 0,
                    "error": {"code": "INTERNAL", "reason": f"{type(exc).__name__}: {exc}", "advice": "看控制台日志。"},
                }
            with lock:
                results.append(row)

        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(host_ids)))) as ex:
            list(ex.map(_one, host_ids))

        ok_count = len([r for r in results if r["status"] == "ok"])
        status = "ok" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
        self.store.save_batch(
            {
                "id": batch_id, "action_id": action_id, "action_title": action.title,
                "risk": action.risk, "host_ids": host_ids, "params": preview["params"],
                "status": status, "total": len(results), "ok_count": ok_count,
                "failed_count": len(results) - ok_count,
                "started_at": started, "ended_at": now_iso(self.cfg),
                "duration_ms": int((time.monotonic() - t0) * 1000),
            }
        )
        return {
            "batch_id": batch_id,
            "action_id": action_id,
            "action_title": action.title,
            "status": status,
            "results": results,
            "diff": self.batch_diff(results),
        }

    @staticmethod
    def batch_diff(results: list[dict[str, Any]]) -> dict[str, Any]:
        """横向对比：**差异才是重点** —— 4 台里只有 1 台不一样，那一台就该被看见。

        ★ 对比口径（T3 实测修正）：按「**任务状态 + 自证结果**」分组，
        **不是**按整段结论文本。原因：结论里天然含有各台不同的值
        （PID、时间戳、路径），拿文本直接比对会把"语义完全一致"误判成"4 组差异"。
        """
        groups: dict[str, list[str]] = {}
        for r in results:
            key = f"{r.get('status') or '?'} / 自证 {r.get('verify_result') or 'none'}"
            groups.setdefault(key, []).append(r["host_name"])
        return {
            "consistent": len(groups) <= 1,
            "groups": [
                {"conclusion": k, "hosts": v, "count": len(v)}
                for k, v in groups.items()
            ],
            "differences": [
                {"conclusion": k, "hosts": v, "count": len(v)}
                for k, v in groups.items()
                if len(v) != len(results)
            ],
            "note": (
                "差异按「任务状态 + 自证结果」判定；各台结论文本含 PID / 时间戳等"
                "天然不同的值，不参与比对（避免把语义一致误报成差异）。"
            ),
        }

    def _verify(self, action: Action, ctx: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
        detail: list[dict[str, Any]] = []
        for v in action.verify:
            value = ctx.get(v.from_)
            if v.field and isinstance(value, dict):
                value = value.get(v.field)
            ok = not (value is None or value == "" or value == [] or value == {})
            detail.append({
                "name": v.name, "from": v.from_, "field": v.field,
                "severity": v.severity, "ok": bool(ok),
                "on_missing": v.on_missing,
                "detail": "" if ok else v.on_missing,
            })
        if any(not d["ok"] and d["severity"] == "fail" for d in detail):
            return "failed", detail
        if any(not d["ok"] for d in detail):
            return "warn", detail
        return "ok", detail
