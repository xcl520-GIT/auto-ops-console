"""任务报告导出（T2 · 验收标准 #4「结果可导出」）。

一个**对动作无感知**的通用能力：把任意一次任务的
「结论 + 自证 + 步骤留证 + 原始输出归档清单」渲染成 txt / md 报告。
这样新增动作时不用碰导出逻辑 —— 延续「加动作只加 YAML」这条主线。

两种格式：
  · txt —— 给人看/给人贴的纯文本报告（固定宽度分节，终端里也整齐）
  · md  —— 给 Markdown 文档/工单系统用（结论放进代码块，保持对齐不被打乱）
"""
from __future__ import annotations

from typing import Any

BAR = "=" * 72
SUB = "-" * 72

STATUS_CN = {
    "ok": "成功",
    "failed": "失败",
    "aborted": "已中止（未执行）",
    "timeout": "超时",
    "skipped": "未执行",
    "rejected": "被拒绝",
}
STEP_CN = dict(STATUS_CN, skipped="未执行（参数未填 / 前序失败）")


def report_filename(detail: dict[str, Any], fmt: str) -> str:
    task = detail.get("task") or {}
    raw = f"aoc-{task.get('id') or 'task'}-{task.get('action_id') or 'action'}.{fmt}"
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in raw)


def build_report(detail: dict[str, Any], fmt: str = "txt") -> str:
    task = detail.get("task") or {}
    if fmt == "md":
        return _markdown(task, detail.get("steps") or [], detail.get("artifacts") or [])
    return _text(task, detail.get("steps") or [], detail.get("artifacts") or [])


# ------------------------------------------------------------------ 共用片段


def _params_line(task: dict[str, Any]) -> str:
    params = task.get("params_json") or task.get("params") or {}
    if not isinstance(params, dict) or not params:
        return "（无参数）"
    return "，".join(f"{k}={v if v not in (None, '') else '（空）'}" for k, v in params.items())


def _verify_lines(task: dict[str, Any]) -> list[str]:
    rows = task.get("verify_detail") or []
    if not rows:
        return ["（本任务没有自证记录）"]
    out = []
    for v in rows:
        mark = "通过" if v.get("ok") else ("警告" if v.get("severity") == "warn" else "不通过")
        src = f"{v.get('from')}" + (f".{v.get('field')}" if v.get("field") else "")
        line = f"[{mark}] {v.get('name')}    ← {src}"
        if not v.get("ok") and v.get("on_missing"):
            line += f"\n         未通过原因：{v.get('on_missing')}"
        out.append(line)
    return out


def _step_header(s: dict[str, Any]) -> str:
    return (f"[{int(s.get('seq') or 0):02d}] {s.get('title') or s.get('name')}"
            + (f" · {s['iter_key']}" if s.get("iter_key") else "")
            + f"    {STEP_CN.get(s.get('status'), s.get('status'))}"
            + f"    退出码 {s.get('exit_code') if s.get('exit_code') is not None else '-'}"
            + f"    {s.get('duration_ms') or 0}ms"
            + ("    （可选步骤）" if s.get("optional") else ""))


def _artifact_lines(arts: list[dict[str, Any]]) -> list[str]:
    if not arts:
        return ["（无归档）"]
    return [
        f"  {a.get('kind'):<10} {a.get('label'):<28} {a.get('size') or 0:>8} B  {a.get('path')}\n"
        f"             sha256={a.get('sha256')}"
        for a in arts
    ]


# ------------------------------------------------------------------ txt


def _text(task: dict[str, Any], steps: list[dict[str, Any]], arts: list[dict[str, Any]]) -> str:
    L: list[str] = []
    L.append(BAR)
    L.append("  auto-ops-console · 任务报告")
    L.append(BAR)
    L.append(f"  任务 ID   : {task.get('id')}")
    L.append(f"  动作      : {task.get('action_id')}（{task.get('action_title')}）")
    L.append(f"  风险等级  : {task.get('risk')}")
    L.append(f"  目标机    : {task.get('host_name')}"
             f"（{task.get('host_user')}@{task.get('host_address')}）")
    L.append(f"  状态      : {STATUS_CN.get(task.get('status'), task.get('status'))}"
             f"        自证：{task.get('verify_result')}")
    L.append(f"  执行时间  : {task.get('started_at')} → {task.get('ended_at')}"
             f"（{task.get('duration_ms') or 0} ms）")
    L.append(f"  步骤      : 共 {task.get('step_total')} 步，失败 {task.get('step_failed')} 步")
    L.append(f"  参数      : {_params_line(task)}")
    L.append("")
    L.append(SUB)
    L.append("【结论】")
    L.append(SUB)
    L.append(task.get("conclusion") or "（本任务没有结论文本）")

    if task.get("error_reason"):
        L += ["", SUB, "【错误】", SUB,
              f"  原因：{task.get('error_reason')}",
              f"  建议：{task.get('error_advice')}", f"  错误码：{task.get('error_code')}"]

    L += ["", SUB, "【自证（verify）】", SUB]
    L += ["  " + x for x in _verify_lines(task)]

    L += ["", SUB, f"【步骤留证（{len(steps)} 步）】", SUB]
    for s in steps:
        L.append("  " + _step_header(s))
        L.append(f"       命令：{s.get('argv_quoted')}")
        if s.get("error_reason"):
            L.append(f"       错误：{s.get('error_reason')}")
            if s.get("error_advice"):
                L.append(f"       建议：{s.get('error_advice')}")
        if s.get("truncated"):
            L.append("       ⚠ 输出已截断（超出单步上限）")
        for label, body in (("stdout", s.get("stdout")), ("stderr", s.get("stderr"))):
            if body:
                L.append(f"       --- {label} ---")
                L += ["       " + ln for ln in str(body).rstrip().splitlines()]
        L.append("")

    L += [SUB, "【原始输出归档（含 sha256，可复核）】", SUB]
    L += _artifact_lines(arts)

    L += ["", SUB, "【执行计划（执行前即已确定的命令）】", SUB]
    L.append(task.get("command_preview") or "（无）")

    L += ["", BAR,
          "  由 auto-ops-console 导出 · 本报告由程序按任务留证自动生成，未手工修饰",
          BAR, ""]
    return "\n".join(L)


# ------------------------------------------------------------------ md


def _markdown(task: dict[str, Any], steps: list[dict[str, Any]], arts: list[dict[str, Any]]) -> str:
    L: list[str] = []
    L.append(f"# 任务报告 · {task.get('action_title')}（`{task.get('action_id')}`）")
    L.append("")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    L.append(f"| 任务 ID | `{task.get('id')}` |")
    L.append(f"| 风险等级 | {task.get('risk')} |")
    L.append(f"| 目标机 | {task.get('host_name')}（{task.get('host_user')}@{task.get('host_address')}） |")
    L.append(f"| 状态 | {STATUS_CN.get(task.get('status'), task.get('status'))}"
             f"（自证 {task.get('verify_result')}） |")
    L.append(f"| 执行时间 | {task.get('started_at')} → {task.get('ended_at')}"
             f"（{task.get('duration_ms') or 0} ms） |")
    L.append(f"| 步骤 | 共 {task.get('step_total')} 步，失败 {task.get('step_failed')} 步 |")
    L.append(f"| 参数 | {_params_line(task)} |")
    L.append("")
    L.append("## 结论")
    L.append("")
    L.append("```text")
    L.append((task.get("conclusion") or "（无结论）").rstrip())
    L.append("```")

    if task.get("error_reason"):
        L += ["", "## 错误", "",
              f"- **原因**：{task.get('error_reason')}",
              f"- **建议**：{task.get('error_advice')}",
              f"- **错误码**：`{task.get('error_code')}`"]

    L += ["", "## 自证（verify）", ""]
    for v in (task.get("verify_detail") or []):
        mark = "✅" if v.get("ok") else ("⚠️" if v.get("severity") == "warn" else "❌")
        # ★ 这里必须容错：自检脚本自己写入的探针任务只有 {"name","ok"} 两个键，
        #   早期版本写成 v.get("from") + ... 会因 None 参与拼接而抛 TypeError
        #   （txt 版因为用 f-string 而侥幸没事 —— 两处渲染逻辑都要按"字段可能缺失"写）。
        src = str(v.get("from") or "?") + (f".{v.get('field')}" if v.get("field") else "")
        L.append(f"- {mark} {v.get('name')} `← {src}`")
        if not v.get("ok") and v.get("on_missing"):
            L.append(f"  - 未通过原因：{v.get('on_missing')}")
    if not (task.get("verify_detail") or []):
        L.append("- （无自证记录）")

    L += ["", f"## 步骤留证（{len(steps)} 步）", ""]
    for s in steps:
        L.append(f"### {_step_header(s)}")
        L.append("")
        L.append("```bash")
        L.append(str(s.get("argv_quoted") or ""))
        L.append("```")
        if s.get("error_reason"):
            L.append(f"- **错误**：{s.get('error_reason')}")
            L.append(f"- **建议**：{s.get('error_advice')}")
        for label, body in (("stdout", s.get("stdout")), ("stderr", s.get("stderr"))):
            if body:
                L += ["", f"<details><summary>{label}</summary>", "", "```text",
                      str(body).rstrip(), "```", "", "</details>"]
        L.append("")

    L += ["## 原始输出归档（含 sha256）", ""]
    if arts:
        L.append("| 类型 | 标签 | 大小 | 路径 | sha256 |")
        L.append("|---|---|---|---|---|")
        for a in arts:
            L.append(f"| {a.get('kind')} | {a.get('label')} | {a.get('size') or 0} B | "
                     f"`{a.get('path')}` | `{str(a.get('sha256'))[:16]}…` |")
    else:
        L.append("（无归档）")

    L += ["", "## 执行计划（执行前即已确定的命令）", "", "```bash",
          str(task.get("command_preview") or "（无）").rstrip(), "```", "",
          "---", "", "*由 auto-ops-console 导出 · 本报告由程序按任务留证自动生成，未手工修饰*", ""]
    return "\n".join(L)


# ------------------------------------------------------------------ 体检报告（T4 · 规范 §10.2.5）


def checkup_report_filename(report: dict[str, Any], fmt: str) -> str:
    host = (report.get("host") or {}).get("id") or "host"
    raw = f"aoc-checkup-{report.get('task_id') or 'task'}-{host}.{fmt}"
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in raw)


def _checkup_lines(report: dict[str, Any]) -> list[str]:
    """阈值 → 人话。报告里必须回显用的是哪一档（规范 §10.2.2）。"""
    th = (report.get("thresholds") or {}).get("values") or {}
    cores = (report.get("thresholds") or {}).get("core_services") or []
    cands = (report.get("thresholds") or {}).get("orphan_port_candidates") or []

    def g(key: str, default: float = 0) -> str:
        v = th.get(key, default)
        return f"{v:g}" if isinstance(v, (int, float)) else str(v)

    return [
        f"挂载点容量：≥{g('disk_pct_warn')}% 黄 / ≥{g('disk_pct_crit')}% 红；inode：≥{g('inode_pct_warn')}% 黄 / ≥{g('inode_pct_crit')}% 红",
        f"失败服务：≥{g('failed_service_warn')} 个判黄；核心服务 {'、'.join(cores)} 失败判红",
        f"内核错误：≥{g('kernel_err_warn')} 条判黄；出现 OOM 判红",
        f"无主放行端口候选：{'、'.join(str(c) for c in cands)}",
        "来源：config.yaml → checkup.thresholds（改阈值不用改代码）",
    ]


def build_checkup_report(report: dict[str, Any], fmt: str = "md") -> str:
    """把体检报告渲染成**可交付文件**（T4 · 规范 §10.2.5）。

    ★ 与 `build_report` 的分工：
      · `build_report`（任务报告）= "做过什么"的留证 → 铺步骤、命令原文、原始输出；
      · 本函数（体检报告）= "这台机器现在好不好"的结论 → 铺总判、每项判定、依据、下一步。
      两条通道互补，不重复：要看原始输出就导出任务报告，要看结论就导出体检报告。
    """
    host = report.get("host") or {}
    items = report.get("items") or []
    counts = report.get("counts") or {}
    title = f"体检报告 · {host.get('name') or host.get('id') or '（未知主机）'}"

    if fmt == "md":
        L: list[str] = [f"# {title}", ""]
        L.append("| 项 | 值 |")
        L.append("|---|---|")
        L.append(f"| 任务 ID | `{report.get('task_id')}` |")
        L.append(f"| 目标机 | {host.get('name')}（{host.get('address')} · role={host.get('role')}） |")
        L.append(f"| 采集时间 | {report.get('started_at')}（耗时 {report.get('duration_ms') or 0} ms） |")
        L.append(f"| 采集任务状态 | {report.get('task_status')}（自证 {report.get('verify_result')}） |")
        L.append(f"| **总判** | **{report.get('summary')}** |")
        L += ["", "## 总判", "", report.get("summary") or "（无）"]
        L += ["", "## 本次判定用的阈值", ""]
        L += [f"- {x}" for x in _checkup_lines(report)]
        L += ["", "## 逐项判定", ""]
        for it in items:
            L.append(f"### {it.get('icon')} {it.get('no')}. {it.get('title')}")
            L.append("")
            L.append(f"- **判定**：{it.get('verdict')}")
            for e in (it.get("evidence") or []):
                L.append(f"- 依据：{e}")
            if it.get("advice"):
                L.append(f"- **建议**：{it.get('advice')}")
            if it.get("next_action") or it.get("next_hint"):
                nxt = it.get("next_action") or ""
                L.append(f"- **先去查**：`{nxt}` {it.get('next_action_title') or it.get('next_hint') or ''}".rstrip())
            L.append("")
        L += ["---", "",
              "*由 auto-ops-console 导出 · 判定由程序按 config.yaml 的阈值自动生成，未手工修饰*", ""]
        return "\n".join(L)

    # ---- txt
    T: list[str] = [BAR, f"  {title}", BAR]
    T.append(f"  任务 ID   : {report.get('task_id')}")
    T.append(f"  目标机    : {host.get('name')}（{host.get('address')} · role={host.get('role')}）")
    T.append(f"  采集时间  : {report.get('started_at')}（{report.get('duration_ms') or 0} ms）")
    T.append(f"  任务状态  : {report.get('task_status')}   自证 {report.get('verify_result')}")
    T.append(f"  总判      : {report.get('overall_icon')} {report.get('summary')}")
    T += ["", SUB, "【本次判定用的阈值】", SUB]
    T += ["  " + x for x in _checkup_lines(report)]
    T += ["", SUB, f"【逐项判定（{len(items)} 项）】", SUB]
    for it in items:
        T.append(f"  {it.get('icon')} {int(it.get('no') or 0):>2d}. {it.get('title')}"
                 f"    {it.get('verdict')}")
        for e in (it.get("evidence") or []):
            T.append(f"        依据：{e}")
        if it.get("advice"):
            T.append(f"        建议：{it.get('advice')}")
        if it.get("next_action") or it.get("next_hint"):
            T.append(f"        先去查：{it.get('next_action') or ''} "
                     f"{it.get('next_action_title') or it.get('next_hint') or ''}".rstrip())
        T.append("")
    T += [SUB, f"  计数：{counts}", BAR,
          "  由 auto-ops-console 导出 · 判定按 config.yaml 的阈值自动生成", BAR, ""]
    return "\n".join(T)
