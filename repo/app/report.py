"""会话报告（T15 · 规范 §12.104 / §12.105）。

★ 主题句：**「报告里每一句结论，都要能被点回它出生的那一次执行。」**

一个**对动作无感知**的纯渲染层：输入是"记录"（会话 / 轮次 / 工具调用 / 变更请求 / 任务留证），
输出是一份 md。它**不读目标机、不碰数据库、不执行任何东西** —— 数据由 `app/api.py` 装好递进来。
这样它可以被**离线**断言逐条问（与 `app/export.py` 同一个做法：新增动作不用碰渲染层）。

三条硬约束（写在这里，免得后来的人重新发明）：

  · ★★ **每条结论都要挂得起证据**：能挂 `task_id` 的才进"结论"区；挂不上的
    **降级标注「没有任务号（不可回放）」**，★ 不许混进结论区（§12.104.1）。
  · ★★ **不许内嵌目标机原文全文**：原文在 `var/artifacts/` 归档与 `/api/tasks/<id>/export` 里；
    报告只给「任务号 + 归档文件名 + 取数命令」。报告是会被转发/贴工单的东西 ——
    内嵌原文 = 又开一条**没设防的出境通道**（T14 缺陷 #1 的同族）。
  · ★★ **报告不许说假话**：措辞由**记录里的状态**决定（`pending` = 未执行（人还没点确认）…），
    且生成完**自己扫一遍**（`scan_claims`）—— 平台自己说的话里出现「已修复 / 已完成」这类词，
    **直接拒绝生成**（§12.104.2）。★ 人说的话与目标机原文放在**围栏块**里，判据不扫它们
    （那是证据，不是我们的断言）。
"""
from __future__ import annotations

from typing import Any

from app.errors import OpsError
from app.export import STATUS_CN as TASK_STATUS_CN

# ── 状态措辞（★ 只许在**这一处**定义；§12.98.3 的同一个纪律）─────────────
#: 任务状态 → 中文（沿用 T2 的单任务报告，别写第二份）
STEP_STATUS_CN = dict(TASK_STATUS_CN, skipped="未执行（参数未填 / 前序失败）")

#: ★★ 变更请求状态 → 中文（§12.104.2 那张表的落点）。
#: ★ 关键：**"批准了"不等于"执行了"**，**"跑不起来"也不等于"没执行"** ——
#:   `pending` 一律写「未执行（人还没点确认）」，`rejected` 一律写「未执行（人驳回了）」。
#: ★ 表里找不到的状态**原样转述**（`状态：<原值>`），**不许**替它编一个好听的词。
REQUEST_STATUS_CN: dict[str, str] = {
    "pending": "未执行（人还没点确认）",
    "rejected": "未执行（人驳回了）",
    "approved": "已执行（人点了确认）",
    "failed": "已执行但未成功（见任务号）",
}

#: ★ 平台自己说的话里**不许出现**的词（§12.104.2 / 红线 10）。
#: 「已修复」必须有 `verdict=proved` 才配说 —— 而 proved 的措辞我们统一写「已证实」，
#: 所以这五个词在任何情况下都不该出现。
FORBIDDEN_CLAIMS: tuple[str, ...] = (
    "已修复", "已完成", "问题已解决", "已经修好", "已恢复正常",
)

#: 复核结论 → 中文
VERDICT_CN: dict[str, str] = {
    "proved": "已证实",
    "disproved": "未证实（有证据说它没成）",
    "not_run": "未证实（复核没跑起来）",
    "not_proved": "未证实",
    "": "未证实（没有复核记录）",
}

#: 时间线里算作"事件"的轮次备注（★ §12.105.4：没有任务号的行**也要出现**）
EVENT_NOTES: dict[str, str] = {
    "ASK_HOST": "停下来问人：要查哪台",
    "AI_NEED_PARAMS": "停下来问人：缺必填参数",
    "AI_NEED_CONFIRM_SCOPE": "停下来问人：检索范围不是用户说过的",
    "AI_BUDGET_STOP": "停下：达到会话预算上限",
    "AI_NO_HOST": "停下：没有可执行的目标机",
    # ★ T15·S3：本地知识检索（★ 它**不是任务**：没有任务号、也不碰目标机）
    "KB_SEARCH": "本地知识检索（只查记录，不碰目标机）",
    "AI_ACTION_REQUEST_PENDING": "停下等人确认：变更请求已登记",
}

#: ★ 不可回放的两种情况（措辞**只许在这里定义一次**）
NO_TASK_ID = "没有任务号（不可回放）"
NO_TASK_NOTE = (
    "★ 这一条**没有挂任务号** ⇒ 它**点不回任何执行现场**。"
    "按 §12.104.1，它**不许**出现在结论区，只在这里如实列出。"
)


# ------------------------------------------------------------------ 判据：不许说假话


def scan_claims(text: str) -> list[str]:
    """扫「平台自己说的话」里有没有 `FORBIDDEN_CLAIMS`（§12.104.2 / 断言 Ⓑ）。

    ★★ 为什么要**先剥围栏块**：报告里有两类文字是**证据**、不是我们的断言 ——
      ① 人说过的话（原话照录）② 目标机原文片段。人可能自己说「修好了没有」，
      那是**证据内容**；把它们一起扫，判据就会**假红**（T14 坑 #8「假红」的同族）。
    ⇒ 判据只扫**围栏之外**的、平台自己生成的那部分。
    """
    outside: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            outside.append(line)
    body = "\n".join(outside)
    return [w for w in FORBIDDEN_CLAIMS if w in body]


def _guard_claims(text: str) -> None:
    bad = scan_claims(text)
    if bad:
        raise OpsError(
            code="REPORT_CLAIM_FORBIDDEN",
            reason=f"报告里出现了不许出现的断言词：{'、'.join(bad)}",
            advice=(
                "这是**渲染层自己的缺陷**，不是环境问题。报告只许转述**记录里的状态**："
                "「已修复」要挂 `verdict=proved`，而 proved 的措辞统一写「已证实」（规范 §12.104.2）。"
            ),
            context={"words": bad},
        )


def _vocabulary_text() -> str:
    """本模块**自己会用到的全部措辞**（状态词表 / 事件词表 / 固定短语）。

    ★★ 为什么单独抽出来给判据扫（§12.104.2）：报告的正文里**必然引用**别人的话
      （任务结论 / 失败解释 / 请求理由 / 人的提问）—— 那些是**证据**，不是我们的断言，
      把它们一起扫会**假红**（T14 坑 #8 同族）。
    ⇒ 判据扫**两块**：① 这张词表（"我们只会用这些词"）② 我们自己生成的两段话
      （§0  tally 与 §4 单列）。**证据部分不扫** —— 它原样照录，改它就是伪造。
    """
    parts: list[str] = [
        *STEP_STATUS_CN.values(),
        *REQUEST_STATUS_CN.values(),
        *VERDICT_CN.values(),
        *EVENT_NOTES.values(),
        NO_TASK_ID,
        NO_TASK_NOTE,
    ]
    return "\n".join(parts)


# ------------------------------------------------------------------ 时间线（§12.105）


def timeline_rows(
    calls: list[dict[str, Any]],
    requests: list[dict[str, Any]],
    turns: list[dict[str, Any]],
    *,
    host_names: dict[str, str] | None = None,
    action_risks: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """把"工具调用 ＋ 变更请求 ＋ 停下来问人的事件"拼成**一条故事**（§12.105）。

    ★★ 排序依据**只有一个**：**记录里的时间**（`created_at`，ISO 秒），
      同一秒再按 `(kind, key)` **稳定**排序 —— ★ 不许拿"我记录它们的顺序"当时间
      （那是用内存顺序冒充事实顺序，与 §9.12 同族）。
    ★★ **跨机永不合并**（§12.86 同源）：一行 = 一条记录，两台机器就是两行。
    ★★ **变更必须看得出来**（§12.105.3）：标签按动作的**风险等级**给 ——
      `green` 写「执行（只读）」、`yellow`/`red` 写「**执行（变更）**」。
      ★ 报告若把"改过东西"写得跟"看了一眼"一样，就是在**制造错觉**（§12.104.2 同族）。
    """
    names = host_names or {}
    risks = action_risks or {}
    rows: list[dict[str, Any]] = []

    for c in calls:
        aid = str(c.get("action_id") or "")
        risk = str(risks.get(aid) or "")
        if risk == "green":
            label = "执行（只读）"
        elif risk in ("yellow", "red"):
            label = f"★ 执行（变更 · {risk}）"
        else:
            # ★ 查不到风险等级就**不猜**：只说"执行"，把动作 id 摆在旁边让人自己看
            label = "执行"
        rows.append({
            "at": str(c.get("created_at") or ""),
            "kind": "call",
            "host_id": str(c.get("host_id") or ""),
            "host": names.get(str(c.get("host_id") or ""), str(c.get("host_id") or "")),
            "action_id": aid,
            "title": str(c.get("title") or ""),
            "status": str(c.get("status") or ""),
            "task_id": str(c.get("task_id") or ""),
            "detail": str(c.get("explain") or ""),
            # ★ `kind` 是内部排序键；`标签` 是给人看的
            "标签": label,
            "_key": f"{c.get('seq') or 0:08d}",
        })

    for r in requests:
        risk = str(r.get("risk") or "")
        rows.append({
            "at": str(r.get("created_at") or ""),
            "kind": "request",
            "host_id": str(r.get("host_id") or ""),
            "host": names.get(str(r.get("host_id") or ""), str(r.get("host_id") or "")),
            "action_id": str(r.get("action_id") or ""),
            "title": "",
            "status": str(r.get("status") or ""),
            "task_id": str(r.get("task_id") or ""),
            "detail": str(r.get("reason") or ""),
            "标签": f"变更请求（{risk or '?'}）",
            "_key": str(r.get("id") or ""),
        })

    for t in turns:
        note = str(t.get("note") or "")
        if note not in EVENT_NOTES:
            continue
        rows.append({
            "at": str(t.get("created_at") or ""),
            "kind": "event",
            "host_id": "",
            "host": "",
            "action_id": "",
            "title": "",
            "status": "未执行",
            "task_id": "",
            "detail": EVENT_NOTES[note],
            "标签": "事件（不是任务）",
            "_key": f"{t.get('seq') or 0:08d}",
        })

    # ★ 时刻 → kind 次序 → 稳定的 key；空时刻排在最前并**如实留着**（不许丢行）
    order = {"call": 0, "request": 1, "event": 2}
    rows.sort(key=lambda r: (r["at"], order.get(r["kind"], 9), r["_key"]))
    return rows


def _row_task_cell(row: dict[str, Any]) -> str:
    tid = row.get("task_id") or ""
    return f"`{tid}`" if tid else f"★ {NO_TASK_ID}"


def _row_status_cell(row: dict[str, Any]) -> str:
    st = row.get("status") or ""
    if row.get("kind") == "request":
        return REQUEST_STATUS_CN.get(st, f"状态：{st or '（空）'}")
    if row.get("kind") == "event":
        return "未执行"
    return STEP_STATUS_CN.get(st, f"状态：{st or '（空）'}")


# ------------------------------------------------------------------ 证据链明细


def _task_block(task_id: str, detail: dict[str, Any] | None) -> list[str]:
    """一个任务的**证据链**（§12.104.1）：它凭什么能回放，原文在哪。"""
    if not detail or not detail.get("task"):
        return [
            f"#### `{task_id}`",
            "",
            f"★ **记录里只有任务号，取不到它的留证**（可能已轮转/被清理）。"
            f"★ 这是「**读不到**」，**不是**「没执行」—— 不许把它当成成功，也不许当成失败。",
            "",
        ]
    task = detail.get("task") or {}
    steps = detail.get("steps") or []
    arts = detail.get("artifacts") or []
    out: list[str] = [
        f"#### `{task_id}` ｜ {task.get('host_id') or '?'} ｜ `{task.get('action_id') or '?'}`",
        "",
        f"- 状态：**{STEP_STATUS_CN.get(str(task.get('status')), str(task.get('status')))}**"
        f"　退出码（末步）{task.get('exit_code') if task.get('exit_code') is not None else '-'}"
        f"　耗时 {task.get('duration_ms') or 0} ms",
        f"- 开始于：{task.get('created_at') or '（无）'}",
    ]
    params = task.get("params_json") or task.get("params") or {}
    if isinstance(params, dict) and params:
        out.append("- 参数：" + "，".join(f"`{k}={v}`" for k, v in params.items()))
    else:
        out.append("- 参数：（无）")

    verify = task.get("verify_detail") or []
    if verify:
        out.append("- 自证：")
        for v in verify:
            mark = "通过" if v.get("ok") else ("警告" if v.get("severity") == "warn" else "不通过")
            src = str(v.get("from") or "") + (f".{v.get('field')}" if v.get("field") else "")
            out.append(f"  - [{mark}] {v.get('name')}　← {src}")
    else:
        out.append("- 自证：**（本任务没有自证记录）** ★ 别把它当成绿灯")

    ok_steps = [s for s in steps if str(s.get("status")) == "ok"]
    bad_steps = [s for s in steps if str(s.get("status")) not in ("ok", "skipped")]
    out.append(
        f"- 步骤：共 {len(steps)} 步（通过 {len(ok_steps)} · 未通过 {len(bad_steps)}）"
    )
    for s in bad_steps:
        out.append(
            f"  - ✗ [{int(s.get('seq') or 0):02d}] {s.get('title') or s.get('name')}"
            f"　{STEP_STATUS_CN.get(str(s.get('status')), str(s.get('status')))}"
            f"　退出码 {s.get('exit_code') if s.get('exit_code') is not None else '-'}"
        )

    out.append(f"- 结论原文：{task.get('conclusion') or '（无）'}")

    if arts:
        out.append(f"- ★ 原始输出归档（{len(arts)} 个，在管理机上）：")
        for a in arts[:12]:
            out.append(f"  - `{a.get('kind')}` `{a.get('label')}` → `{a.get('path')}`")
        if len(arts) > 12:
            out.append(f"  - …（还有 {len(arts) - 12} 个，见归档目录）")
    else:
        out.append("- ★ 原始输出归档：**（无归档）** ★ 如实记「无」，别留白")

    out.append(
        f"- ★ **回放这一段**：`GET /api/tasks/{task_id}/export?format=txt`"
        f"（单任务报告；同样要过鉴权闸门）"
    )
    out.append("")
    return out


def _request_block(row: dict[str, Any], review: dict[str, Any] | None) -> list[str]:
    rid = str(row.get("id") or "")
    st = str(row.get("status") or "")
    # ★ 表里找不到的状态**原样转述**，绝不替它编一个好听的词（§12.104.2）
    st_cn = REQUEST_STATUS_CN.get(st) or f"状态：{st or '（空）'}"
    out = [
        f"#### `{rid}` ｜ {row.get('host_id') or '?'} ｜ `{row.get('action_id') or '?'}`"
        f"（{row.get('risk') or '?'}）",
        "",
        f"- 状态：**{st_cn}**",
        f"- AI 提的理由：{row.get('reason') or '（无）'}",
    ]
    if row.get("decided_at"):
        out.append(f"- 人的决定：{row.get('decided_by') or '（没记是谁）'} 于 {row.get('decided_at')}")
    else:
        out.append("- 人的决定：**（还没有人做过决定）**")
    tid = str(row.get("task_id") or "")
    if tid:
        out.append(f"- 任务号：`{tid}`（执行现场见 §2）")
    else:
        out.append(f"- 任务号：★ {NO_TASK_ID}")
    if review:
        verdict = str(review.get("verdict") or "")
        v_cn = VERDICT_CN.get(verdict) or f"状态：{verdict}"
        out.append(f"- 复核：**{v_cn}**　依据：{review.get('basis') or '（无）'}")
    else:
        out.append("- 复核：**未证实（没有复核记录）**")
    out.append("")
    return out


# ------------------------------------------------------------------ 主入口


def report_name(session_id: str, fmt: str = "md") -> str:
    raw = f"aoc-report-{session_id or 'session'}.{fmt}"
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in raw)


def build_report(
    session: dict[str, Any] | None,
    turns: list[dict[str, Any]] | None = None,
    calls: list[dict[str, Any]] | None = None,
    requests: list[dict[str, Any]] | None = None,
    tasks: dict[str, dict[str, Any]] | None = None,
    usage: dict[str, Any] | None = None,
    *,
    fmt: str = "md",
    generated_at: str = "",
    host_names: dict[str, str] | None = None,
    action_risks: dict[str, str] | None = None,
    base_url: str = "http://127.0.0.1:8787",
) -> str:
    """渲染一份会话报告（md）。

    ★ `tasks` 是 `{task_id: {"task":…, "steps":…, "artifacts":…}}`（＝ `Store.get_task` 的形状）——
      本模块**不去取它**：取数据是接口层的事，这样渲染层可以离线被问（§12.84 同源）。
    ★ 生成的最后一步是 `_guard_claims()`：**自己扫一遍**，说了不该说的话就**拒绝生成**。
    """
    if fmt != "md":
        raise OpsError(
            code="REPORT_FORMAT_UNSUPPORTED",
            reason=f"本期只做 md，收到的是：{fmt}",
            advice=(
                "用 `?format=md`。★ txt 走单任务报告那条路（`/api/tasks/<id>/export?format=txt`）；"
                "PDF 已如实记为 T15 遗留（规范 §12.104.3）。"
            ),
        )

    session = session or {}
    turns = list(turns or [])
    calls = list(calls or [])
    requests = list(requests or [])
    tasks = dict(tasks or {})
    usage = dict(usage or {})
    names = host_names or {}

    sid = str(session.get("id") or "")
    title = str(session.get("title") or "").strip() or "（这次对话没有标题）"

    rows = timeline_rows(calls, requests, turns, host_names=names,
                         action_risks=action_risks or {})

    # ★★ 时间线的「结论 / 说明」列：`ai_tool_call` 里**只存了失败解释**，
    #   成功那一侧是空的 ⇒ 拿**任务结论的第一行**补上（★ 引的是记录里的原文，不是我们编的）。
    #   ★ 理由：报告的价值就在于"一眼看出这次查到了什么"；留一片「（无）」等于没写。
    def _first_line(s: str) -> str:
        for line in str(s or "").splitlines():
            if line.strip():
                return line.strip()
        return ""

    for r in rows:
        if r.get("detail"):
            continue
        tid = str(r.get("task_id") or "")
        if not tid:
            continue
        detail = tasks.get(tid) or {}
        concl = str((detail.get("task") or {}).get("conclusion") or "")
        first = _first_line(concl)
        if first:
            r["detail"] = first

    # ── 账（★ 全部从记录实时算，别手抄）──────────────────────────────
    done = [c for c in calls if str(c.get("status")) == "ok"]
    undone = [c for c in calls if str(c.get("status")) != "ok"]
    no_task = [r for r in rows if r["kind"] != "request" and not r.get("task_id")]
    pending = [r for r in requests if str(r.get("status")) == "pending"]
    rejected = [r for r in requests if str(r.get("status")) == "rejected"]
    approved = [r for r in requests if str(r.get("status")) == "approved"]
    unproved: list[str] = []
    for r in requests:
        card = r.get("card") or {}
        if isinstance(card, str):
            card = {}
        review = card.get("review") if isinstance(card, dict) else None
        if review and str(review.get("verdict")) != "proved":
            unproved.append(str(r.get("id") or ""))

    # ── §0 一句话结论（★ 这一段是**我们自己生成的断言** ⇒ 要过判据）──────────
    tally_lines: list[str] = [
        "## 0. 一句话结论",
        "",
        f"- 执行**成功**：**{len(done)}** 条（每一条都能在 §2 找到它的任务号与原文归档）",
        f"- 执行**未成功**：**{len(undone)}** 条（★ 不许当成「一切正常」）",
        f"- **未执行**：**{len(pending) + len(rejected)}** 条"
        f"（人还没点确认 {len(pending)} · 人驳回了 {len(rejected)}）",
        f"- **未证实**：**{len(unproved)}** 条（复核没到「已证实」）",
        f"- ★ **没有任务号（不可回放）**：**{len(no_task)}** 条",
        "",
        "> ★ 读法（规范 §12.104.2）：**`status` 判「这件事成了没有」，"
        "复核判「有没有证据说它成了」** —— 两个问题，两个字段，别混成一个词。",
        "",
    ]

    out: list[str] = [
        f"# 运维报告 · {title}",
        "",
        f"> ★ 本报告是**快照**：生成于 **{generated_at or '（未记录生成时刻）'}**。",
        f"> 会话 `{sid}` ｜ 模型 `{session.get('model') or '?'}`"
        f" ｜ 提供商 `{session.get('provider') or '?'}`"
        f" ｜ 外流档位 **{session.get('tier') or '?'}**",
        f"> 工具调用 **{len(calls)}** 次（成功 {len(done)} · 未成功 {len(undone)}）"
        f" ｜ 变更请求 **{len(requests)}** 个"
        f" ｜ 没有任务号的行 **{len(no_task)}** 条",
        "",
        *tally_lines,
        "## 1. 时间线（谁在什么时候做了什么）",
        "",
        "| 时刻 | 类型 | 主机 | 做了什么 | 状态 | 结论 / 说明 | 任务号 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        detail = " ".join(str(r.get("detail") or "").split())[:80]
        what = r.get("action_id") or "（无动作）"
        out.append(
            f"| {r['at'] or '（无时刻）'} | {r.get('标签') or r['kind']} | {r['host'] or '-'}"
            f" | `{what}` | {_row_status_cell(r)}"
            f" | {detail or '（无）'} | {_row_task_cell(r)} |"
        )
    if not rows:
        out.append("| （没有记录） | - | - | - | - | ★ 这次会话里没有任何可回放的行 | - |")

    # ── §2 证据链明细 ────────────────────────────────────────────────
    out += ["", "## 2. 证据链明细（每条结论 → 它的任务 → 原文在哪）", ""]
    seen: set[str] = set()
    for c in calls:
        tid = str(c.get("task_id") or "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out += _task_block(tid, tasks.get(tid))
    for r in requests:
        tid = str(r.get("task_id") or "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out += _task_block(tid, tasks.get(tid))
    if not seen:
        out += [
            "★ **这次会话没有产生任何任务** —— 所以没有可回放的执行现场。",
            "★ 如实记「无」：**这不是失败，也不是成功**（§12.104.2：读不到 ≠ 没成功）。",
            "",
        ]

    # ── §3 变更请求 ──────────────────────────────────────────────────
    out += ["", "## 3. 变更请求（AI 提出的、人决定了的）", ""]
    if requests:
        for r in requests:
            card = r.get("card")
            if isinstance(card, str):
                try:
                    import json as _json

                    card = _json.loads(card)
                except Exception:  # noqa: BLE001
                    card = {}
            review = (card or {}).get("review") if isinstance(card, dict) else None
            out += _request_block(r, review)
    else:
        out += ["★ 这次会话**没有**变更请求（一条都没有）。", ""]

    # ── §4 未成功 / 未执行 / 未证实（单列，别混进结论）────────────────
    #   ★ 这一段同样是**我们自己生成的断言** ⇒ 要过判据
    weak: list[str] = ["", "## 4. 未成功 · 未执行 · 未证实（单列，别混进结论）", ""]
    if undone:
        weak.append("**执行未成功的：**")
        for c in undone:
            tid = str(c.get("task_id") or "")
            weak.append(
                f"- `{c.get('action_id')}` @ {names.get(str(c.get('host_id')), c.get('host_id'))}"
                f"　状态 {STEP_STATUS_CN.get(str(c.get('status')), str(c.get('status')))}"
                f"　{'任务号 `' + tid + '`' if tid else '★ ' + NO_TASK_ID}"
                f"　{c.get('explain') or ''}"
            )
    else:
        weak.append("**执行未成功的：**（无）")
    weak.append("")
    weak.append("**未执行的变更请求：**")
    if pending or rejected:
        for r in pending:
            weak.append(f"- `{r.get('id')}` `{r.get('action_id')}` @ {r.get('host_id')}"
                        f"　★ **未执行（人还没点确认）**")
        for r in rejected:
            weak.append(f"- `{r.get('id')}` `{r.get('action_id')}` @ {r.get('host_id')}"
                        f"　★ **未执行（人驳回了）**")
    else:
        weak.append("（无）")
    weak.append("")
    weak.append("**未证实的变更：**")
    if unproved:
        for rid in unproved:
            weak.append(f"- `{rid}`　★ **未证实** —— 不许在这里读出任何『好了』的意思（红线 10）")
    else:
        weak.append("（无）")
    weak.append("")

    if no_task:
        weak.append(f"**{NO_TASK_ID}：**")
        for r in no_task:
            weak.append(f"- [{r['at'] or '（无时刻）'}] {r.get('标签') or r['kind']}"
                        f"　{r.get('detail') or ''}")
        weak.append("")
        weak.append(NO_TASK_NOTE)
        weak.append("")
    out += weak

    # ── §5 账（本地）────────────────────────────────────────────────
    out += [
        "## 5. 这次对话的账（本地，不外发）",
        "",
        f"- 外流次数：**{usage.get('outflow_calls', 0)}**"
        f"　｜ prompt **{usage.get('prompt_tokens', 0)}** ＋ completion "
        f"**{usage.get('completion_tokens', 0)}** ＝ **{usage.get('total_tokens', 0)}** token",
        f"- 工具调用：**{usage.get('tool_calls', 0)}**（成功 {usage.get('tool_ok', 0)}）",
        f"- 双结论**分歧**：**{usage.get('conflicts', 0)}** 条"
        f"（★ 分歧是发现幻觉的唯一机制 —— 有分歧就该有人看）",
        "",
        "## 6. 怎么回放",
        "",
        f"- 单任务报告：`{base_url}/api/tasks/<任务号>/export?format=txt`（上面 §2 每条都给了任务号）",
        f"- 原始输出归档：管理机 `repo/var/artifacts/` 下、按任务号分目录（§2 里逐条列了文件名）",
        f"- 会话记录：`{base_url}/api/ai/sessions/{sid}`（轮次 / 工具调用 / 用量）",
        "",
        "> ★ 本报告**没有内嵌目标机原文**（规范 §12.104.1）：报告是会被转发的东西，",
        "> 原文走归档与导出接口 —— 那里有鉴权闸门，报告本身不承担这个职责。",
        "",
    ]

    text = "\n".join(out)
    # ★★ 说了不该说的话 ⇒ **拒绝生成**，而不是"生成完随它去"（§12.104.2）。
    #    ★ 扫的是**两块**：① 本模块自己的词表 ② 我们自己生成的那两段断言（§0 / §4）——
    #      正文里引用的**别人的话**（任务结论 / 失败解释 / 人的提问）是**证据**，
    #      一起扫会假红（T14 坑 #8 同族）。
    _guard_claims("\n".join([_vocabulary_text(), *tally_lines, *weak]))
    return text
