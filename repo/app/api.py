"""接口层：HTTP 路由、参数校验、错误翻译。

约定：
  · 所有 /api/* 响应形如 {"ok": true, "data": ...} 或 {"ok": false, "error": {...}}
  · error 一定带「原因 + 建议」（errors.OpsError），界面不展示裸 stderr
  · 静态资源（web/）由 HTTP handler 直接读文件，不走这一层
  · ★ **T14 起有鉴权**（规范 §12.97，红线 11）—— 但它**不在这里拦**：
    拦截是 `app/server.py` 那个**唯一漏斗**（`_handle`）的事，本层只负责
    "登录 / 登出 / 改口令 / 自述"这几个接口本身（`_auth_route`）。
    ★ 这么分是有意的：**闸门只有一处**才谈得上"全覆盖"，散在各 handler 里必漏。
"""
from __future__ import annotations

import re
import sys
from typing import Any, Callable

from app import __stage__, __version__
from app import enroll as enroll_mod
from app.catalog import Action, reconcile
from app.checkup import CHECKUP_ACTION_ID, judge as judge_checkup
from app.config import AppConfig
from app.engine import Engine
from app.errors import OpsError
from app.recipe import RecipeRunner
from app.export import build_checkup_report, build_report, checkup_report_filename, report_filename
from app.store import Store
from app.transport import SshTransport
from app.yamlload import describe_backend


class Api:
    def __init__(
        self,
        cfg: AppConfig,
        actions: dict[str, Action],
        map_data: dict[str, Any],
        store: Store,
        engine: Engine,
        runner: RecipeRunner | None = None,
    ) -> None:
        self.cfg = cfg
        self.actions = actions
        self.map_data = map_data
        self.store = store
        self.engine = engine
        # T5：配方引擎（编排层）。它装载失败时 bootstrap 会**直接拒绝启动**，
        # 所以这里不会出现"悄悄少了一半能力"的中间态。
        self.runner = runner
        self.transport = SshTransport(cfg)
        # T4：纳管会话（内存里即可 —— 会话是"一次性的"，最长活 120s；留证另落磁盘）
        self._enroll: dict[str, Any] = {}
        # ── T12：AI 助手基座（五·AI 助手；规范 §12.74）──────────────────
        # ★ 由 `server.bootstrap` 构造后挂上来。**为什么不在 __init__ 里建**：
        #   它需要 `self.dispatch` 这个**同一个入口**（铁律 8）——
        #   在 __init__ 里建只能要么绕成循环、要么诱人"顺手直连引擎"，两条都错。
        self.ai: Any = None
        # ── T14：最小鉴权（五·AI 助手；规范 §12.97）────────────────────
        # ★ 与 `self.ai` 不同，它**可以直接在 __init__ 里建**：它不依赖 `self.dispatch`
        #   （§12.74 那条约束只针对 AI 面），只需要 `cfg`。
        # ★ 装载**不抛异常**：口令文件坏了也要让控制台起得来（但要 fail-closed）——
        #   详见 `app/auth.py` 的 `_load` / `setup_allowed`。
        from app.auth import Auth

        self.auth: Any = Auth(cfg)
        # ── T15：源码指纹（规范 §12.108；清 T14 遗留 #4）──────────────────
        # ★ 在**装载时**算一次（进程内复用），但**留着重算的入口**：
        #   `tools/fingerprint.py` —— 不许"启动时算一次就算完"（§12.108.4）。
        #   ★ 这里算的值就是"这个进程**当时**跑的是哪一份源码"，它不会随文件改动而变 ——
        #     正好用来分辨"跑的是不是旧构建"（T13 那条坑）。
        from app.fingerprint import source_fingerprint

        self.fingerprint: dict[str, Any] = source_fingerprint(cfg.root)

    # ------------------------------------------------------------------ 元信息

    def health(self) -> dict[str, Any]:
        _, control_note = self.cfg.ssh.effective_control_master()
        return {
            "ok": True,
            "service": "auto-ops-console",
            "version": __version__,
            "stage": __stage__,
            "python": sys.version.split()[0],
            "executable": sys.executable,
            "yaml": describe_backend(),
            "bind": f"{self.cfg.server['host']}:{self.cfg.server['port']}",
            "timezone": self.cfg.timezone,
            "ssh_binary": self.cfg.ssh.binary,
            "strict_host_key": self.cfg.ssh.strict_host_key,
            "connection_reuse": control_note,
            "locale_forced": (self.cfg.raw.get("ssh", {}) or {}).get("remote_env", {"LC_ALL": "C", "LANG": "C"}),
            "actions": len(self.actions),
            "recipes": len(self.runner.recipes) if self.runner else 0,
            "hosts": [h.to_public() for h in self.cfg.hosts],
            "db": self.store.stats(),
            # ── ★ T15：源码指纹（§12.108.2）—— 排查时要把"构建"与"机器事实"写在一起 ──
            "build": self.fingerprint,
        }

    def hosts(self) -> dict[str, Any]:
        return {"hosts": [h.to_public() for h in self.cfg.hosts]}

    def host_check(self, host_id: str, *, trust: bool = False,
                   force: bool = False) -> dict[str, Any]:
        """连通性自检（可选顺带信任）。

        ★★ T17·S8 补（§12.139 第 2 条）：`force=True` ⇒ **「接受新指纹」**。
          它与 `trust` 的区别：`trust` 只处理"**没见过**这台机器"（TOFU 首次信任）；
          对"**指纹变了**"（我们刚重置过它的 host key）它一样会拒 ——
          ⇒ `force` 会先把该地址的旧记录**逐字节备份后撤掉**，再重新接受。
          ★ 两者的共同点：**都是人在界面上点的那一下**，平台不会自己决定接受一个指纹。
        """
        host = self.cfg.host(host_id)
        if trust:
            info = self.transport.trust_host(host, force=force)
            ok, err, res = self.transport.check_connectivity(host)
        else:
            ok, err, res = self.transport.check_connectivity(host)
            info = {}
        return {
            "host": host.to_public(),
            "reachable": ok,
            "error": err.to_dict() if err else None,
            "trust": info,
            "probe": {
                "command": res.quoted if res else None,
                "exit_code": res.exit_code if res else None,
                "stderr": (res.stderr if res else "").strip(),
            },
        }

    # ------------------------------------------------------------------ 动作

    def action_list(self) -> dict[str, Any]:
        items = [a.to_public() for a in self.actions.values()]
        items.sort(key=lambda a: (a["domain"], a["priority"], a["id"]))
        domains = (self.map_data.get("domains") or {})
        return {"actions": items, "domains": domains}

    def action_detail(self, action_id: str) -> dict[str, Any]:
        return {"action": self.engine.action(action_id).to_detail()}

    def preview(self, action_id: str, body: dict[str, Any]) -> dict[str, Any]:
        host_id = str(body.get("host_id") or "")
        if not host_id:
            raise OpsError(
                code="PARAM_MISSING",
                reason="没有指定目标机",
                advice="在界面左上角选择一台目标机。",
            )
        return self.engine.preview(action_id, host_id, body.get("params") or {})

    def run_action(self, action_id: str, body: dict[str, Any]) -> dict[str, Any]:
        host_id = str(body.get("host_id") or "")
        if not host_id:
            raise OpsError(
                code="PARAM_MISSING",
                reason="没有指定目标机",
                advice="在界面左上角选择一台目标机。",
            )
        result = self.engine.run(
            action_id,
            host_id,
            body.get("params") or {},
            confirm=bool(body.get("confirm")),
            confirm_text=str(body.get("confirm_text") or ""),
        )
        return result.to_public()

    # ------------------------------------------------------------------ T14·S4：人点确认 ⇒ 真执行（＋自动复核）
    def _ai_run_task(
        self, action_id: str, host_id: str, params: dict[str, Any], *, confirm: bool = False
    ) -> dict[str, Any]:
        """★ 走**既有的那条路**：和界面点「执行」、`POST /api/actions/<id>/run` 是**同一个入口**。

        ★★ 为什么必须是"同一个入口"而不是"再写一遍执行"（§12.96.2 规矩 1）：
          同一个入口 ⇒ 留证 / 护栏（变更前备份）/ 覆盖率账本 **三套体系自动生效**；
          另写一条 ⇒ 它们全都要在第二条路上再实现一遍，而且迟早会漏一处。

        ★ `confirm=True` 的语义：**人在界面上点了那张卡片**就是这一下确认
          （★ 卡片上写的比旧的确认弹窗**更多**：影响面 / 怎么撤 / 撤不回来的是什么 / 判据）。
          ★ `red` 永远到不了这里（`approve_guard` 先拦），而且引擎自己还会再验一次
            「手输确认词」—— **两道，不靠信任**。
        """
        _, payload = self.dispatch(
            "POST", f"/api/actions/{action_id}/run", {},
            {"host_id": host_id, "params": params, "confirm": bool(confirm)},
        )
        return (payload.get("data") or {}).get("task") or {}

    def _ai_decide_unrunnable(
        self, request_id: str, row: dict[str, Any], action: Any,
        exc: OpsError, by: str, *, stage: str,
    ) -> dict[str, Any]:
        """★ 人点过了，但这一步**根本没跑起来**（参数校验就拒）—— 也要落一个**明确的决定**。

        ★ 与"跑了但失败"是两件事：
          · 跑了但失败 ⇒ 有任务号、有留证，复核"没有意义"；
          · **跑不起来** ⇒ 连任务都没有，只有一条"被拒的原因"。
        ★★ 共同点：**卡片都必须离开 `pending`** ——
          "点了却像什么都没发生"是比报错更难收拾的状态（状态与事实不一致）。
        """
        from app.store import now_iso

        card = dict(row.get("card") or {})
        card["run"] = {
            "task_id": "", "status": "rejected", "verify_result": "none",
            "error": {"code": exc.code, "reason": exc.reason},
        }
        card["review"] = {
            "action_id": "", "params": {}, "pass": "", "must_fail": False, "task_id": "",
            "ok": False, "verify_result": "none", "verdict": "not_run", "proved": False,
            "basis": "★ %s**根本没跑起来**（%s：%s）⇒ 这一步没有复核可言"
                     % (stage, exc.code, exc.reason),
        }
        card["decided"] = {"at": now_iso(self.cfg), "by": by}
        self.ai.sessions.update_action_request(
            request_id,
            status="failed",
            decided_at=now_iso(self.cfg),
            decided_by=by,
            card=card,
            note="★ %s没跑起来：%s — %s" % (stage, exc.code, exc.reason),
        )
        return {
            "request_id": request_id,
            "status": "failed",
            "decided_by": by,
            "task": {},
            "review": card["review"],
            "conclusion": "★ **未证实**：%s**根本没跑起来**（%s）—— %s" % (stage, exc.code, exc.reason),
            "card": card,
        }

    def ai_request_decide(self, request_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """★★ 人在界面上按下「确认执行」的那一下（T14·S4；规范 §12.96.2 / §12.100.1）。

        ★★ 这个函数**写在 `app/api.py`、不写在 `app/ai/**`** —— 这是刻意的（开题单 §2.2 明文）：
          `app/ai/**` 里**不许出现执行层**（断言 🄌 与 ⒁ 都在看这件事）。
          AI 包里只有一张"意愿记录"；**执行发生在人点了确认之后**，而且走既有那条路。

        ★ 三段：
          ① **自检**（`approve_guard`：只许 `pending` ＋ `yellow` ＋ 在白名单里 —— 纵深防御）；
          ② **真执行**（登记任务号 —— 与界面点执行完全一样的那条路）；
          ③ **自动复核**（★ **平台发起**，不是 AI 自称；判据读**复核任务自己解析出来的字段**）。
        ★ 执行没成功时**不做复核**并写明理由 —— ✓ "复核只在已经动过手之后才有话说"。
        """
        from app.ai.requests import approve_guard, judge_review, review_plan
        from app.store import now_iso

        face = self.ai.face
        row = self.ai.request_detail(request_id)
        action = approve_guard(row, face.all_actions, face.yellow_allowlist)
        params = dict(row.get("params") or {})
        by = str(body.get("by") or "人（界面上点的确认）")

        # ② 真执行
        try:
            run_task = self._ai_run_task(action.id, row["host_id"], params, confirm=True)
        except OpsError as exc:
            # ★★ **真跑抓到的真缺陷**：变更**根本没跑起来**（参数校验就拒了）时直接抛出 ⇒
            #   卡片会**一直挂在 `pending`**，而人以为自己已经点过了（状态与事实不一致）。
            #   ⇒ 人点过的这一下必须留下一个**明确的决定**（同 §12.59 的老话：
            #     "点了却什么都没发生"比"报错"更难收拾）。
            return self._ai_decide_unrunnable(request_id, row, action, exc, by, stage="变更")
        run_ok = str(run_task.get("status")) == "ok"
        plan = review_plan(action.id, params, face.all_actions)
        review: dict[str, Any] = {
            "action_id": plan["action_id"],
            "params": plan["params"],
            "pass": plan["pass"],
            "must_fail": plan["must_fail"],
            "task_id": "",
            "ok": False,
            "verify_result": "none",
            "verdict": "not_run",
            "proved": False,
            "basis": (
                "★ 变更任务没有成功 ⇒ **复核没有意义**：先看它为什么没成"
                "（★ 复核只在「已经动过手」之后才有话说）"
            ),
        }
        if run_ok:
            try:
                review_task = self._ai_run_task(plan["action_id"], row["host_id"], plan["params"])
            except OpsError as exc:
                # ★★ 同一个坑的**另一半**（真跑抓到的）：**变更已经真的发生了**，但复核任务
                #   起不来（例如复核动作的路径参数过不了它自己的白名单）⇒
                #   绝不能抛出去把卡片留在 `pending`：要落 decided ＋ 判**未证实** ＋ 说清是谁起不来。
                review["basis"] = (
                    "★ 复核**跑不起来**（%s：%s）⇒ 按规矩判**未证实**；"
                    "★ 变更本身**已经执行过了**，请手工确认它的结果（别把「没读到」当成「没成功」）"
                    % (exc.code, exc.reason)
                )
                review["run_error"] = {"code": exc.code, "reason": exc.reason}
            else:
                steps = self.store.get_task(str(review_task.get("id")))["steps"]
                verdict = judge_review(action.id, params, plan, steps)
                review.update({
                    "task_id": str(review_task.get("id") or ""),
                    "ok": str(review_task.get("status")) == "ok",
                    "verify_result": str(review_task.get("verify_result") or "none"),
                })
                review.update(verdict)

        card = dict(row.get("card") or {})
        card["run"] = {
            "task_id": str(run_task.get("id") or ""),
            "status": str(run_task.get("status") or ""),
            "verify_result": str(run_task.get("verify_result") or "none"),
        }
        card["review"] = review
        card["decided"] = {"at": now_iso(self.cfg), "by": by}
        status = "approved" if run_ok else "failed"
        self.ai.sessions.update_action_request(
            request_id,
            status=status,
            decided_at=now_iso(self.cfg),
            decided_by=by,
            task_id=str(run_task.get("id") or ""),
            card=card,
        )
        return {
            "request_id": request_id,
            "status": status,
            "decided_by": by,
            "task": run_task,
            "review": review,
            # ★ 一句话结论：**「已证实」只有复核成立时才说得出口**（红线 10 / §12.100.1）
            "conclusion": (
                "已证实：变更做成了，而且复核读到了它（" + review.get("basis", "") + "）"
                if review.get("proved") else
                "★ **未证实**：变更任务" + ("成功了" if run_ok else "没成功")
                + "，但复核没有成立 —— " + str(review.get("basis") or "")
            ),
            "card": card,
        }

    def ai_request_reject(self, request_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """人驳回一张卡片：★ **什么都不会被执行**，只留一条"谁在什么时候驳的、为什么"。"""
        from app.store import now_iso

        row = self.ai.request_detail(request_id)
        if str(row.get("status")) != "pending":
            raise OpsError(
                code="AI_REQUEST_DECIDED",
                reason=f"这条请求已经处理过了（现在状态是 `{row.get('status')}`）",
                advice="刷新「待确认」列表。",
            )
        reason = str(body.get("reason") or "").strip()
        by = str(body.get("by") or "人（界面上点的驳回）")
        self.ai.sessions.update_action_request(
            request_id,
            status="rejected",
            decided_at=now_iso(self.cfg),
            decided_by=by,
            note=("驳回理由：" + reason) if reason else "驳回（没写理由）",
        )
        return {
            "request_id": request_id,
            "status": "rejected",
            "decided_by": by,
            "note": "★ 驳回了：**目标机上一个字节都没动**，也没有产生任务。",
        }

    # ------------------------------------------------------------------ 历史与回放

    def task_list(self, limit: int = 50) -> dict[str, Any]:
        return {"tasks": self.store.list_tasks(limit=limit)}

    def task_detail(self, task_id: str) -> dict[str, Any]:
        data = self.store.get_task(task_id)
        return {
            "task": data["task"],
            "steps": data["steps"],
            "artifacts": data["artifacts"],
            # T3：该任务的"改动前备份"记录 —— 界面据此展示并提供「恢复此文件」。
            # 历史回放与刚跑完的结果走同一个渲染器，所以两边都要有这份数据。
            "backups": self.store.list_backups(task_id=task_id),
        }

    # ------------------------------------------------------------------ 报告导出（T2 验收 #4）

    def export_task(self, task_id: str, fmt: str = "txt") -> tuple[str, str]:
        """把任务留证渲染成报告，同时归档一份到 var/artifacts/exports/。

        返回 (文件名, 报告正文)。**不走 dispatch 的 JSON 通道** ——
        报告是纯文本、要按文件下载，由 server.py 直接写原始字节
        （见 server.make_handler 的 `_text()` 与 `/api/tasks/<id>/export` 分支）。
        这样做的好处：导出能力与"动作"完全无关，新增动作不需要碰它。
        """
        detail = self.store.get_task(task_id)
        fmt = "md" if (fmt or "").lower() in ("md", "markdown") else "txt"
        text = build_report(detail, fmt)
        name = report_filename(detail, fmt)
        out_dir = self.cfg.paths.artifacts / "exports"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / name).write_text(text, encoding="utf-8")
        except OSError as exc:
            raise OpsError(
                code="STORE_ERROR",
                reason=f"导出报告归档失败：{name}",
                advice="确认 repo/var/artifacts/exports/ 目录可写、磁盘未满。",
                detail=str(exc),
            ) from exc
        return name, text

    # ------------------------------------------------------------------ 会话报告导出（T15 · §12.104）
    def export_session_report(self, session_id: str, fmt: str = "md") -> tuple[str, str]:
        """把**一次对话**渲染成一份带证据链的报告，并归档一份到 `var/artifacts/exports/`。

        ★★ 与 `export_task` 同一个形态：**不走 dispatch 的 JSON 通道** —— 报告是纯文本、
          要按文件下载，由 `server.py` 直接写原始字节（见它的 `_text()` 与那条正则分支）。
        ★★ **必须过鉴权闸门**：那条分支在 `server._handle` 的 ③ 号位置，**闸门（②）之后**
          （T14 缺陷 #1「导出通道未设防」就是位置写错造成的；断言 Ⓒ 看着这一条）。
        ★ 它**只读**：不碰目标机、不新增任务、不写 `catalog/`。
        """
        if self.ai is None:
            raise OpsError(
                code="AI_DISABLED",
                reason="AI 助手没有装载（服务可能是用旧参数启的）",
                advice="重启服务即可（bootstrap 会装载它）；或检查 config.yaml 的 ai.enabled。",
            )
        name, text = self.ai.session_report(session_id, fmt)
        out_dir = self.cfg.paths.artifacts / "exports"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / name).write_text(text, encoding="utf-8")
        except OSError as exc:
            raise OpsError(
                code="STORE_ERROR",
                reason=f"导出报告归档失败：{name}",
                advice="确认 repo/var/artifacts/exports/ 目录可写、磁盘未满。",
                detail=str(exc),
            ) from exc
        return name, text

    # ------------------------------------------------------------------ 备份与恢复（T3 · 规范 §9.1 / §9.2）
    def backup_list(self, task_id: str | None = None) -> dict[str, Any]:
        return {"backups": self.store.list_backups(task_id=task_id)}

    def backup_restore(self, backup_id: int, body: dict[str, Any]) -> dict[str, Any]:
        """把一条备份恢复回原路径（🔴 级：手输确认词，由 engine 校验并留证）。"""
        return self.engine.restore_backup(int(backup_id), str(body.get("confirm_text") or ""))

    # ------------------------------------------------------------------ 批量执行（T3 · 规范 §9.3）

    def batch_preview(self, body: dict[str, Any]) -> dict[str, Any]:
        return self.engine.batch_preview(
            str(body.get("action_id") or ""),
            [str(h) for h in (body.get("host_ids") or [])],
            body.get("params") or {},
        )

    def batch_run(self, body: dict[str, Any]) -> dict[str, Any]:
        return self.engine.batch_run(
            str(body.get("action_id") or ""),
            [str(h) for h in (body.get("host_ids") or [])],
            body.get("params") or {},
            confirm=bool(body.get("confirm")),
        )

    def batch_list(self) -> dict[str, Any]:
        return {"batches": self.store.list_batches()}

    def batch_detail(self, batch_id: str) -> dict[str, Any]:
        """批次回放。**返回结构与 engine.batch_run 完全一致** —— 前端因此只养一套渲染器。

        刻意在这里**重算**而不是存快照：算差异的口径（§9.3 按「任务状态 + 自证结果」分组、
        不比对含 PID/时间戳的结论文本）只存在于 engine.batch_diff 一处。存快照意味着
        口径一改就要改两个地方，而且旧快照会拿过期口径骗后来的人。
        """
        data = self.store.get_batch(batch_id)
        b, tasks = data["batch"], data["tasks"]
        results: list[dict[str, Any]] = []
        for t in tasks:
            err = None
            if t.get("error_reason"):
                err = {
                    "code": t.get("error_code"),
                    "reason": t.get("error_reason"),
                    "advice": t.get("error_advice"),
                }
            results.append({
                "host_id": t.get("host_id"),
                "host_name": t.get("host_name") or t.get("host_id"),
                "task_id": t.get("id"),
                "status": t.get("status"),
                "conclusion": t.get("conclusion") or "",
                "verify_result": t.get("verify_result") or "none",
                "duration_ms": t.get("duration_ms") or 0,
                "step_total": t.get("step_total") or 0,
                "step_failed": t.get("step_failed") or 0,
                "error": err,
            })
        return {
            "batch_id": b.get("id"),
            "action_id": b.get("action_id"),
            "action_title": b.get("action_title"),
            "status": b.get("status"),
            "results": results,
            "diff": self.engine.batch_diff(results),
            "replayed": True,
        }

    # ------------------------------------------------------------------ 覆盖率对账

    # ------------------------------------------------------------------ 一键体检（T4 · 规范 §10.2）

    def checkup_run(self, body: dict[str, Any]) -> dict[str, Any]:
        """跑体检：**多台复用批量框架**，单台直接跑；然后逐台做判定。

        为什么多台要复用批量：开题单 §3.3 要求"单机与 4 台并排"，而批量已经有
        并发、失败隔离、批次留证、横向对比 —— 没有理由再写一套。
        单台**刻意不进批量**：只体检一台机器却在「批次」页留下一条记录，是噪声。
        """
        host_ids = [str(h) for h in (body.get("host_ids") or [])]
        if not host_ids:
            raise OpsError(
                code="PARAM_MISSING",
                reason="没有选择任何目标机",
                advice="至少勾选一台机器再体检（可多选，4 台会并排给出）。",
            )
        rows: list[dict[str, Any]] = []
        batch_id: str | None = None
        status = "ok"
        diff: dict[str, Any] | None = None

        if len(host_ids) == 1:
            hid = host_ids[0]
            try:
                r = self.engine.run(CHECKUP_ACTION_ID, hid, {})
                rows = [{"host_id": hid, "host_name": r.host.name, "task_id": r.id, "error": None}]
                status = r.status
            except OpsError as exc:
                rows = [{"host_id": hid, "host_name": hid, "task_id": None, "error": exc.to_dict()}]
                status = "failed"
        else:
            batch = self.engine.batch_run(CHECKUP_ACTION_ID, host_ids, {})
            batch_id = batch.get("batch_id")
            status = str(batch.get("status") or "")
            diff = batch.get("diff")
            rows = [
                {"host_id": x.get("host_id"), "host_name": x.get("host_name"),
                 "task_id": x.get("task_id"), "error": x.get("error")}
                for x in (batch.get("results") or [])
            ]
            # ★ 批量结果来自线程池，**顺序不保证**（实测 node02 会排在 node01 前面）。
            #   4 台并排的报告必须按"用户勾选的顺序"排，否则对比表看起来是乱的。
            order = {hid: i for i, hid in enumerate(host_ids)}
            rows.sort(key=lambda r: order.get(str(r.get("host_id")), len(order)))

        reports: list[dict[str, Any]] = []
        for row in rows:
            tid = row.get("task_id")
            if not tid:
                reports.append({
                    "task_id": None,
                    "host": {"id": row.get("host_id"), "name": row.get("host_name")},
                    "overall": "unknown", "overall_icon": "⚠️",
                    "summary": "体检未执行（这台机器不可达或执行失败）",
                    "counts": {"crit": 0, "warn": 0, "ok": 0, "unknown": 0},
                    "items": [], "error": row.get("error"),
                })
                continue
            try:
                reports.append(judge_checkup(self.cfg, self.store, str(tid), self.actions))
            except OpsError as exc:
                reports.append({
                    "task_id": tid,
                    "host": {"id": row.get("host_id"), "name": row.get("host_name")},
                    "overall": "unknown", "overall_icon": "⚠️",
                    "summary": f"判定失败：{exc.reason}",
                    "counts": {"crit": 0, "warn": 0, "ok": 0, "unknown": 0},
                    "items": [], "error": exc.to_dict(),
                })

        agg = {
            lv: sum(int((rp.get("counts") or {}).get(lv, 0)) for rp in reports)
            for lv in ("crit", "warn", "ok", "unknown")
        }
        worst = "crit" if agg["crit"] else ("warn" if agg["warn"] else ("ok" if agg["ok"] else "unknown"))
        return {
            "batch_id": batch_id,
            "action_id": CHECKUP_ACTION_ID,
            "action_title": (self.actions.get(CHECKUP_ACTION_ID).title
                             if CHECKUP_ACTION_ID in self.actions else "一键体检"),
            "status": status,
            "hosts_total": len(reports),
            "aggregate": agg,
            "worst": worst,
            "reports": reports,
            "diff": diff,
            "thresholds": (reports[0].get("thresholds") if reports else None),
        }

    def checkup_report(self, task_id: str) -> dict[str, Any]:
        return {"report": judge_checkup(self.cfg, self.store, task_id, self.actions)}

    def checkup_export(self, task_id: str, fmt: str = "md", *, archive: bool = True) -> tuple[str, str]:
        """体检报告导出。**不走 dispatch 的 JSON 通道**（与任务报告同一个模式）。

        返回 (文件名, 报告正文)；同时归档一份到 `var/artifacts/exports/`。
        ★ 与「导出任务报告」互补：那条通道铺步骤与原始输出，这条只铺结论与判定。
        """
        report = judge_checkup(self.cfg, self.store, task_id, self.actions)
        fmt = "txt" if (fmt or "").lower() == "txt" else "md"
        text = build_checkup_report(report, fmt)
        name = checkup_report_filename(report, fmt)
        if archive:
            out_dir = self.cfg.paths.artifacts / "exports"
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / name).write_text(text, encoding="utf-8")
            except OSError as exc:
                raise OpsError(
                    code="STORE_ERROR",
                    reason=f"体检报告归档失败：{name}",
                    advice="确认 repo/var/artifacts/exports/ 目录可写、磁盘未满。",
                    detail=str(exc),
                ) from exc
        return name, text

    # ------------------------------------------------------------------ 主机纳管（T4 · 规范 §10.1）

    def _enroll_ttl(self) -> int:
        try:
            return int((self.cfg.raw.get("enroll") or {}).get("dispatch_ttl_sec") or 120)
        except (TypeError, ValueError):
            return 120

    def _enroll_verify_max(self) -> int:
        """生效校验最多探测几次。

        ★ 为什么要设上限（T4 反例实测逼出来的）：
          第一版把"校验失败"也当成继续等待，于是每 3 秒探测一次、一直探到 120 秒超时 ——
          ① 用户要等两分钟才被告知"公钥写错了"；② 45 次失败登录会把目标机日志刷满。
          现在：探测有上限；认证被拒（permission denied）连续 2 次就**立即判失败**，
          因为"钥匙不对"这件事不会因为多等一会儿而变好。
        """
        try:
            return max(1, int((self.cfg.raw.get("enroll") or {}).get("verify_max_attempts") or 5))
        except (TypeError, ValueError):
            return 5

    def _enroll_auth_fail_limit(self) -> int:
        try:
            return max(1, int((self.cfg.raw.get("enroll") or {}).get("verify_auth_fail_limit") or 2))
        except (TypeError, ValueError):
            return 2

    @staticmethod
    def _derive_host_id(name: str, address: str, taken: set[str]) -> str:
        base = re.sub(r"[^a-z0-9_-]+", "-", (name or "").strip().lower()).strip("-")
        if not base:
            base = "host-" + str(address).rsplit(".", 1)[-1]
        cand, n = base, 2
        while cand in taken:
            cand = f"{base}-{n}"
            n += 1
        return cand

    def enroll_start(self, body: dict[str, Any]) -> dict[str, Any]:
        """纳管第 1~2 步：预检 + 起**一次性分发点**，把"那一条命令"交给用户。"""
        address = str(body.get("address") or "").strip()
        if not address:
            raise OpsError(code="PARAM_MISSING", reason="没有填 IP 地址",
                           advice="填目标机的地址（例如 192.0.2.70），不要填主机名。")
        try:
            port = int(body.get("port") or 22)
        except (TypeError, ValueError):
            raise OpsError(code="PARAM_INVALID", reason="端口必须是数字", advice="一般填 22。") from None
        user = str(body.get("user") or "root").strip() or "root"
        name = str(body.get("name") or "").strip() or address
        role = str(body.get("role") or "lab").strip() or "lab"
        note = str(body.get("note") or "").strip()
        force = bool(body.get("force"))
        raw_tags = body.get("tags")
        tags = ([t.strip() for t in raw_tags] if isinstance(raw_tags, list)
                else [t.strip() for t in str(raw_tags or "").split(",")])
        tags = [t for t in tags if t and "," not in t][:6]

        taken = {h.id for h in self.cfg.hosts}
        host_id = str(body.get("host_id") or "").strip() or self._derive_host_id(name, address, taken)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", host_id):
            raise OpsError(
                code="PARAM_INVALID",
                reason=f"id「{host_id}」不合法",
                advice="只允许小写字母、数字、短横线与下划线，且以字母或数字开头。",
            )
        if role not in enroll_mod.ROLE_WHITELIST:
            raise OpsError(
                code="PARAM_INVALID",
                reason=f"角色「{role}」不在白名单里",
                advice=f"允许值：{'、'.join(enroll_mod.ROLE_WHITELIST)}（规范 §10.1.5）。",
            )

        # ── 第 1 步：预检
        pre = enroll_mod.precheck(self.cfg, address=address, port=port, host_id=host_id, force=force)
        if not pre["reachable"]:
            raise OpsError(
                code="HOST_UNREACHABLE",
                reason=f"{address}:{port} 连不上（纳管预检第 1 步就失败）",
                advice="确认这台机器已开机、IP 没错、sshd 在运行，并且和管理机在同一网段。",
                detail=pre["connect_detail"],
            )
        if pre["duplicate_blocking"]:
            raise OpsError(
                code="HOST_EXISTS",
                reason=f"这台机器已经纳管过了：{'；'.join(pre['duplicate'])}",
                advice="如果确实是同一台机器，不必重复纳管；确实要覆盖，就勾选「强制覆盖」。",
                context=pre,
            )

        # ── 第 2 步：起一次性分发点（内部含"随机路径 + 一次性 token"）
        sess = enroll_mod.EnrollSession(
            self.cfg, address=address, port=port, user=user, host_id=host_id, name=name,
            role=role, tags=tags, note=note, ttl=self._enroll_ttl(),
        )
        sess.trace = [{"step": "预检", "ok": True,
                       "detail": f"{address}:{port} 可达；未发现重复登记"}]
        sess.start()
        sess.trace.append({"step": "铺公钥 · 分发点已就绪", "ok": True,
                           "detail": f"绑定 {sess.bind_host}:{sess.bind_port}（仅内网）· "
                                     f"随机路径 {sess.url_path} · 一次性 token · 存活上限 {sess.ttl}s"})
        self._enroll[sess.id] = sess
        enroll_mod.write_evidence(self.cfg, sess)
        return {"session": sess.to_public(), "precheck": pre}

    def enroll_status(self, session_id: str) -> dict[str, Any]:
        """纳管第 3~5 步的状态推进：**轮询校验 → 关停分发点 → 登记 → 立刻体检**。

        ★ 只在"公钥已被取走"之后才做密钥登录探测：
          否则每 3 秒一次 × 40 次的失败登录会把目标机的日志刷满（而且毫无意义）。
        ★ 生效校验 = 真登录跑三条探针（规范 §10.1.4），不接受"文件写进去了"。
        """
        sess = self._get_enroll(session_id)
        sess.trace = getattr(sess, "trace", [])

        if sess.state == "waiting" and sess.served > 0:
            max_try = self._enroll_verify_max()
            auth_limit = self._enroll_auth_fail_limit()
            if getattr(sess, "verify_attempts", 0) < max_try:
                sess.verify_attempts = getattr(sess, "verify_attempts", 0) + 1
                ok, detail = enroll_mod.verify_key(self.cfg, sess)
                first = (detail.get("probes") or [{}])[0]
                err = detail.get("error") or {}
                code = err.get("code")
                if ok:
                    vals = " ｜ ".join(f"{p['cmd']}={p.get('value')}" for p in detail["probes"])
                    sess.trace.append({
                        "step": "生效校验（真登录）", "ok": True,
                        "detail": f"第 {sess.verify_attempts} 次探测通过：{vals}",
                    })
                    sess.state = "verified"
                    sess.stop("密钥登录校验通过 → 分发点立即关停")
                    sess.trace.append({"step": "关停分发点", "ok": True, "detail": sess.port_closed_proof})

                    # ── 第 4 步：登记（写前备份 + 写后 bootstrap 校验 + 不过就回滚）
                    reg = enroll_mod.register(self.cfg, sess)
                    sess.backup_path = reg.get("backup")
                    if reg.get("ok"):
                        n = enroll_mod.reload_hosts(self.cfg)
                        sess.trace.append({
                            "step": "写入 hosts.yaml", "ok": True,
                            "detail": f"写前备份 {reg.get('backup')}；写后 bootstrap 校验通过；当前清单 {n} 台",
                        })
                        sess.state = "registered"
                        # ── 第 5 步：立刻体检（失败不影响纳管结论）
                        try:
                            r = self.engine.run(CHECKUP_ACTION_ID, sess.host_id, {})
                            sess.checkup_task = r.id
                            sess.state = "checked"
                            sess.trace.append({"step": "自动体检", "ok": True,
                                               "detail": f"体检任务 {r.id}（{r.duration_ms} ms）"})
                        except OpsError as exc:
                            sess.checkup_error = exc.to_dict()
                            sess.trace.append({"step": "自动体检", "ok": False,
                                               "detail": f"{exc.reason}（纳管本身已成功）"})
                    else:
                        sess.state = "failed"
                        sess.error = reg.get("error") or {"reason": reg.get("reason")}
                        sess.trace.append({"step": "写入 hosts.yaml", "ok": False,
                                           "detail": str(reg.get("reason"))})
                else:
                    note = (f"[{code or '校验未通过'}] {err.get('reason') or first.get('stderr') or '（无 stderr）'}")
                    sess._verify_note = note
                    auth_fail = code == "SSH_AUTH_FAILED"
                    sess._auth_fail_streak = (getattr(sess, "_auth_fail_streak", 0) + 1) if auth_fail else 0
                    if not getattr(sess, "_verify_logged", False):
                        sess._verify_logged = True
                        sess.trace.append({
                            "step": "生效校验（真登录）", "ok": False,
                            "detail": f"第 {sess.verify_attempts} 次探测没通过：{note}"
                                      f"（最多探测 {max_try} 次；认证被拒连续 {auth_limit} 次即判失败）",
                        })
                    exhausted = (sess.verify_attempts >= max_try
                                 or getattr(sess, "_auth_fail_streak", 0) >= auth_limit)
                    if exhausted:
                        # ★ 判定失败：明确告诉他卡在哪一步、什么原因、怎么排查（规范 §10.1.4）
                        sess.state = "failed"
                        sess.stop("生效校验失败 → 关停分发点")
                        sess.error = {
                            "code": code or "ENROLL_VERIFY_FAILED",
                            "reason": f"卡在第 3 步（生效校验）：{err.get('reason') or note}",
                            "advice": (str(err.get("advice") or "")
                                       + " 也可以直接重新点一次「纳管新主机」——重新分发一次公钥。").strip(),
                            "detail": first.get("stderr") or "",
                        }
                        sess.trace.append({
                            "step": "生效校验（真登录）", "ok": False,
                            "detail": f"判定失败（探测 {sess.verify_attempts}/{max_try} 次）：{note}",
                        })
                        sess.trace.append({"step": "关停分发点", "ok": True, "detail": sess.port_closed_proof})
            elif sess.state == "waiting":
                # 探测次数用尽但还没到超时：给一条明确的结论，不要让人干等
                sess.state = "failed"
                sess.stop("探测次数用尽 → 关停分发点")
                sess.error = {
                    "code": "ENROLL_VERIFY_EXHAUSTED",
                    "reason": f"生效校验探测 {max_try} 次都没成功：{getattr(sess, '_verify_note', '')}",
                    "advice": "确认目标机上那条命令真的执行成功了（curl 有没有报错），"
                              "以及 ~/.ssh/authorized_keys 是否写入了新的公钥行。",
                }

        data = sess.to_public()
        data["trace"] = sess.trace
        data["backup"] = getattr(sess, "backup_path", None)
        data["checkup_task"] = getattr(sess, "checkup_task", None)
        data["checkup_error"] = getattr(sess, "checkup_error", None)
        data["verify_note"] = getattr(sess, "_verify_note", "")
        if sess.state == "checked" and getattr(sess, "checkup_task", None):
            try:
                data["report"] = judge_checkup(self.cfg, self.store, sess.checkup_task, self.actions)
            except OpsError:
                data["report"] = None
        enroll_mod.write_state(self.cfg, sess, {k: v for k, v in data.items() if k != "report"})
        return data

    def enroll_abort(self, session_id: str) -> dict[str, Any]:
        sess = self._get_enroll(session_id)
        sess.stop("用户主动取消")
        if sess.state in ("waiting", "verified"):
            sess.state = "aborted"
        enroll_mod.write_evidence(self.cfg, sess)
        return {"session": sess.to_public(), "trace": getattr(sess, "trace", [])}

    def _get_enroll(self, session_id: str) -> Any:
        sess = self._enroll.get(session_id)
        if sess is None:
            raise OpsError(
                code="ENROLL_SESSION_GONE",
                reason=f"找不到纳管会话 {session_id}（可能服务重启过，或会话早已结束）",
                advice="重新点一次「纳管新主机」。",
            )
        return sess

    def coverage(self) -> dict[str, Any]:
        return {"coverage": reconcile(self.map_data, self.actions)}

    # ------------------------------------------------------------------ 配方（T5 · 规范 §12）

    def _runner(self) -> RecipeRunner:
        if self.runner is None:
            raise OpsError(
                code="RECIPE_INVALID",
                reason="配方引擎未装载",
                advice="跑 python -m app.server --check 看具体是哪份配方/模板不合格，改正后重启服务。",
            )
        return self.runner

    def _need_host(self, body: dict[str, Any]) -> str:
        host_id = str(body.get("host_id") or "")
        if not host_id:
            raise OpsError(
                code="PARAM_MISSING",
                reason="没有指定目标机",
                advice="在界面左上角选择一台目标机。",
            )
        return host_id

    def recipe_list(self) -> dict[str, Any]:
        r = self._runner()
        # ★ T7（规范 §12.17）：装载结果**必须随列表一起给出去** ——
        #   "装了几份 / 哪几份没装进来 / 为什么"是这一层的规定动作，不许静默少装载。
        return {"recipes": r.list_public(), "load": r.load_report.to_public()}

    def recipe_reload(self) -> dict[str, Any]:
        """显式重载磁盘上的配方（规范 §12.17）—— 写一份新配方**不用重启控制台**。

        ★ 走的是与启动时**同一套**装载期校验（重载不是绕过宪法 1 的后门）；
        ★ 正在执行的那一次**不受影响**（它在开始时就把自己那份定义拿在手里）；
        ★ 返回装载报告：装了几份、哪几份没装进来、为什么。
        """
        r = self._runner()
        report = r.reload()
        return {"load": report.to_public(), "recipes": r.list_public()}

    def recipe_detail(self, recipe_id: str) -> dict[str, Any]:
        return {"recipe": self._runner().recipe(recipe_id).to_public()}

    def recipe_lint(self, recipe_id: str) -> dict[str, Any]:
        """配方体检（T7·S5 · 规范 §12.21）：**不连目标机**的静态检查 ——
        让"自己写配方"的人在点部署**之前**就知道哪几处还欠着。"""
        from app.recipe import lint_recipe, lint_summary
        r = self._runner().recipe(recipe_id)
        return {"recipe_id": r.id, "recipe_title": r.name,
                "lint": lint_summary(lint_recipe(r, self.actions))}

    def recipe_plan(self, recipe_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._runner().plan(
            recipe_id, self._need_host(body), body.get("params") or {},
            str(body.get("mode") or "deploy"),
        )

    def recipe_probe(self, recipe_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """只读地看一眼"这个服务现在是什么状态"（跑健康检查那几条期望，不改任何东西）。"""
        return self._runner().probe(recipe_id, self._need_host(body), body.get("params") or {})

    def recipe_run(self, recipe_id: str, body: dict[str, Any]) -> dict[str, Any]:
        run = self._runner().run(
            recipe_id, self._need_host(body), body.get("params") or {},
            mode=str(body.get("mode") or "deploy"),
            confirm=bool(body.get("confirm")),
            confirm_text=str(body.get("confirm_text") or ""),
        )
        return run.to_public()

    def recipe_runs(self, limit: int = 20) -> dict[str, Any]:
        return {"runs": self.store.list_recipe_runs(limit=max(1, min(int(limit), 200)))}

    # ---------------------------------------------------------- 部署组回退（T7·S4 · 规范 §12.20）

    def recipe_rollback_plan(self, run_id: str) -> dict[str, Any]:
        """「回到这次部署前」的**逐项**计划（只读）：哪一项 / 从哪个备份 / 期望 sha256 /
        能不能回去 / ★ 哪些**回不去**（四类，空也写「无」）。"""
        return self._runner().rollback_plan(run_id)

    def recipe_rollback(self, run_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """逐项恢复（🔴：手输确认词）。★ 一次失败不拖垮其它项，结果逐项回。"""
        ids = body.get("backup_ids")
        return self._runner().rollback_run(
            run_id, str(body.get("confirm_text") or ""),
            [int(x) for x in ids] if isinstance(ids, list) and ids else None,
        )

    # ---------------------------------------------------------- 配方批量（T7·S6 · 规范 §12.18）

    def _host_ids(self, body: dict[str, Any]) -> list[str]:
        raw = body.get("host_ids") or body.get("hosts") or []
        if not isinstance(raw, list) or not raw:
            raise OpsError(code="PARAM_MISSING", reason="没有选目标机",
                           advice="在批量弹窗里勾选至少一台机器。")
        return [str(x) for x in raw]

    def recipe_batch_plan(self, recipe_id: str, body: dict[str, Any], mode: str) -> dict[str, Any]:
        """批量预检（只读）：闸门放不放行 + 每台是什么。"""
        return self._runner().batch_plan(recipe_id, self._host_ids(body), mode=mode)

    def recipe_batch_run(self, recipe_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._runner().batch_run(
            recipe_id, self._host_ids(body), body.get("params") or {},
            mode=str(body.get("mode") or "deploy"),
            confirm=bool(body.get("confirm")),
            confirm_text=str(body.get("confirm_text") or ""),
        )

    def recipe_run_detail(self, run_id: str) -> dict[str, Any]:
        return {"run": self.store.get_recipe_run(run_id)}

    # ------------------------------------------------------------------ 路由

    # ------------------------------------------------------------------ AI 助手面（T12）
    def _ai_route(self, method: str, path: str, body: dict[str, Any],
                  query: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        """`/api/ai/**` 的唯一实现（规范 §12.74）。

        ★ AI 与点击**同权**：这一层自己不执行任何东西 —— 它调的是 `self.dispatch`
          （= 界面点按钮走的那一个函数）。**没有第二条路。**
        ★ 工具面里**没有** `confirm_text` 通道：结构上没有（§12.74.2），不是"约定了不传"。
        """
        if self.ai is None:
            raise OpsError(
                code="AI_DISABLED",
                reason="AI 助手没有装载（服务可能是用旧参数启的）",
                advice="重启服务即可（bootstrap 会装载它）；或检查 config.yaml 的 ai.enabled。",
            )
        if method == "GET":
            if path == "/api/ai/status":
                return 200, {"ok": True, "data": self.ai.status()}
            if path == "/api/ai/tools":
                return 200, {"ok": True, "data": self.ai.tools()}
            if path == "/api/ai/sessions":
                return 200, {"ok": True, "data": self.ai.session_list()}
            m = re.fullmatch(r"/api/ai/sessions/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.ai.session_detail(m.group(1))}
            # ── ★★ T15·S2/S3：报告清单 ＋ 本地知识检索（§12.104 / §12.106）──────
            # ★ 两条都在 **GET** 分支里（它们都只读；★ 报告正文的导出走 server.py 的
            #   纯文本通道 —— 与单任务报告同一条路，同样在鉴权闸门之后）。
            if path == "/api/ai/reports":
                return 200, {"ok": True, "data": self.ai.report_list()}
            if path == "/api/ai/knowledge":
                q = str((query or {}).get("q") or "")
                if not q.strip():
                    raise OpsError(
                        code="AI_EMPTY_QUERY",
                        reason="知识检索的问句是空的",
                        advice="带上问句：`GET /api/ai/knowledge?q=磁盘满了`。",
                    )
                try:
                    klimit = int((query or {}).get("limit", "20"))
                except ValueError:
                    klimit = 20
                return 200, {"ok": True, "data": self.ai.knowledge_search(q, max(1, min(klimit, 100)))}
            # ★ T13：选域命中率（**本地账**，规范 §12.92 —— 它绝不进外发 payload）
            if path == "/api/ai/hitrate":
                return 200, {"ok": True, "data": self.ai.hitrate()}
            # ── ★★ T14·S3/S4：变更"请求"的**待确认队列**（规范 §12.96.2）────────
            # ★ 读队列在这一层；"执行"是**人点确认之后**才发生（`/approve` ⇒ 走既有那条路）。
            if path == "/api/ai/requests":
                return 200, {"ok": True, "data": self.ai.requests_list()}
            m = re.fullmatch(r"/api/ai/requests/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.ai.request_detail(m.group(1))}
        if method == "POST":
            if path == "/api/ai/key":
                return 200, {"ok": True, "data": self.ai.set_key(body)}
            if path == "/api/ai/key/clear":
                return 200, {"ok": True, "data": self.ai.clear_key()}
            if path == "/api/ai/ask":
                return 200, {"ok": True, "data": self.ai.ask(body)}
            # ★ 这一条存在的意义是"**能被反例打**"：拿 yellow/red 打进来必须被拒（验收 #4）
            if path == "/api/ai/tool-call":
                return 200, {"ok": True, "data": self.ai.tool_call(body)}
            # ★★ T14·S3：变更"请求"的手工通道 —— 同上，**存在的意义是能被反例打**：
            #    验收 ②a 要 `pkg.remove`（red）与 `k8s.exec`（白名单外的 yellow）都被拒，
            #    而且**说清该去哪儿办**（§12.99.3）。
            if path == "/api/ai/request-action":
                return 200, {"ok": True, "data": self.ai.request_action(body)}
            # ★★ T14·S4：**人点确认**的那两下 —— 执行只从这里发生（规范 §12.96.2 规矩 1）。
            #   ★ `/approve` 走**既有**那条执行路（和界面点「执行」同一个入口）；
            #   ★ `/reject` **什么都不执行**，只留一条"谁在什么时候驳的、为什么"。
            m = re.fullmatch(r"/api/ai/requests/([^/]+)/(approve|reject)", path)
            if m:
                rid, act = m.group(1), m.group(2)
                if act == "approve":
                    return 200, {"ok": True, "data": self.ai_request_decide(rid, body)}
                return 200, {"ok": True, "data": self.ai_request_reject(rid, body)}
            if path == "/api/ai/tools/export":
                return 200, {"ok": True, "data": self.ai.export_tools()}
            # ── ★★ T15·S3：生成 Recipe **候选草案**（规范 §12.107）─────────────
            # ★★ 它是 **POST**（会往 `var/lab/recipes-candidate/` 写文件）——
            #   ★ 而它**不在工具面里**：AI 侧没有这条通道，只有人能点（§12.107.3）。
            if path == "/api/ai/recipes/candidates":
                try:
                    ms = int(body.get("min_support") or 2)
                    ml = int(body.get("min_len") or 3)
                except (TypeError, ValueError):
                    raise OpsError(
                        code="PARAM_INVALID",
                        reason="min_support / min_len 必须是整数",
                        advice="不填就用默认（支持度 ≥ 2、序列长度 ≥ 3）。",
                    ) from None
                return 200, {"ok": True, "data": self.ai.recipe_candidates(
                    min_support=max(2, ms), min_len=max(2, ml))}
        raise OpsError(
            code="NO_SUCH_ROUTE",
            reason=f"没有这个接口：{method} {path}",
            advice=(
                "AI 面只有：GET status/tools/sessions[<id>]/hitrate/requests[<id>]/reports/knowledge · "
                "POST key / key-clear / ask / tool-call / request-action / "
                "requests/<id>/approve|reject / recipes/candidates / tools-export。"
            ),
        )

    # ------------------------------------------------------------------ 鉴权面（T14）

    def _auth_route(self, method: str, path: str, body: dict[str, Any],
                    ctx: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """登录 / 登出 / 改口令 / 自述。

        ★ 与 `_ai_route` 同一个形态：**这一层自己不执行任何东西**，只碰 `self.auth`。
        ★ `ctx` 由 HTTP 层带进来（`token` / `client`）—— 因为**闸门在 server.py**（§12.97.2），
          本层拿不到令牌，只能收下它。
        """
        auth = self.auth
        client = str(ctx.get("client") or "-")
        token = ctx.get("token") or None

        if path == "/api/auth":
            # ★ 这一条不是给前端调的，是**接口索引**：前端源码里写 `/api/auth/` 前缀时，
            #   `tools/selftest.py` 的「路由对账」会把 `/api/auth` 抽成一个端点点位 ——
            #   这里认领它，"有端点没人认领"就不会误报（§9.9 的口径：接口要登记在 dispatch）。
            # ★ 它**不在**免鉴权白名单里，所以未登录时看不到（只有已登录的人/脚本能读）。
            return 200, {"ok": True, "data": {
                "endpoints": [
                    "GET  /api/auth/ping      （免鉴权：探活 + 策略与边界）",
                    "GET  /api/auth/status    （已鉴权：策略自述 + 本会话）",
                    "POST /api/auth/setup     （免鉴权，**仅首次**：设置口令）",
                    "POST /api/auth/login     （免鉴权：登录取令牌）",
                    "POST /api/auth/logout    （已鉴权：吊销令牌）",
                    "POST /api/auth/password  （已鉴权：改口令，需验旧口令）",
                ],
                **auth.public_policy(),
            }}

        if method == "GET":
            if path == "/api/auth/ping":
                # ★ **免鉴权**（server 的白名单里唯一一个 GET）—— 只回答两件事：
                #   "服务活着吗" ＋ "设过口令没有"（界面要靠后者决定显示"设置"还是"登录"）。
                #   ★ 刻意**不回答**第三件事：绝不吐主机名 / IP / 拓扑 / 库规模（那在 /api/health 里）。
                return 200, {"ok": True, "data": {
                    "service": "auto-ops-console",
                    "version": __version__,
                    "stage": __stage__,
                    "configured": bool(auth.configured),
                    "setup_allowed": bool(auth.setup_allowed),
                    "store_broken": bool(auth.store_broken),
                    # ── ★ T15：**构建指纹**（§12.108.2）──────────────────────
                    # ★ 为什么放在这条免鉴权接口里：它要回答的正是
                    #   「**在跑的是哪个构建**」—— 而这个问题常常出现在"还登不上去"的时候
                    #   （T13 的坑就是"新接口 404，看不出是没启动还是旧进程"）。
                    # ★★ 它**只有文件名与哈希**：不含内容、不含凭据、不含主机信息
                    #   （红线 8 同源）；也**不进**任何给模型看的 payload（§12.108.3）。
                    "build": {
                        "source_short": self.fingerprint.get("short", ""),
                        "files": self.fingerprint.get("files", 0),
                        "algo": self.fingerprint.get("algo", ""),
                    },
                    # ★ 带上策略与**边界自述**：登录前就该看得见"这道门能防什么、不能防什么"
                    #   （§12.97.4）。★ 里面**不含**任何机器私有信息（那在 /api/health 里，已鉴权）。
                    **auth.public_policy(),
                }}
            if path == "/api/auth/status":
                data = auth.status()
                data["this_session"] = auth.session_info(token)
                return 200, {"ok": True, "data": data}

        if method == "POST":
            if path == "/api/auth/setup":
                pw = str(body.get("password") or "")
                res = auth.set_password(pw)
                # 设完直接发牌，省一次往返（★ 这一步只在"从未设过口令"时可达）
                issued = auth.login(pw, client)
                return 200, {"ok": True, "data": {**res, **issued, "first_run": True}}
            if path == "/api/auth/login":
                return 200, {"ok": True, "data": auth.login(str(body.get("password") or ""), client)}
            if path == "/api/auth/logout":
                if body.get("all"):
                    return 200, {"ok": True, "data": {"revoked": auth.revoke_all()}}
                return 200, {"ok": True, "data": {"revoked": 1 if auth.logout(token) else 0}}
            if path == "/api/auth/password":
                res = auth.change_password(
                    str(body.get("old_password") or ""),
                    str(body.get("new_password") or ""),
                )
                revoked = auth.revoke_all()
                issued = auth.login(str(body.get("new_password") or ""), client)
                return 200, {"ok": True, "data": {**res, "revoked": revoked, **issued}}

        raise OpsError(
            code="NO_SUCH_ROUTE",
            reason=f"没有这个接口：{method} {path}",
            advice="鉴权面只有：GET ping / status · POST setup / login / logout / password。",
        )

    def dispatch(self, method: str, path: str, query: dict[str, str], body: dict[str, Any] | None,
                 ctx: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        body = body or {}
        path = path.rstrip("/") or "/"
        # ★ T14：`ctx` 只给 HTTP 层用（带令牌与来源 IP）。**AI 面永远不传它** ——
        #   这是刻意的：AI 侧连"自己在用哪个令牌"都不该知道（§12.99.2 同源）。
        ctx = ctx or {}

        # ── T14：鉴权面（最小鉴权；规范 §12.97）──────────────────────────
        if path == "/api/auth" or path.startswith("/api/auth/"):
            return self._auth_route(method, path, body, ctx)

        # ── T12：AI 助手面（唯一入口；内部仍走本函数，铁律 8）──────────────
        if path == "/api/ai" or path.startswith("/api/ai/"):
            # ★ T15·S3：把 query 一起递进去（知识检索是 GET，问句在 URL 上）
            return self._ai_route(method, path, body, query)

        if method == "GET":
            if path == "/api/health":
                return 200, {"ok": True, "data": self.health()}
            if path == "/api/hosts":
                return 200, {"ok": True, "data": self.hosts()}
            if path == "/api/actions":
                return 200, {"ok": True, "data": self.action_list()}
            if path == "/api/coverage":
                return 200, {"ok": True, "data": self.coverage()}
            # T4：体检报告（按任务 ID 取判定结果；导出走 server.py 的纯文本通道）
            m = re.fullmatch(r"/api/checkup/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.checkup_report(m.group(1))}
            # T5：配方（服务目录）
            if path == "/api/recipes":
                return 200, {"ok": True, "data": self.recipe_list()}
            if path == "/api/recipe-runs":
                try:
                    rlimit = int(query.get("limit", "20"))
                except ValueError:
                    rlimit = 20
                return 200, {"ok": True, "data": self.recipe_runs(rlimit)}
            m = re.fullmatch(r"/api/recipe-runs/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_run_detail(m.group(1))}
            # ★ T7·S4：部署组回退的逐项计划（只读）。★ 必须走在上面那条 `([^/]+)` **之前/之外** ——
            #   后者只匹配"单段路径"，长路径本来就不会被它吃掉；写在这里是为了**读起来不靠推断**。
            m = re.fullmatch(r"/api/recipe-runs/([^/]+)/rollback-plan", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_rollback_plan(m.group(1))}
            m = re.fullmatch(r"/api/recipes/([^/]+)/lint", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_lint(m.group(1))}
            m = re.fullmatch(r"/api/recipes/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_detail(m.group(1))}
            # T4：纳管会话状态（界面每 3 秒轮询一次；状态推进在这里面完成）
            m = re.fullmatch(r"/api/enroll/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.enroll_status(m.group(1))}
            if path == "/api/tasks":
                try:
                    limit = int(query.get("limit", "50"))
                except ValueError:
                    limit = 50
                return 200, {"ok": True, "data": self.task_list(max(1, min(limit, 500)))}

            if path == "/api/backups":
                return 200, {"ok": True, "data": self.backup_list(query.get("task_id") or None)}
            if path == "/api/batches":
                return 200, {"ok": True, "data": self.batch_list()}
            m = re.fullmatch(r"/api/batches/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.batch_detail(m.group(1))}
            m = re.fullmatch(r"/api/actions/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.action_detail(m.group(1))}
            m = re.fullmatch(r"/api/tasks/([^/]+)", path)
            if m:
                return 200, {"ok": True, "data": self.task_detail(m.group(1))}

        if method == "POST":
            # T4：主机纳管（平台能力 —— 起分发点 / 轮询校验 / 登记 / 体检）
            if path == "/api/enroll/start":
                return 200, {"ok": True, "data": self.enroll_start(body)}
            m = re.fullmatch(r"/api/enroll/([^/]+)/abort", path)
            if m:
                return 200, {"ok": True, "data": self.enroll_abort(m.group(1))}
            # T4：一键体检（多台走批量框架；单台直接跑）
            if path == "/api/checkup/run":
                return 200, {"ok": True, "data": self.checkup_run(body)}
            # T5：配方（计划预览 / 现状探测 / 执行 —— 三种模式共用一条 run 路由）
            # ★ T7：重载配方（规范 §12.17）。★ 必须放在 `/api/recipes/<id>/…` 那几条**之前**，
            #   否则 "reload" 会被当成一个配方 id 吃掉（"接口存在但被别的路由截胡"是这一层的老坑）。
            if path == "/api/recipes/reload":
                return 200, {"ok": True, "data": self.recipe_reload()}
            m = re.fullmatch(r"/api/recipes/([^/]+)/plan", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_plan(m.group(1), body)}
            m = re.fullmatch(r"/api/recipes/([^/]+)/probe", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_probe(m.group(1), body)}
            m = re.fullmatch(r"/api/recipes/([^/]+)/run", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_run(m.group(1), body)}
            # ★ T7·S4：部署组回退（🔴 逐项恢复，手输确认词由服务端校验）
            m = re.fullmatch(r"/api/recipe-runs/([^/]+)/rollback", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_rollback(m.group(1), body)}
            # ★ T7·S6：配方批量（每台一个独立执行；red 禁止批量）
            m = re.fullmatch(r"/api/recipes/([^/]+)/batch-plan", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_batch_plan(
                    m.group(1), body, str(body.get("mode") or "deploy"))}
            m = re.fullmatch(r"/api/recipes/([^/]+)/batch-run", path)
            if m:
                return 200, {"ok": True, "data": self.recipe_batch_run(m.group(1), body)}
            m = re.fullmatch(r"/api/actions/([^/]+)/preview", path)
            if m:
                return 200, {"ok": True, "data": self.preview(m.group(1), body)}
            m = re.fullmatch(r"/api/actions/([^/]+)/run", path)
            if m:
                return 200, {"ok": True, "data": self.run_action(m.group(1), body)}
            m = re.fullmatch(r"/api/hosts/([^/]+)/check", path)
            if m:
                return 200, {"ok": True, "data": self.host_check(m.group(1), trust=False)}
            m = re.fullmatch(r"/api/hosts/([^/]+)/trust", path)
            if m:
                # ★ T17·S8：`force` 从请求体里读 —— 它是"**指纹变了**，我确认接受"那一档
                #   （界面会先弹一次确认；服务端不改判据，只多一层人点过的证据）
                return 200, {"ok": True, "data": self.host_check(
                    m.group(1), trust=True, force=bool(body.get("force")))}

            # ★ T3 补漏（界面接入时发现）：下面三条方法在 Api 里早就写好了，
            #   但**路由一直没注册** —— 界面上的「批量执行」与「恢复此文件」点下去必然 400。
            #   教训：Api 方法存在 ≠ 接口可用。`tools/batch_demo.py` 直接调 engine、绕过 HTTP，
            #   所以脚本能跑通而界面跑不通；自检当时也抓不到（见 selftest 的「路由对账」）。
            m = re.fullmatch(r"/api/backups/(\d+)/restore", path)
            if m:
                return 200, {"ok": True, "data": self.backup_restore(int(m.group(1)), body)}
            if path == "/api/batch/preview":
                return 200, {"ok": True, "data": self.batch_preview(body)}
            if path == "/api/batch/run":
                return 200, {"ok": True, "data": self.batch_run(body)}

        raise OpsError(
            # ★ 这条错误以前叫 INTERNAL（"控制台内部错误"）—— 那是**把缺陷藏起来了**：
            #   "前端调了一个不存在的接口" 是**接口对不上**，不是内部故障。改成独立 code 之后，
            #   selftest 的「路由对账」才能精确判定，而不是去匹配中文提示语。
            code="NO_SUCH_ROUTE",
            reason=f"没有这个接口：{method} {path}",
            advice="刷新页面；若仍出现，说明前端与服务端版本不一致，重启服务即可。",
        )
