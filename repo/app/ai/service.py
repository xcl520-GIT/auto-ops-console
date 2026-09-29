"""AI 助手面（`/api/ai/**` 的实现；规范 §12.74）。

★ 本模块是 AI 的**唯一入口**：它内部只调 `api.dispatch('POST', '/api/actions/<id>/run', ...)`
  —— 和界面点按钮走的是**同一个函数**。
★ 这里**没有**第二条路：不 import 执行层、不 import 传输层、不自己拼命令（铁律 8）。
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from app.ai.keystore import KeyStore
from app.ai.knowledge import LocalKnowledge, mine_candidates
from app.ai.provider import build_provider
from app.ai.requests import ActionRequests, card_text
from app.ai.runtime import AiRuntime, Dispatch
from app.ai.sessions import AiSessions
from app.ai.settings import load_ai_settings
from app.ai.tools import ToolFace, write_json
from app.catalog import Action
from app.config import AppConfig
from app.errors import OpsError
from app.report import build_report, report_name


def _now() -> str:
    """报告要写进正文的**生成时刻**（§12.104.1：报告是快照，不是活页）。"""
    return datetime.now().isoformat(timespec="seconds")


class AiService:
    def __init__(
        self,
        cfg: AppConfig,
        actions: dict[str, Action],
        dispatch: Dispatch,
        *,
        task_lister: Any = None,
        task_getter: Any = None,
    ) -> None:
        self.cfg = cfg
        self.actions = actions
        # ★★ T15·S3：任务那半边**只给两个只读回调**（列任务 / 取任务）——
        #   AI 侧**拿不到 `Store` 对象**，与"只拿得到 `api.dispatch` 这个函数本身"
        #   是同一个纪律（T12 断言 🄌 的家族）。
        self.task_lister = task_lister
        self.task_getter = task_getter
        self.settings = load_ai_settings(cfg)
        self.keystore = KeyStore()
        # ★ 注入路径 ①：环境变量（开发 / 自检 / 演示默认）。找不到不报错 —— 还有路径 ②。
        self.keystore.load_from_env(self.settings.key_env)
        self.provider = build_provider(self.settings)
        self.face = ToolFace(cfg, actions)
        self.sessions = AiSessions(cfg.paths.database)
        self.sessions.init()
        # ── ★★ T14·S3：变更"请求"（规范 §12.96）──────────────────────────
        # ★ 它只做两件事：把卡片组装出来（字段全来自平台）、往库里写一条 `pending`。
        #   **它不执行** —— 执行在 `app/api.py`（人点了确认之后，走既有 /api/tasks）。
        self.requests = ActionRequests(cfg, actions, self.face, self.sessions)
        # ── ★★ T15·S3：本地知识（只读）＋ Recipe 候选（**只有人能触发**）──────
        # ★ `LocalKnowledge` 拿不到 Store、拿不到引擎；它只有一个 `search()`。
        # ★★ `mine_candidates()` **不绑在运行时上**：AI 侧**没有**这个工具（§12.107.3），
        #    它只从 `AiService.recipe_candidates()` 出去 —— 而那一条由**人**点界面触发。
        self.knowledge = LocalKnowledge(
            self.sessions,
            task_lister=task_lister,
            task_getter=task_getter,
            host_names={h.id: h.name for h in cfg.hosts},
            actions=actions,
        )
        self.runtime = AiRuntime(
            cfg=cfg,
            settings=self.settings,
            face=self.face,
            provider=self.provider,
            sessions=self.sessions,
            dispatch=dispatch,
            key_provider=self.keystore.get,
            requests=self.requests,
            knowledge=self.knowledge,
        )

    # ------------------------------------------------------------------ 状态
    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.settings.enabled,
            "key": self.keystore.status(),
            "settings": self.settings.to_public(),
            "toolface": {
                "tool_total": len(self.face.green),
                "action_total": len(self.face.all_actions),
                "rule": "★ 工具面只含 green（只读）；yellow/red 不进工具表，且没有确认词通道",
            },
            # ── ★★ T14·S3：放开给 AI「请求」的 `yellow`（★ 一个都不能执行）──
            "requests": {
                "requestable": sorted(self.face.yellow_exposed),
                "requestable_total": len(self.face.yellow_exposed),
                # ★ 把"配置与批准表对不对得上"如实摆出来（有问题时界面也能看见，不只在自检里）
                "allowlist_problems": self.requests.audit_allowlist(),
                "pending": self.requests.listing(limit=200)["pending"],
                "rule": (
                    "★ 这些只是 AI「可以请求」的动作：AI 不执行，"
                    "人在界面点确认之后才走既有的执行那条路（§12.96.2）。"
                ),
            },
            "hosts": [{"id": h.id, "name": h.name, "role": h.role} for h in self.cfg.hosts],
            "sessions": len(self.sessions.list_sessions(limit=999)),
            # ── ★★ T15·S3：本地知识 ＋ 报告（§12.104 / §12.106 / §12.107）──────
            "knowledge": {
                "tool": "kb_search",
                "rule": (
                    "★ 只查**本地结构化记录**（会话 / 人的问句 / 工具调用 / 变更请求 / 任务结论）；"
                    "★ 不含 AI 自己的历史回答（不可核的散文）；"
                    "★ 命中不到会明说「没有记录」并交代查了哪些范围。"
                ),
            },
            "reports": {
                "formats": ["md"],
                "note": "★ md 优先；PDF 记为 T15 遗留。报告导出同样走鉴权闸门。",
            },
            "recipe_candidates": {
                "dir": str(Path(self.cfg.paths.var) / "lab" / "recipes-candidate"),
                "rule": (
                    "★ 只落**草案区**、**不生效**；★ **AI 侧没有这个工具** —— "
                    "生成必须由人触发（§12.107.3）。"
                ),
            },
        }

    # ------------------------------------------------------------------ key
    def set_key(self, body: dict[str, Any]) -> dict[str, Any]:
        self.keystore.set(str(body.get("key") or ""), source="ui")
        return self.keystore.status()

    def clear_key(self) -> dict[str, Any]:
        self.keystore.clear()
        self.keystore.load_from_env(self.settings.key_env)
        return self.keystore.status()

    # ------------------------------------------------------------------ 工具面
    def tools(self) -> dict[str, Any]:
        return self.face.to_json()

    def export_tools(self) -> dict[str, Any]:
        path = Path(self.cfg.paths.catalog) / "ai-tools.json"
        payload = write_json(path, self.face)
        return {"path": str(path), "tool_total": payload["tool_total"]}

    # ------------------------------------------------------------------ 执行
    def ask(self, body: dict[str, Any]) -> dict[str, Any]:
        text = str(body.get("text") or "").strip()
        if not text:
            raise OpsError(code="AI_EMPTY_QUESTION", reason="问题是空的",
                           advice="说点什么，比如「哪台机器磁盘快满了」。")
        session_id = str(body.get("session_id") or "") or None
        return self.runtime.ask(text, session_id)

    def tool_call(self, body: dict[str, Any]) -> dict[str, Any]:
        """★ 手工构造的工具调用通道 —— **它存在的意义是能被反例打**（验收 #4）。

        正常人不会用它（模型走的是 ask 的内部循环）。但"AI 只能跑只读"这条规矩
        必须能被一条命令证伪：拿 `yellow` / `red` 的动作名打进来，**必须被拒且说清原因**。
        """
        action_id = str(body.get("action_id") or "")
        host_ids = [str(x) for x in (body.get("host_ids") or [])] or [
            str(body.get("host_id") or "")
        ]
        params = body.get("params") or {}
        rows = self.runtime.run_action_readonly(action_id, host_ids, params)
        return {
            "host_id": body.get("host_id") or "",
            "results": [
                {
                    "host_id": o.host_id,
                    "status": o.status,
                    "verify_result": o.verify,
                    "ok": o.ok,
                    "task_id": o.task_id,
                    "explain": o.explain,
                }
                for o in rows
            ],
        }

    # ------------------------------------------------------------------ 变更"请求"（T14·S3）
    def requests_list(self, limit: int = 50) -> dict[str, Any]:
        """待确认队列（★ 全是 `pending`：AI 提出过、人还没点过的那些）。"""
        return self.requests.listing(limit)

    def request_detail(self, request_id: str) -> dict[str, Any]:
        return self.requests.detail(request_id)

    def request_action(self, body: dict[str, Any]) -> dict[str, Any]:
        """★ 手工构造的"变更请求"通道 —— **它存在的意义和 `tool_call` 一样：能被反例打**。

        验收 ②a 要的就是这条：拿 `pkg.remove`（`red`）打进来必须**在请求入口就被拒**，
        拿 `k8s.exec`（白名单外的 `yellow`）打进来也必须被拒，而且**说清该去哪儿办**。
        """
        out = self.requests.submit(
            str(body.get("action_id") or ""),
            str(body.get("host_id") or ""),
            body.get("params") or {},
            str(body.get("reason") or ""),
            session_id=str(body.get("session_id") or ""),
        )
        out["card_text"] = card_text(out["card"])
        return out

    # ------------------------------------------------------------------ 本地账（★ 不外发）
    def hitrate(self, limit: int = 200) -> dict[str, Any]:
        """选域命中率（规范 §12.92）：**只给本地看**的账 —— 它不进任何外发 payload。

        ★ 为什么它值得一个接口：T12 遗留 #6 说"选域可能选错，有兜底但没有度量"。
          度量不是给模型看的，是给**我们**看的（判断词表/选域提示词该不该改）。
        """
        return {"source": "本地账（★ 绝不外发）", **self.sessions.hitrate(limit)}

    # ------------------------------------------------------------------ 会话
    def session_list(self, limit: int = 20) -> dict[str, Any]:
        return {"sessions": self.sessions.list_sessions(limit)}

    def session_detail(self, session_id: str) -> dict[str, Any]:
        return self.sessions.get_session(session_id)

    # ------------------------------------------------------------------ 报告（T15·S2 · §12.104）
    # ★★ 报告是"**索引 + 结论**"：它**不去取目标机任何东西**，只是把既有记录重新组织一遍。
    #    所以这一节里没有 dispatch、没有动作、没有执行 —— 全是读。
    def report_list(self, limit: int = 20) -> dict[str, Any]:
        """能出报告的会话清单（带每条的账，供界面下拉）。"""
        out: list[dict[str, Any]] = []
        for s in self.sessions.list_sessions(limit):
            sid = str(s.get("id") or "")
            usage = self.sessions.usage(sid)
            out.append({
                "session_id": sid,
                "title": s.get("title") or "",
                "created_at": s.get("created_at") or "",
                "model": s.get("model") or "",
                "tier": s.get("tier") or "",
                "tool_calls": usage.get("tool_calls", 0),
                "tool_ok": usage.get("tool_ok", 0),
                "requests": len(self.sessions.session_action_requests(sid)),
                "tokens": usage.get("total_tokens", 0),
            })
        return {
            "sessions": out,
            "rule": (
                "★ 报告里每一条结论都要能点回任务号与原始输出（§12.104.1）；"
                "★ 报告**不内嵌**目标机原文（原文走归档与 /api/tasks/<id>/export）。"
            ),
            "formats": ["md"],
            "formats_note": "★ 本期只做 md；PDF 已如实记为 T15 遗留（§12.104.3）。",
        }

    def session_report(self, session_id: str, fmt: str = "md") -> tuple[str, str]:
        """渲染一份会话报告，返回 (文件名, 正文)。★ 归档由接口层做（与单任务报告同一条路）。"""
        detail = self.sessions.get_session(session_id)
        session = detail.get("session")
        if not session:
            raise OpsError(
                code="AI_NO_SUCH_SESSION",
                reason=f"没有这个会话：{session_id}",
                advice="先在「对话」页签里聊一次，或者用 `/api/ai/sessions` 看现成的会话号。",
            )
        calls = detail.get("tool_calls") or []
        requests = self.sessions.session_action_requests(session_id)
        # ── ★ 证据链：把用得到的任务留证**取下来**（★ 只读；缺了也照实说缺）──
        tasks: dict[str, Any] = {}
        ids = {str(c.get("task_id") or "") for c in calls}
        ids |= {str(r.get("task_id") or "") for r in requests}
        for tid in sorted(x for x in ids if x):
            if self.task_getter is None:
                continue
            try:
                tasks[tid] = self.task_getter(tid)
            except OpsError:
                tasks[tid] = {}   # ★ 取不到就留空：报告会写「读不到」，**不是**「没执行」
        text = build_report(
            session,
            detail.get("turns") or [],
            calls,
            requests,
            tasks,
            detail.get("usage") or {},
            fmt=fmt,
            generated_at=_now(),
            host_names={h.id: h.name for h in self.cfg.hosts},
            # ★★ 动作的**风险等级**要进报告：时间线得能看出「这是变更」还是「只是看了一眼」
            #   （§12.105.3 —— 把"改过东西"写得跟"看了一眼"一样，就是在制造错觉）。
            action_risks={a.id: a.risk for a in self.actions.values()},
        )
        return report_name(session_id, fmt), text

    # ------------------------------------------------------------------ 本地知识（T15·S3 · §12.106）
    def knowledge_search(self, query: str, limit: int = 20) -> dict[str, Any]:
        """「上次这类问题是怎么解决的」—— ★ 只查**本地结构化记录**。

        ★ 命中不到会明说「没有记录」并交代查了哪些范围（§12.106.3）。
        """
        return self.knowledge.search(query, limit=limit)

    # ------------------------------------------------------------------ Recipe 候选（T15·S3 · §12.107）
    def recipe_candidates(self, *, min_support: int = 2, min_len: int = 3) -> dict[str, Any]:
        """把**重复出现过的动作序列**固化成候选草案。

        ★★ 落点**只有** `var/lab/recipes-candidate/`；★ **不写** `catalog/recipes/`、
          **不触发**重载；★ **不是 AI 的工具** —— 它只从这条接口出去（人点界面触发）。
        """
        out_dir = Path(self.cfg.paths.var) / "lab" / "recipes-candidate"
        res = mine_candidates(
            sessions=self.sessions,
            actions=self.actions,
            out_dir=out_dir,
            min_support=int(min_support),
            min_len=int(min_len),
            catalog_recipes=Path(self.cfg.paths.catalog) / "recipes",
        )
        res["trigger"] = "★ 由人触发（界面按钮 / 接口）；AI 侧没有这个工具（§12.107.3）"
        return res
