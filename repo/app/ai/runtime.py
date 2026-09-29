"""Agent 运行时（规范 §12.73 / §12.75 / §12.76 / §12.77 / §12.81）。

一次 `ask()` 做的事：

```
人话 ──▶ ① 平台判定主机范围（★ 不由模型挑：模型对"哪台"没有真值）
          └─ 不明确 ⇒ 回问（验收 #3），不猜
       ──▶ ② 多轮 tool-calling：模型只负责"选动作 + 填参数"
              └─ 闸门：只放 green（非 green ⇒ 拒绝 + 说清该去哪儿，验收 #4）
              └─ 执行：★ 经既有 `/api/**` dispatch（铁律 8），只读并发 + 失败隔离
              └─ 失败：★ 本地翻译成"原因 + 建议 + 该去哪台"（§12.77），只外发译文
              └─ 外发：★ 只装箱结论（`outflow.pack_tool_result`，红线 9）
       ──▶ ③ 双结论对照：AI 的说法 vs 工作台判定；冲突 ⇒ 入库（验收 #6）
```

★ 三条不能越过的线（写在这里，免得后来的人"顺手优化"掉）：
  1. **不直连底层**：这里只调 `dispatch`（和界面按钮走的是同一个函数），没有第二条路（铁律 8）。
  2. **不代过闸门**：非 green 一律拒绝，且**没有** `confirm_text` 这条通道（铁律 9 / 红线 7）。
  3. **不发原文**：出境的字段由 `outflow.ALLOWED_TASK_KEYS` 决定（红线 9）。
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from app.ai.outflow import pack_tool_result
from app.ai.retrieval import (
    SEARCH_ACTIONS,
    aggregate,
    classify_param_sources,
    scope_block,
    text_for_model,
)
from app.ai.provider import ChatProvider
from app.ai.sessions import AiSessions
from app.ai.settings import AiSettings
from app.ai.tools import KB_TOOL_NAME, REQUEST_TOOL_NAME, ToolFace, action_id_from_model
from app.catalog import Action
from app.config import AppConfig, Host
from app.errors import OpsError

Dispatch = Callable[[str, str, dict, dict | None], tuple[int, dict[str, Any]]]

SYSTEM_PROMPT = """你是 auto-ops-console（本地 Linux 运维工作台）的**只读运维助手**。

硬规矩（这些规矩由平台强制执行，你只是知道它们）：
1. 你**只能**使用给你的工具（全部是只读动作）。它们会在目标机上真实执行，并返回**结论**与任务号。
2. ★ **主机由平台决定**：工具参数里**没有**主机。问题里没指明机器时，平台会替你判断，必要时会反问你。
3. ★★ **不许凭空断言**：「已修复 / 已确认 / 一切正常 / 没问题」这类话，
   **只有当工具返回值里 `verify_result` 是 `ok` 时**才可以说。否则必须按"未证实"表述。
4. ★★ **查不到就说查不到**，并说明你查了哪些机器、哪些范围。**不许**含糊，**不许**编。
5. ★ **结论以工具返回为准**。你的每一句解释都必须能指到某条工具结果（用任务号引用）。
6. 失败了要**说清是哪种失败**：这台机器没装工具？没有角色（比如读集群要控制面）？参数不对？
7. 用中文回答：**先给结论，再给依据（任务号 / 哪台机器）**。别写客套话，别写"作为 AI"。
"""

# ★ 主机提示词（"哪台 / 所有 / 每台"）—— 这是"人话 → 主机范围"的判定，**由平台做**
# ★ T12·S8 真跑补的："各节点""各台机器"这种说法在运维口语里就是"全部"，
#   而第一版词表里只有「各个/各自」⇒ 漏了单独的「各」，于是把一句明显是"全部"的话
#   问回了人（★ 回问不是错，但**该懂的话要懂** —— 这属于"人话"这一层的真实覆盖）。
_ALL_HINTS = ("哪台", "哪个", "哪些", "所有", "全部", "每台", "各", "都", "全量", "几台",
              # ★ T13 补（S0 用 14 条真实问句样本扫出来的三类错法，规范 §12.93）：
              #   口语里的全量说法 —— 漏一个就是把一句明显是"全部"的话问回了人
              "统统", "通通", "每一台", "逐个", "一一", "分别", "每台机器", "所有的")

# ★ "角色词"（§12.93 的第二类错法：该收窄的没收窄）—— 出现它就**只铺该角色**，
#   而不是把 docker-01 也扫一遍。角色名一律取自 `hosts.yaml` 的 `role`（不新造表）。
_ROLE_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("k8s 节点", ("k8s-control-plane", "k8s-worker")),
    ("节点", ("k8s-control-plane", "k8s-worker")),
    ("集群", ("k8s-control-plane",)),
    ("控制面", ("k8s-control-plane",)),
    ("工作节点", ("k8s-worker",)),
    ("docker", ("docker-registry",)),
    ("harbor", ("docker-registry",)),
)

# ★ 数量词（"四台 / 三台机器的…"）—— 与角色词同时出现时角色词优先（"三台 K8s 节点" = 3 台）
_COUNT_RE = re.compile(r"[一二三四五六七八九1-9]\s*台")

# ★ 选域"退回全量"的固定标记（§12.92 记账要用它判 fallback）
FALLBACK_MARK = "退回全量"

# ★ 这些词一出现，就要求有 verify 支撑（验收 #6 / 红线 10）
_CONFIRM_WORDS = ("已确认", "已修复", "已解决", "一切正常", "没有问题", "全都正常", "已经好了")


@dataclass
class HostDecision:
    host_ids: list[str]
    reason: str
    asked: bool = False
    question: str = ""


@dataclass
class ToolOutcome:
    action_id: str
    host_id: str
    ok: bool
    task_id: str = ""
    status: str = ""
    verify: str = ""
    conclusion: str = ""
    explain: str = ""
    evidence: str = ""      # ★ 本地留档（出处），**不外发**
    error_code: str = ""
    duration_ms: int = 0
    packed: dict[str, Any] = field(default_factory=dict)


def decide_hosts(text: str, hosts: list[Host], settings: AiSettings) -> HostDecision:
    """人话 → 主机范围。★ **模型不参与**这件事（它对本环境没有真值）。

    规则（三条，全部可证伪）：
      ① 点名了某台（id / 名字 / 地址）⇒ 就那一台；
      ② 出现"哪台 / 所有 / 每台"这类词 ⇒ **全部登记主机**（受 `max_hosts_per_action` 限制）；
      ③ 其余 ⇒ **回问**，不猜（验收 #3）。
    """
    lowered = text.lower()
    # ★★ T13：主机**短名**也算点名 —— 运维口语里说的就是「master01 / node01」，
    #    而登记 id 是「node-01 / node-02」（T13·S3 词表回归当场抓到的：P13 被问回了人）。
    #    ★ 安全性靠**唯一性**兜底：只有当这个短名**只指向一台**时才采纳 ——
    #      否则「node01」这种在别的清单里可能撞名，宁可不认（回问比猜错便宜）。
    tail_owner: dict[str, list[str]] = {}
    for h in hosts:
        parts = str(h.id).split("-")
        if len(parts) > 1 and len(parts[-1]) >= 4:
            tail_owner.setdefault(parts[-1], []).append(h.id)

    named: list[str] = []
    for h in hosts:
        short = h.name.split("（")[0].strip()
        tokens = [h.id, short, h.address]
        parts = str(h.id).split("-")
        if len(parts) > 1:
            tokens.append("-".join(parts[-2:]))          # 末两段（防前缀不同、后半相同）
            tail = parts[-1]
            if len(tail) >= 4 and len(tail_owner.get(tail, [])) == 1:
                tokens.append(tail)                       # ★ 唯一的短名才认
        for token in tokens:
            if token and token.lower() in lowered:
                named.append(h.id)
                break
    if named:
        return HostDecision(host_ids=sorted(set(named)), reason=f"问题里点名了：{'、'.join(sorted(set(named)))}")

    # ② 全量词 ⇒ 全部登记主机（★ 优先于角色词："所有节点"在口语里就是"全部"）
    if any(hint in text for hint in _ALL_HINTS):
        ids = [h.id for h in hosts][: settings.max_hosts_per_action]
        return HostDecision(
            host_ids=ids,
            reason=f"问题问的是「哪台/全部」⇒ 铺到全部 {len(ids)} 台登记主机（上限 {settings.max_hosts_per_action}）",
        )

    # ③ ★ T13：角色词 ⇒ **按角色收窄**（§12.93 第二类错法：该收窄的没收窄）
    for kw, roles in _ROLE_HINTS:
        if kw in lowered:
            subset = [h.id for h in hosts if h.role in roles][: settings.max_hosts_per_action]
            if subset:
                return HostDecision(
                    host_ids=subset,
                    reason=f"问题里出现了角色词「{kw}」⇒ 只铺该角色的 {len(subset)} 台"
                           f"（角色取自 hosts.yaml 的 role，不铺其余机器）",
                )

    # ④ ★ T13：数量词（没有角色词时才用）⇒ 当作"全部"（例："四台机器的系统时间对不对"）
    if _COUNT_RE.search(text):
        ids = [h.id for h in hosts][: settings.max_hosts_per_action]
        return HostDecision(
            host_ids=ids,
            reason=f"问题里给了数量（「{_COUNT_RE.search(text).group(0)}」）但没点名 ⇒ 铺全部 {len(ids)} 台登记主机",
        )

    names = "、".join(h.id for h in hosts)
    return HostDecision(
        host_ids=[],
        reason="问题里没有指明机器",
        asked=True,
        question=f"要查哪台机器？（登记在册的有：{names}；也可以说「全部」）",
    )


def _first_sentence(text: str, limit: int = 160) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    line = re.split(r"[\n。；]", text)[0].strip()
    return line[:limit]


def explain_failure(action: Action, host: Host, task: dict[str, Any], err: OpsError | None) -> tuple[str, str]:
    """★ 把失败翻译成"人能用、AI 也能用"的一句话（规范 §12.77）。

    返回 `(译文, 出处)`。★ **译文之外的原始输出一律不外发**（红线 9）——
    出处只落到本地 `ai_tool_call.evidence` 里，供人事后核对。

    判据顺序（**每一条都对应 T12·S0 的实测现场**）：
      ① 角色不对（域 J 类动作跑在没有 kubeconfig 的机器上）—— §12.76 发现 A
      ② 预检某一步的 `note` 早就写清了语义 —— §12.77 发现 B（知识在 YAML 里没被接上）
      ③ 缺命令（rc=127）
      ④ 参数是默认值而目标文件不存在（AI 最容易犯的）
      ⑤ 兜底：给原因 + 去哪个页签看原文
    """
    detail = task.get("error") or {}
    code = str(detail.get("code") or (err.code if err else "") or "")
    reason = str(detail.get("reason") or (err.reason if err else "") or "")
    steps = task.get("steps") or []

    # ① 角色绑定（§12.76）
    if action.domain == "J" and (host.role or "") != "k8s-control-plane":
        entry = next((h for h in ("node-01",) if h), "")
        return (
            f"★ 这台是 {host.role}（不是控制面）：**读集群需要一个能读集群的入口**。"
            f"工作节点上通常没有 kubeconfig —— 这是正常现象，不是集群故障。"
            f"请改用控制面（如 {entry}）。",
            f"规则：`hosts.yaml` 的 role={host.role}；动作域={action.domain}",
        )

    # ② 预检步骤自己写好的语义（§12.77 的核心：把 YAML 里的知识接出来）
    for step in action.precheck:
        failed = next((s for s in steps if s.get("name") == step.name), None)
        if not failed or str(failed.get("status")) in ("ok", "skipped"):
            continue
        note = _first_sentence(step.note, 200)
        if note:
            return (
                f"★ 预检「{step.title or step.name}」不成立 ⇒ 这一步中止了整条动作。"
                f"动作作者写明：{note}",
                f"YAML precheck.{step.name}.note（task={task.get('id')}）",
            )

    # ③ 缺命令
    if "127" in str(reason) or "没有命令" in reason:
        return (
            f"{reason} ⇒ 这台上**没装**这个工具/程序。要么换一台装过的，要么先装它"
            f"（可以先用「包搜索」查是哪个包提供它；装上属于变更动作，要人在界面点）。",
            f"错误码 {code}；task={task.get('id')}",
        )

    # ④ 默认参数指向的对象不存在
    if code in ("PRECHECK_FAILED", "STEP_FAILED") and any(
        "No such file" in str(s.get("stdout") or "") for s in steps
    ):
        defaults = [p.name for p in action.params if p.default not in (None, "")]
        hint = f"（这台动作有默认值的参数：{'、'.join(defaults)}）" if defaults else ""
        return (
            f"★ 这一步要操作的路径/对象**在这台机器上不存在** —— 多半是**参数用了默认值**而没有按实际环境给。"
            f"需要你给出这台机器上的真实路径/名字{hint}。",
            f"步骤原文里出现 No such file；task={task.get('id')}",
        )

    # ⑤ 兜底：不许说"没问题"，也不许编
    extra = "（原文在界面「历史」里按任务号展开）" if task.get("id") else ""
    return (
        f"这一步没成功：{reason or '原因见原始输出'}。★ 我不能从这条信息判断出「一切正常」{extra}",
        f"错误码 {code}；task={task.get('id')}",
    )


_DOMAIN_PICK_PROMPT = """你要先在**动作目录**里选出这次需要哪几个域（**只回 JSON，不要解释**）。

回法（严格按这个形状）：
{"domains": ["<域字母>", ...], "reason": "<一句话为什么>"}

★ 不确定就多选一个域 —— 选错的代价是这一轮看不到那个动作；多选的代价只是多几个工具定义。
★ 最多选 3 个域。只从下面列出的域里选。
"""


class AiRuntime:
    def __init__(
        self,
        cfg: AppConfig,
        settings: AiSettings,
        face: ToolFace,
        provider: ChatProvider,
        sessions: AiSessions,
        dispatch: Dispatch,
        key_provider: Callable[[], str],
        requests: Any = None,
        knowledge: Any = None,
    ) -> None:
        self.cfg = cfg
        self.settings = settings
        self.face = face
        self.provider = provider
        self.sessions = sessions
        self.dispatch = dispatch
        self.key_provider = key_provider
        # ── ★★ T14·S3：变更"请求"（规范 §12.96）────────────────────────
        # ★ 它**不是**执行通道：`ActionRequests.submit()` 只写一条 `pending` 记录 + 一张卡片。
        #   执行永远要人等确认之后由 `app/api.py` 走既有的那条路 —— 所以这里注入的不是
        #   "第二个引擎"，只是"一张待办的登记簿"。
        self.requests = requests
        # ── ★★ T15·S3：本地知识检索（规范 §12.106）──────────────────────
        # ★ 它**只有读**：只查本地结构化记录（会话 / 人的问句 / 工具调用 / 变更请求 / 任务结论）。
        #   ★★ "生成 Recipe 候选"那条**写文件**的通道**不在这里** —— 它由人点界面触发
        #      （§12.107.3 / 断言 Ⓕ：AI 结构上没有写候选这条路）。
        self.knowledge = knowledge

        # ── ★ T13（多机检索与汇总）──────────────���────────────────────
        # ★ 三个会话内状态：当前问句（参数来源判定要用）、累积结果（跨调用聚合）、
        #   上次用过的参数（写进 searched_scope 的"参数范围"）。
        self._current_text = ""
        self._all_outcomes = []
        self._params_by_action = {}

    # ------------------------------------------------------------------ 单次工具执行
    def run_action_readonly(
        self, action_id: str, host_ids: list[str], params: dict[str, Any]
    ) -> list[ToolOutcome]:
        """★ 唯一允许的执行入口：**闸门 → 缺参检查 → 经 dispatch 跑 → 失败本地翻译**。"""
        action = self.face.guard(action_id)          # ← 非 green 在这里被拒（验收 #4）
        self._check_params(action, params)           # ← 缺必填 ⇒ 回问（验收 #3）

        # ★★ T13：**范围只能来自用户意图或动作参数**（规范 §12.85 / 断言 ⑸）
        #    模型自己编一个"在哪找"（既不是用户说的、也不是动作的默认值）⇒ **回问**，不执行。
        #    ★ 这条是 T13 的第一口径：宁可问一句，也不许"猜它可能在哪就去乱翻"。
        if self.settings.require_user_scope:
            sources = classify_param_sources(action, params, self._current_text)
            invented = [k for k, v in sources.items() if v == "model"]
            if invented:
                raise OpsError(
                    code="AI_NEED_CONFIRM_SCOPE",
                    reason=f"动作「{action.title}」的检索范围里有**你没说过的**参数：{'、'.join(invented)}",
                    advice="；".join(
                        f"{k} ＝ {params.get(k)}（这不是你说的、也不是这个动作的默认值）"
                        for k in invented
                    ) + "　⇒ 请明确告诉我要在哪找（或直接说「用默认位置」）。",
                    context={"action_id": action.id, "invented": invented},
                )

        host_ids = [h for h in host_ids if h][: self.settings.max_hosts_per_action]
        if not host_ids:
            raise OpsError(
                code="AI_NO_HOST",
                reason="没有可执行的目标机",
                advice="说清要查哪台（或说「全部」）。",
            )

        if len(host_ids) == 1:
            return [self._run_one(action, host_ids[0], params)]

        # ★ 只读并发 + 失败隔离（沿用批量既有规则：一台失败不拖垮其余）
        with ThreadPoolExecutor(max_workers=max(1, self.settings.batch_workers)) as pool:
            return list(pool.map(lambda hid: self._run_one(action, hid, params), host_ids))

    @staticmethod
    def _check_params(action: Action, params: dict[str, Any]) -> None:
        missing = [
            p
            for p in action.params
            if p.required and p.default in (None, "") and str(params.get(p.name) or "") == ""
        ]
        if missing:
            raise OpsError(
                code="AI_NEED_PARAMS",
                reason=f"动作「{action.title}」还差必填参数：{'、'.join(p.name for p in missing)}",
                advice="；".join(f"{p.name} = {p.label or p.name}（{p.help or '必填，没有默认值'}）" for p in missing),
                context={"action_id": action.id, "missing": [p.name for p in missing]},
            )

    def _run_one(self, action: Action, host_id: str, params: dict[str, Any]) -> ToolOutcome:
        try:
            _, payload = self.dispatch(
                "POST", f"/api/actions/{action.id}/run", {}, {"host_id": host_id, "params": params}
            )
            task = (payload.get("data") or {}).get("task") or {}
            status = str(task.get("status") or "")
            verify = str(task.get("verify_result") or "")
            ok = status == "ok"
            outcome = ToolOutcome(
                action_id=action.id,
                host_id=host_id,
                ok=ok,
                task_id=str(task.get("id") or ""),
                status=status,
                verify=verify,
                conclusion=str(task.get("conclusion") or ""),
                duration_ms=int(task.get("duration_ms") or 0),
            )
            if not ok:
                host = self.cfg.host(host_id)
                outcome.explain, outcome.evidence = explain_failure(action, host, task, None)
            outcome.packed = pack_tool_result(task, host_id, outcome.explain)
        except OpsError as exc:
            outcome = ToolOutcome(
                action_id=action.id,
                host_id=host_id,
                ok=False,
                status="rejected" if exc.code.startswith(("AI_", "CONFIRM", "RISK")) else "error",
                error_code=exc.code,
                explain=f"{exc.reason}｜建议：{exc.advice}",
                evidence=f"错误码 {exc.code}（平台在动作执行前拦下）",
            )
            outcome.packed = {
                "action_id": action.id,
                "host_id": host_id,
                "status": outcome.status,
                "error": {"code": exc.code, "reason": exc.reason, "advice": exc.advice},
                "explain": outcome.explain,
            }
        self.sessions.add_tool_call(
            self._session_id,
            action_id=outcome.action_id,
            host_id=outcome.host_id,
            task_id=outcome.task_id,
            status=outcome.status,
            verify=outcome.verify,
            ok=outcome.ok,
            explain=outcome.explain,
            evidence=outcome.evidence,
        )
        return outcome

    # ------------------------------------------------------------------ 三层暴露：第 1 层
    def _select_domains(self, text: str, key: str) -> tuple[list[str], str, int]:
        """先让模型**只回 JSON 选域**（这一轮没有工具定义，很便宜）。

        ★ 它是"三层递进暴露"的落地（规范 §12.75）：L1/L2 用**纯文本**给，L3 只发命中域的 schema。
        ★ 解析失败 ⇒ **退回全量**（宁可贵，也不许因为它而答不出）。
        """
        all_domains = sorted({a.domain for a in self.face.green.values()})
        digest = self.face.l2_digest_text()
        result = self.provider.chat(
            key,
            [
                {"role": "system", "content": _DOMAIN_PICK_PROMPT},
                {"role": "user", "content": f"【动作目录】\n{digest}\n\n【问题】{text}"},
            ],
            tools=None,
            model=self.settings.model,
        )
        tokens = int((result.usage or {}).get("total_tokens") or 0)
        match = re.search(r"\{.*\}", result.content or "", re.S)
        if not match:
            return all_domains, "选域返回不是 JSON ⇒ 退回全量（宁可贵，也不许答不出）", tokens
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return all_domains, "选域 JSON 解析失败 ⇒ 退回全量", tokens
        picked = [str(d) for d in (data.get("domains") or []) if str(d) in all_domains][:3]
        if not picked:
            return all_domains, "选域结果为空或不可用 ⇒ 退回全量", tokens
        return picked, str(data.get("reason") or "")[:120], tokens

    # ------------------------------------------------------------------ 聚合（先本地聚合再回传）
    def _aggregate(self, outcomes: list[ToolOutcome]) -> dict[str, Any]:
        limit = self.settings.max_tool_result_bytes
        ok = [o for o in outcomes if o.ok]
        bad = [o for o in outcomes if not o.ok]
        per = max(400, limit // max(1, len(outcomes)))
        rows = []
        for o in outcomes:
            row = dict(o.packed)
            conclusion = str(row.get("conclusion") or "")
            if len(conclusion) > per:
                row["conclusion"] = conclusion[:per] + "…（已截断）"
            rows.append(row)
        return {
            "hosts": len(outcomes),
            "succeeded": len(ok),
            "failed": len(bad),
            "failed_hosts": [o.host_id for o in bad],
            "note": (
                f"共 {len(outcomes)} 台：成功 {len(ok)} 台、未成功 {len(bad)} 台"
                + ("（未成功的逐台给了「原因 + 建议」，★ 不许把它当成「一切正常」）" if bad else "")
            ),
            "results": rows,
        }

    # ------------------------------------------------------------------ 主循环
    def _final_view(self):
        """★ 全会话的检索视图（§12.86）：跨调用聚合、去重、排序、定位表 ＋ 三段交代。"""
        return aggregate(
            self._all_outcomes,
            params_by_action=self._params_by_action,
            host_order=[h.id for h in self.cfg.hosts],
            max_rows=self.settings.retrieval_max_rows,
        )

    def _payload(
        self,
        sid: str,
        answer: str,
        outcomes: list[ToolOutcome],
        view: Any,
        conflicts: list[str],
        need_confirm: bool = False,
        stopped_reason: str = "",
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """统一出口（★ T13：把「定位表 ＋ 三段交代」作为**结构化字段**一起返回）。

        ★ 分支出口要**逐个过一遍**（T12 坑 #4：回问路径少返回一个字段）——
          所以所有 return 都走这里，不各写一份 dict。
        """
        payload: dict[str, Any] = {
            "session_id": sid,
            "answer": answer,
            "tool_calls": [
                {
                    "action_id": o.action_id,
                    "host_id": o.host_id,
                    "task_id": o.task_id,
                    "status": o.status,
                    "verify_result": o.verify,
                    "ok": o.ok,
                    "explain": o.explain,
                    "duration_ms": o.duration_ms,
                }
                for o in outcomes
            ],
            "conflicts": conflicts,
            "no_tool_calls": not outcomes,
            "usage": self.sessions.usage(sid),
            "outflow_tier": self.settings.outflow_tier,
            # ── ★ T13 新增：定位式结果 ＋ 三段交代（§12.86 / §12.87 / §12.88）──
            "locate": [
                {"host": r.host, "where": r.where, "what": r.what, "task_id": r.task_id, "kind": r.kind}
                for r in view.rows
            ],
            "retrieval": {
                "hit_count": view.hit_count,
                "host_count": view.host_count,
                "no_hit_hosts": view.no_hit_hosts,
                "possible_incomplete": view.possible_incomplete,
                "note": view.note,
            },
            "scope": {
                "searched": view.searched_scope,
                "not_searched": view.not_searched,
                "truncated": view.truncated,
                "limits": view.limits,
                "text": scope_block(view),
            },
            "need_confirm": need_confirm,
        }
        if request is not None:
            # ★★ T14·S3：变更请求的卡片（★ 它是**平台产出的结构化事实**，不是模型的话，§12.98.2）
            payload["request"] = request
            payload["request_card_text"] = request.get("card_text", "")
        if stopped_reason:
            payload["stopped_reason"] = stopped_reason
        return payload

    # ------------------------------------------------------------------ 变更"请求"（T14·S3）
    def _handle_request_call(
        self, sid: str, call: dict[str, Any], messages: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """★★ 处理一次 `request_action` 调用（规范 §12.96 / §12.99）。

        返回 `None` = **继续循环**（这次是"被拒"，让模型去把"该去哪儿办"讲给用户听）；
        返回一个 payload = **停下来等人工确认**（已经摆出一张卡片了，剩下的事不在 AI 手里）。
        """
        from app.ai.requests import card_text

        args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
        try:
            out = self.requests.submit(
                str(args.get("action_id") or ""),
                str(args.get("host_id") or ""),
                args.get("params") or {},
                str(args.get("reason") or ""),
                session_id=sid,
            )
        except OpsError as exc:
            # ★ 缺参数 ⇒ 停下来问人（与只读路径同口径：不许瞎猜，见 §12.75.1）
            if exc.code == "AI_NEED_PARAMS":
                question = f"{exc.reason}\n{exc.advice}"
                self.sessions.add_turn(sid, "assistant", question, note=exc.code)
                return self._payload(
                    sid, question, self._all_outcomes, self._final_view(), [],
                    need_confirm=True, stopped_reason=exc.code,
                )
            # ★★ 被拒（red / 不在白名单）⇒ **说清"该去哪儿"**，然后把话交回模型
            #    （§12.99.3：拒绝不是终点，"你去哪儿办"才是）
            self.sessions.add_turn(
                sid, "system", f"变更请求被拒：{exc.code}｜{exc.reason}", note=exc.code
            )
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": json.dumps(
                    {
                        "status": "rejected",
                        "error": {"code": exc.code, "reason": exc.reason},
                        "advice": exc.advice,
                        "★": (
                            "这不是故障：这件事**必须由人自己做**。"
                            "请把这个『该去哪儿办』原样讲给用户听，不要换个说法，也不要说你已经办了。"
                        ),
                    },
                    ensure_ascii=False,
                ),
            })
            return None

        card = out["card"]
        text = card_text(card)
        out["card_text"] = text
        self.sessions.add_turn(sid, "system", f"变更请求已登记：{out['request_id']}", note="ACTION_REQUEST")
        self.sessions.add_turn(sid, "assistant", text, note="ACTION_REQUEST_CARD")
        # ★★ **到此为止** —— 后面的每一步都要人等确认（§12.96.2 规矩 3：
        #    AI 只能说"我准备做，等你确认"，不许说"我已经做了"）。
        return self._payload(
            sid, text, self._all_outcomes, self._final_view(), [],
            need_confirm=True, stopped_reason="AI_ACTION_REQUEST_PENDING", request=out,
        )

    def ask(self, text: str, session_id: str | None = None) -> dict[str, Any]:
        if not self.settings.enabled:
            raise OpsError(code="AI_DISABLED", reason="AI 助手在 config.yaml 里被关掉了",
                           advice="把 ai.enabled 改回 true 再重启服务。")
        key = self.key_provider()

        sid = session_id or self.sessions.start_session(
            self.settings.model, self.settings.provider, self.settings.outflow_tier, title=text
        )
        self._session_id = sid
        self._current_text = text          # ★ 参数来源判定要用它（§12.85）
        self._all_outcomes = []
        self._params_by_action = {}
        self.sessions.add_turn(sid, "user", text)

        decision = decide_hosts(text, self.cfg.hosts, self.settings)
        if decision.asked:
            self.sessions.add_turn(sid, "assistant", decision.question, note="ASK_HOST")
            return {
                "session_id": sid,
                "answer": decision.question,
                "need_hosts": True,
                "host_reason": decision.reason,
                "tool_calls": [],
                "conflicts": [],
                "no_tool_calls": True,
                "outflow_tier": self.settings.outflow_tier,
                "usage": self.sessions.usage(sid),
                "locate": [],
                "retrieval": {"hit_count": 0, "host_count": 0, "no_hit_hosts": [],
                              "possible_incomplete": False, "note": "还没开始查（先要确定查哪台）"},
                "scope": {"searched": [], "not_searched": [], "truncated": [], "limits": [], "text": ""},
                "need_confirm": False,
            }

        # ── 三层暴露的第 1 层（★ 实测逼出来的：59 个 schema 全量发 = 单轮 1.5 万 token）──
        domains, domain_reason, pick_tokens = self._select_domains(text, key)
        # ★ T13：选域命中率**本地**记账（§12.92）—— ★ 它永不外发（断言 ⑽）
        if self.settings.hitrate_enabled:
            self.sessions.add_domain_pick(
                sid, text, "、".join(domains), FALLBACK_MARK in domain_reason, domain_reason
            )
        self.sessions.add_turn(
            sid, "system", f"选域：{'、'.join(domains)}（理由：{domain_reason}）", note="DOMAIN_PICK"
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{text}\n\n"
                    f"【平台已判定本次要查的机器】{'、'.join(decision.host_ids)}"
                    f"（理由：{decision.reason}）\n"
                    f"【平台已按域收窄工具面】{'、'.join(domains)}（理由：{domain_reason}）\n"
                    f"★ 你不需要也不允许指定主机；直接选动作、给参数即可。\n"
                    f"★ 检索范围（在哪找）**只能**来自用户说过的话，或动作自己的默认值 —— "
                    f"两者都不是的参数会被平台挡下并要求确认（§12.85）。\n"
                    f"★ 想查「**上次这类问题是怎么解决的**」，用 `kb_search`："
                    f"它只查**本地**记录（会话 / 人的问句 / 工具调用 / 变更请求 / 任务结论），"
                    f"★ 不含 AI 自己的历史回答；命中不到它会明说「没有记录」并交代查了哪些范围 —— "
                    f"**把这句话原样转述**，不许把「没查到」说成「查过了、没问题」（§12.106）。"
                ),
            },
        ]
        tools = self.face.function_specs(domains)
        outcomes: list[ToolOutcome] = []
        answer = ""
        tokens = pick_tokens
        rounds = 0
        covered: set[str] = set()          # ★ 复合读去重（§12.91）

        while rounds < self.settings.max_rounds:
            rounds += 1
            result = self.provider.chat(key, messages, tools=tools, model=self.settings.model)
            usage = result.usage or {}
            tokens += int(usage.get("total_tokens") or 0)
            self.sessions.add_outflow(
                sid,
                self.settings.outflow_tier,
                actions=",".join(sorted({o.action_id for o in outcomes})),
                conclusion_chars=sum(len(o.conclusion) for o in outcomes),
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                content_note=(
                    "含目标机内容" if any(o.action_id in SEARCH_ACTIONS for o in self._all_outcomes) else ""
                ),
            )
            # ★★ T13：超预算 ⇒ **停下问人**，而且**已经拿到的结论不丢**（规范 §12.81 / §12.90）
            if tokens > self.settings.max_session_tokens:
                view = self._final_view()
                head = (
                    f"★ **已达本次会话预算上限**（已用 {tokens} token，上限 "
                    f"{self.settings.max_session_tokens}）—— 我停在这里，**先不往下查了**。\n"
                    f"上面已经查到的东西**都还在**（见下面的定位表与范围交代）。\n"
                    f"要接着查请说一声（或把问题拆小、把范围收窄）。"
                )
                answer = head + ("\n\n" + scope_block(view) if view.hit_count or view.not_searched else "")
                self.sessions.add_turn(sid, "assistant", answer, note="BUDGET_STOP")
                return self._payload(
                    sid, answer, outcomes, view, [],
                    need_confirm=True, stopped_reason="AI_BUDGET_STOP",
                )

            if not result.tool_calls:
                answer = result.content or ""
                break

            messages.append(
                {
                    "role": "assistant",
                    "content": result.content or "",
                    "tool_calls": [
                        {
                            "id": c["id"],
                            "type": "function",
                            "function": {"name": c["name"], "arguments": c.get("arguments_raw") or "{}"},
                        }
                        for c in result.tool_calls
                    ],
                }
            )
            for call in result.tool_calls:
                # ── ★★ T14·S3：`request_action` —— 变更"请求"，**不走执行那条路** ──────
                #   ★★ 它必须**排在 `action_id_from_model` 之前**：这个工具名**不是动作 id**
                #      （没有对应的 YAML、没有对应的命令），让映射函数去处理它，
                #      会得到一个"查无此动作"——那是**错的方向**：它不是动作，是"请求"。
                # ── ★★ T15·S3：`kb_search` —— 本地知识检索，**只读、不碰目标机** ──────
                #   ★ 它必须**排在 `action_id_from_model` 之前**（同 `request_action`）：
                #     它不是动作 id（没有 YAML、没有命令），让映射函数处理它会得到
                #     一个"查无此动作"——那是**错的方向**。
                #   ★★ 它**不执行任何东西**、也不写任何东西：只查本地结构化记录。
                if str(call.get("name") or "") == KB_TOOL_NAME and self.knowledge is not None:
                    args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                    q = str(args.get("query") or "").strip()
                    if not q:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(
                                {"status": "need_params", "missing": ["query"],
                                 "advice": "你要查什么？把用户的原话给我。"},
                                ensure_ascii=False,
                            ),
                        })
                        continue
                    found = self.knowledge.search(q)
                    # ★ 记成**事件轮次**（不是 ai_tool_call）：它没有 task_id，
                    #   也不该被当成"一次执行"（§12.105.4 的口径）。
                    self.sessions.add_turn(
                        sid, "system",
                        f"本地知识检索：{q}（命中 {found.get('hit_count')} 条）",
                        note="KB_SEARCH",
                    )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": found.get("text") or "",
                    })
                    continue

                if str(call.get("name") or "") == REQUEST_TOOL_NAME and self.requests is not None:
                    stop = self._handle_request_call(sid, call, messages)
                    if stop is not None:
                        return stop
                    continue

                action_id = action_id_from_model(call["name"])
                params = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}

                # ★ 复合读去重（§12.91）：同一轮里"更全的那个"已经跑过，就别再跑它的子动作。
                #   ★ 留痕：说清为什么跳过；★ 它**不算"没查"**（不进 not_searched）。
                if self.settings.dedupe_composite and action_id in covered:
                    why = f"本轮的复合读动作已覆盖 {action_id}（规范 §12.91：同一件事不查两遍）"
                    self.sessions.add_turn(sid, "system", f"跳过 {action_id}：{why}", note="DEDUPE")
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(
                                {"status": "skipped", "action_id": action_id, "why": why,
                                 "★": "这不是失败：它已经被一个更全的动作覆盖了，结论就在那一条里。"},
                                ensure_ascii=False,
                            ),
                        }
                    )
                    continue

                try:
                    rows = self.run_action_readonly(action_id, decision.host_ids, params)
                except OpsError as exc:
                    if exc.code in ("AI_NEED_PARAMS", "AI_NEED_CONFIRM_SCOPE", "AI_NO_SUCH_ACTION"):
                        question = f"{exc.reason}\n{exc.advice}"
                        self.sessions.add_turn(sid, "assistant", question, note=exc.code)
                        view = self._final_view()
                        return self._payload(
                            sid, question, outcomes, view, [],
                            need_confirm=True, stopped_reason=exc.code,
                        )
                    # ★ 闸门拒绝：说清"这需要人确认 + 该去哪儿"（规范 §12.47 同源；验收 #4）
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(
                                {
                                    "status": "rejected",
                                    "error": {"code": exc.code, "reason": exc.reason},
                                    "explain": exc.reason,
                                    "advice": exc.advice,
                                    "★": "这不是故障：AI 只允许跑只读动作。要把这件事做完，请让用户在界面里自己点。",
                                },
                                ensure_ascii=False,
                            ),
                        }
                    )
                    continue

                covered.update(self.face.covers(action_id))
                outcomes.extend(rows)
                self._all_outcomes.extend(rows)
                if isinstance(call.get("arguments"), dict):
                    self._params_by_action.setdefault(action_id, dict(call["arguments"]))
                # ★ 回给模型的是**本次调用的聚合**（定位表 ＋ 三段交代的紧凑文本），不是原文
                local = aggregate(
                    rows,
                    params_by_action={action_id: params},
                    host_order=[h.id for h in self.cfg.hosts],
                    max_rows=self.settings.retrieval_max_rows,
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": text_for_model(local),
                    }
                )
        else:
            answer = "（达到轮数上限，先停在这里；把问题拆小一点再问，或提高 ai.max_rounds）"

        conflicts = self._detect_conflicts(answer, outcomes)
        view = self._final_view()
        # ★★ §12.88 规矩 1：只要**有机器没查到**，回答的**第一句**就要说出来（不许埋在末尾）
        if view.not_searched and "没查到" not in answer[:160]:
            answer = "★ **有机器没查到（结论不完整）** —— 详见下面的范围交代。\n" + answer
        self.sessions.add_turn(
            sid, "assistant", answer, conflict=bool(conflicts), note="DUAL_CHECK"
        )
        return self._payload(sid, answer, outcomes, view, conflicts)

    # ------------------------------------------------------------------ 双结论对照
    @staticmethod
    def _detect_conflicts(answer: str, outcomes: list[ToolOutcome]) -> list[str]:
        """★ 冲突 = "AI 说成了" vs "工作台没证成"（验收 #6 / 红线 10）。"""
        hits = [w for w in _CONFIRM_WORDS if w in answer]
        if not hits:
            return []
        bad = [o for o in outcomes if o.verify != "ok"]
        if not bad:
            return []
        return [
            f"★ AI 的措辞里出现「{'、'.join(hits)}」，但工作台判定**未证成**："
            + "；".join(f"{o.action_id}@{o.host_id}（status={o.status}｜verify={o.verify or 'none'}｜任务 {o.task_id or '无'}）" for o in bad)
            + "　⇒ 以工作台为准（规范 §12.73.2）。"
        ]
