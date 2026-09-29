"""工具面导出器：`catalog` → 模型可用的工具表（规范 §12.75 / §12.76 / §12.82）。

三条硬规矩（写在这里，免得后来的人重新发明）：

  · **描述只许有一处定义**：工具描述**直接取自 YAML**，不另写一份。
    ★ 依据 §12.66.2 —— 两张表迟早会漂移（本项目已在"库字段名 ≠ 接口字段名"上付过一次学费）。
  · **风险等级必须进描述**：让模型自己就知道"这个动作我不能擅自跑"。
  · ★ **默认值要连"代价"一起给**：填默认值意味着什么，必须写出来（§12.75.1 第 3 条）。

★ 另外两张表（`COST_NOTES` / `REQUIRE_NOTES`）是 T12·S0 **实测**挣来的知识（不是想象）：
  · 只读 ≠ 无副作用（写远端缓存 / 在管理机落盘 / 长轮询 / 受控逃生口）—— 见 §12.82；
  · 动作 × 主机适配（10 个 `k8s.*` 在 `node-03` 上全撞墙，因为只有控制面有 kubeconfig）—— 见 §12.76。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from app.catalog import Action, Param
from app.config import AppConfig
from app.errors import OpsError
from app.yamlload import load_yaml

# ★ T15·S3：`kb_search` 的 schema（定义在知识模块里 —— 谁实现谁定义，别处只许引用）
from app.ai.knowledge import kb_tool_spec

# ------------------------------------------------------------------ 知识表

# ★ 副作用代价（规范 §12.82）：只读动作里"有代价"的那几类，必须在工具描述里写明。
COST_NOTES: dict[str, str] = {
    "pkg.outdated": "★ 代价：会刷新目标机的包缓存（dnf 取元数据，写 /var/cache/dnf）",
    "pkg.search": "★ 代价：会刷新目标机的包缓存（含 makecache）",
    "file.pull": "★ 代价：会在【管理机】落盘（repo/var/downloads/，文件名与远端一致）",
    "k8s.wait": "★ 代价：会轮询等待（可能长时间占用），必须给 wait_seconds",
    "host.checkup": "★ 代价：聚合十余项检查、耗时较长；★ 不要与它内部的子动作重复调用（同一件事查两遍）",
    "log.view": "★ 代价：大日志会被截断（截断处在结论里标明）",
    "k8s.kubectl": "★ 代价：受控逃生口（只读子命令白名单 + 受控枚举参数）；★ 要写请用对应的 k8s 变更动作",
    # ── ★★ T16（规范 §12.115 ~ §12.122）：域 M · 虚拟化层 ──
    #    ★★ 这五条是 `channel: local` 的动作：它们跑在**宿主机**上（本机 `vmrun.exe`），
    #      **不是** ssh 到目标机 —— 代价要如实说，否则模型会以为"这是一次远程只读"。
    "vm.list": "★ 代价：本机执行（`vmrun list` ＋ 扫 allow_vmx_dirs 下的 .vmx ＋ 只读 inventory.vmls）；★ 很便宜，但读的是**宿主机**不是目标机",
    "vm.status": "★ 代价：本机执行（问 VMware 两次：运行清单 ＋ 快照链）；★ 电源状态问的是 VMware 自己，不是看文件在不在",
    "vm.ip": "★ 代价：本机执行（经 VMware Tools 问 guest 要地址）；★ 关机的 VM 上这条**会失败**（那是结论，不是故障），且它不证明 ssh 通",
    "vm.snapshot-list": "★ 代价：本机执行（`vmrun listSnapshots`）；★ 对**已关机**的 VM 也能读——回滚某条快照**不必先开机**",
    "vm.wait-guest": "★ 代价：**会轮询等待**（最多 timeout_sec 秒，默认 180）；★ 它回答「guest 起来了吗」，**不回答**「能不能 ssh 进去」",
}

# ★ 角色 / 依赖（规范 §12.76）：**角色信息只有一个来源 —— hosts.yaml**；这里只写"动作需要什么"。
REQUIRE_BY_ACTION: dict[str, str] = {
    "sec.cert": "★ 依赖：目标机要有 openssl（本环境只有 docker-01 有）",
    "svc.configtest": "★ 依赖：目标机要装了对应程序（nginx / sshd / mariadbd）",
    "container.overview": "★ 依赖：目标机要有容器运行时与容器",
    "container.runtime": "★ 依赖：目标机要有容器运行时（ctr）",
    "db.mariadb-ping": "★ 依赖：目标机要装过 mariadb（没装 = 结论「没装」，不是故障）",
    "db.valkey-ping": "★ 依赖：目标机要装过 valkey（没装 = 结论「没装」，不是故障）",
    "nfs.export-check": "★ 依赖：目标机要有 NFS 导出（没有导出 = 结论本身，不是故障）",
    "host.checkup": "★ 依赖：无（缺工具会降级，不拖垮报告）",
    # ── ★★ T16（规范 §12.115 / §12.116）：域 M 的动作**依赖的是宿主机**，不是目标机 ──
    #    ★ 这一条非写不可：模型很容易把"vm.* 要一台机器"理解成"要 ssh 上那台 VM"。
    #      真相是：命令跑在**宿主机**上，而"这台 VM 让不让碰"由 `hosts.yaml` 的登记回答。
    "vm.list": "★ 依赖：**宿主机**上跑得动 `vmrun.exe`（本机实测 `C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe`）；★ 不需要 ssh 到任何目标机",
    "vm.status": "★ 依赖：同 `vm.list` —— 本机 `vmrun`；★ 对象必须是**已登记**或**当次点名**的 VM（红线 12）",
    "vm.ip": "★ 依赖：本机 `vmrun` ＋ guest 里装了 VMware Tools；★ 没有 Tools ⇒ 读不到地址（不是「VM 不在」）",
    "vm.snapshot-list": "★ 依赖：本机 `vmrun`；★ 只读，关机也读得到",
    "vm.wait-guest": "★ 依赖：本机 `vmrun` ＋ guest 里的 VMware Tools；★ 等不到会**如实判红**",
}

# 域 → 依赖提示（域级兜底；动作级优先）
REQUIRE_BY_DOMAIN: dict[str, str] = {
    "J": "★ 依赖角色：需要能读集群的入口（控制面；★ 工作节点上没有 kubeconfig 是正常现象，不是集群故障）",
}

# ★ 复合读的**覆盖关系**（T13 · 规范 §12.91）：左边这个动作**已经包含了**右边这些 ——
#   同一轮里若已选左边，就不再单独跑右边（白烧 token，且两边结论可能打架）。
#   ★ 这是"既有知识表里的**一个字段**"，不是第二张知识表（§12.91 规矩 1）。
#   ★ 清单来源：`app/checkup.py` 里的**实际引用**（S2 用脚本逐行扫出来的，不是凭印象列的）；
#     改 `checkup.py` 的检查项时**必须回来同步这里**（否则去重会错，而它错得很安静）。
COVERS: dict[str, tuple[str, ...]] = {
    "host.checkup": (
        "host.datetime", "disk.usage", "disk.topdir", "svc.list", "kernel.log",
        "sec.selinux", "net.firewall", "net.port", "sec.cert", "pkg.installed",
    ),
}

_MON_PREFIX = "mon."


def _require_note(action: Action) -> str:
    if action.id in REQUIRE_BY_ACTION:
        return REQUIRE_BY_ACTION[action.id]
    if action.id.startswith(_MON_PREFIX):
        return "★ 依赖：要在装了监控栈的那台机器上跑（本环境是 node-03）"
    return REQUIRE_BY_DOMAIN.get(action.domain, "")


# ------------------------------------------------------------------ 工具名映射

# ★ OpenAI 兼容接口对 function name 有字符限制（`^[a-zA-Z0-9_-]{1,64}$`），
#   而动作 id 里有点（`k8s.pods`）⇒ **必须映射**，且**必须能反向还原**（否则 AI 的调用对不上动作）。
_MODEL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

#: ★★ T14·S3：**变更"请求"那个工具的名字**（规范 §12.96）。
#: ★ 它是一条**独立的工具**，不是"动作表里的一个动作" —— 这个区别很重要：
#:   动作表（`catalog/actions/*.yaml`）里的每一条**都对应一条真实命令**；
#:   而 `request_action` **不对应任何命令**，它只往库里写一条待办（§12.96.2 规矩 1）。
REQUEST_TOOL_NAME = "request_action"

#: ★★ T15·S3：**本地知识检索**那个工具的名字（规范 §12.106）。
#: ★ 与 `request_action` 同一类的"特殊工具"：它**不对应任何动作**（没有 YAML、没有命令），
#:   它只查**本地结构化记录**（会话 / 人的问句 / 工具调用 / 变更请求 / 任务结论）。
#: ★★ 它**只有读**：没有"写候选 / 存知识"这种入参（§12.107.3 / 断言 Ⓕ）。
KB_TOOL_NAME = "kb_search"


def model_name(action_id: str) -> str:
    return action_id.replace(".", "__").replace("-", "_")


def action_id_from_model(name: str) -> str:
    return name.replace("__", ".").replace("_", "-")


def _check_roundtrip(action_ids: Iterable[str]) -> None:
    """★ 映射必须可逆 —— 不可逆就等于"AI 调了一个不存在的动作"（静默错位）。"""
    for aid in action_ids:
        back = action_id_from_model(model_name(aid))
        if back != aid:
            raise OpsError(
                code="AI_TOOLFACE_INVALID",
                reason=f"工具名映射不可逆：{aid} → {model_name(aid)} → {back}",
                advice="动作 id 里出现了 `_` 或 `-`/`.` 的混合写法，请改用 kebab-case（规范 §1）。",
            )


# ------------------------------------------------------------------ 工具面

class ToolFace:
    """工具面：**只含 green**（铁律 9 / 红线 7）。"""

    def __init__(self, cfg: AppConfig, actions: dict[str, Action]) -> None:
        self.cfg = cfg
        self.all_actions = actions
        self.green = {aid: a for aid, a in actions.items() if a.risk == "green"}
        self.exposed = set(self.green)
        _check_roundtrip(self.green)
        self.domain_names = self._load_domain_names()
        # ── ★★ T14·S3：`yellow` 白名单（规范 §12.96.1 / 开题单 §4.3 D4）──────
        # ★ 默认**空**：`config.yaml` 里没写这一项 ⇒ 一个 `yellow` 都不放开。
        # ★★ 这里**只负责取**，不负责判"该不该放开" —— 判据在
        #    `app/ai/requests.py::APPROVED_YELLOW`（"上限"），审计在 `ActionRequests.audit_allowlist()`。
        #    这样拆的理由：**"配置读没读对"与"该不该放开"是两件事**，混在一起出了错不知道该看哪边。
        raw_allow = ((cfg.raw or {}).get("ai") or {}).get("yellow_allowlist") or []
        if not isinstance(raw_allow, (list, tuple)):
            raise OpsError(
                code="AI_CONFIG_INVALID",
                reason="config.yaml 的 ai.yellow_allowlist 必须是列表",
                advice="写成 `yellow_allowlist: [pkg.install, svc.start]` 这样；不写 = 一个都不放开。",
            )
        self.yellow_allowlist: tuple[str, ...] = tuple(str(x) for x in raw_allow)
        self.yellow_exposed = {
            aid: actions[aid]
            for aid in self.yellow_allowlist
            if aid in actions and actions[aid].risk == "yellow"
        }

    # -- 域名（★ 只有一个来源：map.yaml；不另写一份）────────────────────
    def _load_domain_names(self) -> dict[str, str]:
        try:
            raw = load_yaml(self.cfg.paths.map)
        except Exception:
            return {}
        doms = raw.get("domains") if isinstance(raw, dict) else None
        if not isinstance(doms, dict):
            return {}
        out: dict[str, str] = {}
        for key, value in doms.items():
            if isinstance(value, dict):
                out[str(key)] = str(value.get("name") or key)
            else:
                out[str(key)] = str(value)
        return out

    # -- 闸门：非 green 一律拒绝（说人话，而不是静默失败，规范 §12.47 同源）──
    def covers(self, action_id: str) -> tuple[str, ...]:
        """★ 复合读覆盖关系（§12.91）：这个动作**已经包含了**哪些动作。

        ★ 用途只有一个：同一轮里别把"更全的那个"和"它的子动作"都跑一遍。
        ★ 它**不**改变任何动作的语义，也不进工具面（模型看不到它）。
        """
        return COVERS.get(action_id, ())

    def guard(self, action_id: str) -> Action:
        action = self.all_actions.get(action_id)
        if action is None:
            raise OpsError(
                code="AI_NO_SUCH_ACTION",
                reason=f"没有这个动作：{action_id}",
                advice="用域索引重新挑一个；或先在「动作」页签确认它的 id。",
            )
        if action.risk != "green":
            raise OpsError(
                code="AI_NOT_READONLY",
                reason=(
                    f"动作「{action.title}」（{action.id}）的风险等级是 {action.risk}，"
                    f"AI 只允许跑只读（green）动作"
                ),
                advice=(
                    "这需要人来确认：请在「动作」页签里自己选它 —— "
                    + ("yellow 要点一次确认；red 必须手输确认词。" if action.risk == "red" else "yellow 要点一次确认。")
                ),
                context={"risk": action.risk, "action_id": action.id},
            )
        return action

    # -- L1 域索引（常驻上下文，很短）────────────────────────────────
    def l1_index(self) -> dict[str, Any]:
        by_domain: dict[str, list[str]] = {}
        for aid, action in sorted(self.green.items()):
            by_domain.setdefault(action.domain, []).append(aid)
        domains = [
            {
                "domain": key,
                "name": self.domain_names.get(key, key),
                "tool_count": len(ids),
            }
            for key, ids in sorted(by_domain.items())
        ]
        return {
            "tier": "L1",
            "note": "先按域找人话里的意图，再用 L2 展开该域的动作摘要；要用某个动作时再取 L3 的完整参数。",
            "tool_total": len(self.green),
            # ★ T14·S3：让模型知道"还有一类事情可以**请求**"（★ 只说数量，不说执行）
            "requestable_total": len(self.yellow_exposed),
            "requestable_note": (
                "★ 这些是**变更类**动作：你不能执行，只能**请求**（`request_action`）——"
                "人点确认之后平台才会跑。" if self.yellow_exposed else
                "★ 当前**没有**任何变更动作被放开给你（白名单为空）。"
            ),
            "domains": domains,
            "hosts": [
                {"id": h.id, "name": h.name, "role": h.role, "tags": h.tags}
                for h in self.cfg.hosts
            ],
        }

    # -- L2 域内摘要 ────────────────────────────────────────────────
    def l2_domain(self, domain: str) -> list[dict[str, Any]]:
        rows = []
        for aid, action in sorted(self.green.items()):
            if action.domain != domain:
                continue
            rows.append(
                {
                    "id": aid,
                    "title": action.title,
                    "summary": action.summary,
                    "risk": action.risk,
                    "required_params": [p.name for p in action.params if p.required],
                }
            )
        if not rows:
            raise OpsError(
                code="AI_NO_SUCH_DOMAIN",
                reason=f"域「{domain}」下没有被放开给 AI 的动作",
                advice=f"可用域：{'、'.join(sorted({a.domain for a in self.green.values()}))}",
            )
        return rows

    # -- L3 完整 schema ────────────────────────────────────────────
    def l3_schema(self, action_id: str) -> dict[str, Any]:
        action = self.guard(action_id)
        return {
            "id": action.id,
            "model_name": model_name(action.id),
            "title": action.title,
            "summary": action.summary,
            "domain": action.domain,
            "risk": action.risk,
            "note": action.note.strip(),
            "cost_note": COST_NOTES.get(action.id, ""),
            "require_note": _require_note(action),
            "params": [_param_schema(p) for p in action.params],
            "required": [p.name for p in action.params if p.required],
        }

    # -- 模型可用的 function schema（★ 可按域收窄 —— 三层暴露的落地，规范 §12.75）──
    def function_specs(self, domains: Iterable[str] | None = None) -> list[dict[str, Any]]:
        keep = set(domains) if domains else None
        specs = [
            function_spec(a, _require_note(a))
            for _, a in sorted(self.green.items())
            if keep is None or a.domain in keep
        ]
        # ★★ T14·S3：`request_action` **永远**跟着工具表一起来（它不属于任何域）——
        #   而且**只在白名单非空时**才出现：空白名单下给模型一个"请求变更"的工具，
        #   等于把它引到一个必然被拒的入口上（§12.99.3：不许把人引到死路上）。
        if self.yellow_exposed:
            specs.append(request_spec(self))
        # ── ★★ T15·S3：本地知识检索（§12.106）─────────────────────────
        #   ★ 它**永远**跟着工具表一起来（不属于任何域）："上次这类问题怎么解决的"
        #     跟"这次查哪台机器"是两件事，按域收窄会把它一起收掉。
        #   ★★ 它**只有读**；"生成候选"那条写文件的通道**不在工具面里**（§12.107.3）。
        specs.append(kb_tool_spec())
        return specs

    # -- L2 全量摘要（★ 给"选域"那一轮用的纯文本，比 schema 便宜一个数量级）──
    def l2_digest_text(self) -> str:
        lines: list[str] = []
        for key in sorted({a.domain for a in self.green.values()}):
            rows = self.l2_domain(key)
            lines.append(f"[{key}] {self.domain_names.get(key, key)}（{len(rows)} 个动作）")
            for r in rows:
                req = f" 必填:{','.join(r['required_params'])}" if r["required_params"] else ""
                lines.append(f"  - {r['id']}：{r['title']} —— {r['summary'][:70]}{req}")
        return "\n".join(lines)

    # -- 生成物（★ 进版本控制，供自检对账，规范 §12.75.2）────────────
    def to_json(self) -> dict[str, Any]:
        return {
            "generated_from": "catalog/actions/*.yaml（risk: green）",
            "rule": "★ 工具面只含 green；本文件由 tools/ai-export.py 生成，改动作后需重新生成（自检断言 ⑶ 会对账）",
            "tool_total": len(self.green),
            "action_total": len(self.all_actions),
            # ── ★★ T14·S3：放开给 AI「请求」的 `yellow`（**它不是工具面的一部分**）──
            # ★ 为什么单独一段：`tools` 那一节的口径是"AI 能**执行**的动作"，
            #   而这里列的**一个都不能执行**（只能请求）。混在一起会让读的人以为它能跑。
            "request_tool": REQUEST_TOOL_NAME,
            "request_rule": (
                "★ `yellow` 只可**请求**（`request_action` ⇒ 一张待确认卡片）；"
                "`red` 连请求都不许发（§12.96.1）。"
            ),
            # ── ★★ T15·S3：本地知识检索（§12.106）—— 它**也是特殊工具**，不是动作 ──
            # ★★ 为什么单独一段、不混进 `tools`：那一段的口径是"AI 能**执行**的动作"，
            #   而 `kb_search` **不执行任何东西**（只查本地结构化记录）。
            "kb_tool": KB_TOOL_NAME,
            "kb_rule": (
                "★ `kb_search` 只**读**本地结构化记录（会话 / 人的问句 / 工具调用 / 变更请求 / 任务结论）；"
                "★ **不含** AI 自己的历史回答（不可核的散文，§12.106.2）；"
                "★ 命中不到会明说「没有记录」并交代查了哪些范围（§12.106.3）。"
            ),
            "requestable": [
                {
                    "id": a.id,
                    "title": a.title,
                    "domain": a.domain,
                    "risk": a.risk,
                    "summary": a.summary,
                }
                for _, a in sorted(self.yellow_exposed.items())
            ],
            "tools": [
                {
                    "id": a.id,
                    "model_name": model_name(a.id),
                    "domain": a.domain,
                    "risk": a.risk,
                    "title": a.title,
                    "summary": a.summary,
                    "param_count": len(a.params),
                    "required": [p.name for p in a.params if p.required],
                    "cost_note": COST_NOTES.get(a.id, ""),
                    "require_note": _require_note(a),
                }
                for _, a in sorted(self.green.items())
            ],
        }


# ------------------------------------------------------------------ schema 组装


def _param_schema(p: Param) -> dict[str, Any]:
    """参数 → JSON Schema 片段。★ 默认值连"用它意味着什么"一起给（规范 §12.75.1 第 3 条）。"""
    schema: dict[str, Any] = {}
    if p.type == "int":
        schema["type"] = "integer"
        if p.min is not None:
            schema["minimum"] = p.min
        if p.max is not None:
            schema["maximum"] = p.max
    elif p.type == "bool":
        schema["type"] = "boolean"
    elif p.type == "enum" and p.values:
        schema["type"] = "string"
        schema["enum"] = list(p.values)
    else:
        schema["type"] = "string"
        if p.pattern:
            schema["pattern"] = p.pattern

    bits: list[str] = [p.label or p.name]
    if p.help:
        bits.append(p.help.strip())
    if p.choices:
        bits.append("可取值：" + "、".join(p.choices))
    if p.default not in (None, ""):
        bits.append(f"默认 {p.default} —— 不填就用它（★ 想清楚用它意味着什么再省这一步）")
    else:
        bits.append("★ 没有默认值：必须问清楚或由用户明确给出（不许瞎猜）")
    schema["description"] = "｜".join(bits)
    return {"name": p.name, **schema}


def request_spec(face: ToolFace) -> dict[str, Any]:
    """★★ `request_action` 的工具 schema（T14·S3 · 规范 §12.96 / §12.99.2）。

    ★★ 这个 schema 里**没有**「确认词」那个字段（连拼写都不出现）——
      判据不是「约定了不传」，而是**「它根本不在那里」**（§12.99.2 / 断言 ⒂）。
    ★ 四个入参都是**事实**（选哪个动作、哪台机、什么参数、为什么），
      卡片上那五段文字**一个都不由模型填** —— 它们由 `app/ai/requests.py` 生成（§12.98.2）。
    """
    ids = sorted(face.yellow_exposed)
    listing = "；".join(f"{aid}（{face.yellow_exposed[aid].title}）" for aid in ids)
    desc = [
        "请求一次变更：★ 你**不执行**，只是把一张卡片摆给人看；人点确认之后平台才会跑。",
        "风险：yellow —— ★ AI 只可「请求」，不可执行；red 连请求都不许发。",
        f"可以请求的动作（只列被批准的那些）：{listing}",
        "★ 卡片上的五段话（要做什么 / 影响面 / 怎么撤 / 撤不回来的是什么 / 判据）"
        "**全部由平台填写**，你不需要也不允许自己写 —— 你只负责提出并说明理由。",
        "★ 一次只提一个动作（不许把一串动作揉进一次请求）。",
        "★ 收到卡片后**原样转述**给用户，不许改写、不许承诺结果（「已修复」那种话你没有资格说）。",
    ]
    props: dict[str, Any] = {
        "action_id": {
            "type": "string",
            "enum": ids,
            "description": "要请求的动作 id（只列被批准的那些；不在列表里的会被拒）",
        },
        "host_id": {
            "type": "string",
            "enum": [h.id for h in face.cfg.hosts],
            "description": "目标机 id（取自主机清单，★ 不许自己拼地址）",
        },
        "params": {
            "type": "object",
            "description": "该动作的参数（★ 从 L3 schema 取；缺必填参数会被拒，不许瞎猜）",
        },
        "reason": {
            "type": "string",
            "description": "为什么提议做这件事（人读它做决定，一句话说清）",
        },
    }
    return {
        "type": "function",
        "function": {
            "name": REQUEST_TOOL_NAME,
            "description": "\n".join(desc),
            "parameters": {
                "type": "object",
                "properties": props,
                "required": ["action_id", "host_id", "params", "reason"],
            },
        },
    }


def function_spec(action: Action, require_note: str) -> dict[str, Any]:
    desc = [f"{action.title}｜{action.summary}", f"风险：{action.risk}（只读，可自主执行）"]
    if action.id in COST_NOTES:
        desc.append(COST_NOTES[action.id])
    if require_note:
        desc.append(require_note)
    props: dict[str, Any] = {}
    for p in action.params:
        s = _param_schema(p)
        props[s.pop("name")] = s
    return {
        "type": "function",
        "function": {
            "name": model_name(action.id),
            "description": "\n".join(desc),
            "parameters": {
                "type": "object",
                "properties": props,
                "required": [p.name for p in action.params if p.required],
            },
        },
    }


def write_json(path: Path, face: ToolFace) -> dict[str, Any]:
    payload = face.to_json()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload
