"""检索聚合与范围交代（规范 **§12.86 ~ §12.90** · T13 · 五·AI 助手）。

★ 本模块是**纯函数层**：输入"每次工具调用的结果"，输出「**定位表** ＋ **三段交代**」。
  它**不碰** ssh / engine / dispatch，也不发任何网络请求 ⇒ 可以**离线单测**（断言 ⑹ ⑼ ⑻ 都在离线门里）。

★★ 本模块存在的理由（T13 的主题句）：

    「找不到」是一条结论，不是一句「没查到」。

  所以它有**三种必须在输出里分开**的情形（§12.88）：
    ① 查过了，确实没有（`status=ok` 且结论里是「（无）」）
    ② 没查成（动作跑不出来 ⇒ `not_searched`）
    ③ 查了但可能不全（命中接近上限 / 被截断 ⇒ `truncated`）

★★ 两条不许越过的线：
  · **跨机永不合并**（§12.86）：`host_id` 不同 = 两个东西，哪怕路径逐字相同。
  · **解析不出来就说解析不出来**（`kind="unparsed"`），**不许假装定位到了**。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

# ── 结论里的固定记号（都来自动作自己的 conclusion 模板，改动要同步对应用户可见文案）──
NO_VALUE = "（无）"                      # ★ 独立成行才算"没有"（判读句里的「（无）」带书名号，不算）
TRUNC_RE = re.compile(r"〔已截断：保留 (\d+) 字符 / 共 (\d+) 字符〕")
LIMIT_RE = re.compile(r"最多[^\d\n]{0,12}(\d+)\s*(条|行)")
PARSER_TRUNC_RE = re.compile(r"〔输出已截断：仅显示前\s*(\d+)\s*行／共\s*(\d+)\s*行〕")
GREP_LINE_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+):(?P<text>.*)$")
GREP_BLOCK_RE = re.compile(r"·\s*命中[^\n]*\n(?P<body>.*?)(?:\n\s*判读：|\Z)", re.S)

# ★ 检索类参数：只有这些名字的参数才参与"来源判定"（§12.85）与其他动作区分开
SCOPE_PARAM_NAMES = ("path", "dir", "directory", "keyword", "name", "unit", "target", "binary", "package")

# ★ 只有这些动作才产出"命中行"（§12.86）。非检索类动作（`host.overview` 之类）只进 `searched_scope` ——
#   否则一次概览也会被当成"一条命中"，定位表会被噪音灌满。
SEARCH_ACTIONS = frozenset({
    "file.grep", "file.cat", "file.manifest", "file.stat",
    "disk.bigfiles", "disk.topdir", "disk.usage",
    "log.view", "kernel.log",
    "pkg.installed", "pkg.search",
    "net.port", "net.addr", "net.dns", "net.firewall",
    "svc.list", "svc.status", "timer.list",
    "sec.cert", "sec.avc", "sec.selinux", "sec.ssh-harden",
    "nfs.export-check",
    "k8s.nodes", "k8s.pods", "k8s.workloads", "k8s.certs", "k8s.config",
    "mon.targets", "mon.alerts", "mon.rules",
})


@dataclass
class Hit:
    """一条命中（定位表的一行）。"""
    host: str
    where: str              # 路径:行号 / unit / 端口 / 包名 / 动作摘要
    what: str               # 命中内容（逐字片段）
    task_id: str
    action_id: str = ""
    kind: str = "hit"       # hit（结构化定位）/ summary（有内容但未结构化）

    def key(self) -> tuple[str, str, str]:
        """★ 去重键：**含 host** —— 跨机永不合并（§12.86）。"""
        return (self.host, self.where, self.what)


@dataclass
class RetrievalView:
    rows: list[Hit] = field(default_factory=list)
    hit_count: int = 0                # 去重后命中数
    host_count: int = 0               # 涉及主机数
    searched_scope: list[dict[str, Any]] = field(default_factory=list)
    not_searched: list[dict[str, Any]] = field(default_factory=list)
    truncated: list[dict[str, Any]] = field(default_factory=list)
    limits: list[dict[str, Any]] = field(default_factory=list)   # ★ 动作自带显示上限（≠ 这次被砍）
    no_hit_hosts: list[str] = field(default_factory=list)     # 查过了、确实没有的机器
    ok_hosts: list[str] = field(default_factory=list)         # 查成了的机器
    dropped_dupes: int = 0
    note: str = ""

    @property
    def possible_incomplete(self) -> bool:
        """★ 只要有**动作层上限**，就存在"可能不全"的风险；确实被砍过当然更算（§12.90）。"""
        return bool(self.truncated) or bool(self.limits)


def _standalone_no_value(text: str) -> bool:
    """★ "没有"的判据：**存在独立成行**的「（无）」。

    ★ 为什么不是 `"（无）" in text`（S0 实测踩过）：结论的**判读段**里固定写着
      「显示「（无）」表示…」——带书名号，那是文案，不是数据。
      实测：`file.grep` 有命中时，`text.count("（无）")` 也是 1（来自判读段）。
    """
    for line in (text or "").splitlines():
        if line.strip() == NO_VALUE:
            return True
    return False


def parse_conclusion(action_id: str, host_id: str, task_id: str, conclusion: str) -> tuple[list[Hit], str, bool]:
    """把一条结论变成命中行。

    返回 `(hits, kind, no_hit)`：
      · `kind="grep"`      —— 结构化定位成功（路径:行号:内容）
      · `kind="summary"`   —— 有内容，但**未结构化**（只给一条摘要，★ 不假装定位）
      · `kind="none"`      —— 独立成行的「（无）」 ⇒ 查过了、确实没有
    """
    text = conclusion or ""

    # ⓪ ★ 只有"检索类动作"才产出命中行（§12.86）—— 否则一次 `host.overview` 会变成"一条命中"
    if action_id not in SEARCH_ACTIONS:
        return [], "skip", False

    # ① file.grep：能解析出「路径:行号:内容」⇒ 真正的定位
    if action_id == "file.grep":
        m = GREP_BLOCK_RE.search(text)
        body = m.group("body") if m else ""
        raw_lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        # 命中区块里除分隔行 `--` 外为空、或只有「（无）」⇒ 真的没命中
        real = [ln for ln in raw_lines if ln != "--" and ln != NO_VALUE]
        hits: list[Hit] = []
        for ln in real:
            mm = GREP_LINE_RE.match(ln)
            if mm:
                hits.append(
                    Hit(
                        host=host_id,
                        where="%s:%s" % (mm.group("path"), mm.group("line")),
                        what=mm.group("text").strip(),
                        task_id=task_id,
                        action_id=action_id,
                    )
                )
        if hits:
            return hits, "grep", False
        if not real:
            return [], "none", True

    # ② 通用：独立成行的「（无）」⇒ 查过了、确实没有
    if _standalone_no_value(text):
        return [], "none", True

    # ③ 兜底：有内容但未结构化 ⇒ 只给摘要（★ 不许假装定位到了）
    head = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if not head:
        return [], "none", True
    return (
        [Hit(host=host_id, where="（整条结论，未结构化）", what=head[:160], task_id=task_id,
             action_id=action_id, kind="summary")],
        "summary",
        False,
    )


def _scope_of(action_id: str, params: dict[str, Any] | None) -> str:
    """把一次调用的**参数范围**写成一行（进 `searched_scope`，§12.88）。"""
    if not params:
        return "（动作默认参数）"
    bits = []
    for k, v in params.items():
        if v in (None, ""):
            continue
        bits.append("%s=%s" % (k, str(v)[:60]))
    return "、".join(bits) if bits else "（动作默认参数）"


def _truncation_of(action_id: str, host_id: str, task_id: str, conclusion: str) -> list[dict[str, Any]]:
    """识别**三层截断**（§12.90）：平台层字符配额 / 动作层自带上限 / 解析器层行数上限。"""
    out: list[dict[str, Any]] = []
    text = conclusion or ""
    m = TRUNC_RE.search(text)
    if m:
        out.append({
            "layer": "platform", "host": host_id, "action_id": action_id, "task_id": task_id,
            "kept": int(m.group(1)), "total": int(m.group(2)),
            "note": "平台回传配额所限，只保留了前 %s 字符（共 %s 字符）" % (m.group(1), m.group(2)),
        })
    m = PARSER_TRUNC_RE.search(text)
    if m:
        out.append({
            "layer": "parser", "host": host_id, "action_id": action_id, "task_id": task_id,
            "limit": int(m.group(1)), "total": int(m.group(2)),
            "note": "解析器只取了前 %s 行（原始共 %s 行）—— **可能还有更多**" % (m.group(1), m.group(2)),
        })
    return out


def _limits_of(action_id: str, host_id: str, task_id: str, conclusion: str) -> list[dict[str, Any]]:
    """★ 动作**自带**的显示上限（§12.90）—— 它**不等于**"这次被砍了"，但必须**原样转述**。

    ★ 为什么与 `_truncation_of` 分开（T13 单测当场抓出来的）：
      把两者混在一个列表里，会出现"这台只是有上限"被读成"这台被截断了"——
      而反过来又会漏掉真正被砍的那台。**语义不同就不能同框。**
    """
    out: list[dict[str, Any]] = []
    m = LIMIT_RE.search(conclusion or "")
    if m:
        out.append({
            "layer": "action", "host": host_id, "action_id": action_id, "task_id": task_id,
            "limit": int(m.group(1)), "unit": m.group(2),
            "note": "动作自带显示上限「最多 %s %s」—— 引用时**必须原样转述**，不许说成"
                    "「一共 %s %s」" % (m.group(1), m.group(2), m.group(1), m.group(2)),
        })
    return out


def aggregate(
    outcomes: Sequence[Any],
    params_by_action: dict[str, dict[str, Any]] | None = None,
    host_order: Sequence[str] | None = None,
    max_rows: int = 40,
) -> RetrievalView:
    """跨机聚合：**去重 → 计数 → 排序 → 定位表** ＋ 三段交代（§12.86 / §12.88）。

    `outcomes` 里每个元素需有：`ok / action_id / host_id / task_id / conclusion / explain`（duck typing）。
    `host_order` 用来排序（★ 沿用 `hosts.yaml` 顺序，不是字典序 —— 顺序稳定才可对照）。
    """
    params_by_action = params_by_action or {}
    view = RetrievalView()

    seen: set[tuple[str, str, str]] = set()
    for o in outcomes:
        host_id = str(getattr(o, "host_id", "") or "")
        action_id = str(getattr(o, "action_id", "") or "")
        task_id = str(getattr(o, "task_id", "") or "")
        ok = bool(getattr(o, "ok", False))
        conclusion = str(getattr(o, "conclusion", "") or "")

        # ★ 没查成 ⇒ 进 not_searched（**不许**算成"没有"）
        if not ok:
            view.not_searched.append({
                "host": host_id,
                "action_id": action_id,
                "reason": str(getattr(o, "explain", "") or "这一步没成功")[:300],
                "advice": "★ 这是**没查到**，不等于这台没有",
            })
            continue

        view.ok_hosts.append(host_id)
        view.searched_scope.append({
            "host": host_id,
            "action_id": action_id,
            "params": _scope_of(action_id, params_by_action.get(action_id)),
        })
        view.truncated.extend(_truncation_of(action_id, host_id, task_id, conclusion))
        view.limits.extend(_limits_of(action_id, host_id, task_id, conclusion))

        hits, _kind, no_hit = parse_conclusion(action_id, host_id, task_id, conclusion)
        if no_hit:
            view.no_hit_hosts.append(host_id)
            continue
        for h in hits:
            if h.key() in seen:            # ★ 同机同位置同一行逐字相同 ⇒ 才算重复
                view.dropped_dupes += 1
                continue
            seen.add(h.key())
            view.rows.append(h)

    # 排序：主机按 hosts.yaml 顺序，再按 where（★ 顺序稳定 = 可对照）
    order = {h: i for i, h in enumerate(host_order or [])}
    view.rows.sort(key=lambda r: (order.get(r.host, 99), r.host, r.where))

    view.hit_count = len(view.rows)
    view.host_count = len({r.host for r in view.rows})
    if len(view.rows) > max_rows:
        extra = len(view.rows) - max_rows
        view.rows = view.rows[:max_rows]
        view.truncated.append({
            "layer": "platform", "host": "（多台）", "action_id": "（聚合）", "task_id": "",
            "limit": max_rows, "total": max_rows + extra,
            "note": "定位表只显示前 %d 行（共 %d 行）—— 需要更多请**收窄范围**再查" % (max_rows, max_rows + extra),
        })

    flags = []
    if view.truncated:
        flags.append("★ 有 %d 处**确实被截断**" % len(view.truncated))
    if view.limits:
        flags.append("★ %d 个动作带显示上限（看到的**不一定是全部**）" % len(view.limits))
    view.note = (
        "共 %d 台：查成 %d 台、没查成 %d 台；命中 %d 条（涉及 %d 台）%s"
        % (len(outcomes), len(set(view.ok_hosts)), len(view.not_searched), view.hit_count,
           view.host_count, ("；" + "；".join(flags)) if flags else "")
    )
    return view


def text_for_model(view: RetrievalView, prefix: str = "") -> str:
    """给模型看的**紧凑**文本（★ 只含结论性内容，不含原文）。"""
    lines: list[str] = []
    if prefix:
        lines.append(prefix)
    lines.append(view.note)
    if view.rows:
        lines.append("定位表（host｜where｜what｜task_id）：")
        for r in view.rows:
            lines.append("  %s｜%s｜%s｜%s" % (r.host, r.where, r.what[:120], r.task_id))
    if view.no_hit_hosts:
        lines.append("★ 查过了、**确实没有**的机器：%s（这是结论，不是故障）" % "、".join(view.no_hit_hosts))
    if view.not_searched:
        lines.append("★ **没查到**的（不是「没有」）：")
        for n in view.not_searched:
            lines.append("  %s｜%s｜%s" % (n["host"], n["action_id"], n["reason"][:200]))
    if view.truncated:
        lines.append("★ **确实被截断**的地方（看到的不全）：")
        for t in view.truncated:
            lines.append("  %s｜%s｜%s" % (t.get("host"), t.get("action_id"), t.get("note")))
    if view.limits:
        lines.append("★ **动作自带显示上限**（★ 不许把它读成总数）：")
        for t in view.limits:
            lines.append("  %s｜%s｜%s" % (t.get("host"), t.get("action_id"), t.get("note")))
    return "\n".join(lines)


def scope_block(view: RetrievalView) -> str:
    """人读的三段交代（§12.88）——★ 顺序固定：没查到在前（它最容易被埋掉）。"""
    lines: list[str] = []
    if view.not_searched:
        lines.append("★ **没查到**（这些机器**没有结论**，不代表它们没问题）：")
        for n in view.not_searched:
            lines.append("  · %s ｜ %s ｜ %s" % (n["host"], n["action_id"], n["reason"][:220]))
    if view.hit_count:
        lines.append("**找到了** %d 条（涉及 %d 台）—— 见上面的定位表。" % (view.hit_count, view.host_count))
    if view.no_hit_hosts:
        lines.append("**没找到**（查过了、确实没有 —— 这是结论，不是故障）：%s"
                     % "、".join(view.no_hit_hosts))
    if view.ok_hosts:
        lines.append("查了哪些（可按任务号回放）：")
        for s in view.searched_scope:
            lines.append("  · %s ｜ %s ｜ %s" % (s["host"], s["action_id"], s["params"]))
    if view.truncated:
        lines.append("★ **确实被截断**（看到的不是全部）：")
        for t in view.truncated:
            lines.append("  · %s ｜ %s" % (t.get("action_id"), t.get("note")))
    if view.limits:
        lines.append("★ **动作自带显示上限**（别读成总数）：")
        for t in view.limits:
            lines.append("  · %s ｜ %s" % (t.get("action_id"), t.get("note")))
    return "\n".join(lines)


def classify_param_sources(action: Any, params: dict[str, Any], user_text: str) -> dict[str, str]:
    """★ 每个参数的**来源**判定（§12.85 / 断言 ⑸）。

    只判「检索类参数」（`SCOPE_PARAM_NAMES` 或值以 `/` 开头的字符串），返回 `{参数名: 来源}`：

      · `default` —— 等于动作 YAML 里的默认值（⇒ 合法来源 ②）
      · `user`    —— 值（忽略大小写与空格）**出现在用户问句里**（⇒ 合法来源 ①）
      · `model`   —— 两者都不是 ⇒ ★★ **模型自己编的**，触发回问（不许执行）

    ★ 为什么只判检索类参数：数字/开关类参数（`top` / `tail`）模型给个合理值不算"编范围"；
      而**"在哪找"**这件事一旦由模型编，就是本话题最防的那个东西。
    """
    out: dict[str, str] = {}
    low = (user_text or "").lower()
    for p in getattr(action, "params", []) or []:
        name = str(getattr(p, "name", "") or "")
        val = params.get(name)
        if val in (None, ""):
            continue
        is_scope = name.lower() in SCOPE_PARAM_NAMES or (isinstance(val, str) and val.startswith("/"))
        if not is_scope:
            continue
        default = getattr(p, "default", None)
        sval = str(val)
        if default not in (None, "") and sval == str(default):
            out[name] = "default"
        elif sval.lower().replace(" ", "") and sval.lower() in low.replace(" ", ""):
            out[name] = "user"
        else:
            out[name] = "model"
    return out
