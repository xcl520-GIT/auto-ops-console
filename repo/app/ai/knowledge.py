"""本地知识检索 ＋ Recipe 候选（T15 · 规范 §12.106 / §12.107）。

两件事，一个共同点：**只碰本地结构化记录**。

  · `search()`           —— 回答「**上次这类问题是怎么解决的**」（§12.106）
  · `mine_candidates()`  —— 把**重复出现过的动作序列**固化成 **Recipe 候选**（§12.107）

★★ 四条边界（写在这里，免得后来的人放宽）：

  1. ★★ **语料只含结构化记录**：会话标题 / **人**的问句 / 工具调用 / 变更请求 / 任务。
     ★★ **不含 AI 的自由回答正文** —— 那是**不可核的散文**，拿它当知识库
     = 把幻觉检索回来当天条（§12.106.2）。★ 这条由 `sessions.knowledge_corpus()`
     在 SQL 里就写死（`role='user'`），**不是**一句约定。
  2. ★★ **命中不到要明说**，并**交代查了哪些表、什么条件、扫了多少行**（§12.106.3）——
     「找不到」是一条结论，不是一句「没查到」（§12.88 同源）。
  3. ★ **只在本地**：检索结果**绝不进**任何给模型/外部的 payload 之外的用途；
     它**不新增任何写入或执行能力**。
  4. ★★ **候选只落草案区、不生效**：写 `var/lab/recipes-candidate/`，
     ★ **不写** `catalog/recipes/`、**不触发**重载、★ **AI 侧不存在这个工具**（§12.107.3）。
     理由：候选一旦能自己生效，就等于 **AI 间接造出了一条执行路径** —— 闸门只增不减。
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from app.errors import OpsError

# ------------------------------------------------------------------ 检索（§12.106）

#: 命中不到时**必须**出现的这句话（★ 措辞只许在这里定义一次）
NO_RECORD = "没有记录"

_SPLIT = re.compile(r"[\s,，、；;：:/\|]+")
_CJK_START = 0x2E80


def tokens_of(query: str) -> list[str]:
    """把问句切成检索词。

    ★ **不引分词库**（本项目的纪律：标准库优先、依赖越少越好）。
      中文长词**补二元组**：宁可多召回一点，也不要因为"切不出词"而**假无命中**。
      假无命中比假命中危险得多 —— 它会让平台说出一句"没有记录"，而记录其实在。
    """
    q = (query or "").strip().lower()
    if not q:
        return []
    out: list[str] = []
    for part in _SPLIT.split(q):
        if not part:
            continue
        out.append(part)
        if len(part) >= 3 and all(ord(c) >= _CJK_START for c in part):
            out.extend(part[i:i + 2] for i in range(len(part) - 1))
    return list(dict.fromkeys(out))


def _score(tokens: list[str], text: str) -> int:
    low = text.lower()
    return sum(len(t) for t in tokens if t in low)


def search(
    query: str,
    *,
    sessions: Any,
    task_lister: Any = None,
    task_getter: Any = None,
    limit: int = 20,
    scan_tasks: int = 120,
    host_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    """在**本地结构化记录**里找「上次这类问题」（§12.106）。

    ★ 返回里同时带 `hits`（结构化，供界面/模型）、`text`（紧凑文本）、
      `searched`（**交代范围**：哪些表、什么条件、扫了多少行）与 `sources`（语料边界自述）。
    ★ 任务那半边通过**两个只读回调**拿（`task_lister` / `task_getter`）——
      ★ 我们**不把 `Store` 对象递给 AI 侧**：T12 的纪律是"AI 只拿得到函数，拿不到承重墙"
      （`bootstrap` 里递给 AI 的也只有 `api.dispatch` 这个函数本身）。
    """
    tokens = tokens_of(query)
    corpus = sessions.knowledge_corpus()
    rows: list[dict[str, Any]] = list(corpus["rows"])
    scanned = dict(corpus["scanned"])

    # ── 把**任务**并进语料（动作 / 主机 / 状态 / 结论）──
    #   ★ 任务是"上次到底怎么解决的"最硬的那一半 —— 它有结论、有任务号、能回放。
    task_rows = 0
    if task_lister is not None:
        for t in task_lister(limit=int(scan_tasks)) or []:
            tid = str(t.get("id") or "")
            text = f"{t.get('action_id')} {t.get('action_title') or ''} {t.get('host_name') or ''}"
            conclusion = ""
            if task_getter is not None:
                try:
                    detail = task_getter(tid, include_raw=False)
                    conclusion = str((detail.get("task") or {}).get("conclusion") or "")
                except OpsError:
                    conclusion = ""
            rows.append({
                "kind": "task", "session_id": "", "seq": 0, "at": t.get("created_at"),
                "host_id": "", "action_id": str(t.get("action_id") or ""), "task_id": tid,
                "status": str(t.get("status") or ""),
                "text": (" ".join([text, conclusion])).strip(),
            })
            task_rows += 1
    scanned["task_rows"] = task_rows
    scanned["total_rows"] = sum(scanned.values())

    names = host_names or {}
    hits: list[dict[str, Any]] = []
    for r in rows:
        if not tokens:
            break
        sc = _score(tokens, f"{r.get('action_id') or ''} {r.get('text') or ''}")
        if sc <= 0:
            continue
        hits.append({
            "kind": r["kind"],
            "session_id": r.get("session_id") or "",
            "seq": r.get("seq") or 0,
            "ref": r.get("ref") or "",
            "at": r.get("at") or "",
            "host_id": r.get("host_id") or "",
            "host": names.get(str(r.get("host_id") or ""), str(r.get("host_id") or "")),
            "action_id": r.get("action_id") or "",
            "task_id": r.get("task_id") or "",
            "status": r.get("status") or "",
            "text": " ".join(str(r.get("text") or "").split())[:200],
            "score": sc,
        })
    # ★ 稳定排序：先按分，再按时间倒序，最后按 (kind, session, seq) —— 不许靠字典顺序
    hits.sort(key=lambda h: (-h["score"], str(h["at"]) or "", h["kind"], h["session_id"], h["seq"]))
    top = hits[: int(limit)]

    kind_cn = {"session": "会话标题", "ask": "人的问句", "call": "工具调用",
               "request": "变更请求", "task": "任务"}
    lines: list[str] = []
    if top:
        lines.append(f"命中 **{len(top)}** 条（共扫 {scanned['total_rows']} 行 · "
                     f"{scanned['sessions']} 个会话）：")
        for i, h in enumerate(top, 1):
            where = " / ".join(x for x in [
                h["session_id"] or "（无会话）",
                f"seq {h['seq']}" if h["seq"] else "",
                h["at"] or "",
                h["host"] or "",
                h["action_id"] or "",
                f"请求 {h['ref']}" if h.get("ref") else "",
                f"任务 {h['task_id']}" if h["task_id"] else "",
                h["status"] or "",
            ] if x)
            lines.append(f"{i}. [{kind_cn.get(h['kind'], h['kind'])}] {where} —— {h['text'] or '（无正文）'}")
        lines.append("")
        lines.append("★ 出处四要素在上面每一条里（**会话 / seq / 时间 / 任务号**）—— 顺着它能直接回放。")
        lines.append("★ 读法：这些是**平台记下来的事实**，不是「上次这么干就好了」的建议；"
                     "要不要照做由人决定。")
    else:
        lines.append(f"★ **{NO_RECORD}**：本地结构化记录里找不到与「{query}」相关的东西。")
        lines.append("")
        lines.append("★ 「找不到」是一条**结论**，不是一句「没查到」（§12.88）—— "
                     f"下面说清查了哪些范围。")
    lines.append("")
    lines.append("★ 查了哪些范围（`searched`）：")
    lines.append(f"  - 表与条件：{'；'.join(corpus['sources'])}")
    lines.append(f"  - 扫了多少行：会话 {scanned['session_rows']} · 人的问句 {scanned['ask_rows']}"
                 f" · 工具调用 {scanned['call_rows']} · 变更请求 {scanned['request_rows']}"
                 f" · 任务 {task_rows}（共 {scanned['total_rows']}）")
    lines.append(f"  - {corpus['excluded']}")

    return {
        "query": query,
        "tokens": tokens,
        "hits": top,
        "hit_count": len(top),
        "total_match": len(hits),
        "text": "\n".join(lines),
        "searched": {
            "tables": list(corpus["sources"]),
            "condition": f"子串命中（词：{'、'.join(tokens) or '（空问句）'}）",
            "scanned_rows": scanned["total_rows"],
            "detail": scanned,
            "excluded": corpus["excluded"],
        },
        "note": NO_RECORD if not top else "",
        "local_only": "★ 本地检索：结果不参与任何外发 payload（§12.106.4）",
    }


# ------------------------------------------------------------------ 候选（§12.107）


def recipe_dir_fingerprint(path: Path) -> dict[str, str]:
    """一个目录下 `*.yaml` 的「文件 → sha256」表（用来证明**我们没碰它**）。

    ★ 判据要的是"**逐字节相同**"，不是"文件名还在"（§12.106 家族的老毛病：
      看着像没动，其实内容变了）。
    """
    out: dict[str, str] = {}
    if not path.is_dir():
        return out
    for p in sorted(path.glob("*.yaml")):
        out[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _sequences(rows: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """按会话把 `ai_tool_call` 排成**动作序列**（相邻重复只留一个）。

    ★ 顺序依据是 `seq`（记录里本来的序号），**不是**拿到它们的顺序。
    """
    per: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if r.get("kind") != "call":
            continue
        per.setdefault(str(r.get("session_id") or ""), []).append(r)
    out: dict[str, list[dict[str, Any]]] = {}
    for sid, items in per.items():
        items = sorted(items, key=lambda x: int(x.get("seq") or 0))
        seq: list[dict[str, Any]] = []
        for r in items:
            aid = str(r.get("action_id") or "")
            if not aid:
                continue
            if seq and seq[-1]["action_id"] == aid:
                continue
            seq.append(r)
        if seq:
            out[sid] = seq
    return out


def _is_run(sub: tuple[str, ...], seq: tuple[str, ...]) -> bool:
    """`sub` 是不是 `seq` 的一段**连续**子序列。

    ★ 注意：元组的 `in` 判的是"元素在不在"，**不是**"子序列在不在" ——
      想当然地写 `sub in seq` 会得到一个永远 False 的判据（一条**静默失效**的规则）。
    """
    n = len(sub)
    if n == 0 or n > len(seq):
        return False
    return any(tuple(seq[i:i + n]) == sub for i in range(len(seq) - n + 1))


def mine_candidates(
    *,
    sessions: Any,
    actions: dict[str, Any],
    out_dir: Path,
    min_support: int = 2,
    min_len: int = 3,
    catalog_recipes: Path | None = None,
) -> dict[str, Any]:
    """把**重复出现过的动作序列**固化成 Recipe **候选草案**（§12.107）。

    ★★ 三条硬规矩：
      · 落点只有 `out_dir`（= `var/lab/recipes-candidate/`）；
      · **不写** `catalog/recipes/`、**不触发**重载（返回里带 `recipes_untouched` 作证）；
      · 候选**只描述"重复出现过什么"**，★ **不断言因果**（不写"这样就能修好"）。
    """
    rows = sessions.knowledge_corpus()["rows"]
    seqs = _sequences(rows)

    # ── 统计**连续子序列**的支持度（会话数）与证据 ──
    support: dict[tuple[str, ...], set[str]] = {}
    evidence: dict[tuple[str, ...], list[dict[str, str]]] = {}
    for sid, seq in seqs.items():
        ids = [str(r["action_id"]) for r in seq]
        for i in range(len(ids)):
            for j in range(i + min_len, len(ids) + 1):
                key = tuple(ids[i:j])
                support.setdefault(key, set()).add(sid)
                evidence.setdefault(key, [])
                if len(evidence[key]) < 6:
                    evidence[key].append({
                        "session_id": sid,
                        "task_id": ",".join(str(x.get("task_id") or "") for x in seq[i:j] if x.get("task_id")),
                    })

    picked: list[tuple[str, ...]] = []
    ranked = sorted(
        (k for k, s in support.items() if len(s) >= int(min_support)),
        key=lambda k: (-len(support[k]), -len(k), k),
    )
    for key in ranked:
        # ★ 已被更长的候选包含 ⇒ 不再单列（免得清单里全是同一条的碎片）
        if any(_is_run(key, p) for p in picked):
            continue
        picked.append(key)

    out_dir.mkdir(parents=True, exist_ok=True)
    before = recipe_dir_fingerprint(catalog_recipes) if catalog_recipes else {}
    skipped_steps: list[str] = []
    files: list[str] = []
    list_lines: list[str] = [
        "# Recipe 候选 · 待拍板清单（T15 生成）",
        "",
        "> ★★ **这些草案没有生效**：它们**不在** `catalog/recipes/` 里，",
        "> **不参与**装载，**不出现在**服务目录页。要让它生效，**得由人**把它挪过去并自己拍板。",
        "> ★ 候选只说明「**这串动作被重复执行过**」，**不说明**「照着做就能修好」——",
        "> 因果是人的判断，不是统计结论（规范 §12.107.1）。",
        "",
        f"> 判据：同一串动作在 **≥ {min_support}** 个会话里**连续**出现过（长度 ≥ {min_len}）。",
        f"> 扫了 {len(seqs)} 个会话的动作序列。",
        "",
    ]

    names = {str(a.id): str(getattr(a, "title", "") or "") for a in actions.values()}
    for idx, key in enumerate(picked, 1):
        slug = "-".join(k.replace(".", "-") for k in key)[:60]
        support_sids = sorted(support[key])
        # ★ 动作必须**真实存在**；对不上 ⇒ 这一步不写进草案，并在清单里说明
        keep: list[str] = []
        for aid in key:
            if aid in actions:
                keep.append(aid)
            else:
                skipped_steps.append(f"{slug}：动作 `{aid}` 不在 catalog 里 ⇒ 这一步不写进草案")
        if not keep:
            continue
        body: list[str] = [
            "# ★ 未生效 · 待拍板（T15 生成 · 规范 §12.107）",
            "#",
            "# 这不是配方：它躺在 var/lab/recipes-candidate/ 里，不在 catalog/recipes/ 里，",
            "# 不参与装载、不出现在服务目录页。★ 要生效必须由**人**决定。",
            "#",
            f"# 依据：这串动作在 {len(support_sids)} 个会话里连续出现过 —— "
            f"{'、'.join(support_sids[:6])}",
            "# ★ 它只说明「重复做过」，**不说明**「照着做就能修好」。",
            "",
            f"id: candidate-{slug}",
            "version: 0",
            f"# 参数：★ 只记「出现过的取值」，**不替人挑默认值**（§12.107.4 第 4 条）",
            "steps:",
        ]
        for aid in keep:
            ev = evidence.get(key, [])
            ev_txt = "；".join(
                f"会话 {e['session_id']}" + (f" 任务 {e['task_id']}" if e["task_id"] else "")
                for e in ev[:3]
            )
            body.append(f"  - action: {aid}")
            body.append(f"    # {names.get(aid) or aid}　★ 证据：{ev_txt or '（无）'}")
        path = out_dir / f"candidate-{slug}.yaml"
        path.write_text("\n".join(body) + "\n", encoding="utf-8")
        files.append(str(path))
        list_lines += [
            f"## 候选 {idx} · `candidate-{slug}`",
            "",
            f"- 动作序列（{len(keep)} 步）：" + " → ".join(f"`{a}`" for a in keep),
            f"- 支持度：**{len(support_sids)}** 个会话 ⇒ {'、'.join(support_sids)}",
            f"- 草案：`{path}`",
            f"- ★ 待办：① 这串动作**是不是一件可复用的事**（还是三次不同的排障恰好撞在一起）"
            f" ② 参数填什么 ③ 健康判据是什么 ④ 怎么撤 —— **这四条都得人拍**",
            "",
        ]
    if not picked:
        list_lines += [
            "★ **没有候选**：扫描范围内**没有任何动作序列**在 ≥ 2 个会话里连续重复出现过。",
            "★ 这是一条**结论**，不是失败 —— 如实记下来。",
            "",
        ]
    if skipped_steps:
        list_lines += ["## 被跳过的步骤（动作对不上 catalog）", ""]
        list_lines += [f"- {s}" for s in skipped_steps]
        list_lines.append("")

    list_path = out_dir / "待拍板清单.md"
    list_path.write_text("\n".join(list_lines) + "\n", encoding="utf-8")

    after = recipe_dir_fingerprint(catalog_recipes) if catalog_recipes else {}
    return {
        "candidates": [
            {"id": f"candidate-{'-'.join(k.replace('.', '-') for k in key)[:60]}",
             "actions": list(key), "support": sorted(support[key])}
            for key in picked
        ],
        "files": files,
        "list": str(list_path),
        "out_dir": str(out_dir),
        "scanned_sequences": len(seqs),
        "min_support": int(min_support),
        "recipes_untouched": before == after,
        "recipes_before": before,
        "skipped_steps": skipped_steps,
        "note": (
            "★ 候选**没有生效**：`catalog/recipes/` 一个字节都没动"
            "（返回里的 `recipes_untouched` 就是这条判据）。"
        ),
    }


# ------------------------------------------------------------------ 绑定（给 AI 侧用）


class LocalKnowledge:
    """把"本地知识"绑成一个**只读**的小对象，递给 AI 运行时（§12.106）。

    ★★ 它**只拿得到两个只读回调**（列任务 / 取任务），拿不到 `Store`、拿不到引擎 ——
      与 `bootstrap` 里递给 AI 侧的"只有 `api.dispatch` 这个函数本身"是同一个纪律
      （T12 断言 🄌 的家族）。
    ★ `candidates()` **不暴露给模型**：AI 侧只有一个"读"的工具（`kb_search`），
      没有"生成候选 / 写文件"的工具（§12.107.3 / 断言 Ⓕ）。
    """

    def __init__(
        self,
        sessions: Any,
        *,
        task_lister: Any = None,
        task_getter: Any = None,
        host_names: dict[str, str] | None = None,
        actions: dict[str, Any] | None = None,
    ) -> None:
        self.sessions = sessions
        self.task_lister = task_lister
        self.task_getter = task_getter
        self.host_names = host_names or {}
        self.actions = actions or {}

    def search(self, query: str, limit: int = 20) -> dict[str, Any]:
        return search(
            query,
            sessions=self.sessions,
            task_lister=self.task_lister,
            task_getter=self.task_getter,
            limit=limit,
            host_names=self.host_names,
        )

    #: ★ 模型看得到的**唯一**一个知识工具名（只有"读"）
    TOOL_NAME = "kb_search"

    def tool_spec(self) -> dict[str, Any]:
        return kb_tool_spec()


def kb_tool_spec() -> dict[str, Any]:
    """`kb_search` 的 function schema（§12.106）。

    ★★ 它**只有读**：参数只有一句问句，返回的是"命中 + 出处 + 查了哪些范围"。
      ★ 它**没有** `write` / `save` 之类的任何入参 —— 不是"约定了不传"，是**结构上不存在**。
    """
    return {
        "type": "function",
        "function": {
            "name": "kb_search",
            "description": (
                "在**本地**结构化记录里查「上次这类问题是怎么解决的」。"
                "★ 只读：查会话标题 / 人提的问题 / 工具调用 / 变更请求 / 任务结论 —— "
                "★ **不查** AI 自己的历史回答（那是不可核的散文，规范 §12.106.2）。"
                "★ 命中不到时会明确告诉你「没有记录」并交代查了哪些范围；"
                "★ 你**必须**把这句话原样转述给用户，不许把「没查到」说成「查过了、没问题」。"
                "★ 返回的是**平台记下来的事实与出处**，不是「上次这么干就好了」的建议。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "要查的东西（用户的原话最好；别自己扩写）",
                    },
                },
                "required": ["query"],
            },
        },
    }
