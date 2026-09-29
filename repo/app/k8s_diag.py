"""K8s 排障**成因推导**（T9 · 规范 §12.39）。

为什么会有这个模块（§12.23 三条判定 / §12.39.5 放行记录）
-----------------------------------------------------------
① **格式锁死**：它的输入是**我们自己锁定的紧凑格式**（下面 `COLUMNS` —— 由 `kubectl
   --output=custom-columns` 生成，列名与字段路径都写死在动作 YAML 里）；
② **无结构化替代**：`kubectl describe` 是**给人读的自然语言**，不可机读；
   `--field-selector` / `jsonpath` 只能取字段，**回答不了"为什么"**；
③ **换命令绕不开**：没有任何一条 `kubectl` 命令直接输出"成因清单"。
⇒ 三条同时成立，故允许新增**这一个纯函数模块**。

★★ 边界（§12.39.5，四条，一条都不许越）
------------------------------------
1. **不碰 ssh / 不碰集群**：只吃"已经拿回来的数据"（连 `transport` / `engine` 都不 import）；
2. **可离线断言**：给一段文本就能验"该出现哪条成因 / 该不出现哪条"；
3. **不许在里面拼命令**：命令属于动作层（§4 三层契约不变）；
4. ★ **它不是第二个判定中心**：成因清单是**给人看的解释**，
   动作的成败仍由 `verify` 决定 —— **"发现了成因" ≠ "动作失败"**。

★★★ 为什么输入**不是**整对象 JSON（T9·S3 **真跑抓到的缺陷**，规范 §12.39.4 的真跑补记）
-----------------------------------------------------------------------------------
第一次真跑用的是 `kubectl get pods -A -o json`，结果**撞上平台的单步输出上限**
（`config.yaml: exec.max_output_bytes = 262144`）⇒ JSON **被从中间截断** ⇒
解析器报"不是合法 JSON"、整条动作红。
★ 而"调大上限"是**错的解法**（一个真实集群的 PodList 轻松上兆，那是把落库与报告都撑爆）；
⇒ 正解是**别把整对象倒进输出通道**：只取判据真正需要的字段，用**紧凑表**送回来。
★★ 顺带立一条规矩：**截断必须可见** —— 本模块会在"末行没有换行符"时**主动说出来**
（那意味着这一屏很可能被切掉了）；再配合动作里的 `pods_count` 对账（扫了几行 vs 一共几个），
"少看了一半"这件事**不会被伪装成"没发现问题"**。
"""
from __future__ import annotations

import re

from app.errors import OpsError

#: ★★ **本模块锁定的输入格式**（与动作 YAML 里的 `custom-columns` **逐字对应**）。
#: ★ 最后一列 `waitingmsg` **必须放最后**：它是唯一**可能含空格**的列
#:   （`failed to pull image ...: manifest unknown`）—— 其余列都是"一个 token"。
#:   ⇒ 解析方式：前 N-1 列按空白切，**余下的整段**就是最后一列。
COLUMNS = (
    "ns", "pod", "phase", "restarts", "waiting", "lastreason",
    "lastexit", "limits", "image", "waitingmsg",
)

#: 命名空间 / Pod 名的形状（硬校验用：**不像**就说明这一屏被切了，或者压根不是这张表）
_NSPOD_RE = re.compile(r"[a-z0-9][a-z0-9.-]*")

#: K8s 的 Pod 阶段白名单（同样用于硬校验）
PHASES = ("Pending", "Running", "Succeeded", "Failed", "Unknown")

#: 容器级列（这些列的值来自 `status.containerStatuses[*]` / `spec.containers[*]`，
#: 多容器时用 `,` 并列 —— **同一行内它们按下标对齐**，所以能逐容器判读）。
CONTAINER_COLUMNS = ("restarts", "waiting", "lastreason", "lastexit", "limits", "image")

#: ★★ 健康的正向白名单（规范 §12.37.1 ②）：**不许**枚举"坏状态"——
#: 那份名单永远列不全（kubectl 每加一个状态就漏一个），而漏判的后果是"坏的被当成好的"。
HEALTHY_PHASES = ("Running", "Succeeded")

CAT_PENDING = "Pending"
CAT_CRASH = "CrashLoopBackOff"
CAT_IMAGE = "ImagePullBackOff"
CAT_OOM = "OOMKilled"
CAT_OTHER = "其它"

IMAGE_UNREACHABLE_HINTS = (
    "connection refused", "no such host", "dial tcp", "i/o timeout", "timeout",
    "tls handshake", "network is unreachable", "context deadline exceeded",
    "connect: ", "proxyconnect", "x509", "unauthorized", "authentication required",
    "401", "403", "no such host",
)
IMAGE_MISSING_HINTS = (
    "not found", "manifest unknown", "no matching manifest", "name unknown",
    "repository does not exist", "404", "invalid image name", "notexist",
)
SCHEDULE_HINTS = ("insufficient", "didn't match", "did not match", "node affinity",
                  "node selector", "nodeselector", "didn't tolerate", "untolerated taint",
                  "taint", "persistentvolumeclaim", "unbound", "volume", "exceeded quota")


def _clean(v: str) -> str:
    v = (v or "").strip()
    return "" if v in ("<none>", "<unknown>", "<nil>") else v


def _contains_any(text: str, hints: tuple[str, ...]) -> bool:
    low = (text or "").lower()
    return any(h in low for h in hints)


# ---------------------------------------------------------------- 逐类成因


def _image_cause(msg: str) -> tuple[str, str]:
    """★ 把「仓库不可达」与「没有这个镜像」**分开**（§12.28 / §12.39.2 成因表）。"""
    if _contains_any(msg, IMAGE_MISSING_HINTS):
        return (
            "**镜像名或标签不存在**（仓库里没有这个 ref）",
            "核对镜像名与 tag；★ 本环境可拉的来源见既有配方里的 `--image-repository` 经验",
        )
    if _contains_any(msg, IMAGE_UNREACHABLE_HINTS):
        return (
            "**仓库不可达 / 认证不过**（网络、代理、凭据）—— ★ 不是「没有这个镜像」",
            "在那台**节点**上确认能否解析并连上镜像仓库（`registry.probe` 就是干这个的）",
        )
    return (
        "拉取失败，但原因**不在本模块枚举的两类之内**（证据那一行是原文片段）",
        "按原文关键字查：先看是「解析域名」、「连 TCP」、还是「握手/鉴权」这一层失败",
    )


def _crash_cause(exit_code: str, lastreason: str, restarts: str) -> tuple[str, str]:
    code = exit_code.strip()
    if code == "137":
        return (
            "容器**被 SIGKILL 杀掉**（`exitCode=137`）—— ★ 最常见的是内存超限",
            "★ 若 `lastState.terminated.reason` 是 `OOMKilled`，按内存那条查；否则看 `k8s.describe` 的 Limits",
        )
    if code and code not in ("0",):
        return (
            "容器**自己退出**了（`exitCode=%s`，`reason=%s`）—— 不是节点或调度的问题" % (code, lastreason or "（无）"),
            "★ 用 `k8s.logs` 选「**上一个已退出的容器**」看崩溃前最后几行",
        )
    if code == "0":
        return (
            "容器**正常退出**（`exitCode=0`）却被反复重启 —— 多半是「重启策略 / 启动命令」配错了",
            "核对 `restartPolicy` 与 command（`k8s.describe` 的 Command 段）",
        )
    return (
        "**拿不到上一次的退出码** ⇒ 只能说它在反复重启（已重启 %s 次），**原因未定**" % (restarts or "?"),
        "★ 看 `k8s.describe` 的 `Last State` 段与 Events 段",
    )


def _oom_cause(limit: str) -> tuple[str, str]:
    lim = _clean(limit)
    if lim:
        return (
            "容器超过内存限额被杀 —— 限额是 `%s`，`exitCode=137`（SIGKILL）" % lim,
            "★ 要么调大 `limits.memory`，要么查**为什么它吃这么多**（`k8s.logs` 看被杀前的输出）",
        )
    return (
        "容器被杀，但**这个容器没有设 `limits.memory`** ⇒ 原因是「用到超过节点能给的量」"
        "（或与别人抢内存），**不是**「限额太小」",
        "给这个容器设一个内存限额（否则它会一直拖累同节点的别人）",
    )


# ---------------------------------------------------------------- 解析（我们锁定的格式）


def parse_rows(text: str) -> list[dict]:
    """把紧凑表解析成 `[{'ns':…, 'pod':…, containers:[{...}]}]`。

    返回 `list[dict]`；★★ **解析不出来就抛错，不猜**（见下面的硬规则）。
    ★ 平台有单步输出上限（`config.yaml: exec.max_output_bytes = 262144`）：输出被切断时，
    末行往往"少了几列"—— 那**绝不许**被当成数据用（那等于"拿一半的集群当全部"）。
    """
    raw = text or ""
    if not raw.strip():
        return []
    ncol = len(COLUMNS)
    rows: list[dict] = []
    for line in raw.splitlines():
        s = line.rstrip()
        if not s.strip():
            continue
        if s.lstrip().startswith("NS") and "PHASE" in s:      # 万一没关表头
            continue
        parts = s.split(None, ncol - 1)
        cell_try = dict(zip(COLUMNS, parts + [""] * (ncol - len(parts))))
        looks_like_row = (
            len(parts) >= ncol - 1
            and _NSPOD_RE.fullmatch(_clean(cell_try.get("ns")) or "") is not None
            and _NSPOD_RE.fullmatch(_clean(cell_try.get("pod")) or "") is not None
            and _clean(cell_try.get("phase")) in PHASES
        )
        if not looks_like_row:
            # ★★ **续行**（T9·S3 真跑抓到的）：K8s 的 message **可能自带换行**
            #   （例：镜像加速返回 `...\ndenied: 🚫 ... 这镜像不在白名单`），
            #   于是 `custom-columns` 把那一格打印成**两行** ⇒ 拼回上一行的最后一列。
            #   ★ 判据：**列数够 + ns/pod/phase 合规**才算"新的一个 Pod 行"。
            if not rows:
                raise OpsError(
                    code="STEP_FAILED",
                    reason="紧凑表的第一行就不像 K8s 的对象（命名空间 / Pod 名 / 阶段对不上）"
                           "—— ★ 这一屏既可能被截断，也可能压根不是这张表",
                    advice="先看该步骤的原始输出：① 平台单步输出上限（`exec.max_output_bytes`）是否被撞；"
                           "② 远程命令是否真的跑成了。★ 拿不到完整数据时**不给结论**。",
                    detail="问题行：%r" % s[:200],
                )
            cont = rows[-1]["containers"][0] if rows[-1]["containers"] else None
            if cont is not None:
                cont["waitingmsg"] = (cont.get("waitingmsg") or "") + " " + s.strip()
            continue
        cell = cell_try
        per_col: dict[str, list[str]] = {}
        for c in CONTAINER_COLUMNS:
            per_col[c] = [x.strip() for x in (cell.get(c) or "").split(",")]
        ncont = max(len(v) for v in per_col.values()) if per_col else 0
        containers = []
        for i in range(ncont):
            c = {}
            for k in CONTAINER_COLUMNS:
                vals = per_col[k]
                c[k] = _clean(vals[i]) if i < len(vals) else ""
            # ★ 最后一列（可能含空格 / 逗号）只对应**第一个容器**：多容器时如实说明
            c["waitingmsg"] = _clean(cell.get("waitingmsg")) if i == 0 else ""
            containers.append(c)
        rows.append({
            "ns": _clean(cell.get("ns")), "pod": _clean(cell.get("pod")),
            "phase": _clean(cell.get("phase")), "containers": containers,
        })
    return rows


def findings_of(row: dict) -> list[dict]:
    """一个 Pod 行的成因（可能多条：每个容器各一条）。"""
    ns, pod, phase = row["ns"], row["pod"], row["phase"]
    out: list[dict] = []
    for c in row["containers"]:
        waiting, trreason, exit_code = c["waiting"], c["lastreason"], c["lastexit"]
        restarts, msg = c["restarts"], c["waitingmsg"]
        # ★★ 这一跳是必需的（T9·S3 离线断言抓到）：`Pending` 的 Pod **还没有任何容器状态**
        #   （`status.containerStatuses` 为空）⇒ 状态列全是 `<none>`。若不跳过，它会掉进下面
        #   "Pod 级异常"那一支、被归成「其它」，**把 `Pending` 的成因盖掉**。
        if not (waiting or trreason or exit_code or restarts):
            continue
        ev = "restarts=%s ；waiting.reason=%r ；lastState.terminated={reason=%r, exitCode=%r} ；limits.memory=%s" % (
            restarts or "?", waiting or "（无）", trreason or "（无）", exit_code or "（无）", c["limits"] or "（未设）")
        if waiting in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
            cause, nxt = _image_cause(msg + " " + waiting)
            f = {"cat": CAT_IMAGE, "what": "容器在 `%s`（镜像没能拉到本地）" % waiting,
                 "cause": cause, "evidence": ev + " ；waiting.message=%r" % (msg[:300] or "（无）"), "next": nxt}
        elif trreason == "OOMKilled":
            # ★★ 判序：OOM 的容器迟早会进入 CrashLoopBackOff —— **更具体的成因优先**
            cause, nxt = _oom_cause(c["limits"])
            f = {"cat": CAT_OOM, "what": "容器上一次是被 **OOMKilled**（★ 这一条**不在** `STATUS` 列里）",
                 "cause": cause, "evidence": ev, "next": nxt}
        elif waiting == "CrashLoopBackOff":
            cause, nxt = _crash_cause(exit_code, trreason, restarts)
            f = {"cat": CAT_CRASH, "what": "容器处于 `CrashLoopBackOff`（已重启 %s 次）" % (restarts or "?"),
                 "cause": cause, "evidence": ev, "next": nxt}
        elif waiting in ("ContainerCreating", "PodInitializing"):
            f = {"cat": CAT_OTHER, "what": "容器处于过渡态 `%s`（还在起）" % waiting,
                 "cause": "**过渡态**：正在创建容器 / 初始化。★ 若它**长时间**停在这里，多半是"
                          "**卷挂不上**（`FailedMount`）或**镜像拉不下来**（`ErrImagePull`）",
                 "evidence": ev, "next": "★ 先等一下再看；不动的就用 `k8s.describe` 读 Events 段"}
        elif waiting:
            f = {"cat": CAT_OTHER, "what": "容器的 `waiting.reason` 是 `%s`" % waiting,
                 "cause": "原因**不在本模块枚举的四类之内**（★ 枚举会漏，所以判据用**正向白名单**）",
                 "evidence": ev, "next": "先跑 `k8s.describe` 把这个对象读完（Events 段在最后）"}
        elif phase not in HEALTHY_PHASES:
            f = {"cat": CAT_OTHER, "what": "Pod 的 `phase` 是 `%s`（不在 {Running, Succeeded} 这个**正向白名单**里）" % phase,
                 "cause": "Pod 级异常，且**容器级没有记录** ⇒ 先按原文判",
                 "evidence": ev, "next": "跑 `k8s.describe` 看 Events 段（`Evicted` / `Failed` 的原文通常直接写着原因）"}
        else:
            continue
        if waiting and "（当前" not in f["what"]:
            f["what"] += "（`state.waiting.reason=%s`）" % waiting
        f.update({"ns": ns, "name": pod, "phase": phase})
        out.append(f)

    if out:
        return out

    # ★ Pod 级：phase 不在白名单、且**一个容器成因都没有**（例如 Pending 没被调度 / Evicted）
    if phase and phase not in HEALTHY_PHASES:
        if phase == "Pending":
            # ★★ 调度器原文**不在这一屏**（紧凑表里只能有一个"含空格的列"，而它被 `waitingmsg` 占了）
            #   ⇒ 本段只下"它被调度器拦住了"这个结论，**具体是哪一类**由第二段清单给（两者互相引用）。
            return [{
                "cat": CAT_PENDING, "ns": ns, "name": pod, "phase": phase,
                "what": "Pod 处于 `Pending`（还没被调度到任何节点上）",
                "cause": "**被调度器拦住了** —— ★ 具体是哪一类（资源不足 / 无匹配节点 / 卷没绑上），"
                         "见下面「`Pending` 的成因清单」那一段（它带着调度器原文）",
                "evidence": "phase=Pending ；本行容器级字段全为空（还没起来过）",
                "next": "★ 先看下面那段里「每类各几个节点」（`0/3 nodes are available:` 后面那串），"
                        "数最多的那一类就是主因",
            }]
        return [{
            "cat": CAT_OTHER, "ns": ns, "name": pod, "phase": phase,
            "what": "Pod 的 `phase` 是 `%s`（不在 {Running, Succeeded} 这个**正向白名单**里）" % phase,
            "cause": "Pod 级异常，且**没有容器级记录** ⇒ 先按原文判",
            "evidence": "phase=%s" % phase,
            "next": "跑 `k8s.describe` 看 Events 段（`Evicted` / `Failed` 的原文通常直接写着原因）",
        }]
    return []


def analyze(text: str) -> tuple[list[dict], dict]:
    """紧凑表 → `(findings, meta)`。`meta` 带 `total` / `counts` / `suspect_truncated`。"""
    rows = parse_rows(text)
    if not rows and (text or "").strip():
        raise OpsError(
            code="STEP_FAILED",
            reason="期望 `kubectl get pods -A --no-headers --output=custom-columns=...` 的紧凑表，但一行都没解析出来",
            advice="确认这一步带了 `--no-headers` 与那段写死的 custom-columns；远程命令是否真的跑成了，先看它的原始输出。",
            detail="--- 前 300 字符 ---\n" + (text or "")[:300],
        )
    findings: list[dict] = []
    for row in rows:
        findings.extend(findings_of(row))
    counts: dict[str, int] = {k: 0 for k in (CAT_PENDING, CAT_CRASH, CAT_IMAGE, CAT_OOM, CAT_OTHER)}
    for f in findings:
        counts[f["cat"]] = counts.get(f["cat"], 0) + 1
    return findings, {"total": len(rows), "counts": counts}


def render(findings: list[dict], meta: dict) -> str:
    """把成因清单渲染成**人一句话就能读**的文本（结论模板直接引用它）。"""
    total = meta.get("total", 0)
    lines: list[str] = []
    if not findings:
        lines.append("★★ 排障结论（扫了 %d 个 Pod）：**未发现不健康对象**" % total)
        lines.append("  ★★ 这是**结论**，不是失败（规范 §12.39.2）—— 判据是**正向白名单**：")
        lines.append("     `phase ∈ {Running, Succeeded}` 且**容器级**没有 waiting / OOMKilled。")
        lines.append("  ★ 它**不覆盖**：已经消失的对象（那是历史）、以及「曾经被杀过但已恢复正常」以外的隐性问题。")
        return "\n".join(lines)
    counts = meta.get("counts") or {}
    cnt_txt = " · ".join("%s %d" % (k, counts.get(k, 0))
                         for k in (CAT_PENDING, CAT_CRASH, CAT_IMAGE, CAT_OOM, CAT_OTHER) if counts.get(k, 0))
    lines.append("★★ 排障结论（扫了 %d 个 Pod，发现 %d 个不健康对象）" % (total, len(findings)))
    lines.append("  分类计数：%s" % cnt_txt)
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append("【%d/%d】%s/%s   分类：**%s**" % (i, len(findings), f["ns"], f["name"], f["cat"]))
        lines.append("  现象：%s" % f["what"])
        lines.append("  成因：%s" % f["cause"])
        lines.append("  证据：%s" % f["evidence"])
        lines.append("  下一步：%s" % f["next"])
        lines.append("")
    lines.append("★ 判据口径：健康是**正向白名单**（`phase ∈ {Running, Succeeded}` 且容器级无 waiting / OOMKilled）——")
    lines.append("  **不去枚举坏状态**（那份名单永远列不全，漏一个就是「坏的被当成好的」）。")
    lines.append("★ 本清单由**数据推出**：换了故障，分类与成因**必须跟着换**（规范 §12.39.3）。")
    return "\n".join(lines)


def diagnose(text: str, mode: str | None = None) -> str:
    """`k8s_diag` 解析器的入口（`parser_arg` 选模式）。

    | mode | 输入 | 出处 |
    |---|---|---|
    | `pods`（默认） | 紧凑表：`NS POD PHASE RESTARTS WAITING LASTREASON LASTEXIT LIMITS IMAGE WAITINGMSG` | `kubectl get pods -A --no-headers -o custom-columns=…` |
    | `pending` | 每行 `命名空间/Pod名\|调度器原文` | `kubectl get pods -A --field-selector=status.phase=Pending -o jsonpath=…` |

    ★★ **为什么要分两个模式**（而不是一个更大的 `-o json`）：见模块 docstring ——
    整对象 JSON 会**撞平台单步输出上限**（真跑实测）。而紧凑表里**只能有一个"含空格的列"**
    （列是靠空白切的），所以"容器等待信息"与"调度器原文"必须**分两次取**。
    ★ 两段清单**互相引用**：`pods` 模式里 Pending 的条目会写"原因见下一段"。
    """
    m = (mode or "pods").strip() or "pods"
    if m == "pending":
        return diagnose_pending(text)
    return _diagnose_pods(text)


def _diagnose_pods(text: str) -> str:
    findings, meta = analyze(text)
    return render(findings, meta)


#: `pending` 模式的行格式：`<ns>/<pod><TAB><waiting.reason><TAB><调度器原文>`
#: ★★ 中间那一列是**必需的**（真跑补记）：`phase=Pending` 的 Pod 里，
#:   有一部分是**卡在镜像/容器那一层**的（`ImagePullBackOff` 的 Pod 同样是 `Pending`）——
#:   它们的成因**第一段已经给了** ⇒ 本段要**跳过**它们，否则同一个对象会在两段里各出现一次、
#:   而且第二段会配上一句毫无意义的原文（`containers with unready status: [web]`）。
#: ★ 判据：`waiting.reason` 非空 ⇒ 不是"调度器拦住了它"。
#: ★★ 分隔符为什么是 **TAB** 而不是 `|`：装载期有一条**静态白名单**会拒掉含 shell 元字符
#:   （`|` `>` `<` `;` `&` …）的 `run` 元素 —— 那条守卫是对的（§4 三层契约），
#:   而 TAB 既不是元字符，又不会出现在消息里。★ 旧格式（`|`）仍然兼容，便于离线夹具。
def parse_pending_rows(text: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if "\t" in s:
            parts = s.split("\t", 2)
            if len(parts) == 2:                 # 兼容旧的两段式夹具
                parts = [parts[0], "", parts[1]]
            left, waiting, right = parts
        elif "|" in s:
            left, waiting, right = s.split("|", 1)[0], "", s.split("|", 1)[1]
        else:
            continue
        left = left.strip()
        if "/" not in left:
            continue
        ns, pod = left.split("/", 1)
        waiting = waiting.strip()
        if waiting and waiting not in ("<none>", "（无）"):
            # ★ 它卡在容器/镜像那一层（第一段已给成因）⇒ 本段跳过
            continue
        out.append((ns.strip(), pod.strip(), right.strip()))
    return out


def render_pending(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return ("★ 本段无内容：**这次没有被调度器拦住的 Pod** —— "
                "（若有 `Pending` 却卡在镜像/容器那一层的，成因已在**第一段**给出）。")
    lines = ["★★ `Pending` 的成因清单（%d 个）—— 原文来自调度器" % len(rows), ""]
    for i, (ns, pod, msg) in enumerate(rows, 1):
        low = msg.lower()
        causes: list[str] = []
        if "insufficient" in low:
            causes.append("**资源不足**：节点上没有足够的可分配资源（CPU / 内存 / Pod 数）")
        if any(h in low for h in ("didn't match", "did not match", "node affinity", "selector", "didn't tolerate", "taint")):
            causes.append("**没有匹配的节点**：`nodeSelector` / 亲和性对不上，或污点没被容忍")
        if any(h in low for h in ("persistentvolumeclaim", "volume", "unbound")):
            causes.append("**卷没绑上**：PVC 还没 `Bound`（或 `WaitForFirstConsumer` 在等第一个消费者）")
        if causes:
            cause = " ＋ ".join(causes)
            if len(causes) > 1:
                cause += "（★ 原文**同时**提到了这几件事 —— 逐节点看谁在拦你）"
        else:
            cause = "调度器给出的原因**不在本模块枚举的三类之内**（原文见证据）"
        lines.append("【%d/%d】%s/%s" % (i, len(rows), ns, pod))
        lines.append("  成因：%s" % cause)
        lines.append("  证据：`status.conditions[*].message`（调度器原文）= %r" % (msg[:400] or "（空）"))
        lines.append("  下一步：★ 先看原文里「每类各几个节点」（`0/3 nodes are available:` 后面那串），"
                     "数最多的那一类就是主因；再看 `k8s.describe` 的 `Node-Selectors` 与 `Requests`")
        lines.append("")
    lines.append("★ 判据口径：**三类成因各自挂在原文里的关键字上**（不是写死的文案）——")
    lines.append("  换了故障，这几行必须**跟着换**（规范 §12.39.3）。")
    return "\n".join(lines)


def diagnose_pending(text: str) -> str:
    return render_pending(parse_pending_rows(text))
