"""外发装箱：**A 档的"只发结论"要落成结构，不是自觉**（规范 §12.78 / 红线 9）。

★ 为什么要单独一个文件：
  断言 ⑴ 要能**机械地**问一句"发出去的东西里有没有原文"，而不是靠人读代码。
  ⇒ 把"允许出境的字段"和"绝不出境的字段"写成**两张清单**，装箱只从允许清单取，
    并能对装箱结果做**递归断言**。

| 档 | 内容 | 本期 |
|---|---|---|
| **A（默认）** | `conclusion` + 动作 ID + 参数 | ✅ 只做这档 |
| B / C | 含脱敏片段 / 原始输出 | ❌ 界面置灰占位（**不许谎称已支持**） |

★★ **A 档 ≠ 匿名化**：`conclusion` 里本来就带主机名 / IP / 路径（§12.78.1 第 3 条）。
"""
from __future__ import annotations

from typing import Any, Iterable

from app.errors import OpsError

# ★ 允许出境的任务字段（**只有这些**）。想加字段？先想清楚它是不是"结论"。
ALLOWED_TASK_KEYS: tuple[str, ...] = (
    "id",              # task_id —— 让每句话都能回放（规范 §12.80）
    "action_id",
    "action_title",
    "host_id",
    "host_name",
    "risk",
    "status",
    "verify_result",
    "conclusion",      # ★ 这是 A 档的主角：动作自己的结论（"结论是一等公民"的既有红利）
    "duration_ms",
)

# ★ 绝不出境的键（含它们就是偷渡原文）。★ 断言 ⑴ 会对装箱结果递归检查这张清单。
FORBIDDEN_KEYS: tuple[str, ...] = (
    "steps",
    "stdout",
    "stderr",
    "artifacts",
    "backups",
    "argv",
    "command",
)

TEXT_LIMIT = 4000  # 单条结论的出境上限（★ 再长就截断，并在断点写明）


def pack_tool_result(
    task: dict[str, Any], host_id: str, explain: str = "", content_flag: bool = True
) -> dict[str, Any]:
    """把一次工具结果装成**可出境**的形态。

    ★ 只从 `ALLOWED_TASK_KEYS` 取字段 —— 这是"只发结论"的**实现**，不是文档承诺。
    """
    packed: dict[str, Any] = {k: task.get(k) for k in ALLOWED_TASK_KEYS if task.get(k) is not None}
    packed["host_id"] = host_id
    conclusion = str(packed.get("conclusion") or "")
    if len(conclusion) > TEXT_LIMIT:
        # ★ T13（规范 §12.90）：截断必须**写清保留了多少、一共多少** ——
        #   原来只写"…（已截断）"，读者无法判断"看到的是不是全部"。
        #   ★ 记号形态固定，便于机械识别（`retrieval.TRUNC_RE` 与断言 ⑻ 都认它）。
        packed["conclusion"] = (
            conclusion[:TEXT_LIMIT]
            + "〔已截断：保留 %d 字符 / 共 %d 字符〕" % (TEXT_LIMIT, len(conclusion))
            + "（完整结论在界面「历史」里按任务号查看）"
        )
    if explain:
        packed["explain"] = str(explain)
    if content_flag:
        # ★ 规范 §12.89 第 3 条：让"本次结论**含目标机内容**"这件事在**数据里看得见** ——
        #   不是靠人推理"检索类动作的结论大概会有文件内容吧"。
        # ★ 同时它也是"**A 档 ≠ 匿名化**"的提醒（§12.78.1 第 3 条，清单 178）。
        packed["content_warning"] = (
            "★ 本结论含**目标机上的内容**（A 档允许：它是结论的一部分，不是新开的原文通道）；"
            "★ A 档 ≠ 脱敏 —— 不许对外声称已脱敏"
        )
    assert_no_forbidden(packed)
    return packed


def assert_no_forbidden(obj: Any, path: str = "$") -> None:
    """递归检查：装箱结果里**不许**出现 FORBIDDEN_KEYS 里的任何键。"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in FORBIDDEN_KEYS:
                raise OpsError(
                    code="AI_OUTFLOW_LEAK",
                    reason=f"外发内容里出现了禁止出境的字段：{path}.{key}",
                    advice="A 档只允许发结论（规范 §12.78）；要发原文是 B/C 档的事，本期没实现。",
                )
            assert_no_forbidden(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            assert_no_forbidden(item, f"{path}[{i}]")


def pack_user_facing(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]
