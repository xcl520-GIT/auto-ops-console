"""key 的"四不落"（规范 §12.79 / 红线 8）。

| # | 规矩 |
|---|---|
| 1 | 两条注入路径：① 环境变量 ② 界面输入 ⇒ **只存服务进程内存**（重启即失效） |
| 2 | ★ 界面只显示**掩码**（不显示完整 key，也不做"显示明文"按钮） |
| 3 | ★ **日志层脱敏**（`sk-` 前缀出现即替换）—— 不许"我们不打日志"这种口头保证 |
| 4 | ★★ **不落盘 / 不进 Git / 不进截图** |

★ 沿用 `host.enroll` 的口径：「**口令类信息永不落盘**」—— 它是**结构**，不是纪律。
"""
from __future__ import annotations

import os
import re

from app.errors import OpsError

# ★ 脱敏正则：`sk-` 开头的长串一律替换。宁可错杀，不可放过。
_SCRUB_RE = re.compile(r"\bsk-[A-Za-z0-9_\-]{6,}")


def scrub(text: str) -> str:
    """把文本里出现的 key 形态替换成掩码。★ 日志/异常/报告在出边界前都要过它。"""
    if not text:
        return text
    return _SCRUB_RE.sub("sk-****（已脱敏）", text)


def mask(key: str | None) -> str:
    """只给"能确认是我那把钥匙"的最少信息：前 3 位 + 后 4 位。"""
    if not key:
        return "（未配置）"
    if len(key) <= 8:
        return "sk-****"
    return f"{key[:3]}****{key[-4:]}"


class KeyStore:
    """进程内存态。★ 没有任何写盘方法 —— 这就是"不落盘"的实现方式。"""

    def __init__(self) -> None:
        self._key: str | None = None
        self._source: str | None = None

    # -- 注入路径 ①：环境变量（开发 / 自检 / 演示默认）
    def load_from_env(self, env_name: str) -> bool:
        value = os.environ.get(env_name) or ""
        if value.strip():
            self.set(value.strip(), source=f"env:{env_name}")
            return True
        return False

    # -- 注入路径 ②：界面输入（只存内存）
    def set(self, key: str, source: str = "ui") -> None:
        key = (key or "").strip()
        if not key:
            raise OpsError(
                code="AI_KEY_EMPTY",
                reason="key 是空的",
                advice="填一个模型 API key；★ 它只留在本进程内存里，不写盘、不进日志。",
            )
        if not key.startswith("sk-"):
            raise OpsError(
                code="AI_KEY_SHAPE",
                reason="key 的形态不对（期望以 `sk-` 开头）",
                advice="检查是不是复制串了；本工作台不收别的东西。",
            )
        self._key = key
        self._source = source

    def clear(self) -> None:
        self._key = None
        self._source = None

    def get(self) -> str:
        if not self._key:
            raise OpsError(
                code="AI_NO_KEY",
                reason="还没有配置模型 API key",
                advice=(
                    "两条路任选：① 启动前设环境变量（推荐，见 config.yaml 的 ai.key_env）；"
                    "② 在「对话」页签的设置区输入（只存内存，重启失效）。"
                ),
            )
        return self._key

    # -- 给界面的状态（★ 只给掩码）
    def status(self) -> dict[str, object]:
        return {
            "configured": bool(self._key),
            "source": self._source,
            "mask": mask(self._key),
        }
