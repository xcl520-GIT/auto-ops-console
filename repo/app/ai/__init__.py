"""AI 助手基座（T12 · 五·AI 助手）。

★ 本包的**唯一入口**是 `/api/ai/**`，它内部只允许调用既有的 `/api/**` dispatch。
★ 本包**不许** import `app.engine` / `app.transport` / 任何 ssh 相关模块（铁律 8 / 规范 §12.74）。
  —— 因为"AI 与点击走同一条路"一旦被绕开，**留证 / 护栏 / 确认闸门 / 覆盖率账本**四套体系会同时静悄悄失效。

模块：
  · `tools.py`   工具面导出器（catalog → L1/L2/L3 + 模型可用的 function schema）
"""
from __future__ import annotations

__all__ = ["tools"]
