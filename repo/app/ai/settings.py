"""AI 侧的运行参数（规范 §12.81 ＋ **T13 §12.86~§12.92**）。

★ 为什么单独一个模块、而不是塞进 `app/config.py`：
  本话题的边界是「**AI 侧只读，不改承重墙**」（规范 §12.71 / §12.77.2）。
  平台配置加载器一行不动 —— AI 的开关全部集中在 `config.yaml` 的 `ai:` 段下，
  由本模块读取并给默认值（★ 默认值不是"随便定的"，逐条有出处）。

★★ **本段里不许出现 key**（红线 8）：这里只有 `key_env`（**环境变量的名字**）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import AppConfig

# 默认值出处：T12 开题单 §10.2 拍板（用户 2026-09-27 确认）
#          ＋ T13 开题单 §4.2 / §10.2 拍板（用户 2026-09-27 确认）
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "provider": "deepseek",
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-flash",
    "key_env": "AOC_LLM_API_KEY",
    "outflow_tier": "A",
    "max_rounds": 8,
    "max_tool_result_bytes": 4096,
    # ★★ T13 拍板：**保守档 60000**（跨机检索明显更贵；T12 实测单次约 3.2 万 token）
    "max_session_tokens": 60000,
    "batch_workers": 4,
    "timeout_sec": 120,
    "temperature": 0.2,
    "max_hosts_per_action": 4,
    # ── T13 检索与汇总（规范 §12.86 ~ §12.92）──
    "retrieval_max_rows": 40,       # 定位表一次最多显示几行（§12.86）；超出 ⇒ 标注"共 N 行"＋收窄建议
    "dedupe_composite": True,       # 复合读去重：同一轮里 `host.checkup` 覆盖的子动作不再重复跑（§12.91）
    "hitrate_enabled": True,        # 选域命中率本地记账；★ **绝不外发**（§12.92）
    "budget_stop_mode": "confirm",  # 超预算的形态：`confirm` = 停下问人（★ T13 拍板，取代原先的抛错）
    "require_user_scope": True,     # ★ 模型自编"在哪找"⇒ **回问**而不是执行（§12.85 / 断言 ⑸）
}


@dataclass
class AiSettings:
    enabled: bool
    provider: str
    base_url: str
    model: str
    key_env: str
    outflow_tier: str
    max_rounds: int
    max_tool_result_bytes: int
    max_session_tokens: int
    batch_workers: int
    timeout_sec: int
    temperature: float
    max_hosts_per_action: int
    # ── T13 ──
    retrieval_max_rows: int = 40
    dedupe_composite: bool = True
    hitrate_enabled: bool = True
    budget_stop_mode: str = "confirm"
    require_user_scope: bool = True
    raw: dict[str, Any] | None = None

    def to_public(self) -> dict[str, Any]:
        """给界面的表示。★ 只含档位与预算，**不含 key**。"""
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "key_env": self.key_env,
            "outflow_tier": self.outflow_tier,
            "tiers": [
                {"key": "A", "label": "只发结论（默认）", "enabled": True},
                {"key": "B", "label": "结论 + 脱敏片段", "enabled": False, "why": "本期不实现（§12.78）"},
                {"key": "C", "label": "结论 + 原始输出", "enabled": False, "why": "本期不实现（§12.78）"},
                {"key": "D", "label": "本地模型（不外流）", "enabled": False, "why": "预留"},
            ],
            "budgets": {
                "max_rounds": self.max_rounds,
                "max_tool_result_bytes": self.max_tool_result_bytes,
                "max_session_tokens": self.max_session_tokens,
                "batch_workers": self.batch_workers,
                "timeout_sec": self.timeout_sec,
                # ── T13 ──
                "retrieval_max_rows": self.retrieval_max_rows,
                "dedupe_composite": self.dedupe_composite,
                "hitrate_enabled": self.hitrate_enabled,
                "budget_stop_mode": self.budget_stop_mode,
                "require_user_scope": self.require_user_scope,
            },
        }


def load_ai_settings(cfg: AppConfig) -> AiSettings:
    raw = (cfg.raw or {}).get("ai") or {}
    if not isinstance(raw, dict):
        raw = {}
    merged = {**DEFAULTS, **raw}
    if str(merged.get("outflow_tier", "A")).upper() != "A":
        # ★ 本期只实现 A 档：宁可拒绝，也不假装支持（§12.78）
        merged["outflow_tier"] = "A"
    return AiSettings(
        enabled=bool(merged["enabled"]),
        provider=str(merged["provider"]),
        base_url=str(merged["base_url"]).rstrip("/"),
        model=str(merged["model"]),
        key_env=str(merged["key_env"]),
        outflow_tier="A",
        max_rounds=int(merged["max_rounds"]),
        max_tool_result_bytes=int(merged["max_tool_result_bytes"]),
        max_session_tokens=int(merged["max_session_tokens"]),
        batch_workers=int(merged["batch_workers"]),
        timeout_sec=int(merged["timeout_sec"]),
        temperature=float(merged["temperature"]),
        max_hosts_per_action=int(merged["max_hosts_per_action"]),
        retrieval_max_rows=int(merged["retrieval_max_rows"]),
        dedupe_composite=bool(merged["dedupe_composite"]),
        hitrate_enabled=bool(merged["hitrate_enabled"]),
        budget_stop_mode=str(merged["budget_stop_mode"]),
        require_user_scope=bool(merged["require_user_scope"]),
        raw=raw,
    )
