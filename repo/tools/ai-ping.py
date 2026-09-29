"""模型接入层冒烟测试（S3 的证据生成器）。

用法（在 repo/ 下，key 走环境变量）：
    python tools/ai-ping.py

它做四件事，全部留原始输出：
  ① 问一次模型清单（★ 不凭印象写模型名）
  ② 真发一次带 tools 的请求，看 finish_reason 是否 tool_calls
  ③ 打印 key 的状态（**只有掩码**）
  ④ 验证脱敏：故意把 key 形态的串过一遍 scrub()
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ai.keystore import KeyStore, mask, scrub  # noqa: E402
from app.ai.provider import build_provider  # noqa: E402
from app.ai.settings import load_ai_settings  # noqa: E402
from app.ai.tools import ToolFace, function_spec, _require_note  # noqa: E402
from app.catalog import load_actions  # noqa: E402
from app.config import load as load_config  # noqa: E402


def main() -> int:
    cfg = load_config(Path("."))
    st = load_ai_settings(cfg)
    store = KeyStore()
    found = store.load_from_env(st.key_env)
    print(f"ai.enabled     = {st.enabled}")
    print(f"provider/model = {st.provider} / {st.model}")
    print(f"key            = {store.status()['mask']}（来源 {store.status()['source'] or '未配置'}）")
    print(f"外流档位        = {st.outflow_tier}（★ A 档 = 只发结论 + 动作 ID + 参数）")
    if not found:
        print(f"★ 环境变量 {st.key_env} 里没有 key —— 这是给开发/自检用的注入路径 ①。")
        return 1

    provider = build_provider(st)
    key = store.get()

    print("\n── ① 模型清单 ──────────────────────────────")
    models = provider.list_models(key)
    for item in models.get("data") or []:
        print(
            "  {:<18} {:<22} context={:<9} output={:<7} in={}".format(
                item.get("id", "?"),
                item.get("name", ""),
                item.get("context_window", "?"),
                item.get("max_output_tokens", "?"),
                ",".join(item.get("input_modalities") or []),
            )
        )

    print("\n── ② 带 tools 的真请求（工具面取自 catalog）──────")
    actions = load_actions(cfg.paths.actions)
    if not isinstance(actions, dict):
        actions = {a.id: a for a in actions}
    face = ToolFace(cfg, actions)
    pick = [face.l3_schema(x)["id"] for x in ("disk.usage", "host.overview", "svc.list")]
    tools = [function_spec(actions[x], _require_note(actions[x])) for x in pick]
    print(f"  工具面规模 = {len(face.green)} 个（本次只给了 {len(tools)} 个：{', '.join(pick)}）")
    question = "看看哪台机器的磁盘快满了？"
    print(f"  提问 = {question}")
    result = provider.chat(
        key,
        messages=[
            {"role": "system", "content": "你是运维助手，只能调用给你的只读工具。"},
            {"role": "user", "content": question},
        ],
        tools=tools,
        model=st.model,
    )
    print(f"  finish_reason = {result.finish_reason}")
    print(f"  content       = {result.content[:200]!r}")
    for call in result.tool_calls:
        print(f"  tool_call     = {call['name']}({json.dumps(call['arguments'], ensure_ascii=False)})")
    print(f"  usage         = {result.usage}")

    print("\n── ③ key 状态（界面看到的就是这个）────────────")
    print(f"  {json.dumps(store.status(), ensure_ascii=False)}")
    print(f"  mask('sk-abcdefghijklmnop') = {mask('sk-abcdefghijklmnop')}")

    print("\n── ④ 脱敏自证 ──────────────────────────────")
    sample = f"Authorization: Bearer {key}"
    print(f"  原文样例 = Authorization: Bearer {mask(key)}（★ 这里就不打原文了）")
    print(f"  scrub()  = {scrub(sample)}")
    assert key not in scrub(sample), "★ 脱敏没生效"
    print("  ✅ scrub() 之后原文里的 key 形态已被替换")

    print("\n── ⑤ 用量记账（规范 §12.81：不许凭印象估钱）──")
    print(f"  本次总 token = {result.usage.get('total_tokens')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
