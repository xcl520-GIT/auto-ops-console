"""真跑 AI 助手（★ 走 `/api/ai/**`，不直连任何底层 —— 与铁律 8 一致）。

用法（在 repo/ 下；需要控制台已启动）：
    python tools/ai-ask.py status
    python tools/ai-ask.py tools                       # 看工具面（只读）
    python tools/ai-ask.py ask "哪台机器磁盘快满了？"
    python tools/ai-ask.py ask "看看 node02 的日志" <session_id>
    python tools/ai-ask.py tool-call svc.restart node-01   # ★ 反例：非只读必须被拒
    python tools/ai-ask.py session <session_id>

★★ T14 起控制台有鉴权（红线 11）：先设口令，再把这个脚本要用的口令放进环境变量：
    $env:AOC_CONSOLE_PASSWORD='…'      # PowerShell
    export AOC_CONSOLE_PASSWORD='…'    # bash
   ★ 口令只在本进程内存里用一下；令牌也只在内存 —— **都不落盘**（§12.97.1）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from console_client import AuthFailed, ConsoleClient

BASE = "http://127.0.0.1:8787"
_CLIENT = ConsoleClient(base=BASE)


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    """★ T14：一律走 `ConsoleClient`（它会自动过门），**不再自己拼请求头**。"""
    try:
        return _CLIENT.call(method, path, body)
    except AuthFailed as exc:
        # ★ 过不了门也要给出**完整错误信封**，别让调用方去猜
        return 401, {"ok": False, "error": {
            "code": "AUTH_REQUIRED",
            "reason": str(exc),
            "advice": "设 `AOC_CONSOLE_PASSWORD` 后重试；或先在界面完成「设置口令」。",
        }}


def String70(v) -> str:
    """打印用：把一行截到 70 字（★ 只是显示，不改数据）。"""
    s = str(v or "").replace("\n", " ")
    return s[:70] + ("…" if len(s) > 70 else "")


def show_ask(payload: dict) -> None:
    data = payload.get("data") or {}
    print(f"会话      = {data.get('session_id')}")
    print(f"外流档位  = {data.get('outflow_tier')}")
    print(f"回答      = {data.get('answer')}")
    calls = data.get("tool_calls") or []
    print(f"--- 工具调用（{len(calls)} 次）---")
    for c in calls:
        mark = "✅" if c["ok"] else "❌"
        print(
            f"  {mark} {c['action_id']} @ {c['host_id']}  任务={c['task_id'] or '无'}"
            f"  状态={c['status']}  自证={c['verify_result'] or 'none'}"
        )
        if c.get("explain"):
            print(f"      ↳ 本地译文：{c['explain']}")
    conflicts = data.get("conflicts") or []
    if conflicts:
        print("--- ★ 双结论对照：发现分歧（以工作台为准）---")
        for line in conflicts:
            print(f"  {line}")
    if data.get("no_tool_calls"):
        print("★ 注意：这一轮**没有调用任何工具** —— 结论没有证据支撑。")
    # ── ★ T13：定位表 ＋ 三段交代 ＋ 检索三个数（"找东西"的答案长这样）──
    locate = data.get("locate") or []
    ret = data.get("retrieval") or {}
    scope = data.get("scope") or {}
    if locate or ret.get("hit_count") or scope.get("not_searched") or ret.get("note"):
        print(f"--- ★ 定位表：命中 {ret.get('hit_count', 0)} 条 / 涉及 {ret.get('host_count', 0)} 台 ---")
        for x in locate:
            print(f"  {x['host']} ｜ {x['where']} ｜ {String70(x['what'])} ｜ {x['task_id']}")
        if ret.get("no_hit_hosts"):
            print(f"  ★ 查过了、确实没有：{'、'.join(ret['no_hit_hosts'])}")
        if ret.get("possible_incomplete"):
            print("  ★ **看到的可能不是全部**（有动作上限或被截断）")
        if ret.get("note"):
            print(f"  {ret['note']}")
    if scope.get("not_searched"):
        print("--- ★ **没查到**（不是「这台上没有」）---")
        for x in scope["not_searched"]:
            print(f"  {x['host']} ｜ {x['action_id']} ｜ {x['reason'][:110]}")
    if data.get("need_confirm"):
        print(f"★ 停下等你确认：{data.get('stopped_reason') or '（未给原因）'}")
    print(f"用量      = {data.get('usage')}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]

    if cmd == "status":
        code, payload = call("GET", "/api/ai/status")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if code == 200 else 1

    if cmd == "tools":
        code, payload = call("GET", "/api/ai/tools")
        tools = (payload.get("data") or {}).get("tools") or []
        print(f"工具面：{len(tools)} 个（只含 green）")
        for t in tools[:3]:
            print("  样例：", json.dumps(t, ensure_ascii=False)[:220])
        print(f"返回值：HTTP {code}")
        return 0

    if cmd == "export":
        code, payload = call("POST", "/api/ai/tools/export", {})
        print(json.dumps(payload, ensure_ascii=False))
        return 0 if code == 200 else 1

    if cmd == "ask":
        if len(sys.argv) < 3:
            print('用法：python tools/ai-ask.py ask "问题" [session_id]')
            return 2
        body = {"text": sys.argv[2]}
        if len(sys.argv) > 3:
            body["session_id"] = sys.argv[3]
        code, payload = call("POST", "/api/ai/ask", body)
        if code != 200:
            print(f"HTTP {code}")
            print(json.dumps(payload, ensure_ascii=False, indent=2)[:1500])
            return 1
        show_ask(payload)
        return 0

    if cmd == "tool-call":
        if len(sys.argv) < 4:
            print("用法：python tools/ai-ask.py tool-call <动作id> <主机id[,主机id...]> [k=v ...]")
            return 2
        hosts = [h for h in sys.argv[3].split(",") if h]
        params = {}
        for kv in sys.argv[4:]:
            k, _, v = kv.partition("=")
            params[k] = v
        code, payload = call(
            "POST",
            "/api/ai/tool-call",
            {"action_id": sys.argv[2], "host_ids": hosts, "params": params},
        )
        print(f"HTTP {code}")
        print(json.dumps(payload, ensure_ascii=False, indent=2)[:2000])
        return 0

    if cmd == "hitrate":
        code, payload = call("GET", "/api/ai/hitrate")
        print(json.dumps(payload, ensure_ascii=False, indent=2)[:3000])
        return 0 if code == 200 else 1

    if cmd == "session":
        code, payload = call("GET", f"/api/ai/sessions/{sys.argv[2]}")
        print(json.dumps(payload, ensure_ascii=False, indent=2)[:4000])
        return 0

    print(f"不认识的子命令：{cmd}")
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
