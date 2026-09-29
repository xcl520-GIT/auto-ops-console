"""控制台 HTTP 客户端（★ T14 起：**先过门，再到 `/api/**`**）。

★ 为什么单独做成一个模块：加了鉴权之后**每一个**打控制台的脚本都要先登录，
  同一段登录逻辑抄四遍，迟早有一份忘了改（§12.66.2 同源：同一件事只许有一处定义）。

口令从哪来（按优先级）：
  ① 环境变量 **`AOC_CONSOLE_PASSWORD`**（推荐；与 `AOC_LLM_API_KEY` 同一个风格）
  ② 显式传 `password=...`
  ③ 都没有 ⇒ 只走 `GET /api/auth/ping`（**免鉴权**）—— 能探活、能看策略，
     但一碰 `/api/**` 就会被 401 挡住（那是**服务端**说的真话，不是这个客户端的客气话）。

★ 令牌**只在内存里**（这个进程活着期间有效），**不落盘、不进日志** —— 与规范 §12.97.1 同一条纪律。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BASE = "http://127.0.0.1:8787"


class AuthFailed(RuntimeError):
    """登录相关的失败（口令不对 / 没设过口令 / 被限速 / 口令文件坏了）。"""


class ConsoleClient:
    def __init__(self, base: str = DEFAULT_BASE, password: str | None = None, timeout: int = 600) -> None:
        self.base = base.rstrip("/")
        self.password = password if password is not None else os.environ.get("AOC_CONSOLE_PASSWORD", "")
        self.timeout = timeout
        self.token: str | None = None
        self._ping: dict[str, Any] | None = None

    # ------------------------------------------------------------------ 低层

    def raw(self, method: str, path: str, body: dict | None = None, *,
            auth: bool = True, timeout: int | None = None) -> tuple[int, dict[str, Any]]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, {"ok": False, "raw": raw[:800]}
        except urllib.error.URLError as exc:
            # ★ 服务没起来时给一句人话，而不是让调用方去猜
            return -1, {"ok": False, "error": {
                "code": "UNREACHABLE",
                "reason": f"控制台连不上：{self.base}",
                "advice": "确认控制台已启动（`cd repo` → `python -m app.server`）。",
                "detail": str(exc),
            }}

    # ------------------------------------------------------------------ 门

    def ping(self) -> dict[str, Any]:
        """★ **免鉴权**：探活 ＋ 看策略与边界自述。不缓存错过的结果。"""
        code, payload = self.raw("GET", "/api/auth/ping", auth=False)
        data = dict(payload.get("data") or {})
        data["_http"] = code
        self._ping = data
        return data

    def login(self, password: str | None = None) -> dict[str, Any]:
        """登录取令牌。★ 失败时抛 `AuthFailed`（带后端给的「原因 + 建议」）。"""
        pw = password if password is not None else self.password
        if not pw:
            raise AuthFailed(
                "没拿到口令：设 `AOC_CONSOLE_PASSWORD` 环境变量，或显式传 password=…\n"
                f"  当前门的状态：{json.dumps(self.ping(), ensure_ascii=False)[:300]}"
            )
        code, payload = self.raw("POST", "/api/auth/login", {"password": pw}, auth=False)
        if code != 200 or not payload.get("ok"):
            err = payload.get("error") or {}
            raise AuthFailed(
                f"登录失败（HTTP {code}）[{err.get('code', '?')}] {err.get('reason', '')}\n"
                f"  建议：{err.get('advice', '')}"
            )
        self.token = (payload.get("data") or {}).get("token")
        return payload["data"]

    def setup(self, password: str | None = None) -> dict[str, Any]:
        """首次设置口令（**只在从没设过口令时可用**）。"""
        pw = password if password is not None else self.password
        code, payload = self.raw("POST", "/api/auth/setup", {"password": pw}, auth=False)
        if code != 200 or not payload.get("ok"):
            err = payload.get("error") or {}
            raise AuthFailed(f"设置口令失败（HTTP {code}）[{err.get('code', '?')}] {err.get('reason', '')}")
        self.token = (payload.get("data") or {}).get("token")
        return payload["data"]

    # ------------------------------------------------------------------ 业务

    def call(self, method: str, path: str, body: dict | None = None, *,
             auto_login: bool = True, timeout: int | None = None) -> tuple[int, dict[str, Any]]:
        """打 `/api/**`。★ 收到 `AUTH_REQUIRED` 且给了口令 ⇒ **自动登录一次**再重试。"""
        code, payload = self.raw(method, path, body, timeout=timeout)
        if code == 401 and auto_login:
            err_code = ((payload.get("error") or {}).get("code") or "")
            if err_code in ("AUTH_REQUIRED", "") and self.password:
                self.login()
                code, payload = self.raw(method, path, body, timeout=timeout)
        return code, payload

    def get(self, path: str, **kw: Any) -> tuple[int, dict[str, Any]]:
        return self.call("GET", path, **kw)

    def post(self, path: str, body: dict | None = None, **kw: Any) -> tuple[int, dict[str, Any]]:
        return self.call("POST", path, body or {}, **kw)

    def get_data(self, path: str, **kw: Any) -> dict[str, Any]:
        """只取 `data`；不顺就抛带「原因 + 建议」的 RuntimeError。"""
        code, payload = self.get(path, **kw)
        if code != 200 or not payload.get("ok"):
            err = payload.get("error") or {}
            raise RuntimeError(f"HTTP {code} [{err.get('code', '?')}] {err.get('reason', '')} ｜ {err.get('advice', '')}")
        return payload.get("data") or {}


def from_argv(argv: list[str] | None = None) -> ConsoleClient:
    """给脚本用：认 `--password xxx` / `--base http://…`，其余不管（返回客户端）。"""
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    pw = os.environ.get("AOC_CONSOLE_PASSWORD", "")
    base = DEFAULT_BASE
    if "--password" in argv:
        i = argv.index("--password")
        pw = argv[i + 1] if len(argv) > i + 1 else ""
    if "--base" in argv:
        i = argv.index("--base")
        base = argv[i + 1] if len(argv) > i + 1 else base
    return ConsoleClient(base=base, password=pw)
