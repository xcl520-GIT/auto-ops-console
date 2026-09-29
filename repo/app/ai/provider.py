"""模型接入层：provider 抽象 + DeepSeek adapter（规范 §12.78 / §12.81）。

★ **不写死某一家**（`设计\04` §8 #2）：所有云端差异收在 provider 里，运行时只认 `chat()`。
★ 传输用 **Python 标准库 `urllib`** —— 项目约束是"标准库优先 + 零构建链"，不引第三方依赖。
★ 出边界的一切文本都要过 `keystore.scrub()`：**上游返回的报错里也可能带着 key**（§12.79 规矩 3）。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from app.ai.keystore import scrub
from app.ai.settings import AiSettings
from app.errors import OpsError


@dataclass
class ChatResult:
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    finish_reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    model: str = ""

    def to_public(self) -> dict[str, Any]:
        return {
            "finish_reason": self.finish_reason,
            "content_chars": len(self.content or ""),
            "tool_call_count": len(self.tool_calls),
            "usage": self.usage,
            "model": self.model,
        }


class ChatProvider:
    """只管"说话"：把 messages + tools 发出去，把话收回来。**它不做任何权限判断**。"""

    name = "base"

    def __init__(self, base_url: str, timeout_sec: int = 120, temperature: float = 0.2) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec
        self.temperature = temperature

    # ---------------------------------------------------------------- 传输
    def _request(self, path: str, key: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        url = self.base_url + path
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST" if data else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                pass
            raise self._translate_http(exc.code, body) from None
        except urllib.error.URLError as exc:
            raise OpsError(
                code="AI_UNREACHABLE",
                reason=f"连不上模型服务：{scrub(str(exc.reason))}",
                advice=f"检查网络与 base_url（当前 {self.base_url}）；企业网可能需要代理。",
            ) from None
        except TimeoutError:
            raise OpsError(
                code="AI_TIMEOUT",
                reason=f"模型服务在 {self.timeout_sec} 秒内没有回应",
                advice="调大 config.yaml 里 ai.timeout_sec，或把问题拆小一点再问。",
            ) from None

    @staticmethod
    def _translate_http(code: int, body: str) -> OpsError:
        detail = scrub(body)
        if code in (401, 403):
            return OpsError(
                code="AI_AUTH_ERROR",
                reason=f"模型服务拒绝了这把 key（HTTP {code}）：{detail}",
                advice="检查 key 是否复制完整 / 是否已失效；★ key 只存在内存里，重填一次即可。",
            )
        if code == 429:
            return OpsError(
                code="AI_RATE_LIMIT",
                reason="模型服务限流了（HTTP 429）",
                advice="等一会儿再试；或把单次请求拆小（少发几个工具、少发几张表）。",
            )
        if code >= 500:
            return OpsError(
                code="AI_UPSTREAM",
                reason=f"模型服务自己出错了（HTTP {code}）：{detail}",
                advice="这是对方的问题，不是本工作台的；稍后重试即可。",
            )
        return OpsError(
            code="AI_HTTP_ERROR",
            reason=f"模型服务返回 HTTP {code}：{detail}",
            advice="把这条原因贴出来即可定位（常见成因：模型名不对 / 请求体里有它不认的字段）。",
        )

    # ---------------------------------------------------------------- 能力
    def list_models(self, key: str) -> dict[str, Any]:
        return self._request("/models", key, None)

    def chat(
        self,
        key: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        tool_choice: str = "auto",
    ) -> ChatResult:
        raise NotImplementedError


class DeepSeekProvider(ChatProvider):
    """DeepSeek（OpenAI 兼容）。★ 模型名**不要凭印象写** —— 用 `list_models()` 问它（T12·S0 的现场样本）。"""

    name = "deepseek"

    def chat(
        self,
        key: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        tool_choice: str = "auto",
    ) -> ChatResult:
        payload: dict[str, Any] = {
            "model": model or "deepseek-flash",
            "messages": messages,
            "temperature": self.temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        raw = self._request("/chat/completions", key, payload)
        choices = raw.get("choices") or []
        if not choices:
            raise OpsError(
                code="AI_EMPTY_CHOICES",
                reason="模型服务没有返回任何候选回答",
                advice="重试一次；若持续出现，把原始响应留档再看（可能是被内容策略拦了）。",
            )
        message = choices[0].get("message") or {}
        usage_raw = raw.get("usage") or {}
        usage = {
            "prompt_tokens": int(usage_raw.get("prompt_tokens") or 0),
            "completion_tokens": int(usage_raw.get("completion_tokens") or 0),
            "total_tokens": int(usage_raw.get("total_tokens") or 0),
            "prompt_cache_hit_tokens": int(usage_raw.get("prompt_cache_hit_tokens") or 0),
        }
        calls: list[dict[str, Any]] = []
        for item in message.get("tool_calls") or []:
            fn = item.get("function") or {}
            args_text = fn.get("arguments") or "{}"
            try:
                args = json.loads(args_text)
            except json.JSONDecodeError:
                args = {"__parse_error__": args_text}
            calls.append(
                {
                    "id": item.get("id") or "",
                    "name": str(fn.get("name") or ""),
                    "arguments": args if isinstance(args, dict) else {"__value__": args},
                    "arguments_raw": args_text,
                }
            )
        return ChatResult(
            content=str(message.get("content") or ""),
            tool_calls=calls,
            finish_reason=str(choices[0].get("finish_reason") or ""),
            usage=usage,
            model=str(raw.get("model") or payload["model"]),
        )


PROVIDERS: dict[str, type[ChatProvider]] = {"deepseek": DeepSeekProvider}


def build_provider(settings: AiSettings) -> ChatProvider:
    cls = PROVIDERS.get(settings.provider)
    if cls is None:
        raise OpsError(
            code="AI_UNKNOWN_PROVIDER",
            reason=f"不认识的 provider：{settings.provider}",
            advice=f"可用的：{'、'.join(sorted(PROVIDERS))}（加一家就在 app/ai/provider.py 登记一个适配器）。",
        )
    return cls(settings.base_url, timeout_sec=settings.timeout_sec, temperature=settings.temperature)
