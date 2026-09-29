"""最小鉴权（T14·S2）：本地单用户口令 + 内存会话令牌 + 登录限速。

★ 规范依据（v1.17）：
  · **§12.97.1** 口令只存 **PBKDF2-HMAC-SHA256** 的 `salt` / `iterations` / `hash` ——
    **任何地方不许出现明文**；会话令牌**只在内存、不落盘**（进程重启 ⇒ 全体失效）；
    走 **`Authorization: Bearer`** 而**不用 Cookie**（天然免 CSRF）。
  · **§12.97.3 无口令 ≠ 全放行** —— 从没设过口令时，服务必须拒绝所有 `/api/**`。
    ★ 这条的判据不是"有没有这个字段"，而是**"把校验删掉，断言会不会红"**。
  · **§12.97.4 能防 / 不能防都要写清** —— 这是**「把门」，不是「保险柜」**；
    "只绑 `127.0.0.1`"一个字不动（红线 3），鉴权只是**叠加**一层。

★ 两条刻意的"fail-closed"设计（都不是顺手，是判断）：
  1. **口令文件坏了 ⇒ 报错，不许当成"没设过口令"** ——
     若坏文件被当成"未配置"，那"设置口令"这条流程就成了**免鉴权的重置口令 = 把门打开**。
  2. **已经设过口令 ⇒ 不允许再"初始化"一次**（要改口令必须**先登录**）——
     同上一条理由：初始化接口是攻击面，不能是后门。

★ 本模块**不认识** engine / transport / store 的执行面 —— 它只做"口令与令牌"这一件事。
  "谁被拦下"由 `app/server.py` 那个**唯一漏斗**决定（§12.97.2）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from app.config import AppConfig
from app.errors import OpsError
from app.store import now_iso

_FILE_VERSION = 1
_ALGO = "pbkdf2_hmac_sha256"

#: `config.yaml` 的 `auth:` 段默认值。
#: ★ 本段**不许出现口令本身**（红线 8 同源）—— 这里只有路径与策略参数。
_DEFAULTS: dict[str, Any] = {
    "file": "var/auth.json",
    "token_ttl_sec": 8 * 3600,      # 8 小时
    "pbkdf2_iterations": 210_000,   # OWASP 2023 对 PBKDF2-HMAC-SHA256 的推荐下限
    "max_fail_per_minute": 5,       # 速率闸
    "lockout_after": 10,            # 连续失败到这个数 ⇒ 锁
    "lockout_sec": 60,
    "min_password_len": 8,
}

_MIN_ALLOWED_LEN = 6  # 再低就是"假口令"，配置写小了也按它兜底

#: ★★ §12.97.4 的**边界自述**：能防什么 / 不能防什么。
#: ★ 只许有**这一处定义** —— `status()`（登录后）与 `ping()`（登录前）都从这里取，
#:   界面、报告、文档一律引用它，不许各自再写一遍（§12.66.2 同源）。
_CAN_PROTECT: tuple[str, ...] = (
    "同机上别的用户 / 别的程序 / 别的浏览器，不经登录就用这个控制台",
    "「任何能对 127.0.0.1:8787 说话的进程 = 拿到执行权」这个缺口",
)
_CANNOT_PROTECT: tuple[str, ...] = (
    "拿到令牌的人",
    "拿到 root 的本地用户",
    "内存 dump",
    "本机键盘记录",
)
_BOUNDARY_NOTE = "这是「把门」，不是「保险柜」；★ 「只绑 127.0.0.1」这一层一个字没动。"


class Auth:
    """口令 + 会话令牌 + 限速。**不碰任何执行层**（见模块 docstring）。"""

    def __init__(self, cfg: AppConfig, *, clock: Callable[[], float] = time.time) -> None:
        raw = dict((cfg.raw or {}).get("auth") or {})
        self.cfg = cfg
        self.raw = raw

        def _int(key: str) -> int:
            v = raw.get(key)
            if v is None:
                v = _DEFAULTS[key]
            try:
                return int(v)
            except (TypeError, ValueError):
                raise OpsError(
                    code="CONFIG_INVALID",
                    reason=f"config.yaml 的 auth.{key} 不是整数（当前是 {v!r}）",
                    advice=f"把它改成整数，默认 {_DEFAULTS[key]}。",
                ) from None

        rel = str(raw.get("file") or _DEFAULTS["file"])
        p = Path(rel)
        self.path: Path = p if p.is_absolute() else (cfg.root / rel)
        self.token_ttl_sec: int = _int("token_ttl_sec")
        self.iterations: int = _int("pbkdf2_iterations")
        self.max_fail_per_minute: int = _int("max_fail_per_minute")
        self.lockout_after: int = _int("lockout_after")
        self.lockout_sec: int = _int("lockout_sec")
        self.min_password_len: int = max(_MIN_ALLOWED_LEN, _int("min_password_len"))
        self._clock = clock

        # ★ 装载**不抛异常**：口令文件坏了也不能让控制台起不来
        #   （T7·§12.17 的教训 —— 用户手滑时"连看错误的界面都没有"是更糟的结果）。
        #   ★ 但**必须 fail-closed**：坏文件 ⇒ `configured=False` **且** `setup_allowed=False`
        #   （连"设置口令"都不给），否则"初始化"就成了免鉴权的重置口令 = 后门。见 `setup_allowed`。
        self._rec, self._load_error, self._file_existed = self._load()
        # ★ 会话**只在内存**（§12.97.1）：进程重启即失效，磁盘上永远没有可用凭据。
        self._sessions: dict[str, dict[str, Any]] = {}
        self._fails: dict[str, list[float]] = {}
        self._consec: dict[str, int] = {}
        self._locked: dict[str, float] = {}

    # ------------------------------------------------------------------ 装载

    def _load(self) -> tuple[dict[str, Any] | None, OpsError | None, bool]:
        """读口令文件 ⇒ `(记录, 装载错误, 文件是否存在过)`。

        ★ **不抛异常**，但把"坏了"如实带出来 —— 由调用方决定怎么拦（见 `setup_allowed`）。
        ★ 关键区别：`文件不存在`（⇒ 可以走首次设置）与 `文件存在但坏了`（⇒ 连设置都不给）
          是**两件事**。把它们混成一件就是把门打开。
        """
        if not self.path.is_file():
            return None, None, False
        try:
            rec = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return None, OpsError(
                code="AUTH_STORE_BROKEN",
                reason=f"口令文件读不出来：{self.path}",
                advice=(
                    "★ **不要删掉它当作「没设过口令」** —— 那等于把门打开（fail-closed）。"
                    "请从备份恢复；确认这是本机自己的文件后再手工处理。"
                ),
                detail=f"{type(exc).__name__}: {exc}",
            ), True
        if not isinstance(rec, dict) or not rec.get("hash") or not rec.get("salt"):
            return None, OpsError(
                code="AUTH_STORE_BROKEN",
                reason="口令文件内容不完整（缺 salt / hash）",
                advice="同上：**不要**当成「没设过口令」，也不要把这个文件删掉。",
                detail=(json.dumps(rec, ensure_ascii=False)[:400] if isinstance(rec, dict) else str(rec)[:400]),
            ), True
        return rec, None, True

    @property
    def load_error(self) -> OpsError | None:
        """口令文件装载错误（`None` = 正常）。给闸门与自述用。"""
        return self._load_error

    @property
    def configured(self) -> bool:
        """是否设过口令。**这是闸门的核心判据**（§12.97.3）。"""
        return self._rec is not None

    @property
    def store_broken(self) -> bool:
        """口令文件存在但坏了。"""
        return self._load_error is not None

    @property
    def setup_allowed(self) -> bool:
        """允不允许走「首次设置口令」。

        ★ **判据是"从来没有过口令文件"，不是"当前没有口令"。**
          若拿 `not configured` 当判据，口令文件坏掉时就等价于"没设过" ⇒
          `POST /api/auth/setup` 可以把门重新设成攻击者自己的口令 = **免鉴权重置 = 后门**。
        """
        return (not self._file_existed) and self._load_error is None

    # ------------------------------------------------------------------ 口令

    @staticmethod
    def _derive(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iterations)

    def _write_password(self, password: str) -> dict[str, Any]:
        pw = password or ""
        if len(pw) < self.min_password_len:
            raise OpsError(
                code="AUTH_WEAK_PASSWORD",
                reason=f"口令至少要 {self.min_password_len} 个字符（当前 {len(pw)} 个）",
                advice="换一个长一点的。★ 这是本机唯一的门，别用空口令或纯数字短口令。",
            )
        salt = secrets.token_bytes(16)
        it = self.iterations
        digest = self._derive(pw, salt, it)
        rec = {
            "version": _FILE_VERSION,
            "algo": _ALGO,
            "salt": salt.hex(),
            "iterations": it,
            "hash": digest.hex(),
            "created_at": now_iso(self.cfg),
            "updated_at": now_iso(self.cfg),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # ★ 只落 salt + 参数 + hash；**明文一个字节都不落**（§12.97.1）
        self.path.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass  # Windows 上 chmod 能力有限；这里只是尽力而为，不是判据
        self._rec = rec
        # ★ 关键：把"文件曾经不存在"这个状态**立刻翻掉**，否则在本进程存活期间
        #   `setup_allowed` 会一直是 True ⇒ 任何人可以再"初始化"一次覆盖口令 = 后门。
        self._file_existed = True
        self._load_error = None
        return {"configured": True, "iterations": it, "algo": _ALGO, "file": self.path.name}

    def set_password(self, password: str) -> dict[str, Any]:
        """首次设置口令。★ **只要口令文件曾经存在过，就拒绝**（防"重置口令 = 把门打开"）。"""
        if self._load_error is not None:
            raise self._load_error
        if self._file_existed:
            raise OpsError(
                code="AUTH_ALREADY_INITIALIZED",
                reason="本机已经设过口令，不能再「初始化」一次",
                advice=(
                    "用 `/api/auth/login` 登录；登录后要改口令请走 `/api/auth/password`（需带旧口令）。"
                    "★ 这条是刻意拒的：初始化接口若可重复调用，它就是免鉴权的重置口令 = 后门。"
                    "（若确实忘了口令，请在管理机上手工处理 `var/auth.json` —— 那属于**人为**介入，"
                    "不是控制台自己开的口子。）"
                ),
            )
        return self._write_password(password)

    def verify(self, password: str) -> bool:
        if not self._rec:
            return False
        try:
            salt = bytes.fromhex(str(self._rec["salt"]))
            it = int(self._rec["iterations"])
            expect = bytes.fromhex(str(self._rec["hash"]))
        except (KeyError, TypeError, ValueError):
            return False
        return hmac.compare_digest(self._derive(password or "", salt, it), expect)

    def change_password(self, old: str, new: str) -> dict[str, Any]:
        """改口令。**必须先验旧口令**（所以调用方一定是已登录的人）。"""
        if not self.verify(old):
            raise OpsError(
                code="AUTH_BAD_CREDENTIALS",
                reason="旧口令不正确",
                advice="确认当前口令后重试。",
            )
        return self._write_password(new)

    # ------------------------------------------------------------------ 限速

    def _guard_rate(self, client: str) -> None:
        now = self._clock()
        until = self._locked.get(client, 0.0)
        if now < until:
            left = int(until - now + 0.999)
            raise OpsError(
                code="AUTH_RATE_LIMITED",
                reason=f"登录尝试过于频繁，已锁定 {left} 秒",
                advice="等锁定期过去再试。★ 这道闸是为「本机其它程序乱撞」准备的，不是防公网。",
                context={"retry_after_sec": left},
            )
        fails = [t for t in self._fails.get(client, []) if now - t < 60.0]
        self._fails[client] = fails
        if len(fails) >= self.max_fail_per_minute:
            self._locked[client] = now + self.lockout_sec
            raise OpsError(
                code="AUTH_RATE_LIMITED",
                reason=f"一分钟内失败 {len(fails)} 次（上限 {self.max_fail_per_minute}），锁定 {self.lockout_sec} 秒",
                advice="等锁定期过去再试。",
                context={"retry_after_sec": self.lockout_sec},
            )

    def _note_failure(self, client: str) -> None:
        now = self._clock()
        fails = self._fails.setdefault(client, [])
        fails.append(now)
        fails[:] = [t for t in fails if now - t < 60.0]
        n = self._consec.get(client, 0) + 1
        self._consec[client] = n
        if n >= self.lockout_after:
            self._locked[client] = now + self.lockout_sec
            self._consec[client] = 0

    def _note_success(self, client: str) -> None:
        self._fails.pop(client, None)
        self._consec.pop(client, None)
        self._locked.pop(client, None)

    # ------------------------------------------------------------------ 会话

    def _purge(self, now: float) -> None:
        dead = [t for t, s in self._sessions.items() if now - float(s["created"]) > self.token_ttl_sec]
        for t in dead:
            self._sessions.pop(t, None)

    def login(self, password: str, client: str = "-") -> dict[str, Any]:
        """验口令 ⇒ 发一个内存令牌。"""
        if self._load_error is not None:
            raise self._load_error
        if not self.configured:
            raise OpsError(
                code="AUTH_NOT_INITIALIZED",
                reason="本机还没设过口令，控制台现在是「全拒」状态",
                advice=(
                    "先在界面上完成「设置口令」（`POST /api/auth/setup`）。"
                    "★ 这是红线 11：**没有口令就不许用** —— 不是「没口令就放行」。"
                ),
            )
        self._guard_rate(client)
        if not self.verify(password):
            self._note_failure(client)
            raise OpsError(
                code="AUTH_BAD_CREDENTIALS",
                reason="口令不正确",
                advice=f"重试；连续 {self.lockout_after} 次失败会锁定 {self.lockout_sec} 秒。",
            )
        self._note_success(client)
        now = self._clock()
        self._purge(now)
        token = secrets.token_urlsafe(32)
        self._sessions[token] = {"created": now, "last_seen": now, "client": client}
        return {
            "token": token,
            "ttl_sec": self.token_ttl_sec,
            "issued_at": now_iso(self.cfg),
            "expires_at_epoch": int(now) + self.token_ttl_sec,
            "sessions": len(self._sessions),
        }

    def check(self, token: str | None) -> bool:
        """令牌有效吗？有效则刷新 `last_seen`。"""
        if not token:
            return False
        now = self._clock()
        self._purge(now)
        s = self._sessions.get(token)
        if not s:
            return False
        s["last_seen"] = now
        return True

    def logout(self, token: str | None) -> bool:
        if not token:
            return False
        return self._sessions.pop(token, None) is not None

    def revoke_all(self) -> int:
        n = len(self._sessions)
        self._sessions.clear()
        return n

    def session_info(self, token: str | None) -> dict[str, Any] | None:
        """这个令牌对应会话的公开信息（★ 不外泄令牌本身）。"""
        s = self._sessions.get(token or "")
        if not s:
            return None
        return {
            "created_epoch": int(s["created"]),
            "last_seen_epoch": int(s["last_seen"]),
            "client": str(s.get("client") or "-"),
            "age_sec": int(self._clock() - float(s["created"])),
        }

    # ------------------------------------------------------------------ 自述

    def public_policy(self) -> dict[str, Any]:
        """可公开的策略与**边界自述**（登录前也要能看到 —— 见 §12.97.4）。

        ★ 这里**不含**任何机器私有信息（主机名 / IP / 拓扑 / 库规模都不在），
          所以 `GET /api/auth/ping` 免鉴权地带上它是安全的，而且**应该**带上：
          "这道门能防什么、不能防什么"是给人看的承诺，不该藏在登录之后。
        """
        return {
            "min_password_len": self.min_password_len,
            "token_ttl_sec": self.token_ttl_sec,
            "max_fail_per_minute": self.max_fail_per_minute,
            "lockout_after": self.lockout_after,
            "lockout_sec": self.lockout_sec,
            "can_protect": list(_CAN_PROTECT),
            "cannot_protect": list(_CANNOT_PROTECT),
            "note": _BOUNDARY_NOTE,
        }

    def status(self) -> dict[str, Any]:
        """给界面看的策略自述。★ **不许吐 salt / hash**。"""
        now = self._clock()
        self._purge(now)
        return {
            "configured": self.configured,
            "setup_allowed": self.setup_allowed,
            "store_broken": self.store_broken,
            "blocked_reason": (self._load_error.reason if self._load_error else ""),
            "algo": _ALGO if self.configured else "",
            "file": self.path.name,
            "sessions": len(self._sessions),
            **self.public_policy(),
        }
