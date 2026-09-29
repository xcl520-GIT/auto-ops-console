"""主机纳管 `host.enroll`（T4 · 平台能力，规范 §10.1）。

要兑现的体验（T3 期间用户的批评）：
> 「以后为了用你这个平台工具，还要自己去改公钥，不是本末倒置吗」

现在：填「IP + 账号」→ 工作台起一个**一次性内网分发点** → 界面上给你**一条**命令 →
你在目标机控制台粘一次 → 之后「校验 / 登记 / 体检」全自动，**你不需要知道公钥是什么**。

★ 为什么不是动作（规范 §10.1.1）：
  动作 = 目标机上一串命令 + 自证。而纳管要
  ① 在**管理机**上起/停一个临时 HTTP 服务 ② 改**管理机**的 `hosts.yaml`
  ③ **轮询等待人在目标机操作** ④ 驱动后续体检 —— 四条都超出动作 YAML 的 schema。

★ 边界（规范 §10.1）：
  · 分发点：只绑内网 IP（过 allow_bind_prefixes 白名单，永不 0.0.0.0）、随机路径 + 一次性 token、
    **用完即停 + 超时兜底**、关停必须自证（端口无监听 + 线程已退出）；
  · 生效校验**必须真登录**（hostname / id -un / uname -r 三条都拿到非空输出），
    不接受"文件写进去了"；
  · 写 `hosts.yaml` 前**本地备份**，写后**重新 bootstrap 校验**，不过就回滚；
  · **口令类信息永不落盘** —— 本版本只走零依赖路径 A，不需要密码，所以不收密码。
"""
from __future__ import annotations

import errno
import json
import secrets
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.config import AppConfig, Host, validate_bind
from app.errors import OpsError
from app.store import now_iso
from app.transport import SshTransport, classify_ssh_failure

SESSION_DIR_NAME = "_enroll"

# hosts.yaml 里"已退役"那一节的分隔注释 —— 新主机插在它**之前**（保持"活跃主机"连成一片）
RETIRED_MARKER = "# ── 已退役"

# 允许写入 hosts.yaml 的字段白名单（规范 §10.1.5）
ENTRY_FIELDS = ("id", "name", "address", "port", "user", "auth", "identity_file", "role", "tags", "note")
ROLE_WHITELIST = ("lab", "k8s-control-plane", "k8s-worker", "docker-registry", "other")


# ------------------------------------------------------------------ 公钥


def _expand(p: str) -> Path:
    return Path(p).expanduser()


def pubkey_path(cfg: AppConfig) -> Path:
    return _expand(str((cfg.raw.get("enroll") or {}).get("pubkey") or "~/.ssh/id_ed25519.pub"))


def identity_path(cfg: AppConfig) -> str:
    return str((cfg.raw.get("enroll") or {}).get("identity_file") or "~/.ssh/id_ed25519")


def ensure_keypair(cfg: AppConfig) -> tuple[Path, bool]:
    """确保管理机上有可用的公钥。

    不存在就**自动生成**（无口令 ed25519）并明确告知 —— 这是"零依赖"的一部分：
    用户不需要先懂 ssh-keygen 才能用这个工作台。
    """
    pub = pubkey_path(cfg)
    if pub.exists():
        return pub, False
    priv_path = pub.parent / pub.stem
    try:
        pub.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "lobehub-ops", "-f", str(priv_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OpsError(
            code="ENROLL_KEYGEN_FAILED",
            reason="管理机上生成 SSH 密钥失败（ssh-keygen 不可用或不可写）",
            advice=f"手工执行 ssh-keygen -t ed25519 生成一对密钥，或在 config.yaml 的 enroll.pubkey 指定已有公钥。",
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc
    if proc.returncode != 0 or not pub.exists():
        raise OpsError(
            code="ENROLL_KEYGEN_FAILED",
            reason="ssh-keygen 没有生成公钥",
            advice="检查 ~/.ssh 目录权限；或手工生成后在 config.yaml 的 enroll.pubkey 指定路径。",
            detail=(proc.stderr or b"").decode("utf-8", "replace").strip(),
        )
    return pub, True


def public_key_text(cfg: AppConfig) -> tuple[str, Path, bool]:
    pub, created = ensure_keypair(cfg)
    try:
        text = pub.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise OpsError(
            code="ENROLL_NO_PUBKEY",
            reason=f"读不到公钥文件：{pub}",
            advice="确认 config.yaml 的 enroll.pubkey 指向的文件存在且可读。",
            detail=str(exc),
        ) from exc
    if not text:
        raise OpsError(code="ENROLL_NO_PUBKEY", reason=f"公钥文件是空的：{pub}", advice="重新生成一对密钥。")
    return text, pub, created


def key_fingerprint(pub: Path) -> str:
    try:
        proc = subprocess.run(["ssh-keygen", "-lf", str(pub)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, timeout=15)
        return (proc.stdout or b"").decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError):
        return "（取指纹失败，不影响使用）"


# ------------------------------------------------------------------ 一次性分发点


class _KeyHandler(BaseHTTPRequestHandler):
    """只服务**一个**端点：`<随机路径>/aoc-ops.pub?t=<一次性 token>`。

    · 只暴露公钥内容（不提供目录列表、不接受 `/`）—— 最小暴露面；
    · 路径或 token 不对一律 404（不泄露"这里确实有个服务"）；
    · 不打访问日志（免得把 token 写进控制台输出）。
    """

    server_version = "aoc-enroll/1.0"

    def log_message(self, *args: Any) -> None:  # noqa: D102  静音
        return

    def do_GET(self) -> None:  # noqa: N802
        sess: EnrollSession = self.server.session  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        query = dict(parse_qsl(parsed.query))
        if parsed.path != f"{sess.url_path}/aoc-ops.pub" or query.get("t") != sess.token:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"not found\n")
            return
        body = (sess.pubkey_text + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        sess.mark_served()

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(404)
        self.end_headers()


class EnrollSession:
    """一次纳管会话。状态机：waiting → verified → registered → checked（成功链）或 timeout/aborted/failed。"""

    def __init__(
        self,
        cfg: AppConfig,
        *,
        address: str,
        port: int,
        user: str,
        host_id: str,
        name: str,
        role: str,
        tags: list[str],
        note: str = "",
        ttl: int = 120,
    ) -> None:
        self.cfg = cfg
        self.id = "E" + secrets.token_hex(6)
        self.address = address
        self.port = int(port)
        self.user = user
        self.host_id = host_id
        self.name = name
        self.role = role
        self.tags = tags
        self.note = note
        self.ttl = max(30, int(ttl))

        self.token = secrets.token_urlsafe(24)
        self.url_path = "/" + secrets.token_urlsafe(16)
        self.pubkey_text, self.pubkey_file, self.keygen_created = public_key_text(cfg)
        self.fingerprint = key_fingerprint(self.pubkey_file)

        self.bind_host = ""
        self.bind_port = 0
        self.url = ""
        self.command = ""

        self.state = "waiting"
        self.error: dict[str, Any] | None = None
        self.served = 0
        self.started_at = now_iso(cfg)
        self.deadline = time.monotonic() + self.ttl
        self.stopped_at: str | None = None
        self.stop_reason = ""
        self.port_closed_proof = ""
        self.thread: threading.Thread | None = None
        self._httpd: ThreadingHTTPServer | None = None
        self._watchdog: threading.Thread | None = None
        self._serve_done = threading.Event()
        # ★ 关停的串行化（实测踩过：看门狗与接口线程同时调 stop()，后来者拿到空的自证）
        self._stop_lock = threading.Lock()
        self._stopped_event = threading.Event()
        self.trace: list[dict[str, Any]] = []

    # -------------------------------------------------- 生命周期

    def _pick_bind_host(self) -> str:
        """挑一个**内网**地址绑定：配置优先；否则探测"通往目标机的本机地址"。"""
        conf = str((self.cfg.raw.get("enroll") or {}).get("bind_host") or "").strip()
        if conf:
            return conf
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((self.address, self.port))   # UDP connect 不发包，只是让内核选路由
            return str(probe.getsockname()[0])
        except OSError:
            return "127.0.0.1"
        finally:
            probe.close()

    def start(self) -> None:
        bind_host = self._pick_bind_host()
        # 复用 server 的同一条红线：只允许本机/内网地址。
        # ★ 这里传 1 只是为了让 validate_bind 通过端口合法性检查 ——
        #   真正的端口由内核分配（bind port 0），校验的是**地址**而不是端口。
        bind_host, _ = validate_bind(bind_host, 1, (self.cfg.raw.get("server") or {}).get("allow_bind_prefixes"))
        httpd = ThreadingHTTPServer((bind_host, 0), _KeyHandler)
        httpd.daemon_threads = True
        httpd.session = self  # type: ignore[attr-defined]
        self._httpd = httpd
        self.bind_host = bind_host
        self.bind_port = int(httpd.server_address[1])
        self.url = f"http://{bind_host}:{self.bind_port}{self.url_path}/aoc-ops.pub"
        # ★ 这条命令是"给人在目标机控制台执行的一条命令"，不是动作 YAML 的 run ——
        #   与 write_file / 传输层加 < /dev/null 属于同一类"平台内部实现"（规范 §10.1.3）。
        self.command = (
            'mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
            f'curl -fsSL "{self.url}?t={self.token}" >> ~/.ssh/authorized_keys && '
            'chmod 600 ~/.ssh/authorized_keys; restorecon -R ~/.ssh 2>/dev/null'
        )
        self.thread = threading.Thread(target=httpd.serve_forever, name=f"enroll-{self.id}", daemon=True)
        self.thread.start()
        self._watchdog = threading.Thread(target=self._watch, name=f"enroll-wd-{self.id}", daemon=True)
        self._watchdog.start()

    def _watch(self) -> None:
        """看门狗：**用完即停**（首次成功取走）或**超时兜底**（TTL 到点）。

        为什么必须有它（规范 §10.1.2 第 3/4 条）：T3 就忘关过一次 8799 上的临时服务。
        人的手会抖、人会走开 —— 临时服务不能指望人来收尾。
        """
        while True:
            if self._serve_done.is_set():
                self.stop("公钥已被目标机取走（用完即停）")
                return
            if time.monotonic() >= self.deadline:
                self.stop("超过分发点存活时间，自动关停（超时兜底）")
                return
            time.sleep(0.2)

    def stop(self, reason: str) -> None:
        """关停分发点。**幂等且会等第一个调用者做完** —— 这一点很关键。

        实测踩到过：看门狗（用完即停）与接口线程（校验通过即关）几乎同时调 stop()，
        接口线程先返回、拿到的是**空的**关停自证，而留证里就记成"关停了但没证据"。
        所以用一把锁把两个调用者串起来：后来者阻塞等待，拿到的一定是做完之后的结论。
        """
        with self._stop_lock:
            if self._stopped_event.is_set():
                if reason and reason != self.stop_reason:
                    self.stop_reason = f"{self.stop_reason}；{reason}" if self.stop_reason else reason
                return
            httpd = self._httpd
            self._httpd = None
            if httpd is not None:
                try:
                    httpd.shutdown()
                    httpd.server_close()
                except Exception:  # noqa: BLE001  关停失败也要继续（下面会自证端口状态）
                    pass
            if self.thread is not None:
                self.thread.join(timeout=3)
            self.stopped_at = now_iso(self.cfg)
            self.stop_reason = reason
            # ★ 关停必须自证（规范 §10.1.2 第 5 条）：「我关了」不算证据
            self.port_closed_proof = self._prove_closed()
            if self.state == "waiting":
                self.state = "timeout" if "超时" in reason else self.state
            self._stopped_event.set()

    def _prove_closed(self) -> str:
        """三重自证：TCP 连接被拒 + HTTP 取公钥失败 + serve 线程已退出。

        ★ 为什么不是简单一句 connect_ex != 0：带超时的 socket 是**非阻塞语义**，
          connect_ex 会立刻返回 EWOULDBLOCK/10035（"连接正在进行"），而不是"被拒绝"。
          实测第一次就写错了 —— 拿"正在进行"当成"没有监听"，是典型的**验证自己会骗人**
          （T3 §9.12 的同族问题）。正确做法：用 select 等 connect 有结果，再读 SO_ERROR。
        """
        # ① TCP：连接必须被拒（SO_ERROR 给出 10061 WSAECONNREFUSED / 111 ECONNREFUSED）
        code: Any = "?"
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(1.5)
            rc = probe.connect_ex((self.bind_host, self.bind_port))
            if rc in (errno.EINPROGRESS, errno.EWOULDBLOCK, 10035, 10036):
                import select

                _, writable, exceptional = select.select([], [probe], [probe], 1.5)
                if writable or exceptional:
                    code = probe.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                else:
                    code = f"{rc}（connect 无结果，按异常处理）"
            else:
                code = rc
            probe.close()
        except OSError as exc:
            code = f"{type(exc).__name__}: {exc}"
        tcp_line = f"TCP {self.bind_host}:{self.bind_port} SO_ERROR={code}（0 = 还连着；10061/111 = 已被拒）"

        # ② HTTP：拿旧 URL 再取一次公钥，必须失败
        import urllib.error
        import urllib.request

        http_line = ""
        try:
            with urllib.request.urlopen(f"{self.url}?t={self.token}", timeout=2) as resp:
                http_line = f"HTTP 取公钥居然还成功（status={resp.status}）← 关停没生效！"
        except urllib.error.URLError as exc:
            http_line = f"HTTP 取公钥失败（{type(exc.reason).__name__}: {exc.reason}）= 关停生效"
        except Exception as exc:  # noqa: BLE001
            http_line = f"HTTP 取公钥失败（{type(exc).__name__}）= 关停生效"

        alive = bool(self.thread and self.thread.is_alive())
        return f"{tcp_line}｜{http_line}｜serve 线程存活={alive}"

    def mark_served(self) -> None:
        self.served += 1
        self._serve_done.set()

    def seconds_left(self) -> int:
        return max(0, int(self.deadline - time.monotonic()))

    # -------------------------------------------------- 对外表示

    def to_public(self) -> dict[str, Any]:
        return {
            "session_id": self.id,
            "state": self.state,
            "address": self.address,
            "port": self.port,
            "user": self.user,
            "host_id": self.host_id,
            "name": self.name,
            "role": self.role,
            "tags": self.tags,
            "command": self.command,
            "pubkey_fingerprint": self.fingerprint,
            "pubkey_file": str(self.pubkey_file),
            "keygen_created": self.keygen_created,
            "bind": f"{self.bind_host}:{self.bind_port}",
            "served": self.served,
            "seconds_left": self.seconds_left(),
            "ttl": self.ttl,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "stop_reason": self.stop_reason,
            "port_closed_proof": self.port_closed_proof,
            "error": self.error,
            # ★ token / 完整 URL 只在"还没被用过"时给界面；用过后只留掩码（避免它被复制传播）
            "token_masked": (self.token[:4] + "…") if self.served else "",
        }

    # -------------------------------------------------- 留证

    def evidence_markdown(self) -> str:
        return "\n".join([
            f"# 纳管会话留证 · {self.id}",
            "",
            f"- 目标机：{self.user}@{self.address}:{self.port}（登记 id={self.host_id} · role={self.role}）",
            f"- 分发点：{self.bind_host}:{self.bind_port}{self.url_path}",
            f"- 公钥：{self.pubkey_file}（{self.fingerprint}）"
            + ("　★ 本次为自动生成" if self.keygen_created else ""),
            f"- token：{self.token[:4]}…（掩码留证；完整值只在界面出现一次）",
            f"- 存活时长上限：{self.ttl}s",
            f"- 起始：{self.started_at}　关停：{self.stopped_at or '（未关停）'}",
            f"- 关停原因：{self.stop_reason or '（未关停）'}",
            f"- 关停自证：{self.port_closed_proof or '（未关停）'}",
            f"- 被取走次数：{self.served}",
            f"- 最终状态：{self.state}",
            "",
            "## 给用户在目标机执行的那一条命令",
            "",
            "```sh",
            self.command.replace(self.token, self.token[:4] + "…").replace(self.url, self.url.split("?")[0]),
            "```",
            "",
            "> 规范 §10.1.2：只绑内网 IP（过白名单，永不 0.0.0.0）、随机路径 + 一次性 token、",
            "> 用完即停 + 超时兜底、关停必须自证（端口无监听 + 线程已退出）。",
            "",
        ])


# ------------------------------------------------------------------ 六步流程


def precheck(cfg: AppConfig, *, address: str, port: int, host_id: str, force: bool) -> dict[str, Any]:
    """第 1 步：预检 —— 22 端口可达？这台机器是不是已经在清单里？"""
    dup: list[str] = []
    for h in cfg.hosts:
        if h.address == address:
            dup.append(f"IP 相同：{h.id}（{h.name}）")
        elif h.id == host_id:
            dup.append(f"id 相同：{h.id}")
    reachable = False
    detail = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    try:
        sock.connect((address, int(port)))
        reachable = True
    except OSError as exc:
        detail = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return {
        "reachable": reachable,
        "connect_detail": detail,
        "duplicate": dup,
        "duplicate_blocking": bool(dup) and not force,
    }


def verify_key(cfg: AppConfig, sess: EnrollSession) -> tuple[bool, dict[str, Any]]:
    """第 3 步：**生效校验必须真登录**（规范 §10.1.4）。

    跑 hostname / id -un / uname -r，**三条都要有非空输出**才算过；
    "文件写进去了"不算成功 —— 这是「执行完就假定成功是禁止的」在平台层的同一条规矩。
    """
    host = Host(
        id=sess.host_id, name=sess.name, address=sess.address, port=sess.port,
        user=sess.user, auth="key", identity_file=identity_path(cfg), role=sess.role,
    )
    tr = SshTransport(cfg)
    out: dict[str, Any] = {"probes": [], "identity_file": identity_path(cfg)}
    ok = True
    for argv in (["hostname"], ["id", "-un"], ["uname", "-r"]):
        try:
            res = tr.run(host, argv, timeout=8)
        except Exception as exc:  # noqa: BLE001
            out["probes"].append({"cmd": " ".join(argv), "ok": False, "stderr": f"{type(exc).__name__}: {exc}"})
            ok = False
            break
        value = (res.stdout or "").strip()
        good = res.exit_code == 0 and bool(value)
        out["probes"].append({"cmd": " ".join(argv), "ok": good, "value": value,
                              "exit_code": res.exit_code, "stderr": (res.stderr or "").strip()[:400]})
        if not good:
            ok = False
            break
    if not ok:
        last = out["probes"][-1] if out["probes"] else {}
        err = classify_ssh_failure(str(last.get("stderr") or ""), host)
        out["error"] = err.to_dict()
        out["advice"] = err.advice
    return ok, out


def register(cfg: AppConfig, sess: EnrollSession) -> dict[str, Any]:
    """第 4 步：登记进 `hosts.yaml`（写前备份 + 写后 bootstrap 校验 + 不过就回滚）。

    ★ 这里**不是** YAML round-trip，而是**文本插入**。理由：hosts.yaml 里写着大量有意义的注释
      （网络事实、靶子纪律、"已退役"历史）。用 yaml.dump 重写会把它们全部抹掉 ——
      那是把"人的知识"换成"程序的最小表示"。插入点在「已退役」标记之前，
      这样新主机和活跃主机连成一片。
    """
    if sess.role not in ROLE_WHITELIST:
        raise OpsError(
            code="PARAM_INVALID",
            reason=f"role 只允许：{'、'.join(ROLE_WHITELIST)}",
            advice="换个角色，或先把新角色加进 ROLE_WHITELIST（规范 §10.1.5）。",
        )
    path = cfg.paths.hosts
    try:
        original = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpsError(code="INTERNAL", reason=f"读不到 {path}", advice="确认 repo/hosts.yaml 存在。",
                       detail=str(exc)) from exc

    # ---- 写前备份（本地文件，走本地备份；不是 §9.1 的远端备份机制）
    backup_dir = cfg.paths.var / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_iso(cfg).replace(":", "").replace("-", "").replace("+", "_")[:15]
    backup = backup_dir / f"hosts.yaml.{stamp}.bak"
    shutil.copy2(path, backup)

    # ---- 文本插入新条目
    block = [
        "",
        f"  # ★ T4 {now_iso(cfg)[:10]} 由「主机纳管」自动登记（会话 {sess.id}）",
        f"  - id: {sess.host_id}",
        f"    name: {sess.name}",
        f"    address: {sess.address}",
        f"    port: {sess.port}",
        f"    user: {sess.user}",
        "    auth: key",
        f"    identity_file: {identity_path(cfg)}",
        f"    role: {sess.role}",
        f"    tags: [{', '.join(sess.tags)}]",
        "    note: >",
        f"      {sess.note or '由工作台「主机纳管」登记；纳管时已通过密钥登录实测校验。'}",
    ]
    lines = original.splitlines()
    idx = next((i for i, ln in enumerate(lines) if ln.startswith(RETIRED_MARKER)), len(lines))
    new_text = "\n".join(lines[:idx] + block + lines[idx:]) + "\n"
    path.write_text(new_text, encoding="utf-8")

    # ---- 写后校验：重新 bootstrap（装载自检过了才算登记成功）
    from app.server import bootstrap  # 局部导入：避免 app.server ← app.enroll 的循环导入

    try:
        bootstrap(cfg.root)
    except OpsError as exc:
        shutil.copy2(backup, path)
        return {
            "ok": False, "rolled_back": True, "backup": str(backup),
            "error": exc.to_dict(),
            "reason": f"写进 hosts.yaml 后装载自检没通过，已回滚到备份：{exc.reason}",
        }
    except Exception as exc:  # noqa: BLE001
        shutil.copy2(backup, path)
        return {
            "ok": False, "rolled_back": True, "backup": str(backup),
            "reason": f"写进 hosts.yaml 后校验抛异常，已回滚：{type(exc).__name__}: {exc}",
        }
    return {"ok": True, "rolled_back": False, "backup": str(backup), "wrote": str(path)}


def reload_hosts(cfg: AppConfig) -> int:
    """登记成功后把新主机刷进**当前进程**的配置（否则要重启服务才能用新机器）。"""
    from app.config import load as load_config  # 局部导入：避免循环

    fresh = load_config(cfg.root)
    cfg.hosts = fresh.hosts
    return len(fresh.hosts)


def write_evidence(cfg: AppConfig, sess: EnrollSession, extra: str = "") -> str:
    """把会话留证写到 var/artifacts/_enroll/<会话ID>.md（平台能力的留证落点）。"""
    out_dir = cfg.paths.artifacts / SESSION_DIR_NAME
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{sess.id}.md"
    body = sess.evidence_markdown() + ("\n" + extra if extra else "")
    path.write_text(body, encoding="utf-8")
    return str(path)


def write_state(cfg: AppConfig, sess: EnrollSession, state: dict[str, Any]) -> str:
    out_dir = cfg.paths.artifacts / SESSION_DIR_NAME
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{sess.id}.state.json"
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(path)
