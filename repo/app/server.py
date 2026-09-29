"""进程入口：装载配置与动作 → 起 HTTP 服务（只绑本机/内网）。

用法（在 repo 根目录下）：
    python -m app.server                 # 起服务，默认读 config.yaml 的 server.host/port
    python -m app.server --port 8899
    python -m app.server --check         # 只做装载自检，不起服务（CI / selftest 用）

启动失败一律打印「原因 + 建议」，不吐裸堆栈 —— 与界面错误同一个标准。

★★ T14 起：**这里就是那道闸门**（规范 §12.97.2）。
  `_handle()` 是**唯一**的请求漏斗（静态资源 / 导出通道 / `/api/**` 全从它过），
  所以鉴权只加这一处就全覆盖 —— 散落在各 handler 里必漏，而且**漏了不会报错**。
  · 免鉴权白名单**只有三处**：登录页静态资源 · `POST /api/auth/login` · `GET /api/auth/ping`。
  · ★★ `GET /api/health` **不**在白名单里 —— 它会吐主机名 / IP / `user=root` / 拓扑 / 库规模。
  · ★★ 没设过口令 ⇒ **一切 `/api/**` 全拒**（不是"没口令就放行"）；口令文件坏了 ⇒ **同样全拒**。
"""
from __future__ import annotations

import json
import mimetypes
import re
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from app import __stage__, __version__
from app.api import Api
from app.catalog import load_actions, load_map, reconcile
from app.config import AppConfig, load as load_config
from app.engine import Engine
from app.errors import OpsError
from app.recipe import RecipeRunner, load_recipes
from app.store import Store
from app.transport import SshTransport
from app.yamlload import describe_backend, yaml_available

ROOT = Path(__file__).resolve().parent.parent


def _fix_streams() -> None:
    """让启动横幅在任意控制台编码下都不会把服务打崩。

    ★ T1 期间踩过：Windows 中文控制台默认 gbk，无法编码 "✅" 这类字符，
      于是 print_check() 抛 UnicodeEncodeError → 服务启动即退出（退出码 1）。
      而这个坑只在 **stdout 被重定向** 时才暴露（直接跑控制台反而不触发），
      非常容易漏掉。
    处理策略：
      · 输出到管道/文件（非 tty）→ 统一改成 utf-8，日志可 grep、不丢字符
      · 输出到控制台（tty）      → 保持控制台本地编码，仅把无法编码的字符替换掉
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001  某些环境下 stream 不支持 reconfigure
            pass


# ------------------------------------------------------------------ HTTP 处理


#: 鉴权类错误码 ⇒ HTTP 状态码（★ T14：规范 §12.97 明确要求 401 / 429 这两个形态）。
#: ★ 刻意做成"显式小表 + 其余一律 400"：不猜、不兜底成 401 —— 兜底会让
#:   一个普通的参数错误看起来像"没登录"，把排查方向带偏。
_AUTH_HTTP_STATUS: dict[str, int] = {
    "AUTH_REQUIRED": 401,
    "AUTH_NOT_INITIALIZED": 401,
    "AUTH_STORE_BROKEN": 401,
    "AUTH_BAD_CREDENTIALS": 401,
    "AUTH_ALREADY_INITIALIZED": 401,
    "AUTH_WEAK_PASSWORD": 400,
    "AUTH_RATE_LIMITED": 429,
}


def _error_body(exc: OpsError) -> dict:
    """错误响应的**信封**。

    ★ 约定（`api.py` 的文档里一直写着）：所有 `/api/*` 响应形如
      `{"ok": true, "data": ...}` 或 `{"ok": false, "error": {...}}`。

      但 T5 收尾时发现：**异常路径**直接把 `exc.to_dict()` 当响应体发了出去 ——
      不带 `ok`、也不放在 `error` 里。而前端是按"有信封"写的：

          if (!data.ok) throw data.error || { reason: '未知错误', advice: '' };

      于是 `data.error` 是 `undefined`，**每一次服务端拒绝都被降级成界面上的「未知错误」**，
      原因与建议（这个项目最核心的对外承诺）全部丢掉。

      前端本来就按约定写的，所以修在服务端，而不是去改前端兼容两种形状。
    """
    return {"ok": False, "error": exc.to_dict()}


def make_handler(api: Api, cfg: AppConfig):
    web_root = cfg.paths.web.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"auto-ops-console/{__version__}"
        protocol_version = "HTTP/1.1"

        #: ★★ 本次请求的**请求体到底读没读过**（T14·S2 修掉的第 3 个真缺陷）。
        #: 请求体是**一次性的**：只有"还没读过"才需要 `_drain()`（理由见它的注释）。
        #: `_handle()` 在**每个请求开头**复位 —— HTTP/1.1 是长连接，同一个 Handler 实例
        #: 会连着处理多个请求；忘了复位，就会把"上一个请求读过"错带到下一个请求上，
        #: 于是"该 drain 的没 drain"⇒ RST 又回来了。两头都得立住。
        _body_read = False

        # 静默默认的逐请求日志，改为写 stderr（带时间）
        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            sys.stderr.write(f"[{self.log_date_time_string()}] {fmt % args}\n")

        # -- 工具 --
        def _json(self, status: int, payload: dict) -> None:
            raw = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _text(self, name: str, text: str, *, download: bool = False) -> None:
            """回纯文本（T2 新增）：给「结果可导出」用。

            为什么单独开一个方法而不复用 _json：
            报告是**文件**（要能另存、能直接粘进工单），必须带正确的 Content-Type 与
            Content-Disposition；塞进 JSON 再让前端解包会让大报告多一层转义，得不偿失。
            """
            raw = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            disp = "attachment" if download else "inline"
            self.send_header("Content-Disposition", f'{disp}; filename="{name}"')
            self.end_headers()
            self.wfile.write(raw)

        def _file(self, path: Path) -> None:
            if not path.is_file():
                self._json(404, _error_body(OpsError(
                    code="INTERNAL",
                    reason=f"静态资源不存在：{path.name}",
                    advice="确认 repo/web/ 下的文件完整。",
                )))
                return
            data = path.read_bytes()
            ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            if n <= 0:
                # ★ 没有请求体 —— 记成"已读"，否则 `_drain()` 会去等永远不来的字节
                self._body_read = True
                return {}
            raw = self.rfile.read(n)
            # ★ 抢在**解析之前**记账：字节已经离开 socket 了，后面 JSON 解析成不成功
            #   都不影响"它已经被读走"这个事实。
            self._body_read = True
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise OpsError(
                    code="PARAM_INVALID",
                    reason="请求体不是合法 JSON",
                    advice="前端刷新后重试。",
                    detail=str(exc),
                ) from exc
            return parsed if isinstance(parsed, dict) else {}

        # -- ★★ T14 鉴权闸门（规范 §12.97.2）--

        def _bearer(self) -> str:
            """取出 `Authorization: Bearer <token>` 里的令牌；没有就是空串。"""
            raw = self.headers.get("Authorization") or ""
            if raw[:7].lower() == "bearer ":
                return raw[7:].strip()
            return ""

        def _client(self) -> str:
            try:
                return str(self.client_address[0])
            except (IndexError, TypeError):
                return "-"

        def _store_broken_error(self, auth) -> OpsError:
            err = auth.load_error
            return OpsError(
                code="AUTH_STORE_BROKEN",
                reason=f"口令文件坏了，控制台整体拒绝服务：{err.reason if err else '未知原因'}",
                advice=(
                    "★ **不要**把口令文件删掉当作「没设过口令」—— 那等于把门打开（fail-closed）。"
                    "从备份恢复，或确认这是本机自己的文件后再手工处理；处理之前控制台一律不可用。"
                ),
                detail=(err.detail if err else ""),
            )

        def _auth_gate(self, method: str, path: str, auth, token: str) -> tuple[int, OpsError] | None:
            """返回 `None` = 放行；返回 `(状态码, 错误)` = 拒。

            ★ 拒的时候**必须给出"该去哪儿办"**（§12.99.3 的同族教训）——
              只说"不行"的错误，对用户等于没说。
            """
            # ── 免鉴权白名单（**最小**，§12.97.2 只列这三处）──────────────
            if method == "GET" and path == "/api/auth/ping":
                return None
            if method == "POST" and path == "/api/auth/login":
                # ★ 没设过口令时**也放进来**：让 login 给出「先去设置口令」这条可执行建议，
                #   比在闸门这里拦掉、只剩一句 401 有用得多（§12.99.3 的同一条理由）。
                return None
            if method == "POST" and path == "/api/auth/setup":
                if auth.setup_allowed:
                    return None
                if auth.store_broken:
                    return 401, self._store_broken_error(auth)
                return 401, OpsError(
                    code="AUTH_ALREADY_INITIALIZED",
                    reason="本机已经设过口令 —— 初始化接口**刻意**不允许重复调用",
                    advice=(
                        "先登录（`POST /api/auth/login`），再走改口令流程（`POST /api/auth/password`）。"
                        "★ 若确实忘了口令，请在管理机上**人工**处理 `var/auth.json` —— "
                        "那属于人为介入，不是控制台自己开的口子。"
                    ),
                )

            # ── 三道拒绝，顺序有意（先"整体不可用"，再"没配"，最后"没令牌"）──
            if auth.store_broken:
                return 401, self._store_broken_error(auth)
            if not auth.configured:
                return 401, OpsError(
                    code="AUTH_NOT_INITIALIZED",
                    reason="本机还没设过口令，控制台现在是「全拒」状态",
                    advice="在界面上完成「设置口令」：`POST /api/auth/setup`。★ 红线 11：没口令就不许用。",
                )
            if not auth.check(token):
                return 401, OpsError(
                    code="AUTH_REQUIRED",
                    reason="这个请求没带有效令牌",
                    advice=(
                        "在控制台界面上登录；命令行工具先把令牌放进 `Authorization: Bearer <token>`。"
                        "★ 令牌只在内存里，服务重启后会全体失效 —— 重新登录即可。"
                    ),
                )
            return None

        def _drain(self) -> None:
            """在**回错误之前**先把手里的请求体读掉（读完丢掉）。

            ★★ 为什么必须 —— 这条是真跑抓出来的，不是想出来的：
              如果服务端**没读请求体**就回响应并关连接，接收缓冲里还剩着没被读走的字节，
              Windows 会给客户端一个 **RST**，客户端看到的是
              `ConnectionAbortedError: [WinError 10053]`，**而不是我们的 401 信封**。
              ⇒ 「拒绝也要带完整信封」这条纪律（T5 的教训），**不 drain 就守不住**。
            ★ 复现条件：`POST /api/auth/setup` 在"已经设过口令"时被闸门拒 ——
              离线门没复现，**完整门复现了**（机器更忙，客户端还没来得及写完 body）。
              这类时序问题只有"多跑一遍"才看得见。
            ★ 上限 1MB：恶意的超长 body 不许把内存吃掉（这里只是丢弃，不解析）。

            ★★ 判据是「**我到底读没读过**」，**不是**「`Content-Length` 说有多少」——
              第一版就是拿 `Content-Length` 当"还剩多少"，于是在 `dispatch` **已经读过**
              请求体的路径上（例如 `POST /api/auth/login` 返 401）又去
              `rfile.read(n)` 等**永远不会再来**的字节 ⇒ 服务端在那里挂死，
              客户端只看到自己的超时（`TimeoutError: timed out`）；
              ★ 它红的是离线门 ⑿b（那条断言**没崩**），**不是**任何一条业务断言 ——
              "一条也不许用『反正业务断言是绿的』解释过去"。见 `_body_read`。
            """
            if self._body_read:
                return
            self._body_read = True   # ★ 只 drain 一次：这次读不掉，就没有第二次机会
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                return
            if n <= 0:
                return
            try:
                self.rfile.read(min(n, 1024 * 1024))
            except OSError:
                pass

        # -- 路由 --
        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def _handle(self, method: str) -> None:
            # ★★ 每个请求开头复位（见 `_body_read` 的注释）：长连接上同一实例会处理多个请求
            self._body_read = False
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            try:
                # ① 首页与静态资源：**免鉴权**（登录页自己要能加载）
                if path in ("/", "/index.html"):
                    self._file(web_root / "index.html")
                    return
                if path.startswith("/static/"):
                    rel = path[len("/static/"):].lstrip("/")
                    target = (web_root / rel).resolve()
                    if not str(target).startswith(str(web_root)):
                        raise OpsError(
                            code="INTERNAL",
                            reason="拒绝越权访问静态资源路径",
                            advice="路径里不允许出现 .. 等跳出 web 目录的片段。",
                        )
                    self._file(target)
                    return

                # ② ★★ 鉴权闸门（唯一漏斗；规范 §12.97.2）
                #   ★★ 位置是**有讲究的**：必须在**所有** `/api/**` 之前 ——
                #      **包括下面那两条导出通道**。
                #      ★ 第一版把闸门放在导出通道**之后**，那是个真洞：
                #        `/api/tasks/<id>/export` 导出的是**目标机原始输出全文**，
                #        它当时**不需要任何令牌**就能下载。
                #      ★ 抓到它的不是人眼，是自检断言 ⑾a（它坚持"导出通道也必须 401"）。
                token = self._bearer()
                client = self._client()
                deny = self._auth_gate(method, path, api.auth, token)
                if deny is not None:
                    status_code, exc = deny
                    self._drain()  # ★ 先把请求体读掉，否则客户端看不到这个 401（见 _drain 注释）
                    self._json(status_code, _error_body(exc))
                    return

                # ③ 任务报告导出（纯文本下载，不走 JSON 通道；★ 已过闸）
                #   形如 /api/tasks/<任务ID>/export?format=txt|md&download=1
                if method == "GET":
                    m = re.fullmatch(r"/api/tasks/([^/]+)/export", path)
                    if m:
                        name, text = api.export_task(m.group(1), query.get("format", "txt"))
                        self._text(name, text, download=query.get("download") == "1")
                        return
                    # ★ T4 新增：体检报告导出（同样走纯文本通道，不经过 JSON）
                    #   形如 /api/checkup/<任务ID>/export?format=md|txt&download=1
                    m = re.fullmatch(r"/api/checkup/([^/]+)/export", path)
                    if m:
                        name, text = api.checkup_export(m.group(1), query.get("format", "md"))
                        self._text(name, text, download=query.get("download") == "1")
                        return
                    # ★★ T15 新增：**会话报告**导出（T15 · §12.104.3）
                    #   形如 /api/ai/reports/<会话ID>/export?format=md&download=1
                    #   ★★ 位置与上面两条**逐字一样**：都在闸门（②）**之后** ——
                    #      报告是"更长的原始输出"，放错位置就是 T14 缺陷 #1 重演。
                    #      ★ 断言 Ⓒ 看着这一条（不带令牌必须 401）。
                    m = re.fullmatch(r"/api/ai/reports/([^/]+)/export", path)
                    if m:
                        name, text = api.export_session_report(
                            m.group(1), query.get("format", "md")
                        )
                        self._text(name, text, download=query.get("download") == "1")
                        return

                # ④ 其余全部走 dispatch（AI 面也在里面，铁律 8）
                status, payload = api.dispatch(
                    method, path, query,
                    self._body() if method == "POST" else {},
                    # ★ 只在这里把令牌与来源 IP 交给接口层（AI 面永远拿不到它）
                    {"token": token, "client": client},
                )
                self._json(status, payload)
            except OpsError as exc:
                # ★ 同上：错误响应之前先把请求体读掉（否则 401/400 在传输层变成连接中断）
                self._drain()
                # ★ T14：鉴权类错误有自己的状态码（401 / 429）；其余**仍然** 400 ——
                #   不把普通错误兜底成 401，否则"没登录"会把排查方向带偏。
                self._json(_AUTH_HTTP_STATUS.get(exc.code, 400), _error_body(exc))
            except Exception as exc:  # noqa: BLE001
                self._json(500, _error_body(OpsError(
                    code="INTERNAL",
                    reason="控制台内部错误",
                    advice="这是控制台自身的缺陷，不是目标机的问题。请记录下面的详情。",
                    detail=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
                    context={"path": path, "method": method},
                )))

    return Handler


# ------------------------------------------------------------------ 装载


def bootstrap(root: Path) -> tuple[AppConfig, dict, dict, Store, Engine, Api]:
    if not yaml_available():
        raise OpsError(
            code="CONFIG_INVALID",
            reason="缺少 YAML 解析器，无法装载配置与动作",
            advice=describe_backend()["vendor_dir"] and (
                "python -m pip install --target repo\\vendor pyyaml"
                "（或部署到 RHEL 时 sudo dnf install -y python3-pyyaml）"
            ),
        )

    cfg = load_config(root)
    actions = load_actions(cfg.paths.actions)
    map_data = load_map(cfg.paths.map)
    store = Store(cfg)
    store.init()
    engine = Engine(cfg, actions, store)
    # ── T5：配方（编排层）────────────────────────────────────────
    # ★ T7·v1.8 行为变更（规范 §12.17）：配方**不再"一份坏就拒绝启动"** ——
    #   不合格的那份不装载、其余照装，并把"哪一份、哪一行、哪个键"如实记录下来。
    #   理由：用户自己写一份新配方时手滑，如果整个控制台起不来，他**连看错误的界面都没有**。
    #   ★ 校验一步没少（重载接口走的也是这一套）；而"我们自己的配方必须全部装载成功"
    #     由 `--check`（下面的退出码）与自检的断言守着 —— 交付物上仍然是会红的。
    recipes, load_report = load_recipes(cfg.paths.catalog / "recipes", actions)
    runner = RecipeRunner(cfg, actions, engine, store, recipes, load_report)
    api = Api(cfg, actions, map_data, store, engine, runner)
    # ── T12：AI 助手基座（五·AI 助手；规范 §12.74）────────────────────
    # ★ 把 `api.dispatch` **这个函数本身**交给 AI 侧 —— 于是"AI 与点击同权"不是一句承诺，
    #   而是**唯一可用的通道**：AI 侧拿不到引擎、拿不到传输层（自检断言 🄌 静态验证这一点）。
    # ★ 装载失败**不拖垮控制台**：AI 是加法（总纲 §11.1），点界面那条路必须照常能用。
    if bool(((cfg.raw or {}).get("ai") or {}).get("enabled", True)):
        try:
            from app.ai.service import AiService

            # ★★ T15·S3：给 AI 侧的**只有两个只读回调**（列任务 / 取任务）——
            #    ★ 不把 `store`、`engine`、`transport` 里的任何一个对象递过去
            #      （T12 的纪律：AI 侧拿得到的只有"函数"，拿不到承重墙；断言 🄌 的家族）。
            api.ai = AiService(
                cfg, actions, api.dispatch,
                task_lister=store.list_tasks,
                task_getter=store.get_task,
            )
        except Exception as exc:  # noqa: BLE001 - 兜底：AI 坏了也不许影响主路径
            print(f"[warn] AI 助手装载失败（点界面那条路不受影响）：{exc}")
    return cfg, actions, map_data, store, engine, api


def print_check(cfg: AppConfig, actions: dict, map_data: dict, store: Store,
                load_report=None) -> None:
    cov = reconcile(map_data, actions)
    transport = SshTransport(cfg)
    _, control_note = cfg.ssh.effective_control_master()
    yb = describe_backend()
    rem = (cfg.raw.get("ssh", {}) or {}).get("remote_env", {"LC_ALL": "C", "LANG": "C"})

    print("=" * 68)
    print(f"  auto-ops-console · 装载自检（阶段 {__stage__} / 版本 {__version__}）")
    print("=" * 68)
    print(f"  根目录        : {cfg.root}")
    print(f"  Python        : {sys.version.split()[0]}  ({sys.executable})")
    print(f"  YAML 解析器    : {yb['backend'] or '未找到'}"
          + (f" (PyYAML {yb['version']})" if yb["version"] else ""))
    print(f"  监听地址      : {cfg.server['host']}:{cfg.server['port']}  "
          f"{'✅ 本机/内网（符合红线）' if cfg.server['host'] != '0.0.0.0' else '❌ 违反红线'}")
    print(f"  业务时区      : {cfg.timezone}")
    print(f"  ssh 客户端     : {transport.binary()}")
    print(f"  主机指纹策略   : {cfg.ssh.strict_host_key}   连接复用: {control_note}")
    print(f"  远端 locale    : {' '.join(f'{k}={v}' for k, v in rem.items())}（防字段名本地化导致静默取空）")
    print(f"  数据库         : {store.stats()['db']}  任务数 {store.stats()['tasks_total']}")
    print("-" * 68)
    print(f"  动作           : {len(actions)} 个  ->  {', '.join(sorted(actions))}")
    print(f"  覆盖地图       : 已实现 {cov['done']}/{cov['total']}（{cov['rate']}%）"
          f" ｜ P0 {cov['p0_done']}/{cov['p0_total']}（{cov['p0_rate']}%）")
    for d, v in sorted(cov["by_domain"].items()):
        print(f"      · 域 {d} {v['name']}：{v['done']}/{v['total']}（{v['rate']}%）")
    if cov["missing"]:
        print(f"  缺口（{len(cov['missing'])} 项，属正常，是按阶段预留的）：")
        for m in cov["missing"]:
            print(f"      · {m['id']:22s} {m['priority']:3s} 计划 {m['stage'] or '-':3s} {m['label']}")
    print("-" * 68)
    print("  主机清单：")
    for h in cfg.hosts:
        print(f"      · {h.id:12s} {h.name}  {h.target}:{h.port}  [{h.role}]")
    # ── T7：配方装载结果（规范 §12.17「不许静默少装载」）────────────
    if load_report is not None:
        print("-" * 68)
        print(f"  配方           : {load_report.summary()}")
        for f in load_report.failed:
            print(f"      ❌ {f.get('file')}（未装载）")
            for e in (f.get("errors") or [])[:6]:
                print(f"         · {e}")


# ------------------------------------------------------------------ 入口


def main(argv: list[str] | None = None) -> int:
    _fix_streams()
    argv = list(sys.argv[1:] if argv is None else argv)
    root = ROOT
    check_only = "--check" in argv
    port_override: int | None = None

    if "--root" in argv:
        root = Path(argv[argv.index("--root") + 1]).resolve()
    if "--port" in argv:
        try:
            port_override = int(argv[argv.index("--port") + 1])
        except (IndexError, ValueError):
            print("❌ --port 需要一个整数", file=sys.stderr)
            return 2

    try:
        cfg, actions, map_data, store, _engine, api = bootstrap(root)
    except OpsError as exc:
        print("❌ 装载失败", file=sys.stderr)
        print(f"   原因：{exc.reason}", file=sys.stderr)
        if exc.advice:
            print(f"   建议：{exc.advice}", file=sys.stderr)
        if exc.detail:
            print("   ---- 详情 ----", file=sys.stderr)
            for line in exc.detail.splitlines():
                print(f"   {line}", file=sys.stderr)
        return 2

    if port_override:
        cfg.server["port"] = port_override

    print_check(cfg, actions, map_data, store, api.runner.load_report if api.runner else None)

    # ★ T14：开机就把"门的状态"说清楚 —— 不许静默。
    #   （这一段是给**管理机上看启动横幅的人**看的，不是给界面的。）
    _a = api.auth
    if _a.store_broken:
        print(f"  ⛔ 鉴权          : 口令文件坏了 ⇒ **一切 /api/** 全拒**（fail-closed）："
              f"{(_a.load_error.reason if _a.load_error else '')}")
    elif not _a.configured:
        print("  ⛔ 鉴权          : **还没设过口令** ⇒ 一切 `/api/**` 全拒（红线 11）——"
              " 打开界面完成「设置口令」即可")
    else:
        print(f"  ✅ 鉴权          : 已启用（PBKDF2 · 令牌只在内存 · TTL {_a.token_ttl_sec}s ·"
              f" 密码文件 {_a.path.name}）")
        if _a.setup_allowed:
            print("  ⚠️  鉴权          : 口令文件不存在却报已配置 —— 这是不应出现的状态，请记录并上报")

    if check_only:
        # ★ T7（规范 §12.17）：**服务照起，但 `--check` 必须红**。
        #   两者刻意不同：用户写坏一份新配方不该让控制台起不来（连界面都看不到），
        #   而"我们仓库里的配方是否全部合法"是**交付物质量**的问题，
        #   必须在 CI / 自检 / 交接这条线上被抓住 —— 否则它会悄悄烂掉。
        bad = api.runner.load_report if api.runner else None
        if bad is not None and not bad.ok:
            print(f"\n❌ 装载自检未通过：有 {len(bad.failed)} 份配方没装进来（见上面逐条列出的原因）")
            print("   注意：服务**仍然可以启动**（起不来就看不到界面里的错误了）；"
                  "但在仓库交付物里，配方必须全部合法。")
            return 2
        print("\n✅ 装载自检通过（未启动服务）")
        return 0

    host, port = cfg.server["host"], cfg.server["port"]
    handler = make_handler(api, cfg)
    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError as exc:
        err = OpsError(
            code="CONFIG_INVALID",
            reason=f"无法监听 {host}:{port}（{exc.strerror or exc}）",
            advice=(
                "端口被占用时换一个：python -m app.server --port 8899；"
                "或先关掉占用的进程。"
            ),
        )
        print(f"\n❌ 启动失败\n   原因：{err.reason}\n   建议：{err.advice}", file=sys.stderr)
        return 2

    print("-" * 68)
    print(f"  ✅ 服务已启动：http://{host}:{port}/")
    print("  · 只监听本机/内网，不对外暴露（项目安全红线）")
    print("  · 按 Ctrl+C 停止")
    print("=" * 68)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    # 允许 `python app\server.py` 与 `python -m app.server` 两种跑法
    if __package__ in (None, ""):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    raise SystemExit(main())
