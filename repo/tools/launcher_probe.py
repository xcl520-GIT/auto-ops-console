"""T18 · 启动器探针 —— 拿**交付物真身**做判据，全程跑在**临时端口 + 临时目录**上。

★ 为什么要有它
  启动器跑在 `repo\\` 之外，两道门（`tools\\selftest.py`）扫不到它 ⇒ 它的行为此前
  **一条判据都没有**，六件事全靠"人肉试过"。这个探针就是把它拉进可证伪面。

★ 为什么必须用临时端口
  用户此刻正在用的控制台就在 8787 上。任何"占住端口再测认不认人"的判据，只要用的是
  真端口，就会动到它 —— 撞本项目硬口径「**判据不许伤到环境**」（T17 §一.4 第 4 条）。

★ 断言的是**不变量**，不是环境事实
  例：不假设"这台机器上控制台正在跑"，只断言"退出码与 state 自洽"、"JSON 只有一行"、
  "端口不是 8787 时，人话里就不许再出现 8787"。

用法：
    python tools\\launcher_probe.py           # 人话 + 结论
    python tools\\launcher_probe.py --json    # 一行 JSON（给自检读）

退出码：0 = 全部符合预期 · 1 = 有不符合预期的项 · 2 = 连启动器都找不到
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# ★ 规范 §12.134：命令行工具自己 pin 住 stdout 编码（否则结论里的 `⇒` 在 cp936 下崩）。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[2]          # 项目根
REPO = ROOT / "repo"
EXE = ROOT / "工具" / "AutoOpsConsole.exe"
DEFAULT_PORT = 8787

# ★★ T18 · S8：`--json` 的**合同** —— 每一个入口都必须带这几个键（没有的给 null）。
#   为什么把它写死在这里：脚本是按"键一定在"来取值的。谁悄悄改掉半个键，
#   这里必须红 —— 而不是等某个脚本在半夜 `KeyError`。
CORE_KEYS = {"ok", "action", "port", "port_source", "state", "pid", "version", "stage",
             "disk_version", "disk_stage", "configured", "browser", "error", "reason", "exit"}

# ★ 临时 root：**不拷 `var\`** —— 那个实例会自己建一个**自己的**库。
#   （`repo\.gitignore` 里 `var/` 是运行期产物，不进 Git，本来也不该被拷进去当"初始状态"。）
_SKIP_TOP = {"var", ".git", "__pycache__"}


# --------------------------------------------------------------------- 小工具

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _Quiet(socketserver.BaseRequestHandler):
    def handle(self) -> None:                       # 占位监听器：只接受连接，什么都不回
        try:
            self.request.settimeout(0.3)
            self.request.recv(64)
        except Exception:
            pass


def start_placeholder(port: int):
    """起一个**占住端口的陌生程序**（既不认 auth/ping 也不认 health）。

    ★ 它就是我们用来验"认人"的那只『别人的程序』—— 而"不杀它"是纪律，所以要能被复核。
    """
    srv = socketserver.TCPServer(("127.0.0.1", port), _Quiet, bind_and_activate=False)
    srv.allow_reuse_address = True
    srv.server_bind()
    srv.server_activate()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


RC_TIMEOUT = 124        # ★ 探针自己的哨兵值：**"启动器把调用者挂住了"**（不是"命令失败"）


def run_launcher(args: list[str], env_extra: dict | None = None, timeout: int = 90,
                 cwd: str | None = None):
    """跑一次启动器真身，把 stdout/stderr **用管道收回来**。

    ★★ T18 · S8：这里**必须**用 `Popen` 而不是 `subprocess.run(timeout=...)`。
      现场：`start` 拉起的 `cmd.exe` 会**继承**启动器的 stdout，并一直活到 python 退出
      ⇒ 调用者的管道**永远等不到 EOF**。`subprocess.run` 在超时后还会**再 `communicate()` 一次**
      （它要回收管道）⇒ 于是它**自己也会挂住**，超时形同虚设。
      ⇒ 超时之后只做一件事：`kill()` 掉启动器，然后**如实报超时**（哨兵 124）。
    """
    env = dict(os.environ)
    env["AOC_ROOT"] = str(ROOT)                     # ★ 我们不假设它放在哪 —— 点名给它
    env.pop("AOC_PORT", None)
    env.pop("AOC_LOGDIR", None)
    env.pop("AOC_SHORTCUT_DIR", None)
    if env_extra:
        for k, v in env_extra.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
    t0 = time.time()
    # ★ `cwd` 可指定 —— 现场（F/G）：`--logdir --json` 那条边界输入会让启动器在 **cwd 下**
    #   `CreateDirectory("--json")`；不换 cwd，探针就往**仓库里**扔了个目录。
    proc = subprocess.Popen([str(EXE)] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", env=env, cwd=cwd)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, (out or ""), (err or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return RC_TIMEOUT, "", "PROBE_TIMEOUT", time.time() - t0


def make_temp_root(base: Path) -> Path:
    """把 `repo\\`（**不含 `var\\`**）整份拷到 `base\\repo\\`，返回 `base`（= 给 `AOC_ROOT`）。

    ★★ 为什么必须这么干（S8 收工时想到的那一条）：
    **「端口可注入」≠「环境可隔离」** —— 在临时端口上真起一个实例，它的 cwd 仍是 `repo\\`，
    `app\\server.py` 的 ROOT 就是 `repo\\` ⇒ 它会和**用户此刻正在用的那个控制台共用
    `repo\\var\\ops.db`**（SQLite）。那等于**拿生产库做测试** —— 撞「判据不许伤到环境」。
    ★ 而 `app\\server.py` 认不认 `--root` 都无所谓：`-m app.server` 的 **cwd 落在哪，
      ROOT 就取哪一份** ⇒ 拷一份 root 就够，**不必碰启动器**（少一处改动 = 少一处风险）。
    """
    dst_repo = base / "repo"
    if dst_repo.exists():
        shutil.rmtree(dst_repo)
    dst_repo.mkdir(parents=True)
    for item in sorted(REPO.iterdir()):
        if item.name in _SKIP_TOP:
            continue
        if item.is_dir():
            shutil.copytree(item, dst_repo / item.name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(item, dst_repo / item.name)
    (dst_repo / "var").mkdir(exist_ok=True)
    return base


def tree_sha256(d: Path) -> str:
    """目录内容指纹 —— 用来证明"临时 root 里的代码与仓库里的是**同一份**"。"""
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            h.update(str(p.relative_to(d)).replace("\\", "/").encode("utf-8"))
            h.update(b"\0")
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def file_sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if Path(p).is_file() else "(缺)"


def listener_pids(port: int) -> list[int]:
    """纯 netstat 解析（不依赖 PowerShell / WMI）—— 探针自己也要能看住"谁在占着"。"""
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=20).stdout
    except Exception:
        return []
    pids = []
    for line in (out or "").splitlines():
        l = line.strip()
        if not l.upper().startswith("TCP") or ":%d " % port not in l:
            continue
        if "LISTENING" not in l.upper():
            continue
        parts = l.split()
        if len(parts) >= 5 and parts[-1].isdigit() and int(parts[-1]) > 0:
            pids.append(int(parts[-1]))
    return sorted(set(pids))


def kill_pids(pids: list[int]) -> None:
    for pid in pids:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=20)
        except Exception:
            pass


def one_json_line(out: str):
    """★ JSON 模式的定义：stdout 上**恰好一行**、且是合法 JSON。"""
    lines = [ln for ln in out.replace("\r\n", "\n").split("\n") if ln.strip()]
    if len(lines) != 1:
        return None
    try:
        return json.loads(lines[0])
    except Exception:
        return None


# --------------------------------------------------------------------- 判据

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, bool(ok), detail))


def _make_foreign_lnk(path: str) -> bool:
    """在同一个目录里造一个**别人建的** .lnk（指向记事本）——
    用来验「撤销只删自己建的」。★ 借 WScript.Shell 走 COM，不装任何东西。"""
    ps = ("$s=New-Object -ComObject WScript.Shell;"
          "$l=$s.CreateShortcut('%s');"
          "$l.TargetPath=$env:SystemRoot+'\\notepad.exe';$l.Save()" % path.replace("'", "''"))
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    return Path(path).is_file()


def probe_shortcut() -> None:
    """⑤ 交付形态：**可建 / 可撤 / 可审计**，且撤销**只删自己建的**。

    ★ 落点全程在临时目录（`--shortcut-dir`）—— 判据**不许**往用户真桌面上写东西。
    """
    with tempfile.TemporaryDirectory(prefix="aoc-t18-lnk-") as td:
        rc, out, _e, _dt = run_launcher(["shortcut", "add", "--shortcut-dir", td])
        mine = [p for p in Path(td).glob("*.lnk")]
        check("⑤-a `shortcut add` 退出码 0", rc == 0, f"rc={rc}")
        check("⑤-b 真的建出两个 .lnk", len(mine) == 2, f"数到 {len(mine)} 个")
        check("⑤-c 结论里说清「读回一致」", "读回一致" in out,
              out.strip().replace("\n", " / ")[:160])

        rc, out, _e, _dt = run_launcher(["shortcut", "list", "--shortcut-dir", td])
        check("⑤-d `shortcut list` 退出码 0（默认子命令非破坏）", rc == 0, f"rc={rc}")
        check("⑤-e 审计读回来的是**我们的产物**路径", "AutoOpsConsole.exe" in out,
              out.strip().replace("\n", " / ")[:200])

        # ★★ 夹具必须造在**我们自己的落点之一**上，否则那条分支根本走不到。
        #   真正的风险场景不是"目录里另有一个别人的 .lnk"（我们压根不看它），
        #   而是"**我们那个位置上的 .lnk 已经不是我们的了**"（被人换过 / 有同名残留）
        #   ⇒ 那一颗才是"撤销会不会误删别人的东西"的考场。
        hijacked = str(Path(td) / "auto-ops-console-menu.lnk")
        made = _make_foreign_lnk(hijacked)
        check("⑤-f 测试夹具就位：**我们的第二个落点**已被换成别人的（指向记事本）",
              made, hijacked)

        rc, out, _e, _dt = run_launcher(["shortcut", "remove", "--shortcut-dir", td])
        check("⑤-g `shortcut remove` 退出码 0", rc == 0, f"rc={rc}")
        ours = Path(td) / "auto-ops-console.lnk"
        check("⑤-h ★★ 我们建的那个**已删**", not ours.exists(),
              f"auto-ops-console.lnk 还在={ours.exists()}")
        check("⑤-i ★★★ 落点上那个**别人的** .lnk **还在**（撤销只删自己建的）",
              Path(hijacked).is_file(),
              f"它还在={Path(hijacked).is_file()}")
        # ★ detail 一律是**字符串** —— 现场（S5）：这里原来放了个 list，
        #   打印那行时 `str + list` 抛 TypeError ⇒ **探针在 ⑤-j 处直接崩、stdout 戛然而止**
        #   （"结论自己把自己弄没了"，属"报告不许说假话"那一族）。
        hit = [ln.strip() for ln in out.splitlines() if "不是我们建的" in ln or "不动它" in ln]
        check("⑤-j 结论里点明「不是我们建的，不动它」", bool(hit),
              hit[0][:120] if hit else "结论里没有这句话")


def probe_version_consistency() -> None:
    """③ 版本一致性 + 认人只在**一道口子**上（stop / restart 不许绕过它）。

    ★★ 制造"磁盘与跑着的不一致"时**绝不去改真仓库的 `app\\__init__.py`**
       （`repo\\app` 一行不改是本话题的硬边界）—— 改用一个**临时根**：里面只放
       `repo\\app\\{server.py,__init__.py}`，版本写一个不可能的值 ⇒ 启动器读到的
       「磁盘版本」必然与跑着那个进程不同。
    """
    # ---- (1) 版本一致性 ----
    with tempfile.TemporaryDirectory(prefix="aoc-t18-fakeroot-") as td:
        appdir = Path(td) / "repo" / "app"
        appdir.mkdir(parents=True)
        (appdir / "server.py").write_text("# fake root for the probe\n", encoding="utf-8")
        (appdir / "__init__.py").write_text('__version__ = "9.9.9"\n__stage__ = "T99"\n',
                                            encoding="utf-8")
        rc_real, out_real, _e, _dt = run_launcher(["status", "--json"])
        running = False
        try:
            js_real = json.loads([l for l in out_real.splitlines() if l.strip()][0])
            running = js_real.get("state") in ("running", "running_stale")
        except Exception:
            running = False
        rc, out, _e, _dt = run_launcher(["status", "--json"], env_extra={"AOC_ROOT": td})
        js = one_json_line(out)
        if not running:
            check("③-a 版本一致性（★ **跳过**：8787 上没有真控制台在跑 ⇒ 这一条这次验不到）",
                  True, "跳过 ≠ 通过")
        else:
            check("③-a 磁盘版本被读出来了（fake root 里写的 9.9.9）",
                  js is not None and js.get("disk_version") == "9.9.9",
                  f"disk_version={js.get('disk_version') if js else None}")
            check("③-b ★★ 磁盘 ≠ 跑着的 ⇒ state=running_stale", js is not None and js.get("state") == "running_stale",
                  f"state={js.get('state') if js else None}")
            check("③-c ★★ 退出码 5（脚本能据此判「你看到的可能是旧进程」）", rc == 5, f"rc={rc}")
            check("③-d 跑着那一版的 version 仍然报出来（不是用它顶替磁盘版本）",
                  js is not None and bool(js.get("version")) and js.get("version") != "9.9.9",
                  f"version={js.get('version') if js else None}")

    # ---- (2) stop / restart 不许绕过认人 ----
    port = free_port()
    srv = start_placeholder(port)
    try:
        rc, out, _e, _dt = run_launcher(["stop", "--port", str(port)])
        check("③-e ★★ `stop` 遇到**别的程序** ⇒ 拒绝动手（退出码 3）", rc == 3, f"rc={rc}")
        check("③-f 拒绝话里点明「不是我们的控制台」", "不是我们的控制台" in out,
              out.strip().replace("\n", " / ")[:160])
        alive1 = _port_alive(port)
        check("③-g ★★ 拒绝之后那个程序**还活着**", alive1,
              "端口 %d 可连=%s（★ detail 不许写「失败话」—— 绿行里那句话读起来像红）" % (port, alive1))

        rc, out, _e, _dt = run_launcher(["restart", "--port", str(port)])
        check("③-h ★★★ `restart` 走**同一道**认人（它不许是绕过它的后门）⇒ 退出码 3", rc == 3, f"rc={rc}")
        alive2 = _port_alive(port)
        check("③-i ★★★ `restart` 之后那个程序**也还活着**（S0 读到的口径不一致，到此被证伪）",
              alive2, "端口 %d 可连=%s" % (port, alive2))
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass


def _port_alive(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except Exception:
        return False


def probe_freshness() -> None:
    """⓪ 产物新鲜度：**改了源码别忘了重编**。

    ★ 为什么要有这一条（现场）：S3 真跑时探针 A 组连红两条，根因不是代码错，
      而是我改完 `.cs` **忘了重编**（磁盘上的 exe 是旧的）——
      **"改了源码" ≠ "产物跟着变"，而此前没有任何判据看住它。**
    ★ 这是一条**形态判据**（比 mtime，不比行为），如实标注：它只防"忘了重编"这一类，
      防不住"拿旧源码编了个新的"。行为等价由 ① ~ ④ 那几组来管。
    """
    src = ROOT / "工具" / "launcher" / "AutoOpsConsole.cs"
    if not src.is_file():
        check("⓪ 源码存在", False, f"找不到 {src}")
        return
    check("⓪ ★ 产物不比源码旧（改了源码要记得重编）",
          EXE.stat().st_mtime >= src.stat().st_mtime,
          "exe mtime=%s < cs mtime=%s" % (int(EXE.stat().st_mtime), int(src.stat().st_mtime)))


def probe_status_not_running() -> None:
    """情形 ①：没在跑 —— 退出码 4 ＋ `state=not_running` ＋ 人话里是**这个**端口，不是 8787。"""
    port = free_port()
    rc, out, _err, _dt = run_launcher(["status", "--port", str(port)])
    check("①-a 没在跑 ⇒ 退出码 4", rc == 4, f"rc={rc}")
    check("①-b 人话里回显的是注入的那个端口", str(port) in out, f"找 {port}")
    # ★ 这条是 T18·S2 抓到的那条真缺陷的**回归判据**：注入之后人话里不许再提 8787。
    check("①-c ★ 注入之后人话里不许再出现 8787", str(DEFAULT_PORT) not in out,
          "命中 8787" if str(DEFAULT_PORT) in out else "干净")

    rc, out, _err, _dt = run_launcher(["status", "--port", str(port), "--json"])
    js = one_json_line(out)
    check("①-d --json 恰好一行且可解析", js is not None, f"段数/内容异常：{out[:120]!r}")
    if js:
        check("①-e JSON 的退出码与进程退出码一致", js.get("exit") == rc, f"json.exit={js.get('exit')} rc={rc}")
        check("①-f state=not_running 与 rc=4 自洽", js.get("state") == "not_running" and rc == 4,
              f"state={js.get('state')} rc={rc}")
        check("①-g port_source=injected", js.get("port_source") == "injected", str(js.get("port_source")))
        check("①-h JSON 里回显的端口就是注入的那个", js.get("port") == port, str(js.get("port")))


def probe_status_default() -> None:
    """情形 ②：默认端口 —— ★ 不假设它一定在跑，只断言"退出码与 state 自洽"。"""
    rc, out, _err, _dt = run_launcher(["status"])
    rc2, out2, _err2, _dt2 = run_launcher(["status", "--json"])
    js = one_json_line(out2)
    check("②-a 默认端口：--json 一行可解析", js is not None, f"{out2[:120]!r}")
    if not js:
        return
    ok_self = ((rc == 0 and js.get("state") == "running")
               or (rc == 4 and js.get("state") == "not_running")
               or (rc == 3 and js.get("state") in ("ours_but_old", "not_ours")))
    check("②-b ★ 退出码与 state 自洽（不假设环境）", ok_self,
          f"rc={rc} state={js.get('state')}")
    check("②-c 默认端口时 port_source=default", js.get("port_source") == "default",
          str(js.get("port_source")))
    check("②-d 人话里的端口是 8787", str(DEFAULT_PORT) in out, "缺")
    if js.get("state") == "running":
        check("②-e 真在跑时：version/stage 非空（★ 这就是「跑的是哪一版」）",
              bool(js.get("version")) and bool(js.get("stage")),
              f"version={js.get('version')} stage={js.get('stage')}")
        check("②-f 真在跑时：pid 非空", bool(js.get("pid")), str(js.get("pid")))


def probe_not_ours() -> None:
    """情形 ④：端口被**别的程序**占着 ⇒ 拒绝动手 ＋ **不杀它**。"""
    port = free_port()
    srv = start_placeholder(port)
    try:
        rc, out, _err, _dt = run_launcher(["status", "--port", str(port), "--json"])
        js = one_json_line(out)
        check("④-a 别的程序占着 ⇒ 退出码 3", rc == 3, f"rc={rc}")
        if js:
            check("④-b state=not_ours", js.get("state") == "not_ours", str(js.get("state")))
            check("④-c pid 能看到是谁", bool(js.get("pid")), str(js.get("pid")))
        rc, out_h, _err, _dt = run_launcher(["status", "--port", str(port)])
        check("④-d 人话说清「不是本控制台」", "别的程序" in out_h, out_h.strip().replace("\n", " / ")[:160])
        # ★★ 最重要的一条：**它还在**。判据不许伤到环境，"不杀别人的进程"是纪律不是能力不足。
        alive = False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                alive = True
        except Exception:
            alive = False
        check("④-e ★★ 那个「别人的程序」**还活着**（启动器没杀它）", alive,
              "端口 %d 可连=%s" % (port, alive))
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass


def probe_bad_args() -> None:
    """反例：坏参数在 `--json` 模式下**也必须给 JSON，且不许挂死等按键**。"""
    rc, out, _err, dt = run_launcher(["status", "--port", "abc", "--json"], timeout=30)
    js = one_json_line(out)
    check("A-a 坏端口 + --json ⇒ 恰好一行 JSON", js is not None, f"{out[:140]!r}")
    check("A-b 退出码 1", rc == 1, f"rc={rc}")
    # ★★ 关键：不带 --json 时 Fail() 会 Console.ReadKey() 留窗口 —— 脚本会**挂死**。
    check("A-c ★★ 不许挂死等按键（30 秒内返回）", dt < 10, f"耗时 {dt:.1f}s")

    # ★ 把 `--json` 放在**最前面**：既测"缺值会报错"，又顺带测"`--json` 与位置无关"
    #   （它由一次**前置扫描**认出，不依赖参数顺序 —— S3 抓到的真缺陷就是顺序依赖）。
    rc, out, _err, _dt = run_launcher(["--json", "status", "--logdir"], timeout=30)
    js = one_json_line(out)
    check("B-a --logdir 缺参数 + --json ⇒ 一行 JSON", js is not None, f"{out[:140]!r}")
    check("B-b 退出码 1", rc == 1, f"rc={rc}")

    # ★ 现场（S3 真跑照出来的）：`--logdir --json` 是**有歧义**的输入（`--json` 会被当成
    #   它的值）⇒ 探针不该拿它当反例。这里如实记下这条边界：**缺值只在"后面真的没有东西"时成立**。
    #
    # ★★ T18 · S8：这一条**同时**照出探针自己的两个毛病（两条都已经修）：
    #   **F —— 断言写宽了**：原来断言 `rc == 0`，而那等于断言「**8787 上一定有控制台在跑**」
    #        （重启前它绿，纯属真控制台恰好在跑；重启后 8787 空着 ⇒ `rc=4` ⇒ 红）。
    #        探针自己的头注写着「断言的是**不变量**，不是环境事实」—— 这条正好违了。
    #   **G —— 判据弄脏了仓库**：`--json` 被当成日志目录的**值** ⇒ `Locate()` 在
    #        **cwd（= `repo\`）** 下 `CreateDirectory("--json")` ⇒ 仓库里多出一个 `repo\--json\`。
    #    ⇒ 修法：**换到临时 cwd 里跑**，并且只断言"**不是参数错**（`--json` 确实被当成了值）＋ 恰好一行"。
    with tempfile.TemporaryDirectory(prefix="aoc-t18-cwd-") as cwd:
        rc, out, _err, _dt = run_launcher(["status", "--logdir", "--json"], timeout=30, cwd=cwd)
        js = one_json_line(out)
        check("B-c 边界：`--logdir --json` 把 --json 当成值（**不是**参数错）⇒ 仍是一行 JSON",
              js is not None and rc != 1, f"rc={rc} {out[:100]!r}")
        check("B-d ★★ 判据**不许伤到环境**：那次运行没有在仓库里留下 `--json` 目录"
              "（S8 之前它会——`repo\\--json\\` 就是它造的）",
              not (REPO / "--json").exists(), str(REPO / "--json") + " 被造出来了")

    rc, out, _err, _dt = run_launcher(["status", "--json"], env_extra={"AOC_PORT": "notanumber"},
                                      timeout=30)
    js = one_json_line(out)
    check("C-a AOC_PORT 非法 + --json ⇒ 一行 JSON", js is not None, f"{out[:140]!r}")
    check("C-b 退出码 1", rc == 1, f"rc={rc}")


def probe_logdir_init() -> None:
    """日志目录注入：结论里回显实际用的那个（第二只眼睛）。"""
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="aoc-t18-logs-") as td:
        rc, out, _err, _dt = run_launcher(["status", "--port", str(port), "--logdir", td])
        check("D-a 日志目录注入 ⇒ 退出码仍是 4（不影响状态判定）", rc == 4, f"rc={rc}")
        # 结论里回显的是**相对路径**（Rel()），所以只断言"目录名出现在结论里"
        check("D-b 结论里回显了那个日志目录", Path(td).name in out or td in out,
              out.strip().replace("\n", " / ")[:160])


def probe_json_contract() -> None:
    """★ T18 · S8：`--json` 的合同 —— **恰好一行** ＋ **核心字段一个不少**，对**每个入口**成立。

    ★ 现场（S8 取数坐实）：此前「恰好一行」**只在 `status` 上成立** ——
      `stop` / `restart` / `shortcut` / 失败的 `start` 都是**两行**（子函数发一次、`Main` 又兜底发一次），
      而且两行**字段还不一样**。脚本没法说"我读第二行" ⇒ 那条纪律当时已经没人守了。
    ★ 检测手法：**数非空行**（不是"看第一行能不能解析"）—— 多一行就必须红。
    """
    foreign = free_port()
    srv = start_placeholder(foreign)
    try:
        with tempfile.TemporaryDirectory(prefix="aoc-t18-json-") as td:
            cases = [
                ("status（没在跑）", ["status", "--port", str(free_port()), "--json"]),
                ("status（别人的程序占着）", ["status", "--port", str(foreign), "--json"]),
                ("stop（本来就没在跑）", ["stop", "--port", str(free_port()), "--json"]),
                ("stop（别人的程序占着）", ["stop", "--port", str(foreign), "--json"]),
                ("start（别人的程序占着）", ["start", "--port", str(foreign), "--json"]),
                ("restart（别人的程序占着）", ["restart", "--port", str(foreign), "--json"]),
                ("shortcut list", ["shortcut", "list", "--shortcut-dir", td, "--json"]),
                ("参数错", ["status", "--port", "abc", "--json"]),
            ]
            for name, args in cases:
                rc, out, _e, _dt = run_launcher(args, timeout=60)
                nonempty = [ln for ln in out.replace("\r\n", "\n").split("\n") if ln.strip()]
                js = one_json_line(out)
                check("J-1 ★★ `--json` 恰好一行：" + name,
                      js is not None and len(nonempty) == 1,
                      "非空行数=%d rc=%d %s" % (len(nonempty), rc, out[:120].replace("\n", " ⏎ ")))
                if js is None:
                    continue
                miss = sorted(CORE_KEYS - set(js))
                check("J-2 ★ 核心字段一个不少：" + name, not miss,
                      "缺 %s" % miss if miss else "全在")
                check("J-3 退出码：JSON 的 exit == 进程退出码：" + name,
                      js.get("exit") == rc, "json.exit=%s rc=%s" % (js.get("exit"), rc))
        # ★★ `start` 撞上"别人的程序"：退出码必须是表里写的 **3**，而且**不许杀它**。
        #   现场（S8）：此前走的是 `Fail()` ⇒ 给 **1**，脚本分不出"别人占着"（要去找人）
        #   和"参数写错"（要改命令）—— 这是「同一个开口，两处实现都要认账」的第 4 次现场。
        rc, out, _e, _dt = run_launcher(["start", "--port", str(foreign), "--json"], timeout=60)
        js = one_json_line(out)
        check("J-4 ★★★ `start` 撞上别人的程序 ⇒ 退出码 **3**（与 `stop`/`restart`/`status` **同一个码**）",
              rc == 3, "rc=%d" % rc)
        check("J-5 `start` 同一情形给出同一个 state=not_ours",
              js is not None and js.get("state") == "not_ours",
              "state=%s" % (js.get("state") if js else None))
        check("J-6 ★★ 而且它**没有杀**那个别人的程序", _port_alive(foreign),
              "端口 %d 可连=%s" % (foreign, _port_alive(foreign)))
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass


def probe_env_injection() -> None:
    """★ T18 · S8：环境变量那两条 —— 一个**承诺了却没实现**，一个**优先级反了**。

    ★ 现场 D：`--help` 里写着「也可用 `AOC_SHORTCUT_DIR`」，而 `Main` 里**只认 `--shortcut-dir`**
      （`AOC_LOGDIR` 有兜底、它没有）⇒ 那句帮助是**假话**。
    ★ 现场 E：`--port` 的兜底条件写的是 `Port == DefaultPort` ⇒ 显式 `--port 8787`
      又设了 `AOC_PORT=9999` 时，**环境变量反超命令行**（实测：生效的是 9999）。
    """
    with tempfile.TemporaryDirectory(prefix="aoc-t18-env-") as td:
        env = {"AOC_SHORTCUT_DIR": td}
        rc, out, _e, _dt = run_launcher(["shortcut", "add"], env_extra=env, timeout=60)
        made = sorted(p.name for p in Path(td).glob("*.lnk"))
        check("K-1 ★★ `AOC_SHORTCUT_DIR` **真的被读**（此前帮助里承诺了它，代码里没有）",
              rc == 0 and len(made) == 2, "rc=%d 建了 %s" % (rc, made))
        rc, out, _e, _dt = run_launcher(["shortcut", "remove"], env_extra=env, timeout=60)
        check("K-2 用它撤也认（同一个落点）", rc == 0 and not list(Path(td).glob("*.lnk")),
              "rc=%d 还剩 %s" % (rc, sorted(p.name for p in Path(td).glob("*.lnk"))))

    # ★ 命令行 > 环境变量 > 默认值
    rc, out, _e, _dt = run_launcher(["status", "--port", str(DEFAULT_PORT), "--json"],
                                    env_extra={"AOC_PORT": "9999"}, timeout=60)
    js = one_json_line(out)
    check("K-3 ★★ 显式 `--port 8787` **不被** `AOC_PORT=9999` 反超（命令行 > 环境变量）",
          js is not None and js.get("port") == DEFAULT_PORT,
          "生效端口=%s（期望 %d）" % (js.get("port") if js else None, DEFAULT_PORT))


def probe_real_start_stop() -> None:
    """★★ ⑥⑦ T18 · S8：**真 `start` 到就绪 → 再 `stop`** —— 探针此前覆盖不到的**那一跳**。

    ★ 为什么必须补：此前"六种情形"里，① ② ⑥ 都只是"看它怎么说"（`status` 说没在跑 / 口令没设过），
      **从来没有真起过一个实例到就绪再停掉**。而"等就绪是真就绪"（验收 #7）只有真跑才验得动。

    ★★ 隔离（S8 收工时想到的那一条）：**「端口可注入」≠「环境可隔离」** ——
      临时端口上真起一个实例，它的 cwd 仍是仓库的 `repo\\` ⇒ `app\\server.py` 的 ROOT 就是它
      ⇒ 它会和**用户正在用的那个控制台共用 `repo\\var\\ops.db`**（等于拿生产库做测试）。
      ⇒ 探针把 `repo\\`（**不含 `var\\`**）整份拷成**临时 root**，实例的 var / 库 / 日志全落在那里。

    ★ 解释器从哪来：**`sys.executable`** —— 探针自己就跑在一个解释器上，把它交给启动器用。
      这一条很关键：否则这一组就会依赖本机那条**硬编码的** `D:\\Python311\\python.exe`
      （S0 照出来的 §0.3），**换台机器就红** —— 那正是"别人复算不了"。
    """
    port = free_port()
    db = REPO / "var" / "ops.db"
    real_running = _port_alive(DEFAULT_PORT)
    db_before = file_sha256(db)
    pids_left: list[int] = []

    with tempfile.TemporaryDirectory(prefix="aoc-t18-real-") as td:
        aoc_root = make_temp_root(Path(td))
        tmp_repo = aoc_root / "repo"
        env = {"AOC_ROOT": str(aoc_root), "AOC_PYTHON": sys.executable}
        check("⑥-a ★ 临时 root 就位，且与仓库里的代码**同一份**（`app\\` 内容指纹相等）",
              tree_sha256(REPO / "app") == tree_sha256(tmp_repo / "app"),
              "app 指纹 %s" % tree_sha256(tmp_repo / "app")[:16] + "…")
        check("⑥-b 临时 root 里**没有** `var\\ops.db`（只有这样，「没碰生产库」才成立）",
              not (tmp_repo / "var" / "ops.db").exists(), str(tmp_repo / "var"))
        try:
            # ---- 真 start 到就绪 ----
            rc, out, _e, dt = run_launcher(["start", "--port", str(port), "--json"],
                                           env_extra=env, timeout=180)
            js = one_json_line(out)
            check("⑥-c ★★ 真 `start` 到**就绪**（轮询 `/api/auth/ping`，不是「睡 N 秒」）⇒ 退出码 0",
                  rc == 0, "rc=%d（%.1fs）%s" % (rc, dt, out[:160]))
            # ★★ 这一条是 S8 那条**真缺陷**的回归判据：`start` 拉起的 cmd.exe 曾**继承启动器的
            #   stdout** ⇒ 用管道收输出的调用者**永远等不到 EOF**（探针当时真卡了 4 分钟）。
            check("⑥-c2 ★★★ `start` **不攥着调用者的管道**（用管道收输出的脚本不会挂死）"
                  "—— 交付物要能被**接口型**地调用，这条是前提",
                  rc != RC_TIMEOUT and dt < 120,
                  "rc=%d 耗时 %.1fs%s" % (rc, dt, "　← 探针自己的哨兵：它把调用者挂住了"
                                          if rc == RC_TIMEOUT else ""))
            if rc != 0:
                return
            pids_left = listener_pids(port)
            check("⑥-d `state=running`，且 PID 能看见", js is not None and js.get("state") == "running"
                  and bool(js.get("pid")), "state=%s pid=%s" % (js.get("state") if js else None,
                                                               js.get("pid") if js else None))
            ver = None
            init = (tmp_repo / "app" / "__init__.py").read_text(encoding="utf-8", errors="replace")
            import re as _re
            mm = _re.search(r'__version__\s*=\s*"([^"]+)"', init)
            ver = mm.group(1) if mm else None
            check("⑥-e ★ 报出来的就是**临时 root 上那一版**（version 与磁盘对得上）",
                  js is not None and js.get("version") == ver,
                  "ping 报 %s ｜ 磁盘 %s" % (js.get("version") if js else None, ver))
            check("⑥-f ★★ 情形 ⑥：**口令还没设过** ⇒ `configured=false`"
                  "（临时 root 是全新的，没有 `var\\auth.json`）",
                  js is not None and js.get("configured") is False,
                  "configured=%s（类型 %s）" % (js.get("configured") if js else None,
                                              type(js.get("configured")).__name__ if js else "-"))
            check("⑥-g ★★ `--json` 下**不弹浏览器**（脚本模式的副作用清单：不留窗口 · 不等按键 · **不弹浏览器**）",
                  js is not None and js.get("browser") == "suppressed",
                  "browser=%s" % (js.get("browser") if js else None))
            check("⑥-h ★★ **隔离成立**：那个实例把库写进了**临时 root**，不是仓库那个",
                  (tmp_repo / "var" / "ops.db").is_file(),
                  "临时 root 里没有 ops.db ⇒ 它写别处去了")

            # ---- 人话那条路也得说清楚（情形 ⑥ 的"给人看"那一半） ----
            rc_h, out_h, _e, _dt = run_launcher(["status", "--port", str(port)], env_extra=env)
            check("⑥-i 人话里点明「口令：★ 还没设过」（与 ⑥-f 同一件事的两种说法）",
                  "还没设过" in out_h, out_h.strip().replace("\n", " / ")[:160])

            # ---- 幂等 ----
            pid1 = listener_pids(port)
            rc, out, _e, _dt = run_launcher(["start", "--port", str(port), "--json"],
                                            env_extra=env, timeout=120)
            js = one_json_line(out)
            pid2 = listener_pids(port)
            check("⑥-j ★ 幂等：连点两次 ⇒ 退出码 0，**不重复起**（PID 没变）",
                  rc == 0 and pid1 == pid2 and len(pid2) == 1,
                  "第一次 %s ｜ 第二次 %s" % (pid1, pid2))

            # ---- restart：只有一个**新**进程 ----
            rc, out, _e, _dt = run_launcher(["restart", "--port", str(port), "--json"],
                                            env_extra=env, timeout=180)
            js = one_json_line(out)
            pid3 = listener_pids(port)
            check("⑥-k ★ `restart` 之后**恰好一个**监听进程，且是**新的**那个",
                  rc == 0 and len(pid3) == 1 and pid3 != pid2,
                  "rc=%d 之前 %s ｜ 之后 %s" % (rc, pid2, pid3))
            pids_left = pid3

            # ---- stop ----
            rc, out, _e, _dt = run_launcher(["stop", "--port", str(port), "--json"],
                                            env_extra=env, timeout=120)
            js = one_json_line(out)
            check("⑥-l ★ 真 `stop` ⇒ 退出码 0，端口**真的**释放了", rc == 0 and not _port_alive(port),
                  "rc=%d ｜ 还活着=%s" % (rc, _port_alive(port)))
            pids_left = listener_pids(port)

            # ---- 再 stop 一次：这条是情形 ① 的**真跑版** ----
            rc, out, _e, _dt = run_launcher(["stop", "--port", str(port), "--json"],
                                            env_extra=env, timeout=60)
            js = one_json_line(out)
            check("⑥-m 停过之后再 `stop` ⇒ 退出码 0 ＋ `state=not_running`（幂等，且说清「本来就没在跑」）",
                  rc == 0 and js is not None and js.get("state") == "not_running",
                  "rc=%d state=%s" % (rc, js.get("state") if js else None))

            rc, out, _e, _dt = run_launcher(["status", "--port", str(port), "--json"],
                                            env_extra=env, timeout=60)
            js = one_json_line(out)
            check("⑥-n 情形 ①（真跑版）：没在跑 ⇒ 退出码 4 ＋ `state=not_running`",
                  rc == 4 and js is not None and js.get("state") == "not_running",
                  "rc=%d state=%s" % (rc, js.get("state") if js else None))
        finally:
            kill_pids(listener_pids(port))

    # ★★ 生产库那条：**当前提成立时才验**（不许把它写成环境假设 —— 那正是探针 F 那个毛病）。
    if real_running:
        check("⑥-o 生产库没被动过（★ **跳过**：8787 上真控制台正在跑，它自己随时可能写库 ⇒ "
              "这一次**验不到**）", True, "跳过 ≠ 通过")
    else:
        check("⑥-o ★★★ 全程没碰生产库：`repo\\var\\ops.db` 的 sha256 前后一致",
              file_sha256(db) == db_before,
              "前 %s ｜ 后 %s" % (db_before[:16] + "…", file_sha256(db)[:16] + "…"))


def probe_two_instances() -> None:
    """⑦ ★★★ T18 · S8：**同一个 root 上两个端口各起一个实例**，外加"日志护栏"两条。

    ★★ 现场（S8 的 A 级真跑照出来的**真缺陷**，三条对照坐实）：
      同一个 root 上已有实例在跑时，`console.out.log` 被它占着 ⇒ `cmd` **打不开重定向目标**
      ⇒ 子进程**根本没被拉起来**（日志文件也没被创建、端口从头到尾没有监听）
      ⇒ 而启动器白等 **138 秒**，并把结论写成「**服务没能在预期时间内回应**」
      —— ★★ **假话**：它压根**没起来**。
      ★ 对照：把 `--logdir` 换开 ⇒ **2.4 秒**就绿。
    ★ 修法（两条）：**日志文件名带上端口**（一个端口一个实例，一个实例一组日志）
      ＋ **拉起之前先确认"日志写得进去"**（把 138 秒的假结论换成 1 秒的真话）。
    ★ 顺带治了另一条：`--logdir` 指到一个**已存在的文件**时，原来是**未捕获异常直接崩**
      （退出码是个 .NET 异常码 `0xE0434352`，没有结论、没有约定退出码）。
    """
    pa, pb = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="aoc-t18-two-") as td:
        aoc_root = make_temp_root(Path(td))
        logs = aoc_root / "repo" / "var" / "logs"
        env = {"AOC_ROOT": str(aoc_root), "AOC_PYTHON": sys.executable}
        try:
            rc, _o, _e, dt = run_launcher(["start", "--port", str(pa), "--json"],
                                          env_extra=env, timeout=180)
            check("⑦-a 第一个实例起得来（干净起点）", rc == 0, "rc=%d（%.1fs）" % (rc, dt))
            if rc != 0:
                return
            rc2, _o2, _e2, dt2 = run_launcher(["start", "--port", str(pb), "--json"],
                                              env_extra=env, timeout=180)
            check("⑦-b ★★★ 第一个**还在跑**时，第二个实例**照样起得来**"
                  "（S8 之前：日志文件被抢 ⇒ 子进程静默死掉 ＋ 白等 138 秒 ＋ 结论说假话）",
                  rc2 == 0, "rc=%d（%.1fs）" % (rc2, dt2))
            check("⑦-c ★★ 两个实例的日志**按端口分家**（`console-<端口>.out.log`）",
                  (logs / ("console-%d.out.log" % pa)).is_file()
                  and (logs / ("console-%d.out.log" % pb)).is_file(),
                  "在场：%s" % sorted(p.name for p in logs.glob("*.log")))
            check("⑦-d 两个实例都认 `/api/auth/ping`（两个都真的活着）",
                  _port_alive(pa) and _port_alive(pb),
                  "%d=%s ｜ %d=%s" % (pa, _port_alive(pa), pb, _port_alive(pb)))
            blocker = Path(td) / "blocker.txt"
            blocker.write_text("x", encoding="utf-8")
            rc3, out3, _e3, dt3 = run_launcher(
                ["start", "--port", str(free_port()), "--logdir", str(blocker), "--json"],
                env_extra=env, timeout=60)
            js3 = one_json_line(out3)
            check("⑦-e ★★ 日志目录用不了 ⇒ **快速**说清楚（≤ 10 秒）＋ `state=logdir_bad` ＋ 退出码 1"
                  "（S8 之前：**未捕获异常直接崩**，退出码是 .NET 异常码 `0xE0434352`）",
                  rc3 == 1 and dt3 <= 10 and js3 is not None and js3.get("state") == "logdir_bad",
                  "rc=%d（%.1fs）state=%s" % (rc3, dt3, js3.get("state") if js3 else None))
        finally:
            for p in (pa, pb):
                run_launcher(["stop", "--port", str(p), "--json"], env_extra=env, timeout=120)
                kill_pids(listener_pids(p))


def probe_interpreter_detection() -> None:
    """⑧ ★★ T18 · S9：**「自动找解释器」要真的自动，而且要问得到**（可移植性收口）。

    ★ 改造前的样子（S0 §0.3）：候选只有四条，最后的兜底是**一条硬编码的机器专属路径**
      ⇒ 换台机器就只能靠运气。改造后是**六层探测**：
      `AOC_PYTHON` → PATH 上的 `python` / `python3` → **`py -3`**（Windows 官方启动器）→
      `%LOCALAPPDATA%\\Programs\\Python\\Python3*` → `%ProgramFiles%\\Python3*` →（最后）那条硬编码路径。
      ★ 而且**必须校验 3.10+**（代码用了 `X | Y` 类型写法），"版本太低"要**跳过并继续**。

    ★★ 这里刻意**不依赖"这台机器的 PATH 上正好有 python"**（那是环境事实，不是不变量）：
      而是喂两个**受我们控制**的候选 —— 一个能用（`sys.executable`）、一个**不是 python**（`cmd.exe`），
      看它是不是**逐个试、跳过不会 python 的、最后仍然起得来**。
    """
    pa, pb = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="aoc-t18-py-") as td:
        aoc_root = make_temp_root(Path(td))
        base = {"AOC_ROOT": str(aoc_root)}
        try:
            # ① 第一个候选就是能用的 ⇒ 不该跳过任何东西
            env1 = dict(base, AOC_PYTHON=sys.executable)
            rc, out, _e, dt = run_launcher(["start", "--port", str(pa), "--json"],
                                           env_extra=env1, timeout=180)
            js = one_json_line(out)
            check("⑧-a ★★ 第一个候选（点名 `AOC_PYTHON`）能用 ⇒ 起得来 ＋ 跳过 0 个 ＋ "
                  "结论里报得出**用的是谁、什么版本**（`python` / `python_minor` / `python_skipped`）",
                  rc == 0 and js is not None and js.get("python_skipped") == 0
                  and (js.get("python_minor") or 0) >= 10,
                  "rc=%d python=%s 3.%s skipped=%s" % (rc, (js or {}).get("python"),
                                                       (js or {}).get("python_minor"),
                                                       (js or {}).get("python_skipped")))
            run_launcher(["stop", "--port", str(pa), "--json"], env_extra=env1, timeout=120)

            # ② 第一个候选**不是 python** ⇒ 必须**跳过并继续找**（★ 这是"自动"的另一半）
            fake = os.environ.get("ComSpec") or "cmd.exe"     # cmd.exe 是个真 exe，但它不是 python
            env2 = dict(base, AOC_PYTHON=fake)
            rc2, out2, _e2, dt2 = run_launcher(["start", "--port", str(pb), "--json"],
                                               env_extra=env2, timeout=180)
            js2 = one_json_line(out2)
            check("⑧-b ★★★ 第一个候选**不是 python**（拿 `cmd.exe` 冒充）⇒ **跳过它并继续找**，"
                  "★ 仍然起得来（`python_skipped ≥ 1`）",
                  rc2 == 0 and js2 is not None and (js2.get("python_skipped") or 0) >= 1,
                  "rc=%d（%.1fs）skipped=%s python=%s" % (rc2, dt2,
                                                         (js2 or {}).get("python_skipped"),
                                                         (js2 or {}).get("python")))
        finally:
            for p in (pa, pb):
                run_launcher(["stop", "--port", str(p), "--json"], env_extra=base, timeout=120)
                kill_pids(listener_pids(p))


# --------------------------------------------------------------------- 主流程

def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    if not EXE.is_file():
        msg = f"找不到启动器：{EXE}"
        print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False) if as_json else msg)
        return 2

    for fn in (probe_freshness, probe_status_not_running, probe_status_default, probe_not_ours,
               probe_shortcut, probe_version_consistency, probe_bad_args, probe_logdir_init,
               probe_json_contract, probe_env_injection, probe_real_start_stop,
               probe_two_instances, probe_interpreter_detection):
        try:
            fn()
        except Exception as exc:                     # 探针自己崩了也要如实报，不许假装通过
            check(fn.__name__ + "（探针自己抛了异常）", False, f"{type(exc).__name__}: {exc}")

    bad = [r for r in RESULTS if not r[1]]
    if as_json:
        print(json.dumps({"ok": not bad, "total": len(RESULTS), "failed": len(bad),
                          "items": [{"name": n, "ok": o, "detail": d} for n, o, d in RESULTS]},
                         ensure_ascii=False))
    else:
        for n, o, d in RESULTS:
            print(("  ✅ " if o else "  ❌ ") + n + "    " + d)
        print(f"\n  结果：通过 {len(RESULTS) - len(bad)} / 共 {len(RESULTS)}　失败 {len(bad)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
