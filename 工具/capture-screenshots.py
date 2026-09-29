# -*- coding: utf-8 -*-
"""交付包 · 界面截图（可脚本复现）

用法（★ 先起控制台：`cd repo` → `python -m app.server`）：

    python 工具\\capture-screenshots.py                 # 全部页签
    python 工具\\capture-screenshots.py gaps mon       # 只截指定页签

产出：
    docs\\screenshots\\01-动作.png … 12-虚拟机.png
    docs\\screenshots\\界面-结论原文-<日期>.md     ← ★★ **机器可核的那一半**（逐字可对）
    docs\\screenshots\\_capture-log.txt

★ 为什么截图要与"结论原文"成对：**PNG 不可复核**（没法逐字比对），
  而这个项目真的发生过"只看成功横幅、差点把一个假成功签收掉"的事 ——
  是**把结论原文读了一遍**才发现不对。
★ 纪律：用**独立 user-data-dir + 独立调试端口**，不碰用户正在用的浏览器；用完只杀自己启的那个进程。

★★ T16（规范 §12.121）：本脚本现在有**两段**走查，边界不同，别混为一谈：
  ① **渲染与切换**：12 个页签逐个点开 ⇒ 截图 ＋ 文字快照 ＋ **运行时错误归因到具体页签**；
  ② **按钮级（真点一次）**：导出（.txt）· 锁定 → 登录 · 改口令（只点开、**不真改**）
     —— ★ 这一段存在的理由：T14 那颗「三个导出入口全部 401」的洞是在**所有页签都不报错**的
       情况下存在的；**静态断言全绿、切换全绿，只有真按下去才现形**。
     ★ 它**不能**覆盖的（写在明面上，免得边界被说大）：yellow/red 变更动作**不在这里执行**
       （闸门只有一处），跨机器/跨集群的真实变更、真实快照回滚、AI 侧的模型调用都不覆盖。
★ 退出码：**2** 服务没起 / 找不到浏览器 · **4** 版本没对齐（★ 等于"在给旧进程拍照"）·
  **5** 走查表与界面页签对不上 · **3** 有页签在运行时报错 · **6** 按钮级走查有失败 · **0** 干净。
"""
import base64
import datetime as _dt
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ROOT = Path(__file__).resolve().parent.parent          # 项目根
OUT = ROOT / "docs" / "screenshots"
PROFILE = ROOT / "_cdp-screenshots"
BASE = "http://127.0.0.1:8787"
PORT = 9225
EDGE_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

# (data-tab, 输出名, 说明)
TABS = [
    ("actions", "01-动作.png", "动作页：只读/变更分级、参数表单、命令预览"),
    ("recipes", "02-服务目录.png", "服务目录：10 份配方、计划预览、三个反向按钮"),
    ("checkup", "03-体检.png", "健康体检：12 项、阈值可配置、4 台并排"),
    ("history", "04-历史.png", "执行历史：每条结论可回放、可点回任务号"),
    ("batches", "05-批次.png", "批量执行：横向对比、失败隔离"),
    ("gaps", "06-覆盖率与缺口.png", "覆盖率与缺口：双口径并列、权重可追溯"),
    ("k8s", "07-K8s管理台.png", "K8s 管理台：六块一键取结论"),
    ("mon", "08-监控告警.png", "监控告警：在采 / 在判 / 送出去了"),
    # ★★ T15·S10 补：原来只有 8 个 —— **缺的正好是 T12 / T14 / T15 各自新增的那个页签**
    #    （对话 / 待确认 / 报告）。★ 这件事本身就是 T14 那颗洞的一半原因：
    #    「界面走查没做」＋「走查表没跟着页签长」= 新页签**没有任何真人看过**。
    #    ⇒ 已加断言把这张表和 `web\index.html` 的 `data-tab` **绑在一一对应上**（清单 237）。
    ("chat", "09-对话.png", "对话：把话交给 AI；动作仍是它自己一条条选的（工具面是白名单）"),
    ("pending", "10-待确认.png", "待确认：AI 的变更请求卡片（人在环 —— 请求不等于执行）"),
    ("reports", "11-报告.png", "报告：一次对话一份带证据链的报告，每条结论可点回任务号"),
    # ★★ T16：第 12 个页签「虚拟机」。★ 这一行**必须**跟着界面一起长：
    #    断言 Ⓘ 会拿这张表和 `web\index.html` 的 `data-tab` 逐项同序核对（清单 237），
    #    漏了它 ⇒ 新页签**永远没人看过**，而"界面走查没做"是看不出来的（它会安静地绿着）。
    ("vm", "12-虚拟机.png", "虚拟机：清单 / 状态 / 地址 / 快照链 / 等就绪 ＋ ★T17 造机块（表单 → 配方 vm-provision / 动作 vm.clone，两条都跳既有闸门；克隆是 red）（★ 执行面是宿主机，不是顶栏那台）"),
]


# ----------------------------------------------------------------- 最小 WebSocket 客户端
class WS:
    """CDP 的截图接口只能走 WebSocket；这里只实现握手 + 文本帧 + ping/pong，够用就好。"""

    def __init__(self, url):
        assert url.startswith("ws://"), url
        hostport, path = url[5:].split("/", 1)
        host, port = hostport.split(":")
        self.sock = socket.create_connection((host, int(port)), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(("GET /%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
                           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                           "Sec-WebSocket-Version: 13\r\n\r\n"
                           % (path, hostport, key)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(4096)
        assert b"101" in buf.split(b"\r\n")[0], buf[:200]
        self.buf = buf.split(b"\r\n\r\n", 1)[1]

    def _recv(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("ws closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, text):
        data = text.encode("utf-8")
        head = bytearray([0x81])
        n = len(data)
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head.append(0x80 | 126)
            head += struct.pack(">H", n)
        else:
            head.append(0x80 | 127)
            head += struct.pack(">Q", n)
        mask = os.urandom(4)
        head += mask
        self.sock.sendall(bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        while True:
            b1, b2 = self._recv(2)
            opcode, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._recv(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._recv(8))[0]
            payload = self._recv(n) if n else b""
            if opcode == 0x9:
                self.sock.sendall(bytes([0x8A, 0x80]) + os.urandom(4))
                continue
            if opcode in (0x1, 0x2):
                return payload.decode("utf-8", "replace")
            if opcode == 0x8:
                raise EOFError("ws close frame")


class CDP:
    def __init__(self, ws_url):
        self.ws = WS(ws_url)
        self.i = 0

    def call(self, method, params=None, timeout=60):
        self.i += 1
        mid = self.i
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        t0 = time.time()
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError("%s -> %s" % (method, msg["error"]))
                return msg.get("result")
            if time.time() - t0 > timeout:
                raise TimeoutError(method)

    def js(self, expr, timeout=60):
        r = self.call("Runtime.evaluate",
                      {"expression": expr, "returnByValue": True, "awaitPromise": True}, timeout)
        if r.get("exceptionDetails"):
            raise RuntimeError(json.dumps(r["exceptionDetails"], ensure_ascii=False)[:300])
        return (r.get("result") or {}).get("value")

    def shot(self, path):
        r = self.call("Page.captureScreenshot",
                      {"format": "png", "captureBeyondViewport": True}, timeout=90)
        Path(path).write_bytes(base64.b64decode(r["data"]))
        return Path(path).stat().st_size


def _find_page():
    with urllib.request.urlopen("http://127.0.0.1:%d/json/list" % PORT, timeout=10) as r:
        for t in json.loads(r.read().decode()):
            if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                return t["webSocketDebuggerUrl"]
    raise RuntimeError("没有可用的 page target")


def _console_up():
    """★ T14：探活改走**免鉴权**的 `/api/auth/ping`。

    为什么不能再用 `/api/health`：它现在**要鉴权**（会吐主机名 / IP / 拓扑 / 库规模），
    拿它探活会永远 401 —— 然后你会以为"控制台没起来"，去查一个不存在的问题。
    """
    try:
        with urllib.request.urlopen(BASE + "/api/auth/ping", timeout=5) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def _running_version():
    """★ T15·S10：问一下**正在跑的那个进程**是哪一版 —— 走查前必须先核对。

    ★ 为什么值得单列一条判据：本轮第一次走查就是**给一个 T14 的旧进程拍的照**
      —— 磁盘上早就不是那一版了，页首写着「T14 · v0.12.0」，而「报告」页签
      背后的 `/api/ai/reports` 在旧进程里**根本不存在**。
      ★ 拍出一叠好看但**无效**的截图，比不拍更糟（它会让人以为"界面已经验过了"）。
    ★ 所以：**跑着的版本必须等于磁盘的版本**，不等就直接拒绝跑。
    """
    with urllib.request.urlopen(BASE + "/api/auth/ping", timeout=5) as r:
        d = json.loads(r.read().decode()).get("data", {})
    return d.get("version", "?"), d.get("stage", "?")


def _disk_version():
    """磁盘上的 `repo\\app\\__init__.py` 里写的是什么版本（★ 判据的另一半）。"""
    src = (ROOT / "repo" / "app" / "__init__.py").read_text(encoding="utf-8")
    return (re.search(r'__version__\s*=\s*"([^"]+)"', src).group(1),
            re.search(r'__stage__\s*=\s*"([^"]+)"', src).group(1))


def _tabs_vs_html():
    """走查表 `TABS` 必须与 `web\\index.html` 的 `data-tab` **按顺序**一一对应。

    ★ 为什么：T14 那颗「三个导出入口全部 401」的洞，**一半原因是这张表没跟着页签长**
      —— 它当时只有 8 个页签，而界面已经有 11 个：新页签**没有任何真人看过**。
    ★ 判据：**顺序也要一致**（走查稿是按界面顺序读的，顺序错=读错）。
    """
    html = (ROOT / "repo" / "web" / "index.html").read_text(encoding="utf-8")
    return [t[0] for t in TABS], re.findall(r'data-tab="([a-z0-9_-]+)"', html)


def _login_in_page(c, log) -> bool:
    """★ T14：在页面里过门（控制台有鉴权了）。

    做法：页内 `fetch` 登录 ⇒ 把令牌写进 `sessionStorage` ⇒ 重新加载。
    ★ 为什么不用 `Page.addScriptToEvaluateOnNewDocument`：那种要在**首次导航之前**装，
      调试起来更绕；而"先登录再重载"这条路，失败时页面上留着痕迹，好查。
    ★ 口令只从环境变量 `AOC_CONSOLE_PASSWORD` 来 —— **不写进这个脚本、不落盘**（§12.97.1）。
    """
    pw = os.environ.get("AOC_CONSOLE_PASSWORD", "")
    if not pw:
        state = c.js("(async()=>{const r=await fetch('/api/auth/ping');const d=await r.json();"
                     "return JSON.stringify(d.data||{});})()")
        log("⚠️ 没给 AOC_CONSOLE_PASSWORD ⇒ 过不了门；门的状态：%s" % state)
        log("   下面的截图会是**登录页**（那本身也是一张有效证据，但它不是'界面走查'）")
        return False
    res = c.js(
        "(async()=>{const r=await fetch('/api/auth/login',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({password:%s})});const d=await r.json();"
        "if(!d.ok) return 'FAIL:'+JSON.stringify(d.error||{});"
        "sessionStorage.setItem('aoc.token', d.data.token); return 'OK';})()" % json.dumps(pw)
    )
    if str(res) != "OK":
        log("❌ 过门失败：%s" % res)
        return False
    log("✅ 已过鉴权门（令牌写进本浏览器 profile 的 sessionStorage，仅本次会话）")
    c.call("Page.navigate", {"url": BASE + "/"})
    time.sleep(4)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# ★★ T18：**合成任务**不许当走查对象（历史列表里混着自检自己造的那几条）
# ──────────────────────────────────────────────────────────────────────────────
# ★ 现场：T17 的界面走查里，「导出（.txt）」这一步失败过一次 —— 点下去之后判
#   "回放后**没有**导出按钮"。到真界面上复核：那条**真任务**（`T20260928-150717-65213d`）
#   的导出段**正常存在**。⇒ 变量不是界面，是**被点到的那一条**：
#   历史列表里混着三条自检造的**合成任务**（`SELFTEST-TASK` / `SELFTEST-CHECKUP-A` /
#   `SELFTEST-CHECKUP-B`），它们**本来就没有导出段** —— 点到它们就判红，
#   而红的原因**跟界面毫无关系**。
# ★ 这与 `config.yaml` 里 `selftest.host_id` 那条教训是**同一条**：
#   **判据红的原因，不该是"环境不是我以为的那样"**。
# ★ 判据（实测）：真任务的编号长这样 `T + YYYYMMDD-HHMMSS + '-' + 6 位十六进制`
#   —— 库里 6351 条任务**全部**符合，而**唯三**不符合的**正好**就是那三条合成任务。
#   ★ 认不出这个形状的（包括将来可能出现的别种编号）**一律不点**：不猜、不赌，
#     宁可报一句"这次没验到"，也不拿一条来路不明的任务去替界面的导出能力背书。
REAL_TASK_ID = re.compile(r"^T\d{8}-\d{6}-[0-9a-f]{6}$")


def _real_tasks(ids):
    """把历史里的任务编号分成（真任务, 合成/不认识）两组 —— 只给真任务发"可点"许可。"""
    real = [t for t in ids if REAL_TASK_ID.match(t)]
    synth = [t for t in ids if not REAL_TASK_ID.match(t)]
    return real, synth


def _button_walk(c, log):
    """★★ T16（规范 §12.121 / 断言 Ⓢ ③）：**按钮级**走查 —— 清 T15 遗留的那条边界。

    ★ 原来的边界是「仅渲染与切换」：页签点得开、文字读得回，就记"走查通过"。
      但 T14 那颗「**三个导出入口全部 401**」的洞，恰恰是在**所有页签都不报错**的情况下存在的
      —— ★ 静态断言全绿、页签切换全绿，**只有真按下去才现形**。
      ⇒ 所以这里至少真点一次：**导出（.txt）** · **锁定 → 登录** · **改口令**。

    ★ 返回 `[(名称, ok, 细节)]`，其中 `ok=None` = **这次没验到**（跳过），当次说明为什么。
      ★ **跳过不算通过**：跳过的含义就是"这一次没验到"（与自检里那条「跳过 1」同一套规矩）——
        给它记一个"通过"，等于让走查替一段没跑过的路背书。
    """
    res = []

    def step(name, ok, detail):
        res.append((name, ok, detail))
        log("  %s %-16s %s" % ("✅" if ok else ("⏭" if ok is None else "❌"), name, detail))

    # ---- ① 导出（.txt）：历史 → 回放 → 真按一次 → **看它有没有落盘** ----
    # ★ 判据不是"按钮点下去了"，而是"下载目录里真出现了这个文件"（§12.117 同一族：
    #   收条 ≠ 事情成了）。
    dl_dir = PROFILE / "downloads"          # ★ 在 profile 里 ⇒ 随 `.gitignore` 的 `_cdp-*/` 一起不入库
    dl_dir.mkdir(parents=True, exist_ok=True)
    for f in dl_dir.glob("*"):
        try:
            f.unlink()
        except OSError:
            pass
    for meth in ("Browser.setDownloadBehavior", "Page.setDownloadBehavior"):
        try:
            c.call(meth, {"behavior": "allow", "downloadPath": str(dl_dir)})
            break
        except Exception:  # noqa: BLE001
            continue
    c.js("window.__aocErrs=[]")
    c.js("(function(){var e=document.querySelector('.tab[data-tab=\"history\"]');"
         "if(!e) return false; e.click(); return true;})()")
    time.sleep(2.0)
    # ★★ T18：先把历史里的任务**分队** —— 只对「真任务」发可点许可（合成任务一律不点）。
    ids = json.loads(c.js(
        "(function(){var o=[];document.querySelectorAll('#pane-history .task-item')"
        ".forEach(function(e){o.push(String(e.getAttribute('data-id')||''));});"
        "return JSON.stringify(o);})()") or "[]")
    real, synth = _real_tasks(ids)
    if synth:
        log("  ⏭ 不点这 %d 条**合成任务**（自检造出来的，回放里本来就没有导出段）：%s"
            % (len(synth), "、".join(synth[:5])))
    if not real:
        step("导出（.txt）", None,
             "历史里 %d 条，**没有一条**是真任务编号形状（跳过合成 %d 条）⇒ **这次没验到**"
             "（先跑一个真动作再走查）" % (len(ids), len(synth)))
    else:
        got, clicked, no_btn = None, "", []
        for tid in real[:5]:                    # ★ 最多试 5 条真任务（这一条没导出段就往后找）
            # ★★ 防御写在循环体里：「点到的必须是有导出段的**真任务**」这一条，
            #    **不许**靠"上游已经筛过了" —— 断言要能在被断的东西旁边站着。
            assert REAL_TASK_ID.match(tid), "走查点错对象：%r 不是真任务编号" % tid
            c.js("(function(){var e=document.querySelector("
                 "'#pane-history .task-item[data-id=%s]'); if(!e) return false;"
                 " e.click(); return true;})()" % json.dumps(tid))
            time.sleep(2.5)
            clicked = tid
            if not c.js("!!document.querySelector('#btnExportTxt')"):
                no_btn.append(tid)              # 这条回放里没有导出段 ⇒ 换下一条真任务
                continue
            c.js("document.querySelector('#btnExportTxt').click()")
            for _ in range(24):                 # 最多等 12 秒
                time.sleep(0.5)
                files = [p for p in dl_dir.glob("*") if not p.name.endswith(".crdownload")]
                if files:
                    got = max(files, key=lambda p: p.stat().st_mtime)
                    break
            break
        errs = json.loads(c.js("JSON.stringify(window.__aocErrs||[])") or "[]")
        if got and got.stat().st_size > 0:
            step("导出（.txt）", True,
                 "真点一次 ⇒ **落盘** %s（%d bytes）· 点的是真任务 %s · 运行时错误 %d 条"
                 % (got.name, got.stat().st_size, clicked, len(errs)))
        elif len(no_btn) == len(real[:5]):
            step("导出（.txt）", False,
                 "试了 %d 条**真任务**（%s），回放后**都没有**导出按钮 —— 界面回退了？"
                 % (len(no_btn), "、".join(no_btn)))
        else:
            step("导出（.txt）", False,
                 "按钮点了，但下载目录里**没有文件** —— 这一步正是「点了 ≠ 成了」（令牌？401？）· "
                 "点的是真任务 %s · 运行时错误 %d 条" % (clicked, len(errs)))

    # ---- ② 锁定 → 登录：真吊销一次服务端会话，再用口令走回门里 ----
    pw = os.environ.get("AOC_CONSOLE_PASSWORD", "")
    c.js("(function(){var b=document.getElementById('btnLogout'); if(!b) return false; b.click(); return true;})()")
    time.sleep(1.5)
    shown = c.js("!document.getElementById('login').classList.contains('hidden')")
    gone = c.js("!sessionStorage.getItem('aoc.token')")
    step("锁定", bool(shown and gone),
         "点「锁定」⇒ 门亮出来=%s、令牌已清=%s（服务端会话一并吊销）" % (shown, gone))
    if not pw:
        step("登录", None, "没给 AOC_CONSOLE_PASSWORD ⇒ **这次没验到**（口令只从环境变量来，不入库、不落盘）")
    else:
        c.js("document.getElementById('loginPw').value=%s" % json.dumps(pw))
        c.js("document.getElementById('loginBtn').click()")   # ★ 真按那颗按钮，不是直接调函数
        time.sleep(3.0)
        back_hidden = c.js("document.getElementById('login').classList.contains('hidden')")
        back_token = c.js("!!sessionStorage.getItem('aoc.token')")
        cards = c.js("document.querySelectorAll('#pane-actions .card').length") or 0
        step("登录", bool(back_hidden and back_token and cards),
             "真输口令 ⇒ 门关闭=%s、拿到新令牌=%s、动作卡片 %s 张" % (back_hidden, back_token, cards))

    # ---- ③ 改口令：★ 只点开看清，**不真改** ----
    # ★★★ 为什么不真改：改口令会**真的吊销所有已发令牌**并改掉用户存在环境变量里的那个秘密 ——
    #    那属于"走查把用户的真东西改掉了"（§12.97.1：口令只从环境变量来）。所以这一步断言的是
    #    **点开后的界面契约**（三个字段的显隐、标题、首字段标签），**不是**改口令这件事本身。
    c.js("(function(){var b=document.getElementById('btnChangePw'); if(!b) return false; b.click(); return true;})()")
    time.sleep(1.0)
    title = c.js("document.getElementById('loginTitle').textContent")
    old_w = c.js("!document.getElementById('loginPwOldWrap').classList.contains('hidden')")
    two_w = c.js("!document.getElementById('loginPw2Wrap').classList.contains('hidden')")
    label = c.js("document.getElementById('loginPw1Label').textContent")
    ok3 = (title == "改控制台口令") and bool(old_w) and bool(two_w) and label == "新口令"
    step("改口令（只点开）", bool(ok3),
         "标题=%r · 当前口令字段=%s · 两次输入=%s · 首字段=%r ★ **没真改**（真改会改掉你的秘密）"
         % (title, old_w, two_w, label))
    c.js("(function(){try{hideLogin();return 'closed';}catch(e){return 'no-hideLogin';}})()")
    return res


def main() -> int:
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    want = [t for t in TABS if not only or t[0] in only]

    if not _console_up():
        print("❌ 控制台没在跑（%s）。先在 repo\\ 下执行：python -m app.server" % BASE)
        return 2

    # ★★ T15·S10 两道**前置判据**（都来自真踩过的坑，宁可拒绝跑也别产出无效证据）
    rv, rs = _running_version()
    dv, ds = _disk_version()
    if (rv, rs) != (dv, ds):
        print("❌ **你正在给一个旧进程拍照**：跑着的是 %s · v%s，而磁盘上已经是 %s · v%s"
              % (rs, rv, ds, dv))
        print("   ⇒ 先重启控制台（`repo\\` 下：`python -m app.server`）再走查 ——")
        print("     否则新页签背后的接口在旧进程里**根本不存在**：图好看，**但无效**。")
        return 4
    print("✅ 版本对齐：磁盘 %s · v%s ＝ 正在跑的那一个" % (ds, dv))

    walk_tabs, html_tabs = _tabs_vs_html()
    if walk_tabs != html_tabs:
        print("❌ **走查表与界面页签对不上**（顺序也算）：")
        print("   走查表：%s" % walk_tabs)
        print("   界面里：%s" % html_tabs)
        print("   ⇒ 补 `TABS` / 改名 —— 否则**新页签永远没人看过**（T14 那颗洞就是这么来的）。")
        return 5
    print("✅ 走查表与界面页签一一对应（%d 个，顺序一致）" % len(walk_tabs))

    edge = next((p for p in EDGE_CANDIDATES if Path(p).is_file()), None)
    if edge is None:
        print("❌ 找不到 Edge / Chrome。用参数里的浏览器列表检查一下 EDGE_CANDIDATES。")
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    PROFILE.mkdir(parents=True, exist_ok=True)
    log_lines = []

    def log(s):
        print(s)
        log_lines.append(s)

    log("启动受控浏览器：%s（独立 profile + 独立调试端口 %d）" % (Path(edge).name, PORT))
    proc = subprocess.Popen(
        [edge, "--remote-debugging-port=%d" % PORT, "--user-data-dir=" + str(PROFILE),
         "--headless=new", "--no-first-run", "--no-default-browser-check",
         "--disable-extensions", "--disable-sync", "--window-size=1680,1500",
         "--hide-scrollbars", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)

    try:
        c = CDP(_find_page())
        c.call("Page.enable")
        c.call("Runtime.enable")
        c.call("Emulation.setDeviceMetricsOverride",
               {"width": 1680, "height": 1500, "deviceScaleFactor": 1, "mobile": False})
        c.call("Page.navigate", {"url": BASE + "/"})
        time.sleep(4)
        # ★★ T14：先过门，再走查 —— 否则所有页签的截图都是登录页（看着像"界面没做"）
        _login_in_page(c, log)
        # ★★ T15·S10：装一个**运行时错误收集器** —— 走查必须能抓「页签点下去就炸」这类洞
        #    （T14 那颗「三个导出入口全部 401」正是这一类：**静态断言全绿，真点才现形**）。
        #    ★ `capture=true` ⇒ **资源加载失败**（某张图 / 某个 js 404）也算进来。
        #    ★ 只在"页内"收集，**不动产品代码**；每个页签点之前清空，好归因到具体页签。
        c.js(
            "(function(){if(window.__aocErrs)return 'already';window.__aocErrs=[];"
            "window.addEventListener('error',function(e){"
            "var w=e.target&&e.target.tagName;"
            "window.__aocErrs.push((w?'resource '+w+' ':(e.message||'error'))+' @ '+"
            "String(e.filename||(e.target&&e.target.src)||'')+':'+String(e.lineno||''));},true);"
            "window.addEventListener('unhandledrejection',function(e){"
            "var r=e.reason;window.__aocErrs.push('unhandledrejection: '+String((r&&r.message)||r));});"
            "return 'installed';})()"
        )
        c.js("window.scrollTo(0,0)")
        title = c.js("document.title")
        ver = c.js("document.body.innerText.split('\\n').slice(0,3).join(' | ')")
        log("页面标题：%s" % title)
        log("页首：%s" % ver)

        snap = ["# 界面结论原文（文字快照）", "",
                "> ★★ 这是**机器可核的那一半**：界面真实渲染出来的文字，可以逐字比对。",
                "> 截图（`*.png`）只是**给人看的辅助**，不给独立结论权。",
                "> 生成时间：%s ｜ 控制台：%s ｜ 复跑：`python 工具\\capture-screenshots.py`"
                "（★ 口令走环境变量 `AOC_CONSOLE_PASSWORD`，**不写进脚本、不落盘**）"
                % (_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), BASE), ""]

        bad_tabs = []
        for tab, fname, note in want:
            c.js("window.__aocErrs=[]")          # ★ 每个页签**单独归因**
            c.js("window.scrollTo(0,0)")
            ok = c.js("(function(){var e=document.querySelector('.tab[data-tab=%s]');"
                      "if(!e) return false; e.click(); return true;})()" % json.dumps(tab))
            time.sleep(2.5)
            size = c.shot(OUT / fname)
            text = c.js("document.body.innerText") or ""
            raw_errs = c.js("JSON.stringify(window.__aocErrs||[])")
            try:
                errs = json.loads(raw_errs or "[]")
            except Exception:  # noqa: BLE001
                errs = ["<错误列表读不回来：%s>" % str(raw_errs)[:60]]
            token = c.js("!!sessionStorage.getItem('aoc.token')")
            if errs:
                bad_tabs.append(tab)
            log("📷 %-22s %8d bytes   %s（页签点击=%s，文本 %d 字符，"
                "**运行时错误 %d 条**，令牌仍在=%s）"
                % (fname, size, note, ok, len(text), len(errs), token))
            for _e in errs[:5]:
                log("     ⚠️ %s" % _e)
            snap += ["", "---", "", "## %s  ·  `%s`" % (note, fname), "",
                     "> 页签点击成功：**%s** ｜ 令牌仍在：**%s** ｜ 运行时错误：**%d** 条%s"
                     % (ok, token, len(errs),
                        ("　→　" + "；".join("`%s`" % _e for _e in errs[:5])) if errs else "（干净）"),
                     "", "```text", text.strip(), "```"]

        # ★★ T16（规范 §12.121 / 断言 Ⓢ ③）：**按钮级**走查 —— 清 T15 遗留的边界。
        #    ★ 位置刻意排在"页签逐个点过"**之后**：它要在一份已经确认不报错的界面上做，
        #      否则出了错分不清是页签本来就坏，还是这一段自己弄坏的。
        log("")
        log("🖱 按钮级走查（★ 真点一次：导出 / 锁定 / 登录 / 改口令）")
        btns = _button_walk(c, log)
        bad_btns = [n for (n, ok, _d) in btns if ok is False]
        skip_btns = [n for (n, ok, _d) in btns if ok is None]

        stamp = _dt.datetime.now().strftime("%Y%m%d")
        snap_path = OUT / ("界面-结论原文-%s.md" % stamp)
        snap += ["", "---", "", "## 按钮级走查（★ 真点一次）", "",
                 "> ★ 这一段存在的理由：T14 那颗「三个导出入口全部 401」的洞，是在**所有页签都不报错**的"
                 "情况下存在的 —— 静态断言全绿、切换全绿，**只有真按下去才现形**（规范 §12.121）。",
                 "> ★ `⏭` = **这次没验到**（跳过），**不算通过**。", ""]
        for (n, ok, d) in btns:
            snap.append("- %s **%s** —— %s" % ("✅" if ok else ("⏭" if ok is None else "❌"), n, d))
        snap_path.write_text("\n".join(snap) + "\n", encoding="utf-8", newline="\n")
        log("🅣 文字快照：%s（%d 行）" % (snap_path.name, len(snap)))

        # ★★ T15·S10：**走查自己也要有结论**（而且它决定退出码）
        #    —— 「拍到了 12 张图」不等于"12 个页签都没事"。
        if bad_tabs:
            log("❌ **有页签在运行时报错**：%s" % "、".join(bad_tabs))
        else:
            log("✅ %d 个页签逐个点过：**运行时 0 错误**（含资源加载失败）" % len(want))
        # ★★ T16：按钮级的结论**单独一行**，而且**它决定退出码 6**
        log("%s 按钮级：%d 步 —— 通过 %d · 失败 %d · 跳过 %d%s"
            % ("❌" if bad_btns else "✅", len(btns),
               len([1 for (_n, ok, _d) in btns if ok is True]), len(bad_btns), len(skip_btns),
               ("（失败：%s）" % "、".join(bad_btns)) if bad_btns else ""))
        for n in skip_btns:
            log("   ⏭ %s：**这次没验到**（跳过 ≠ 通过）" % n)

        (OUT / "_capture-log.txt").write_text("\n".join(log_lines) + "\n", encoding="utf-8", newline="\n")
        print("\n✅ 完成：%d 张截图 + 1 份文字快照 → %s" % (len(want), OUT))
        # ★ 退出码（按"哪一件更该被先修"排先后）：
        #   6 = 按钮级有失败（真按下去才现形的洞）· 3 = 页签运行时报错 · 0 = 两件都干净
        if bad_btns:
            return 6
        return 3 if bad_tabs else 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()
        print("已关闭受控浏览器进程（pid=%d）" % proc.pid)


if __name__ == "__main__":
    raise SystemExit(main())
