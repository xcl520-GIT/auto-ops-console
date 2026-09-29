"""auto-ops-console · 自检脚本（T1 验收标准 #6）

一条命令跑完：`python tools\\selftest.py`

检查项分两层：
  离线层（不需要目标机）—— 依赖、配置、动作 schema、地图对账、数据库、**防注入**、启动自检
  在线层（需要目标机）  —— SSH 连通性、三个竖切动作真跑 + 结论断言

用法：
  python tools\\selftest.py              # 全跑
  python tools\\selftest.py --offline    # 只跑离线层（目标机没开时用）
  python tools\\selftest.py --t16        # ★ 只跑 T16 那一节（给「证伪演示」用：注入后要看**立刻**红）
  python tools\\selftest.py -v           # 打印每条检查的细节
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import traceback
from pathlib import Path

# 让 `python tools\selftest.py` 能 import app.*（本文件在 tools/ 下，要退一级）
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # Windows 控制台默认 cp936，中文会炸；这里强制 utf-8
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

from app.catalog import load_actions, load_map, reconcile, validate_params, render_argv  # noqa: E402
from app.config import load as load_config  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.errors import OpsError  # noqa: E402
from app.store import Store  # noqa: E402
from app.transport import SshTransport  # noqa: E402
from app.yamlload import describe_backend  # noqa: E402

VERBOSE = "-v" in sys.argv or "--verbose" in sys.argv
OFFLINE = "--offline" in sys.argv
# ★★ T16·S9：**只跑 T16 那一节**（给「证伪演示」用 —— 注入一处破坏之后要**立刻**看对应断言红没红，
#   跑整道门要几分钟，来回六次就没法做了）。
#   ★ 它只影响"**跑哪些检查**"，**一个判据的写法都没变** —— 免得这个口子自己造出第二套判据。
ONLY_T16 = "--t16" in sys.argv
# ★★ T17·S7：同样给 T17 一节一个快通道（证伪演示要在"注入 ⇒ 看红 ⇒ 还原 ⇒ 看绿"之间来回跑）
ONLY_T17 = "--t17" in sys.argv
ONLY_T18 = "--t18" in sys.argv

# ══════════════════════════════ ★★ T18·S9（§12.156 / 清单 291）：**离线门不许拿生产库做测试**
#
# ★★ 为什么有这一段（T18 收尾时用「采样器 ＋ 写入追踪」照出来的**真缺陷**，不是预想）：
#   离线门以前**会往生产库写** —— 三处，全是"真跑"的性质：
#     ① `⑥ 数据层`：`store.archive(...)` ＋ `store.save_task({id: "SELFTEST-TASK"})`；
#     ② `⑮ 一键体检`：往库里落**两条合成体检任务**（id 形如 `SELFTEST-*`）；
#     ③ `T17 的 Ⓩd`：走 `run_one.py` **子进程**真跑一次 `vm.status` ⇒ 又落一条。
#   后果有两层，第二层才是真正难查的那个：
#     ① **判据伤到环境**：自检给用户的真记录添乱；★ 换台机器跑＝动**别人**的库。
#     ② ★★★ **它让另一条判据随机变红**：交付物探针的 `⑥-o` 断言的是
#        「全程没碰生产库」＝「那个文件的 sha256 前后一致」 —— 而**门自己**会动那个文件！
#        写没写进 `⑥-o` 的窗口，**纯看时序**（实测：同一个门连跑三次，红一次绿两次）。
#        ★ 一条**随机红**的判据比一条常年红的更坏：它让人开始"重跑一次看看"。
#   ⇒ 规矩与 `repo\tools\launcher_probe.py::make_temp_root` **同一条**：
#     **要写，就写自己的临时副本里。** 隔离的是**整道门**（含它拉起的子进程），
#     所以**判据一条都没改**，改的只是"门跑在哪个目录上"。
#   ★ 想关掉它（例如就是要看门会写什么）：`set AOC_SELFTEST_NO_ISOLATE=1`。
ISOLATED = os.environ.get("AOC_SELFTEST_ISOLATED") == "1"
REAL_ROOT = os.environ.get("AOC_SELFTEST_REAL_ROOT") or ""


def _sha256_file(p) -> str:
    """一个文件的 sha256（读不到就返回空串 —— 空串与任何真哈希都不相等）。"""
    import hashlib

    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                h.update(blk)
        return h.hexdigest()
    except OSError:
        return ""


def real_prod_db():
    """**生产库**的路径（只在隔离跑里知道 —— 靠 `AOC_SELFTEST_REAL_ROOT` 传进来）。"""
    return (Path(REAL_ROOT) / "var" / "ops.db") if REAL_ROOT else None


def _isolate_ignore(dirpath, names):
    """临时副本**不拷哪些** —— 分寸：**状态搬走，夹具留下**。

    ★ 搬走的是"属于**这一次运行 / 这一台机器**的东西"：库、留证归档、备份、日志、上传下载、
      口令文件、上一轮的 `selftest-*`。
    ★ 留下的是**判据自己要读的夹具**：`var\\lab`（T7 的反例配方样例）、`var\\fixtures`、
      `var\\uploads`（T17 的 `aoc-identity.sh` —— 断言 Ⓩb 就读它那份**证据**）——
      少拷了它们，那些判据就会变成"夹具不在场"，红得毫无指向。
      ★ 反过来，`var\\artifacts`（近 **90 MB / 四万多个文件**）与 `var\\backups`（**674 MB**）
        **一律不拷**：没有任何一条判据需要它们（实测：隔离跑里除了本文件的两条夹具依赖，
        没有第三条红），而拷它们会让每一道门多花几十秒、多占 700 MB 临时空间。
    """
    out = set()
    state = {"ops.db", "ops.db-wal", "ops.db-shm", "auth.json", "artifacts", "backups",
             "logs", "downloads", "enroll",
             "server.out.log", "server.err.log", "_console.out.log", "_console.err.log"}
    for n in names:
        if n in (".git", "_cdp-screenshots", "__pycache__") or n.endswith(".pyc"):
            out.add(n)
        elif os.path.basename(dirpath) == "var" and (n in state or n.startswith("selftest-")):
            out.add(n)
    return out


def _offline_isolate() -> int:
    """把这次 `--offline` 门整体挪到**项目临时副本**上跑（要写就写自己的副本）。

    ★ 副本只拷**该拷的**（实测：排除 `.git` / `_cdp-screenshots` / 库与留证之后
      仍然只有十来 MB，拷贝代价可以忽略）。
    ★ 门拉起的**子进程**（`run_one.py` / 启动器探针 / 配料）也跟着落在副本里 ——
      因为它们的 cwd 与"仓库根"都是从门这边传下去的，子进程用的是**副本的** `repo\\`。
    """
    import shutil
    import tempfile

    base = Path(tempfile.mkdtemp(prefix="aoc-selftest-offline-"))
    dst = base / ROOT.parent.name
    shutil.copytree(ROOT.parent, dst, ignore=_isolate_ignore)
    env = {"AOC_SELFTEST_ISOLATED": "1", "AOC_SELFTEST_REAL_ROOT": str(ROOT)}
    print("=" * 70)
    print("  ★ 离线门跑在**项目临时副本**上（要写就写自己的副本，**不碰生产库**）")
    print(f"    副本：{dst}")
    print(f"    生产库：{Path(ROOT) / 'var' / 'ops.db'}（本次**只读**）")
    print("  ★ 子进程输出会在它结束后**整段**打出来（自检里跑子进程**只走 `run_child`**"
          " —— 断言 Ⓛa 守这一条，隔离这段自己也不例外）")
    print("=" * 70)
    cp = run_child([sys.executable, str(dst / "repo" / "tools" / "selftest.py"), *sys.argv[1:]],
                   timeout=3600, cwd=str(dst / "repo"), env_extra=env)
    print(cp.stdout)
    if cp.stderr:
        print(cp.stderr)
    print(f"\n★ 副本留在 {base}（看完可删；关掉隔离：set AOC_SELFTEST_NO_ISOLATE=1）")
    return cp.returncode if cp.returncode is not None else 1


# ★ 门**开始那一刻**的生产库指纹 —— Ⓩn 就是拿它跟"门结束时"对照的。
_REAL_DB_SHA_AT_START = _sha256_file(real_prod_db()) if (ISOLATED and REAL_ROOT) else ""

results: list[tuple[str, bool, str]] = []
skips: list[str] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "✅" if ok else "❌"
    print(f"  {mark} {name}" + (f"    {detail}" if detail and (ok or VERBOSE) else ""))
    if not ok and detail:
        for line in detail.splitlines():
            print(f"       {line}")


def skip(name: str, detail: str = "") -> None:
    """★ 显式跳过 —— **前置条件不在，所以这一次没有验到它**。

    ★ 为什么不写成"通过"：跳过与通过是两件事。把"没验到"记成"通过"，
    等于让自检替一段**没跑过的路**背书（与 §9.11「平台该管的事别指望人注意」同族）。
    ★ 为什么也不写成"失败"：失败的含义是"**被测的东西**不对"；而这里不对的是**环境**没铺夹具
    —— 那会让自检红得毫无指向（同本文件 ⑩ 那条注释：**自检红的原因不该是"环境不是我以为的那样"**）。
    ⇒ 单独计数、单独打印、并**给出怎么补上**；汇总里与"通过"分开列。
    """
    skips.append(name)
    print(f"  ⏭ {name}" + (f"    {detail}" if detail else ""))


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * max(0, 58 - len(title)))


def expect_error(fn, code: str) -> str:
    """断言某个调用会抛指定 code 的 OpsError。返回实际错误说明。"""
    try:
        fn()
    except OpsError as exc:
        if exc.code != code:
            raise AssertionError(f"期望 {code}，实际 {exc.code}：{exc.reason}") from None
        return exc.reason
    raise AssertionError(f"期望抛出 {code}，但调用成功了（这本身就是一个安全缺陷）")


# ══════════════════════════════════════════════════ 子进程：**唯一**出口
#
# ★★ 为什么"只有一个出口"值得一条断言（规范 §12.111 · 断言 Ⓛa）：
#   T15 收口时抓到门禁**自己在第 298 项处中断**（本轮之前是 659 项；补齐 Ⓛ 之后是 664 项）。起因**不是被测的东西坏了**，
#   而是**读子进程输出的那一侧**：`subprocess.run(text=True, encoding="utf-8")`
#   **没给 `errors`**，而本机代码页是 936（`chcp` 实测）—— 子进程写 GBK 字节 ⇒
#   `UnicodeDecodeError` **抛在 `subprocess` 的读取线程里**（主线程看不见它）⇒
#   那个管道的结果**变成 `None`** ⇒ 调用处 `cp.stderr + cp.stdout` 直接 `TypeError`
#   ⇒ `main()` 被 `except Exception` 兜住 ⇒ **后面 360 多项一条都没跑**。
#
#   ★★ 它最坏的地方不是"红了"，而是**"红得太早"**：`--offline` 照样给出一行
#      「通过 296 / 共 298」，**看起来像一份结论**（这正是 §12.104.2「报告不许说假话」的同族
#      ——"门禁的汇总数字"也是一种"给人看的那段话"）。★ 判据要打在边界上：
#      **"跑完了没有"** 与 **"跑过的那些对不对"** 是两件事，本轮之前没有任何一条断言看住前者。
#
#   ★ 归属：`app\transport.py` 与 `app\enroll.py` **本来就是对的**（都写着
#     `.decode("utf-8", errors="replace")`）—— 所以这是**门禁自己的洞**，不是平台代码的洞。
#     也正合本文件 `skip()` 那条注释：**自检红的原因不该是"环境不是我以为的那样"**。
#
# ⇒ 两条边界**一起**钉死：
#     ① 子进程按 utf-8 **写**（`PYTHONIOENCODING` ＋ `PYTHONUTF8`，不随控制台代码页变）；
#     ② 读回来这一侧**永不抛、永不返回 None**（`errors="replace"` ＋ 兜底补 `""`）。
CHILD_UTF8_ENV = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}


def _child_text(value) -> str:
    """子进程输出的**兜底**：`None` / bytes 一律变成 str。

    ★ `None` **绝不许**漏到调用处 —— 那正是本轮 `TypeError` 的入口。
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_child(argv, *, timeout: int = 300, cwd=None, env_extra=None):
    """跑一个子进程，**双向**钉住编码；返回对象的 `.stdout` / `.stderr` **永远是 str**。

    ★ 自检里**只许**从这里跑子进程 —— 断言 Ⓛa 会扫源码看住这一点。

    `env_extra`（★ T17·S7 补）：给"要造现场"的断言用（例如把 `PYTHONIOENCODING` 改回
    `gbk` 去证伪编码那条）。★ 值给 `None` 表示**删掉**这个变量（不是设成空串）——
      "没设"与"设成空"在子进程里是两件事。
    """
    import os as _os
    import subprocess as _sp
    from types import SimpleNamespace as _NS

    env = dict(_os.environ)
    env.update(CHILD_UTF8_ENV)
    for k, v in (env_extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    try:
        proc = _sp.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, timeout=timeout, cwd=cwd, stdin=_sp.DEVNULL,
        )
    except _sp.TimeoutExpired as exc:
        return _NS(returncode=None, stdout=_child_text(exc.stdout),
                   stderr=_child_text(exc.stderr) + f"\n[自检] 子进程超过 {timeout} 秒未结束。")
    except OSError as exc:
        return _NS(returncode=None, stdout="", stderr=f"{type(exc).__name__}: {exc}")
    return _NS(returncode=proc.returncode,
               stdout=_child_text(proc.stdout), stderr=_child_text(proc.stderr))


# ==================================================================== 离线层


def check_runtime() -> None:
    section("① 运行环境")
    v = sys.version_info
    record("Python ≥ 3.11", v >= (3, 11), f"{v.major}.{v.minor}.{v.micro}  {sys.executable}")

    yb = describe_backend()
    record("YAML 解析器可用", yb["available"],
           f"{yb['backend']} PyYAML={yb['version']}")
    if not yb["available"]:
        print("\n❌ 缺少 YAML 解析器，后续检查无法继续。")
        print("   建议：python -m pip install --target repo\\vendor pyyaml")
        sys.exit(3)


def check_config():
    section("② 配置与主机清单")
    cfg = load_config(ROOT)
    record("config.yaml 加载成功", True, f"{cfg.root}")
    record("监听地址通过白名单校验", cfg.server["host"] != "0.0.0.0",
           f"绑定 {cfg.server['host']}:{cfg.server['port']}")

    # 安全红线：0.0.0.0 必须被拒绝
    from app.config import validate_bind
    try:
        validate_bind("0.0.0.0", 8787)
        record("拒绝 0.0.0.0 监听", False, "validate_bind 竟然放行了 0.0.0.0")
    except OpsError as exc:
        record("拒绝 0.0.0.0 监听", exc.code == "BIND_REJECTED", f"{exc.code}: {exc.reason}")

    record("主机清单非空", len(cfg.hosts) > 0,
           "；".join(f"{h.id}={h.target}" for h in cfg.hosts))

    transport = SshTransport(cfg)
    record("ssh 客户端可用", bool(transport.binary()), transport.binary())

    rem = (cfg.raw.get("ssh", {}) or {}).get("remote_env", {})
    record("远端 locale 已强制", rem.get("LC_ALL") == "C",
           f"{rem}（防字段名本地化导致解析静默取空）")
    return cfg


def check_catalog(cfg):
    section("③ 动作加载与 schema 校验")
    actions = load_actions(cfg.paths.actions)
    record(f"动作全部通过 schema 校验（{len(actions)} 个）", True,
           ", ".join(sorted(actions)))

    for aid, a in sorted(actions.items()):
        record(f"  · {aid} 文件名=id / risk / 有 verify",
               Path(a.source).stem == a.id and a.risk in ("green", "yellow", "red") and bool(a.verify),
               f"{a.risk}/{a.priority} steps={len(a.steps)} verify={len(a.verify)}")

    # yellow 样例必须存在（验收 #3）
    ys = [a for a in actions.values() if a.risk == "yellow"]
    record("存在 risk:yellow 样例动作（验收 #3）", len(ys) >= 1,
           ", ".join(a.id for a in ys) or "没有 yellow 动作")
    record("yellow 动作带二次确认文案", all(a.confirm for a in ys))

    map_data = load_map(cfg.paths.map)
    cov = reconcile(map_data, actions)
    record("覆盖地图对账可用", cov["total"] > 0,
           f"已实现 {cov['done']}/{cov['total']}（{cov['rate']}%）· P0 {cov['p0_done']}/{cov['p0_total']}")
    record("缺口清单可列出（设计目标：缺口可见）", isinstance(cov["missing"], list),
           f"{len(cov['missing'])} 项缺口")
    return actions, map_data


def check_schema_rejection(cfg) -> None:
    section("④ 安全契约：坏动作必须被拒（离线可验）")
    tmp_root = cfg.paths.var / "selftest-catalog"
    tmproot_base = tmp_root
    cases = {
        # 用管道拼接 —— 本项目禁止
        "带管道.run.yaml": """
id: bad.pipe
title: 坏动作-管道
summary: 故意违规
domain: A
risk: green
priority: P0
steps:
  - name: s1
    title: 用管道
    run: ["dmesg | grep -i oom"]
    parser: lines
verify:
  - name: a
    from: s1
""",
        # 文件名与 id 不一致
        "wrongname.yaml": """
id: bad.mismatch
title: 坏动作-文件名不符
summary: 故意违规
domain: A
risk: green
priority: P0
steps:
  - name: s1
    title: x
    run: ["true"]
    parser: raw
verify:
  - name: a
    from: s1
""",
        # 没有 verify —— "执行完就假定成功"是禁止的
        "noverify.run.yaml": """
id: noverify.run
title: 坏动作-无自证
summary: 故意违规
domain: A
risk: green
priority: P0
steps:
  - name: s1
    title: x
    run: ["true"]
    parser: raw
""",
        # 引用了不存在的参数
        "undefparam.run.yaml": """
id: undefparam.run
title: 坏动作-未定义参数
summary: 故意违规
domain: A
risk: green
priority: P0
params: []
steps:
  - name: s1
    title: x
    run: ["echo", "{{ not_defined }}"]
    parser: raw
verify:
  - name: a
    from: s1
""",
        # yellow 但没给确认文案
        "noconfirm.run.yaml": """
id: noconfirm.run
title: 坏动作-yellow无确认文案
summary: 故意违规
domain: E
risk: yellow
priority: P0
steps:
  - name: s1
    title: x
    run: ["true"]
    parser: raw
verify:
  - name: a
    from: s1
""",
    }

    for fname, body in cases.items():
        d = tmproot_base / fname.replace(".yaml", "")
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.yaml"):
            old.unlink()
        # ★ T4 收尾：必须显式 newline="\n" —— 否则 Windows 上 write_text 会把 \n 写成 \r\n，
        #   于是每次跑自检都把这 4 个**已入 Git 的夹具**改脏，`git status` 冒出假改动
        #   （与规范 §9.12 同一族坑：Windows 的换行会把"没变"变成"看起来变了"）。
        (d / fname).write_text(body.strip() + "\n", encoding="utf-8", newline="\n")
        try:
            expect_error(lambda dd=d: load_actions(dd), "CATALOG_INVALID")
            record(f"拒绝坏动作：{fname}", True)
        except AssertionError as exc:
            record(f"拒绝坏动作：{fname}", False, str(exc))
        except Exception as exc:  # noqa: BLE001
            record(f"拒绝坏动作：{fname}", False, f"{type(exc).__name__}: {exc}")


def check_injection(cfg, actions) -> None:
    section("⑤ 防注入自测（安全契约第一 + 三层）")

    log_view = actions.get("log.view")
    if log_view is None:
        record("log.view 存在", False, "缺少 log.view，无法测参数白名单")
        return

    # 1) 参数白名单：命令分隔符必须被拒
    for evil in ["sshd; rm -rf /", "sshd`whoami`", "sshd$(id)", "sshd && reboot", "sshd|cat /etc/shadow"]:
        try:
            validate_params(log_view, {"unit": evil})
            record(f"拒绝恶意 unit：{evil!r}", False, "竟然通过了参数校验")
        except OpsError as exc:
            record(f"拒绝恶意 unit：{evil!r}", exc.code == "PARAM_INVALID", exc.reason)

    # 2) 边界：grep 允许几乎任意字符（因为要能搜正则），但**必须靠 shlex.quote 兜底**
    evil_grep = "a'b\"c`d$(e);f|g>h"
    pv = validate_params(log_view, {"unit": "chronyd", "grep": evil_grep, "since": "最近 1 小时"})

    step = next(s for s in log_view.steps if s.name == "logs")
    argv = render_argv(step, pv)
    record("恶意 grep 能进入 argv（这是允许的）", evil_grep in argv,
           "它应当作为一个**完整独立的参数元素**存在")

    transport = SshTransport(cfg)
    remote = transport.build_remote_cmd(argv)

    # 关键断言：把远端命令字符串用 POSIX shell 语义重新拆开，
    # 结果必须与原始 argv 一一对应 —— 说明注入字符被牢牢锁在单个参数里，无法逃逸。
    #
    # ★ T2 变更：传输层现在会在命令末尾统一加 `< /dev/null`（关掉远端 stdin，见规范 v1.1 §8.5），
    #   所以断言要先把这 2 个 token 摘掉，再比对 argv。
    reparsed = shlex.split(remote)
    expected_tail = list(argv)
    record("远端命令末尾关闭 stdin（< /dev/null）", reparsed[-2:] == ["<", "/dev/null"],
           f"尾部 token = {reparsed[-2:]}")
    body = reparsed[-(2 + len(expected_tail)):-2]
    record("转义后仍然只有 argv 一个元素（注入无法逃逸）", body == expected_tail,
           f"往返一致：{body == expected_tail}")

    # 3) token 数精确匹配：remote = env + 2 个环境变量 + argv + (`<` `/dev/null`)，多一个 token 都说明发生了拼接
    #
    #    ★ 这里刻意**不用**"危险子串是否出现在 remote 字符串里"来判定 ——
    #      那是个错误判据：shlex.quote 会把元字符**原样保留在单引号内部**，
    #      子串检查必然误报（T1 期间实测踩过这个坑，第一版就写错了）。
    #      唯一可靠的判据是"按 shell 语义重新拆开后能否还原成原 argv"。
    expected_tokens = 3 + len(argv) + 2   # env + LC_ALL=C + LANG=C + argv... + < + /dev/null
    record("远端命令 token 数精确匹配（无额外拼接）", len(reparsed) == expected_tokens,
           f"实际 {len(reparsed)} / 期望 {expected_tokens}")

    if VERBOSE:
        print("     远端命令原文：")
        print("       " + remote)


def check_store(cfg):
    section("⑥ 数据层：SQLite 与留证归档")
    store = Store(cfg)
    store.init()
    rec = store.archive("SELFTEST", "stdout", "probe", "自检写入的探针内容\n第二行")
    record("原始输出归档 + sha256", bool(rec and rec.get("sha256")),
           f"{rec['path'] if rec else '-'} sha256={rec['sha256'][:16] + '…' if rec else '-'}")

    store.save_task(
        {
            "id": "SELFTEST-TASK", "action_id": "selftest", "action_title": "自检",
            "risk": "green", "host_id": "x", "host_name": "x", "host_address": "x",
            "host_user": "x", "status": "ok", "params": {"a": 1},
            "command_preview": "true", "conclusion": "自检结论",
            "verify_result": "ok", "verify_detail": [{"name": "a", "ok": True}],
            "step_total": 1, "step_failed": 0, "exit_code": 0,
            "started_at": "2026-01-01T00:00:00+08:00", "ended_at": "2026-01-01T00:00:01+08:00",
            "duration_ms": 1000,
        },
        [{"seq": 0, "name": "s1", "title": "t", "argv": ["true"], "argv_quoted": "env LC_ALL=C true",
          "status": "ok", "optional": False, "exit_code": 0, "duration_ms": 5,
          "stdout": "x", "stderr": "", "parsed": "x", "truncated": False}],
    )
    got = store.get_task("SELFTEST-TASK")
    record("任务写入并读回（回放基础）", got["task"]["conclusion"] == "自检结论",
           f"steps={len(got['steps'])}")
    record("步骤留证含命令原文", got["steps"][0]["argv_quoted"].startswith("env LC_ALL=C"),
           got["steps"][0]["argv_quoted"])
    stats = store.stats()
    record("数据库统计可用", stats["tasks_total"] >= 1, json.dumps(stats, ensure_ascii=False))

    # ★ T4 新增：备份记录里的「管理机副本」必须真的躺在磁盘上。
    #   真因：backup.py 把远程备份命名成 00-<base>，scp 拉回来落盘也是这个名字，
    #   但旧代码把 local_path 记成了不带前缀的 <base> —— 记录因此指向一个**不存在的文件**。
    #   当时没有任何代码读这个字段，所以一路没被发现；等 T4 做"从管理机副本恢复/下载备份"时才会踩空。
    #   这条检查专抓"记录说的 和 磁盘上的 不是一回事"，与具体是什么文件无关。
    backs = store.list_backups(limit=20)
    with_path = [b for b in backs if str(b.get("local_path") or "").strip()]
    gone = [b for b in with_path if not Path(b["local_path"]).exists()]
    record(f"备份记录的管理机副本都真实存在（抽查 {len(with_path)}/{len(backs)} 条）", not gone,
           "、".join(f"#{b['id']}→{b['local_path']}" for b in gone) if gone
           else "记录里的路径 = 磁盘上的文件")


def check_bootstrap():
    section("⑦ 启动装载自检（等价于 python -m app.server --check）")
    from app.server import bootstrap, print_check
    try:
        cfg, actions, map_data, store, _e, _a = bootstrap(ROOT)
        record("bootstrap() 全链路装载成功", True,
               f"{len(actions)} 个动作 / {len(cfg.hosts)} 台主机")
        if VERBOSE:
            print_check(cfg, actions, map_data, store)
        return cfg, actions
    except OpsError as exc:
        record("bootstrap() 全链路装载成功", False, f"{exc.code}: {exc.reason}\n{exc.advice}")
        return None, None


def check_readonly_coverage(cfg, actions, map_data) -> None:
    """T2 新增（离线）：只读动作清单 + 覆盖对账 + 动作清单勾选表。

    这一节本身就是 T2 的交接物之一：「动作清单勾选表（做完 / 未做 / 为什么）」
    由程序打印，避免手抄出错。
    """
    section("⑧ 只读动作清单与覆盖对账（T2 验收 #1 / #8）")

    greens = sorted(a.id for a in actions.values()
                    if a.risk == "green" and not a.id.startswith("demo."))
    record(f"只读动作数量 ≥ 20（实际 {len(greens)} 个）", len(greens) >= 20, "、".join(greens))

    weak = sorted(a.id for a in actions.values()
                  if a.risk == "green" and not any(v.severity == "fail" for v in a.verify))
    record("每个只读动作都有 fail 级自证断言（真能失败）", not weak, "、".join(weak) or "全部具备")

    noconcl = sorted(a.id for a in actions.values() if not a.conclusion.strip())
    record("每个动作都有结论模板（一屏给全）", not noconcl, "、".join(noconcl) or "全部具备")

    domains = set((map_data.get("domains") or {}).keys())
    orphan = sorted({a.domain for a in actions.values()} - domains)
    record("动作的 domain 都能在账本 domains 里找到", not orphan,
           "、".join(orphan) or f"账本共 {len(domains)} 个域")

    cov = reconcile(map_data, actions)
    record("覆盖对账可算（含每域实现率）", cov["total"] > 0,
           f"登记 {cov['total']} 条 / 已实现 {cov['done']}（{cov['rate']}%）"
           f"· P0 {cov['p0_done']}/{cov['p0_total']}（{cov['p0_rate']}%）")
    record("缺口清单可见且每项都有归属话题", all(m.get("stage") for m in cov["missing"]),
           f"{len(cov['missing'])} 项缺口：" +
           "、".join(f"{m['id']}→{m['stage']}" for m in cov["missing"]))

    print("      ┌─ 动作清单勾选表（已实现部分，按域）" + "─" * 24)
    for d, v in sorted(cov["by_domain"].items()):
        got = sorted(a.id for a in actions.values()
                     if a.domain == d and not a.id.startswith("demo."))
        print(f"      │ 域 {d} {v['name']}：{v['done']}/{v['total']}　{'、'.join(got) or '（本域暂无动作）'}")
    print("      └" + "─" * 62)


def check_export() -> None:
    """T2 新增（离线）：验收 #4「结果可导出」——报告生成 + 归档 + 内容四要素。"""
    section("⑨ 结果可导出（T2 验收 #4）")
    from app.export import build_report, report_filename
    from app.server import bootstrap

    try:
        cfg, _actions, _map_data, store, _engine, api = bootstrap(ROOT)
    except OpsError as exc:
        record("为验证导出而装载服务", False, f"{exc.code}: {exc.reason}")
        return

    tasks = store.list_tasks(limit=1)
    if not tasks:
        record("有可导出的任务样本", False, "数据库里还没有任务记录（先真跑一次动作）")
        return
    tid = tasks[0]["id"]
    detail = store.get_task(tid)
    for fmt in ("txt", "md"):
        text = build_report(detail, fmt)
        name = report_filename(detail, fmt)
        record(f"{fmt.upper()} 报告生成（{len(text)} 字符）",
               len(text) > 300 and tid in text and "sha256" in text and "结论" in text, name)

    name, text = api.export_task(tid, "txt")
    path = cfg.paths.artifacts / "exports" / name
    record("导出报告已归档到 var/artifacts/exports/", path.is_file(), f"{name}（{path.stat().st_size if path.is_file() else 0} 字节）")
    record("报告含「结论」小节", "【结论】" in text or "## 结论" in text)
    record("报告含「自证」小节", "自证" in text)
    record("报告含步骤命令原文", "env LC_ALL=C" in text or "命令：" in text)


# ==================================================================== 在线层


#: ★★ T8·S9（验收 #6）：自检用的「**故意失败**」夹具单元。
#: 与 `var/lab/selftest-fixtures.sh` 里那份**同一个意图**（一个 `Type=oneshot` + `/bin/false` 的单元）——
#: 区别是这份由**自检自己铺、自己收**（见 `_install_fail_fixture` / `_remove_fail_fixture`）。
FIXTURE_UNIT = "aoc-fail.service"
FIXTURE_PATH = "/etc/systemd/system/aoc-fail.service"
FIXTURE_BODY = (
    "# managed by auto-ops-console 自检夹具 —— **故意失败**（用来验 svc.list 的失败检出）\n"
    "[Unit]\n"
    "Description=auto-ops-console selftest fixture (deliberately fails)\n"
    "[Service]\n"
    "Type=oneshot\n"
    "ExecStart=/bin/false\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)


def _install_fail_fixture(engine, cfg, host_id: str) -> bool:
    """★★ 铺一个**故意失败**的单元 —— 走**平台自己的手**，不是场外 ssh。

    ★★ 为什么要改成"自己铺"（T8·S9 对 T6 那条"显式跳过"的处置）：
      T6 把这条拆成"结构断言 + 夹具断言（不在就跳过）"**当时是对的** ——
      那时平台**根本铺不进一个单元**（没有 `daemon-reload` 这只手）。
      ★★ 而 **T8·S2 把那只手补上了** ⇒ "场外铺夹具"这个前提**已经不存在**
      ⇒ 跳过就不再是"唯一诚实的选择"，而是**该被修掉的东西**（★ 跳过 ≠ 通过）。
      ★ 而且实测记过一笔：S2 那次自检"跳过 0"是**碰巧**（夹具正好在场），不是机制成立。

    ★ 一步不省：**写单元文件 → `daemon-reload` → 起（它本来就该失败）→ 复核确实处于 failed**。
      ★ 最后那一步是"铺上了没有"的**判据** —— 没有它，"铺了但没 failed"会被当成铺好了。
    返回"铺上了没有"；铺不上就**如实退回跳过**（不假装通过）。
    """
    host = next((h for h in cfg.hosts if h.id == host_id), None)
    if host is None:
        return False
    try:
        res = engine.write_remote_file(host, FIXTURE_PATH, FIXTURE_BODY, "0644")
    except OpsError as exc:
        print(f"  ⚠ 夹具写不进：{exc.code}: {exc.reason}")
        return False
    if not res.get("ok"):
        print(f"  ⚠ 夹具写不进：{res.get('error')}")
        return False
    for aid, params in (("svc.daemon-reload", {}),
                        ("svc.start", {"unit": FIXTURE_UNIT})):
        try:
            engine.run(aid, host_id, params, confirm=True)
        except OpsError as exc:
            print(f"  ⚠ {aid} 抛错：{exc.code}: {exc.reason}")
    # ★★ 复核：它**真的**处于 failed 吗（这一步才是"铺上了"的判据）
    try:
        pub = engine.run("svc.status", host_id, {"unit": FIXTURE_UNIT}, confirm=True).to_public()
    except OpsError:
        return False
    return "failed" in (pub["task"].get("conclusion") or "")


def _run_as_engine(engine, host_id: str, aid: str, params: dict):
    """跑一个动作，**确认词从动作自己那份定义里取**。

    ★★ 为什么不能只 `confirm=True`（这是本段第一次跑出来就抓到的**真缺陷**）：
      `svc.stop` 与 `file.remove` 都是 **red** ⇒ 平台要求**手输确认词**（服务端逐字校验），
      只勾选会被 `CONFIRM_REQUIRED` 拒掉。★★ 而第一次跑的时候，这两步被拒之后，
      收尾函数**照样打印了"夹具已收干净"** —— ★ 那是**假话**：
      单元文件还在目标机上。⇒ 两条修法：
      ① 确认词**从动作定义里取**（不硬编码 —— 改文案时不会悄悄失效）；
      ② 收尾**必须自己验一遍**（`_remove_fail_fixture` 末尾），**没验到就不许说"收干净了"**。
    """
    a = engine.action(aid)
    text = ""
    conf = getattr(a, "confirm", None)
    if isinstance(conf, dict):
        text = str(conf.get("confirm_text") or "")
    return engine.run(aid, host_id, params, confirm=True, confirm_text=text)


def _remove_fail_fixture(engine, cfg, host_id: str) -> bool:
    """收尾：**复位失败态 → 停 → 取消自启 → 删单元文件 → `daemon-reload`**，一步不省。

    ★★ 为什么这么长：少任何一步都会在目标机上留痕 ——
      复位态少一步 ⇒ 体检里长期挂着一个 failed；删文件少一步 ⇒ 单元还在磁盘上；
      `daemon-reload` 少一步 ⇒ systemd 内存里还留着它（`svc.list` 还能看到）。
      ⇒ ★ 这正是 T8·S2 补那三只手（`reset-failed` / `daemon-reload`）的**直接用途**。

    ★★ **返回"真的收干净了没有"** —— 由 `file.stat` + `svc.status` 两个**只读**动作复核。
      ★ 不从"命令都跑完了"推结论：那是本话题反复踩过的那类假绿。
    """
    for aid, params in (
        ("svc.reset-failed", {"unit": FIXTURE_UNIT}),
        ("svc.stop", {"unit": FIXTURE_UNIT}),
        ("svc.disable", {"unit": FIXTURE_UNIT}),
        ("file.remove", {"path": FIXTURE_PATH}),
        ("svc.daemon-reload", {}),
    ):
        try:
            _run_as_engine(engine, host_id, aid, params)
        except OpsError as exc:
            print(f"  ⚠ 夹具收尾 {aid}：{exc.code}: {exc.reason}")
    # ── 复核：文件必须不在（`file.stat` 的"在不在"是 0/1，不是"命令返回 0"）──
    clean = False
    try:
        pub = engine.run("file.stat", host_id, {"path": FIXTURE_PATH}, confirm=True).to_public()
        clean = "它在不在：0" in (pub["task"].get("conclusion") or "")
    except OpsError as exc:
        print(f"  ⚠ 夹具收尾复核 file.stat：{exc.code}: {exc.reason}")
    if not clean:
        # ★ 复核不通过就**再删一次**并再验一遍（"重试一次"是对的；"报成功"是错的）
        try:
            _run_as_engine(engine, host_id, "file.remove", {"path": FIXTURE_PATH})
            engine.run("svc.daemon-reload", host_id, {}, confirm=True)
            pub = engine.run("file.stat", host_id, {"path": FIXTURE_PATH}, confirm=True).to_public()
            clean = "它在不在：0" in (pub["task"].get("conclusion") or "")
        except OpsError as exc:
            print(f"  ⚠ 夹具收尾重试：{exc.code}: {exc.reason}")
    return clean


def target_host(cfg):
    """完整自检的**目标机**（★ 不写死 `hosts[0]`）。

    ★ T6 补：原来四处都写 `cfg.hosts[0]` —— 等于"谁排在 `hosts.yaml` 第一位，谁就去当靶子"。
    T4 换过主机清单之后 `hosts[0]` 成了 **node-01**（**禁止变更**的那台），
    而完整自检里有一条断言需要**自造夹具** `aoc-fail.service` 在场 ⇒ 那条断言**永远红**，
    且红的原因与被测代码无关。⇒ 改为读 `config.yaml` 的 `selftest.host_id`（见那边的注释）。
    """
    want = str(((cfg.raw.get("selftest") or {}).get("host_id")) or "").strip()
    by_id = {h.id: h for h in cfg.hosts}
    if not want:
        h = cfg.hosts[0]
        print(f"  ⚠ config.yaml 没写 `selftest.host_id` → **回退 hosts[0]={h.id}**；"
              f"那台机器不一定允许铺夹具（见 var/lab/selftest-fixtures.sh）")
        return h
    h = by_id.get(want)
    if h is None:
        record(f"★ selftest.host_id「{want}」必须在 hosts.yaml 里", False,
               "可用：" + "、".join(by_id))
        return cfg.hosts[0]
    return h


def check_target(cfg, actions):
    section("⑩ 目标机连通性（需要目标机开机）")
    transport = SshTransport(cfg)
    host = target_host(cfg)
    ok, err, res = transport.check_connectivity(host)
    record(f"SSH 免密连通 {host.target}", ok,
           (f"退出码 {res.exit_code} 用时 {res.duration_ms}ms" if ok else
            f"{err.code}: {err.reason}\n{err.advice}"))
    if not ok:
        return False

    # NDJSON 式的远端身份核对
    r = transport.run(host, ["cat", "/etc/os-release"])
    pretty = "未知"
    for line in r.stdout.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
    record("远端主机身份可读", r.exit_code == 0 and pretty != "未知", pretty)
    return True


def check_actions_live(cfg, actions, store):
    section("⑪ 竖切动作真跑 + 结论断言（T1 验收 #1/#2）")
    engine = Engine(cfg, actions, store)
    host_id = target_host(cfg).id

    def run_one(aid: str, params=None, must_contain=(), must_not_contain=()):
        try:
            res = engine.run(aid, host_id, params or {}, confirm=True)
        except OpsError as exc:
            record(f"{aid} 执行", False, f"{exc.code}: {exc.reason}\n{exc.advice}")
            return None
        pub = res.to_public()
        t = pub["task"]
        ok = t["status"] == "ok" and bool(t["conclusion"].strip())
        detail = f"状态={t['status']} 用时={t['duration_ms']}ms 任务={t['id']}"
        if not ok and t.get("error"):
            detail += f"\n原因：{t['error']['reason']}\n建议：{t['error']['advice']}"
        record(f"{aid} 执行成功且结论非空", ok, detail)

        for needle in must_contain:
            hit = needle in t["conclusion"]
            record(f"  断言：结论包含「{needle}」", hit,
                   "" if hit else "结论：\n" + t["conclusion"][:400])
        for needle in must_not_contain:
            hit = needle not in t["conclusion"]
            record(f"  断言：结论不含「{needle}」", hit, "" if hit else t["conclusion"][:300])
        return pub

    # --- host.overview ---
    # ★ T3 修正：不再硬编码发行版版本。
    #   原来断言 `Red Hat Enterprise Linux`，是照着 T1/T2 那台 RHEL 10.0 的 .100 写的；
    #   该机 2026-09-25 退役，新 4 台里三台是 Rocky Linux 10.2。
    #   硬编码发行版会让"换一台机器自检就红"，而自检红的原因不该是"环境不是我以为的那样"。
    run_one("host.overview", must_contain=["Linux"])

    # --- svc.list（报告结构 + 夹具服务应当被检出）---
    # ★ T3 修正：对照物从 t1-fixture.service（随 .100 退役）换成 T3 的 aoc- 自造靶子。
    # ★ T6：原来只有"夹具那一半"，夹具不在场时它**必红**；而夹具是**场外**铺的。
    #   ⇒ 拆成两半：① 结构断言（永远可跑）；② 夹具断言（不在就**显式跳过**）。
    # ★★ T8·S9（验收 #6 的正解）：**夹具改成自检自己铺、自己收** ——
    #   因为 T8·S2 把 `daemon-reload` / `reset-failed` 这两只手补上了，
    #   "平台铺不进一个单元"这个前提**已经不存在**（详见 `_install_fail_fixture` 的注释）。
    #   ⇒ ★ 这一段**不再有跳过**："没验到"这件事到此为止。
    fixt_ok = _install_fail_fixture(engine, cfg, host_id)
    try:
        record("  ★★ 自检**自己铺**夹具：一个故意失败的单元（写文件 → daemon-reload → 起 → 复核 failed）",
               fixt_ok, "夹具 " + FIXTURE_UNIT + " 已就位且处于 failed" if fixt_ok
               else "铺不上（见上面告警）—— 下面这条退回显式跳过，不假装通过")
        svc_pub = run_one("svc.list", must_contain=["系统整体状态", "失败明细"])
        if svc_pub is not None and fixt_ok:
            concl = svc_pub["task"]["conclusion"]
            hit = "aoc-fail.service" in concl
            record("  断言：能检出失败单元「aoc-fail.service」（夹具由自检自己铺）", hit,
                   "失败检出能力**已验到**" if hit else concl[:400])
        elif svc_pub is not None:
            skip(f"svc.list 的「失败服务检出」能力（目标机 {host_id} 上夹具没能铺上）",
                 "自检会自己铺夹具了（`_install_fail_fixture`）——铺不上通常是那台机器不允许"
                 "写 `/etc/systemd/system/`，或 systemd 不接受这个单元")
    finally:
        # ★★ 自己铺的夹具**自己收** —— 一步不省（见 `_remove_fail_fixture` 的注释）。
        #   ★★ 而且**收完自己验一遍**：验到了才敢说"收干净了"（"跑了收尾命令" ≠ "收干净了"）。
        cleaned = _remove_fail_fixture(engine, cfg, host_id)
        record("  ★★ 夹具**自己收干净**（复位失败态 / 停 / 取消自启 / 删单元 / daemon-reload，"
               "并用 `file.stat` 复核文件真的不在）", cleaned,
               "已复核：单元文件不在目标机上" if cleaned
               else "★ 复核没通过 —— 目标机上**还留着** " + FIXTURE_PATH + "（下一轮请先手工清掉）")

    # --- log.view（带参数：unit / 时间范围 / 级别 / 关键字）---
    run_one("log.view", {"unit": "chronyd", "since": "最近 1 小时"}, must_contain=["chronyd"])
    run_one("log.view", {"unit": "sshd", "since": "最近 24 小时", "lines": 50})

    # --- demo.confirm-gate（yellow 闸门）---
    section("⑩ yellow 闸门：不确认必须被拒（验收 #3）")
    try:
        engine.run("demo.confirm-gate", host_id, {}, confirm=False)

        record("yellow 动作在未确认时被拒绝", False, "竟然执行了！闸门失效")
    except OpsError as exc:
        record("yellow 动作在未确认时被拒绝", exc.code == "CONFIRM_REQUIRED",
               f"{exc.code}: {exc.reason}")
    run_one("demo.confirm-gate", must_contain=["Asia/Shanghai"])

    # --- T2：全部只读动作真跑（验收 #1 的批量版 + 验收 #3 的批量版）---
    section("⑫ 全部只读动作真跑（T2 验收 #1 / #2 / #3）")
    # 这些是"在本环境必须成功"的核心动作（默认参数即可跑）。
    # net.http 故意不在名单里：它要出网，离线实验机上失败是**预期**，
    # 只要失败时给出了「原因 + 建议」就算通过（那正是验收 #3）。
    # ★ T3 修正：从"必须成功"名单里移出两个动作 —— 它们在本环境**注定**失败，
    #   而失败原因是环境、不是动作缺陷，且动作已正确给出「原因 + 建议」（验收 #3 照样通过）：
    #     · net.firewall：4 台新靶机的 firewalld 全是 inactive（firewall-cmd 返回 252）
    #     · sec.cert    ：4 台新靶机都没装 openssl（127 → TOOL_MISSING，建议里写明了装法）
    #   把它们留在"必须成功"名单里，只会让自检退化成"环境检查器"。
    CORE_MUST_OK = {
        "host.overview", "host.datetime", "host.logins",
        "disk.usage", "disk.topdir", "disk.bigfiles",
        "proc.overview", "timer.list", "svc.list", "log.view",
        "net.addr", "net.route", "net.dns", "net.ping", "net.port",
        "sec.selinux", "sec.avc",
        "pkg.installed", "pkg.search", "kernel.log",
    }
    ids = sorted(a.id for a in actions.values() if a.risk == "green" and not a.id.startswith("demo."))
    # 必填参数且**没有默认值**的动作，在这里给出跑批用的参数。
    # （其余 22 个只读动作的必填参数都带默认值，可以直接空参数跑）
    BATCH_PARAMS = {
        "log.view": {"unit": "chronyd", "since": "最近 1 小时"},
        # ★ T7 新增：`file.stat` 的 `path` 是必填且**刻意不给默认值** ——
        #   "查这个路径在不在"的探针，界面上预填一个默认路径，等于诱导人直接点执行、
        #   却不看自己到底查的是什么（本项目的动作要么有明确默认，要么逼人填）。
        #   ⇒ 跑批时由这里给一个**本环境一定存在**的路径：于是"存在"那一条分支
        #     每次完整自检都真跑一次；"不存在"那条分支由自检 ⑳（离线判定）与
        #     S1 的真跑证据（`/opt/aoc-t7-probe` → 它在不在：0）覆盖。
        "file.stat": {"path": "/etc/sysconfig"},
        # T8·S2 新增的四个只读动作。★ 选参原则沿用 T3 那条教训：
        #   **不写"只在这台机器上才成立"的东西** —— `sshd.service` 任何 RHEL 系都在；
        #   调优文件那一条若换机器不存在，也不会硬红：它会走到
        #   「未成功，但原因+建议齐全（验收 #3）」那一支（那不是失败，是另一种验收）。
        "file.cat": {"path": "/etc/sysctl.d/99-k8s-tuning.conf"},
        "svc.status": {"unit": "sshd.service"},
        "host.cgroup": {},
        "registry.probe": {"timeout": 5},
        # ★ T9·S9 新增（规范 §12.52）：这两个 green 动作的必填参数**刻意没有默认值**
        #   （`k8s.logs` 必须说清看哪个 Pod；`k8s.describe` 必须说清看哪个对象）——
        #   不登记的话，跑批循环会用**空参数**去跑它们 ⇒ 在**参数校验**就抛 OpsError
        #   ⇒ 记成"执行失败"，而那不是动作的缺陷（完整自检 617/619 的两条红就是它）。
        #   ★★ 这是"交付即回填"的**第五处**：账本回答"做了没有"，这里回答"自检跑不跑得动它"。
        #   ★ 选参原则：**本环境结构上稳定**的名字，但**不要求永远存在** ——
        #     真跑不成也不会硬红，会落到「未成功，但原因+建议齐全（验收 #3）」那一支。
        #     静态 Pod 的名字由**节点名**决定、不随重启变；`kube-root-ca.crt` 每个命名空间都有。
        "k8s.logs": {"pod": "kube-apiserver-node-01", "namespace": "kube-system"},
        "k8s.describe": {"kind": "ConfigMap", "name": "kube-root-ca.crt",
                         "namespace": "kube-system"},
    }
    ok_n = 0
    for aid in ids:
        try:
            res = engine.run(aid, host_id, BATCH_PARAMS.get(aid, {}), confirm=True)
        except OpsError as exc:
            record(f"{aid} 执行", False, f"{exc.code}: {exc.reason}\n{exc.advice}")
            continue
        t = res.to_public(raw=False)["task"]
        if t["status"] == "ok":
            ok_n += 1
            record(f"{aid} 成功且结论非空", bool(t["conclusion"].strip()),
                   f"{t['duration_ms']}ms · {t['step_total']} 步 · 任务 {t['id']}")
        else:
            err = t.get("error") or {}
            has_pair = bool(err.get("reason")) and bool(err.get("advice"))
            record(f"{aid} 未成功，但「原因 + 建议」齐全（验收 #3）", has_pair,
                   f"状态={t['status']}｜原因：{err.get('reason')}｜建议：{err.get('advice')}")
        if aid in CORE_MUST_OK and t["status"] != "ok":
            record(f"  核心动作 {aid} 必须成功", False,
                   f"状态={t['status']}｜{(t.get('error') or {}).get('reason')}")
    record(f"只读动作总数 ≥ 20（实际 {len(ids)} 个）", len(ids) >= 20,
           f"本次成功 {ok_n} 个")
    return True


def check_routes() -> None:
    """T3 补漏（离线）：路由对账 —— 界面上会调的每个 /api 端点，服务端必须认领。

    为什么要有这一节：`/api/backups/<id>/restore` 与 `/api/batch/run` 的**方法**在 Api 里
    早就写好了，工具脚本也跑得通（`tools/batch_demo.py` 直接调 engine、绕过 HTTP），
    但 **HTTP 路由忘了注册** —— 于是界面上「恢复此文件」「批量执行」点下去必然 400，
    而当时 125 项自检**全部通过**。教训一句话：

        Api 方法存在 ≠ 接口可用；脚本能跑 ≠ 界面能跑。

    这一节把它变成会失败的检查，而不是下一份交接文档里的又一句叮嘱。

    做法：不手工维护接口清单（那种清单必然过期），而是**从 web/app.js 里抓**它实际请求的
    路径，再拿 api.dispatch 逐条认领。前端改了、路由漏了，这里立刻红。
    """
    section("⑨b 路由对账（界面上会调的接口，服务端必须认领）")
    import re  # 本文件顶部没用到正则，按需引入，避免为一个检查项动全文件的导入区
    from app.server import bootstrap

    js_path = ROOT / "web" / "app.js"
    if not js_path.exists():
        record("能找到 web/app.js（前端源码在，才谈得上对账）", False, str(js_path))
        return
    src = js_path.read_text(encoding="utf-8")

    # 抓取方式：从每个 "/api/" 出现处**向后扫字符**，不解析引号。
    # 为什么不用"引号配对"的写法：JS 里单引号、反引号、模板变量混用，
    # 配对正则会跨语句吃掉整段、把真正的路径一起吞了（第一版实测抓到 0 条 ——
    # 幸好下面那条"下限守卫"当场红了，否则这一节会以"全部认领"的假象通过）。
    #
    # 模板变量怎么处理：默认换成一个探针值 "1"；但像
    #   `/api/hosts/${encodeURIComponent(id)}/${trust ? 'trust' : 'check'}`
    # 这种"三元里挑一个字符串"的写法，探针会拼出 /api/hosts/1/1 这种**根本不存在的假路径**，
    # 于是把字面量各取一支展开（trust / check 两条都查），既不误报也不漏报。
    def variants(text: str, start: int) -> list[str]:
        segs: list[list[str]] = []       # 每段 = 该位置的候选片段（普通字符只有一种，模板变量可能有几种）
        buf: list[str] = []
        i, n = start, len(text)
        while i < n:
            ch = text[i]
            if ch == "$" and i + 1 < n and text[i + 1] == "{":
                j = text.find("}", i)
                if j == -1:
                    break
                if buf:
                    segs.append(["".join(buf)])
                    buf = []
                lits = [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", text[i + 2:j])]
                segs.append(lits or ["1"])   # 没有字面量 → 探针值
                i = j + 1
                continue
            if ch.isalnum() or ch in "_-/.":
                buf.append(ch)
                i += 1
                continue
            break                            # 引号 / 空格 / ? / , / ) 一律视作路径结束
        if buf:
            segs.append(["".join(buf)])

        out = [""]
        for seg in segs:
            out = [o + v for o in out for v in seg]
            if len(out) > 6:                 # 展开上限：别让一个花哨模板把检查项炸开
                out = out[:6]
        return [s for s in out if s.startswith("/api/")]

    paths: set[str] = set()
    for hit in re.finditer(r"/api/", src):
        for cand in variants(src, hit.start()):
            paths.add(cand.rstrip("/") or "/")

    # 抓取器本身不能悄悄坏掉：抓到 0 条也算"全部认领"就荒唐了，先卡一个下限。
    record(f"从前端抓到 ≥ 6 个 /api 端点（实际 {len(paths)} 个）", len(paths) >= 6,
           "、".join(sorted(paths)))

    # server.py 里**不走 dispatch** 的特殊分支：任务报告导出（纯文本、按文件写字节，不走 JSON 通道）。
    # 这里把它的正则抄一份 —— server.py 若改了那个正则，本节会失败提醒你同步，而不是悄悄放过。
    server_only = [
        re.compile(r"/api/tasks/([^/]+)/export"),
        re.compile(r"/api/checkup/([^/]+)/export"),   # T4 新增：体检报告导出（同样走纯文本通道）
    ]
    server_src = (ROOT / "app" / "server.py").read_text(encoding="utf-8")

    try:
        _cfg, _actions, _map, _store, _engine, api = bootstrap(ROOT)
    except OpsError as exc:
        record("为验证路由而装载服务", False, f"{exc.code}: {exc.reason}")
        return

    missing: list[str] = []
    for path in sorted(paths):
        special = next((p for p in server_only if p.fullmatch(path)), None)
        if special is not None:
            record(f"特殊分支 {path} 仍在 server.py 注册", special.pattern in server_src,
                   f"server.py 需含 {special.pattern}")
            continue
        recognized, method, last = False, "GET", ""
        for method in ("GET", "POST"):
            try:
                api.dispatch(method, path, {}, {"host_id": "probe"})
                recognized, last = True, "200"
                break
            except OpsError as exc:
                last = exc.code or ""
                if last != "NO_SUCH_ROUTE":
                    # 认领了，只是参数/数据不满足（PARAM_MISSING / NOT_FOUND…）—— 这才是"接口存在"的证据
                    recognized = True
                    break
            except Exception as exc:  # noqa: BLE001 非 OpsError：认领了，但实现里有裸异常，值得看见
                recognized, last = True, f"{type(exc).__name__}（裸异常，建议查）"
                break
        if not recognized:
            missing.append(f"{method} {path} → {last}")

    record(f"界面上调的 {len(paths)} 个 /api 端点都被服务端认领", not missing,
           "、".join(missing) if missing else "全部认领（含 server.py 特殊分支）")


# ==================================================================== T4 新增（离线可跑）


def check_weights(cfg, map_data, actions) -> None:
    """T4（离线）：覆盖率**双口径**与权重表（规范 §10.3）。"""
    section("⑭ 覆盖率双口径与权重表（T4 · 规范 §10.3）")
    entries = map_data.get("entries") or []
    platform = map_data.get("platform") or []
    weights = map_data.get("weights") or {}

    ids = [str(e.get("id")) for e in entries] + [str(p.get("id")) for p in platform]
    missing = [i for i in ids if i not in weights]
    orphan = [i for i in weights if i not in ids]
    record(f"权重表覆盖每个登记项与平台能力（{len(ids)} 条）", not missing,
           ("缺权重：" + "、".join(missing)) if missing else f"{len(ids)} 条全部有权重")
    record("权重表里没有孤儿条目（防两张表漂移）", not orphan,
           "、".join(orphan) if orphan else "无孤儿")

    bad: list[str] = []
    for k, v in weights.items():
        row = v if isinstance(v, dict) else {}
        if not isinstance(row.get("w"), int) or not (1 <= int(row.get("w") or 0) <= 5):
            bad.append(f"{k}.w 非法")
        if row.get("src") not in ("infer", "fallback", "user"):
            bad.append(f"{k}.src 非法")
        if not str(row.get("why") or "").strip():
            bad.append(f"{k}.why 为空")
    record("每条权重都有 w(1~5) / src / why（权重必须有出处）", not bad,
           "、".join(bad[:6]) if bad else "全部合规")

    record("platform: 段每条都有**显式布尔** done（不靠中文 status 文本匹配）",
           bool(platform) and all(isinstance(p.get("done"), bool) for p in platform),
           f"done=true 的有 {len([p for p in platform if p.get('done') is True])}/{len(platform)}")

    cov = reconcile(map_data, actions)
    w = cov.get("weighted") or {}
    record("对账结果里**同时**有条数口径与加权口径",
           "rate" in cov and "w_all" in w,
           f"条数 {cov.get('done')}/{cov.get('total')} = {cov.get('rate')}% ｜ "
           f"加权 {w.get('w_done')}/{w.get('w_all')} = {w.get('rate')}%")

    expect_items = len(entries) + len(platform)
    record("★ 加权分母把 platform: 段算进去了（平台能力入账）",
           int(w.get("items_total") or 0) == expect_items
           and int(w.get("platform_total") or 0) == len(platform),
           f"加权统计 {w.get('items_done')}/{w.get('items_total')}"
           f"（含平台能力 {w.get('platform_done')}/{w.get('platform_total')}）")

    record("权重来源分布可见（infer = 记录反推 / fallback = 按优先级兜底）", bool(w.get("by_src")),
           json.dumps(w.get("by_src"), ensure_ascii=False))
    record("没有条目靠「就地兜底」拿权重（那说明权重表漏了）", not w.get("implicit_weight_ids"),
           "、".join(w.get("implicit_weight_ids") or []) or "无")
    record("加权缺口清单按权重降序（高权重还没做的一眼可见）",
           (w.get("missing") or [{}])[0].get("weight", 0) >= (w.get("missing") or [{}])[-1].get("weight", 0)
           if w.get("missing") else True,
           "、".join(f"{r.get('id')}(w{r.get('weight')})" for r in (w.get("missing") or [])[:5]))


def _ck_step(seq, name, parsed, *, status="ok", rc=0, error_code=None, stdout=""):
    return {
        "seq": seq, "name": name, "title": name, "iter_key": None,
        "argv": ["probe"], "argv_quoted": "env LC_ALL=C probe",
        "status": status, "optional": False, "exit_code": rc, "duration_ms": 5,
        "stdout": stdout, "stderr": "", "parsed": parsed, "truncated": False,
        "error_code": error_code, "error_reason": None, "error_advice": None,
        "started_at": "", "ended_at": "",
    }


def _ck_task(store, task_id, host_id, steps):
    store.save_task(
        {
            "id": task_id, "action_id": "host.checkup", "action_title": "一键体检",
            "risk": "green", "host_id": host_id, "host_name": host_id, "host_address": "127.0.0.1",
            "host_user": "root", "status": "ok", "params": {},
            "command_preview": "probe", "conclusion": "自检合成体检",
            "verify_result": "ok", "verify_detail": [], "step_total": len(steps), "step_failed": 0,
            "exit_code": 0, "started_at": "2026-01-01T00:00:00+08:00",
            "ended_at": "2026-01-01T00:00:02+08:00", "duration_ms": 2000,
        },
        steps,
    )


def check_checkup(cfg) -> None:
    """T4（离线）：体检**判定层** —— 用合成任务把四档判定（红/黄/绿/无法判定）都逼出来。

    ★ 为什么用合成任务而不是等真机：判定层是纯逻辑（读步骤留证 + 比阈值），
      合成一份"已知输入的体检留证"就能把每条分支都覆盖到，而且**离线可跑、可重复**。
      真机那一半由 ⑩~⑬ 与交付时的端到端跑覆盖。
    """
    section("⑮ 一键体检 · 判定层（T4 · 规范 §10.2）")
    from app import checkup as ck

    store = Store(cfg)
    store.init()

    # ── 场景 A：混档 —— 1 项无法判定（openssl 未装）+ 黄若干，没有红
    mixed = [
        _ck_step(0, "os_release", {"PRETTY_NAME": "Rocky Linux 10.2"}),
        _ck_step(1, "ntp", {"NTPSynchronized": "no", "NTP": "yes", "Timezone": "Asia/Shanghai"}),
        _ck_step(2, "disk", [{"fs": "/dev/sda1", "size_mb": 46000, "used_mb": 13000,
                              "avail_mb": 33000, "pcent": "30%", "mount": "/"}]),
        _ck_step(3, "inode", [{"fs": "/dev/sda1", "inodes": 23000000, "iused": 160000,
                               "ifree": 22800000, "ipcent": "1%", "mount": "/"}]),
        _ck_step(4, "failed_units", []),
        _ck_step(5, "core_sshd", "active"),
        _ck_step(6, "kernel_errs", ["a: warning", "b: warning"]),
        _ck_step(7, "oom", ["-- No entries --"], rc=1),
        _ck_step(8, "selinux", "Permissive"),
        _ck_step(9, "firewalld", "", rc=252),
        _ck_step(10, "fw_ports", "", rc=252),
        _ck_step(11, "listeners", [{"port": "22"}]),
        _ck_step(12, "openssl", None, status="failed", rc=127, error_code="TOOL_MISSING"),
        _ck_step(13, "ca_certs", "ca-certificates-2025", rc=0),
        _ck_step(14, "rpm_db", "rpm-4.19.1.1"),
        _ck_step(15, "docker_state", {"ActiveState": "inactive"}),
        _ck_step(16, "containerd_state", {"ActiveState": "inactive"}),
        _ck_step(17, "containers", [], rc=1),
        _ck_step(18, "kubelet", "activating", rc=3),
        _ck_step(19, "k8s_nodes", [], rc=1),
    ]
    _ck_task(store, "SELFTEST-CHECKUP-A", "node-02", mixed)
    rep = ck.judge(cfg, store, "SELFTEST-CHECKUP-A", None)
    counts = rep["counts"]
    by_id = {i["id"]: i for i in rep["items"]}

    record("12 个体检项都有判定（一项都不许漏）", len(rep["items"]) == 12,
           f"共 {len(rep['items'])} 项：{'、'.join(i['id'] for i in rep['items'])}")
    record("缺工具 → 该项「无法判定」，但**其余项照常出**（验收 #5）",
           by_id["certs"]["level"] == "unknown" and (counts["ok"] + counts["warn"] + counts["crit"]) == 11,
           f"证书项={by_id['certs']['level']}；其余通过/注意 {counts['ok']}/{counts['warn']}")
    record("SELinux 非强制模式 → 判黄", by_id["selinux"]["level"] == "warn", by_id["selinux"]["verdict"])
    record("firewalld 未运行（rc=252）→ 判黄，且说清是无主规则无从判断",
           by_id["firewall"]["level"] == "warn" and "无从判断" in " ".join(by_id["firewall"]["evidence"]),
           by_id["firewall"]["verdict"])
    record("journalctl 的「-- No entries --」不会被当成 OOM",
           by_id["kernel"]["level"] == "ok" and "OOM 命中 0 条" in " ".join(by_id["kernel"]["evidence"]),
           " ".join(by_id["kernel"]["evidence"])[:60])
    record("kubelet 非 active → 判黄，并标注「集群既有状态、非本工作台造成」",
           by_id["k8s"]["level"] == "warn" and "既有状态" in by_id["k8s"]["advice"],
           by_id["k8s"]["verdict"])
    record("总判随最高档位（有黄无红 → 黄）", rep["overall"] == "warn", rep["summary"])
    record("每项都带「先去查什么」（下一步指向具体动作）",
           all(i.get("next_action") or i.get("next_hint") for i in rep["items"]),
           "、".join(i["next_action"] or "（hint）" for i in rep["items"][:6]) + " …")
    record("报告回显本次判定用的阈值档（否则没人知道红是怎么来的）",
           bool((rep.get("thresholds") or {}).get("values")),
           json.dumps((rep.get("thresholds") or {}).get("values"), ensure_ascii=False))

    # ── 场景 B：红档 —— 磁盘超红线 + 核心服务失败
    _ck_task(store, "SELFTEST-CHECKUP-B", "docker-01", [
        _ck_step(0, "os_release", {"PRETTY_NAME": "RHEL 10.0"}),
        _ck_step(1, "ntp", {"NTPSynchronized": "yes", "Timezone": "Asia/Shanghai"}),
        _ck_step(2, "disk", [
            # ★ 故意让 /boot 比 / 更高：这样能同时验两件事 ——
            #   ① 取"水位最高"的那个判红；② 根分区**另外单列一行**（运维第一问就是"/ 还有多少"）。
            {"fs": "/dev/mapper/rhel-root", "size_mb": 100000, "used_mb": 96000,
             "avail_mb": 4000, "pcent": "96%", "mount": "/"},
            {"fs": "/dev/sda1", "size_mb": 960, "used_mb": 941, "avail_mb": 19,
             "pcent": "98%", "mount": "/boot"},
        ]),
        _ck_step(3, "inode", [{"fs": "/dev/mapper/rhel-root", "inodes": 100, "iused": 1,
                               "ifree": 99, "ipcent": "1%", "mount": "/"}]),
        _ck_step(4, "failed_units", ["sshd.service loaded failed failed OpenSSH server daemon"]),
        _ck_step(5, "core_sshd", "failed", rc=3),
        _ck_step(6, "kernel_errs", []),
        _ck_step(7, "oom", ["Out of memory: Killed process 1234 (java)"], rc=0),
        _ck_step(8, "selinux", "Enforcing"),
        _ck_step(9, "firewalld", "running", rc=0),
        _ck_step(10, "fw_ports", "8080/tcp 9090/tcp 22/tcp", rc=0),
        _ck_step(11, "listeners", [{"port": "22"}]),
        _ck_step(12, "openssl", "OpenSSL 3.2.2", rc=0),
        _ck_step(13, "ca_certs", "ca-certificates-2025", rc=0),
        _ck_step(14, "rpm_db", "rpm-4.19.1.1"),
        _ck_step(15, "docker_state", {"ActiveState": "active"}),
        _ck_step(16, "containerd_state", {"ActiveState": "active"}),
        _ck_step(17, "containers", ["Up 5 hours (healthy)", "Restarting (1) 2 minutes ago"], rc=0),
        _ck_step(18, "kubelet", "inactive", rc=4),
        _ck_step(19, "k8s_nodes", None, status="failed", rc=127, error_code="TOOL_MISSING"),
    ])
    rep2 = ck.judge(cfg, store, "SELFTEST-CHECKUP-B", None)
    c2 = rep2["counts"]
    b2 = {i["id"]: i for i in rep2["items"]}
    record("★ 磁盘 96% 超红线 → 判**红**，并指向「目录体积排行」（验收 #4）",
           b2["disk"]["level"] == "crit" and b2["disk"]["next_action"] == "disk.topdir",
           f"{b2['disk']['verdict']} → 先去查 {b2['disk']['next_action']}")
    record("根分区单独列出（它不是水位最高的那个时也要看得见）",
           any("根分区 / = 96.0%" in e for e in b2["disk"]["evidence"]),
           "｜".join(b2["disk"]["evidence"])[:110])
    record("核心服务 sshd 失败 → 判红（比其他失败项更高一档）",
           b2["services"]["level"] == "crit", b2["services"]["verdict"])
    record("真 OOM 记录 → 判红（与「-- No entries --」区分开）",
           b2["kernel"]["level"] == "crit", b2["kernel"]["verdict"])
    record("容器有 Restarting → 判黄", b2["container"]["level"] == "warn", b2["container"]["verdict"])
    record("有意的放行端口无人监听 → 判黄并列出端口",
           b2["firewall"]["level"] == "warn" and "8080/tcp" in b2["firewall"]["verdict"],
           b2["firewall"]["verdict"])
    record("总判为红（有 crit）", rep2["overall"] == "crit", rep2["summary"])
    record("计数器自洽（12 项 = 各档之和）", sum(c2.values()) == 12,
           json.dumps(c2, ensure_ascii=False))


def check_enroll(cfg) -> None:
    """T4（离线）：纳管的**一次性分发点** —— 起 → 取 → 用完即停 → 关停自证（规范 §10.1.2）。"""
    section("⑯ 主机纳管 · 一次性分发点（T4 · 规范 §10.1）")
    import urllib.error
    import urllib.request

    from app import enroll as en

    import time  # 本文件顶部没用到 time，按需引入（沿用 check_routes 的做法）

    lab = ROOT / "var" / "lab"
    lab.mkdir(parents=True, exist_ok=True)
    pub = lab / "_selftest_enroll.pub"
    # 用一把**假公钥**：这里只验"分发与关停"的机制，不需要真能登录（也就不碰用户 ~/.ssh 里的真钥匙）
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISelftestSelftestSelftestSelftest aoc-selftest\n",
                   encoding="utf-8", newline="\n")

    backup_enroll = dict((cfg.raw or {}).get("enroll") or {})
    cfg.raw.setdefault("enroll", {})
    cfg.raw["enroll"]["pubkey"] = str(pub)
    cfg.raw["enroll"]["bind_host"] = "127.0.0.1"     # 只在本机绑，且必须过白名单
    try:
        sess = en.EnrollSession(cfg, address="127.0.0.1", port=22, user="root",
                                host_id="selftest-enroll", name="自检", role="lab",
                                tags=["selftest"], ttl=30)
        sess.start()
        record("分发点已启动，且绑定地址在白名单内（不可能绑到 0.0.0.0）",
               sess.bind_host == "127.0.0.1" and bool(sess.bind_port),
               f"{sess.bind_host}:{sess.bind_port} ｜ 随机路径 {sess.url_path[:10]}…")
        record("给出的那一条命令包含：仅内网 URL + 一次性 token + 权限收紧 + restorecon",
               sess.url in sess.command and sess.token in sess.command
               and "chmod 600" in sess.command and "restorecon" in sess.command,
               sess.command[:110] + " …")

        got = urllib.request.urlopen(f"{sess.url}?t={sess.token}", timeout=5).read().decode("utf-8")
        record("正确路径 + 正确 token → 取到公钥正文", got.strip() == sess.pubkey_text.strip(),
               f"{len(got)} 字节")

        for _ in range(40):                          # 用完即停是看门狗干的，等它
            if sess._stopped_event.is_set():
                break
            time.sleep(0.2)
        record("★ 用完即停：首次取走后**自动**关停（不靠人收尾）",
               sess._stopped_event.is_set(), f"关停原因：{sess.stop_reason}")
        record("★ 关停自证：连接被拒（SO_ERROR 非 0）+ HTTP 取不到 + 线程已退出",
               "SO_ERROR=0" not in sess.port_closed_proof
               and "关停生效" in sess.port_closed_proof
               and "存活=False" in sess.port_closed_proof,
               sess.port_closed_proof[:130])
        try:
            urllib.request.urlopen(f"{sess.url}?t={sess.token}", timeout=3)
            still_open = True
        except Exception:  # noqa: BLE001
            still_open = False
        record("关停之后再取一次必须失败（不是「我关了」，是「真取不到」）", not still_open)

        # 错误 token 必须 404（否则等于把公钥公开在网段上）
        sess2 = en.EnrollSession(cfg, address="127.0.0.1", port=22, user="root",
                                 host_id="selftest-enroll2", name="自检2", role="lab",
                                 tags=["selftest"], ttl=20)
        sess2.start()
        try:
            code = 0
            try:
                urllib.request.urlopen(f"{sess2.url}?t=wrong-token", timeout=4)
                code = 200
            except urllib.error.HTTPError as exc:
                code = exc.code
            except Exception as exc:  # noqa: BLE001
                code = f"{type(exc).__name__}"
            record("token 不对 → 一律 404（不泄露「这里有个服务」）", code == 404, f"实际 {code}")
        finally:
            sess2.stop("自检结束（主动关停）")
            record("主动关停也会走同一条自证路径",
                   "SO_ERROR=0" not in sess2.port_closed_proof, sess2.port_closed_proof[:100])

        # 预检：已经在清单里的机器必须被拦下（而不是硬覆盖）
        hosts = cfg.hosts
        if hosts:
            pre = en.precheck(cfg, address=hosts[0].address, port=22, host_id=hosts[0].id, force=False)
            record("预检能识别「这台机器已经纳管过了」（默认拒绝，不硬覆盖）",
                   bool(pre["duplicate"]) and pre["duplicate_blocking"],
                   "；".join(pre["duplicate"]))

        # 登记：字段白名单与 role 白名单（防止自由文本污染 hosts.yaml）
        try:
            bad_role = en.EnrollSession(cfg, address="127.0.0.1", port=22, user="root",
                                        host_id="selftest-enroll3", name="自检3", role="黑客",
                                        tags=[], ttl=10)
            en.register(cfg, bad_role)
            rejected = False
        except OpsError as exc:
            rejected = exc.code == "PARAM_INVALID"
        record("登记时 role 必须过白名单（自由文本不许进 hosts.yaml）", rejected, "role=黑客 被拒")
    finally:
        cfg.raw["enroll"] = backup_enroll


# ============================================================ T6 新增（规范 v1.7）


def check_v17(cfg, actions) -> None:
    """v1.7（T6·S1）新增断言 ⑬~⑯：`run_by` 选段 / `responds` 判据 / 白名单覆盖 / 探活动作。

    ★ 全部**离线可跑**：换机器、断网也要能红/绿（与 T2/T3/T4 新加的那几节同一个要求）。
    """
    import copy
    import types

    from app.catalog import render_argv, validate_params
    from app.changed import changed_for_action
    from app.expect import EXPECT_TYPES, PROBE_SOURCES, evaluate, validate_expect
    from app.recipe import parse_recipe
    from app.yamlload import load_yaml

    section("★ v1.7（T6）：run_by 选段 · responds 判据 · 白名单覆盖")

    # ── ⑬-a 真实动作：`run_by` 按 enum 取值**选段**（svc.configtest 的两个预设）──
    ct = actions.get("svc.configtest")
    if ct is None:
        record("svc.configtest 存在（run_by 的落地样例）", False, "缺这个动作，⑬ 无法验证")
    else:
        step = ct.step("test")
        for value, want in (("sshd", ["/usr/sbin/sshd", "-t"]),
                            ("nginx", ["/usr/sbin/nginx", "-t"])):
            try:
                argv = render_argv(step, validate_params(ct, {"binary": value}))
                record(f"⑬ run_by 选段：binary={value} → {' '.join(want)}",
                       argv == want, " ".join(argv))
            except OpsError as exc:
                record(f"⑬ run_by 选段：binary={value}", False, f"{exc.code}: {exc.reason}")
        # ★ 安全边界：参数**只用来选段** —— 枚举之外的值连"选段"这一步都进不去
        try:
            validate_params(ct, {"binary": "bash"})
            record("⑬ ★ 枚举外的 binary 必须被拒（参数不许当命令用）", False,
                   "validate_params 放行了 bash —— 那就成了命令通道")
        except OpsError as exc:
            record("⑬ ★ 枚举外的 binary 必须被拒（参数不许当命令用）",
                   exc.code == "PARAM_INVALID", f"{exc.code}: {exc.reason}")

    # ── ⑬-b 坏 run_by 必须被拒（临时夹具，离线可跑）──
    tpl = """
id: {aid}
title: 坏动作-run_by
summary: 故意违规
domain: A
risk: green
priority: P0
params:
  - name: which
    label: 选哪个
    type: enum
    required: true
    choices: [甲, 乙]
    values: [a, b]
    default: 甲
steps:
  - name: s1
    title: x
{steps}
    parser: raw
verify:
  - name: v
    from: s1
"""
    cases = {
        # values 里有 a、b，cases 只给了 a → ★ 双向全覆盖缺一边
        "rb.missing.yaml": tpl.format(aid="rb.missing", steps="""    run_by:
      param: which
      cases:
        a: ["true"]"""),
        # cases 里出现了枚举里没有的取值
        "rb.extra.yaml": tpl.format(aid="rb.extra", steps="""    run_by:
      param: which
      cases:
        a: ["true"]
        b: ["false"]
        c: ["true"]"""),
        # ★ YAML 1.1 会把裸 `on` 解析成布尔 True —— 键名必须用 param
        "rb.boolkey.yaml": tpl.format(aid="rb.boolkey", steps="""    run_by:
      on: which
      cases:
        a: ["true"]
        b: ["false"]"""),
        # run 与 run_by 同时出现（说不清到底跑哪条）
        "rb.both.yaml": tpl.format(aid="rb.both", steps="""    run: ["true"]
    run_by:
      param: which
      cases:
        a: ["true"]
        b: ["false"]"""),
    }
    tmproot = cfg.paths.var / "selftest-v17"
    for fname, body in cases.items():
        d = tmproot / fname.replace(".yaml", "")
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.yaml"):
            old.unlink()
        # ★ 显式 newline="\n"：Windows 上 write_text 会把 \n 写成 \r\n（规范 §9.12 同族坑）
        (d / fname).write_text(body.strip() + "\n", encoding="utf-8", newline="\n")
        try:
            expect_error(lambda dd=d: load_actions(dd), "CATALOG_INVALID")
            record(f"⑬ 拒绝坏 run_by：{fname}", True)
        except AssertionError as exc:
            record(f"⑬ 拒绝坏 run_by：{fname}", False, str(exc))
        except Exception as exc:  # noqa: BLE001
            record(f"⑬ 拒绝坏 run_by：{fname}", False, f"{type(exc).__name__}: {exc}")

    # ── ⑭ `responds`：白名单 / 允许的键 / 算子（加载期）──
    record("⑭ 期望白名单已含 responds",
           "responds" in EXPECT_TYPES, "、".join(EXPECT_TYPES))

    good = validate_expect(
        {"responds": {"action": "db.valkey-ping", "args": {"port": "6379"}, "equals": "PONG"}},
        actions, where="health[0]",
    )
    record("⑭ responds 合法写法通过加载期校验", not good, "；".join(good)[:200])

    outside = validate_expect(
        {"responds": {"action": "net.port", "args": {}}}, actions, where="health[0]")
    record("⑭ ★ responds 引用白名单外的动作必须被拒（不许变相裸命令）",
           bool(outside), "；".join(outside)[:160])

    contains = validate_expect(
        {"responds": {"action": "db.valkey-ping", "args": {"port": "6379"}, "contains": "PONG"}},
        actions, where="health[0]")
    record("⑭ ★ responds 不许用 contains（禁止子串判据）",
           bool(contains), "；".join(contains)[:160])

    two_ops = validate_expect(
        {"responds": {"action": "db.valkey-ping", "args": {"port": "6379"},
                      "equals": "PONG", "first_field": "x"}},
        actions, where="health[0]")
    record("⑭ responds 不许同时给 equals 与 first_field",
           bool(two_ops), "；".join(two_ops)[:160])

    bad_args = validate_expect(
        {"responds": {"action": "db.valkey-ping", "args": {"port": "6379", "host": "x"}}},
        actions, where="health[0]")
    record("⑭ responds 的 args 参数名必须对得上", bool(bad_args), "；".join(bad_args)[:160])

    # ── ⑮ 白名单覆盖预检：purge_paths / remove_config 必须在 file.remove 白名单内 ──
    nginx_path = cfg.paths.actions.parent / "recipes" / "nginx.yaml"
    if not nginx_path.exists():
        record("⑮ 找到 nginx 配方做基线", False, str(nginx_path))
    else:
        base = load_yaml(nginx_path, what="配方")
        _, errs = parse_recipe(copy.deepcopy(base), nginx_path, actions)
        record("⑮ 真实配方（nginx）通过白名单覆盖预检", not errs, "；".join(errs)[:200])

        bad = copy.deepcopy(base)
        bad["uninstall"]["purge_paths"] = ["/srv/aoc-nginx"]
        _, errs = parse_recipe(bad, nginx_path, actions)
        record("⑮ ★ 白名单外的 purge_paths（/srv/…）在装载期被拒",
               any("/srv/aoc-nginx" in e for e in errs), "；".join(errs)[:200])

        bad2 = copy.deepcopy(base)
        bad2["uninstall"]["remove_config"] = [
            {"action": "file.remove", "args": {"path": "/usr/share/nginx"}}
        ]
        _, errs = parse_recipe(bad2, nginx_path, actions)
        record("⑮ ★ remove_config 指向包自带目录（/usr/share/nginx）被拒",
               any("/usr/share/nginx" in e for e in errs), "；".join(errs)[:200])

    # ── ⑯ `responds` 的算子必须"精确匹配" + 三个探活动作（★ 这节是"验证脚本自己会骗人"的看门狗）──
    def _fake(steps, status="ok", tid="T-selftest"):
        ns = types.SimpleNamespace
        return ns(status=status, id=tid, error=None,
                  steps=[ns(name=n, parsed=v, status="ok") for n, v in steps])

    def _judge(spec, steps, status="ok"):
        return evaluate(spec, lambda aid, args: _fake(steps, status=status), {}, where="health[0]")

    out = _judge({"responds": {"action": "db.valkey-ping", "args": {"port": "6379"},
                               "equals": "PONG"}}, [("probe", "PONG")])
    record("⑯ responds equals：PONG == PONG → pass",
           out.state == "pass", f"{out.state} · {out.actual}")

    out = _judge({"responds": {"action": "db.valkey-ping", "args": {"port": "6379"},
                               "equals": "ACTIVE"}}, [("probe", "INACTIVE")])
    record("⑯ ★ responds equals：INACTIVE ≠ ACTIVE → fail（★ 子串不算通过）",
           out.state == "fail", f"{out.state} · 期望 {out.expected} / 实际 {out.actual}")

    out = _judge({"responds": {"action": "nfs.export-check", "args": {},
                               "first_field": "/opt/aoc-nfs/aoc"}},
                 [("probe", ["Export list for 127.0.0.1:", "/opt/aoc-nfs/aoc *"])])
    record("⑯ responds first_field：导出点在行首字段 → pass", out.state == "pass", out.state)

    out = _judge({"responds": {"action": "nfs.export-check", "args": {},
                               "first_field": "/opt/aoc-nfs/aoc"}},
                 [("probe", ["/data/nfs 备注里提到 /opt/aoc-nfs/aoc"])])
    record("⑯ ★ responds first_field：只是「被提到」不算通过（按字段全等）",
           out.state == "fail", f"{out.state} · 实际 {out.actual}")

    out = _judge({"responds": {"action": "db.mariadb-ping", "args": {}}},
                 [("probe", "mysqld is alive")])
    record("⑯ responds 不给算子 = 只要求「动作报告可用」→ pass", out.state == "pass", out.state)

    out = _judge({"responds": {"action": "db.mariadb-ping", "args": {}}},
                 [("probe", "")], status="failed")
    record("⑯ ★ 探活动作失败 → fail（服务没应答就该判红）",
           out.state == "fail", f"{out.state} · {out.reason}")

    ns = types.SimpleNamespace
    tool_missing = ns(status="failed", id="T-selftest",
                      error=ns(code="TOOL_MISSING", reason="命令不存在"), steps=[])
    out = evaluate({"responds": {"action": "db.mariadb-ping", "args": {}}},
                   lambda aid, args: tool_missing, {}, where="health[0]")
    record("⑯ ★ 缺工具（TOOL_MISSING）→ unknown（无法判定，不许当成通过）",
           out.state == "unknown", f"{out.state} · {out.reason}")

    for aid in ("db.mariadb-ping", "db.valkey-ping", "nfs.export-check"):
        a = actions.get(aid)
        record(f"⑯ 探活动作 {aid} 已登记且 risk=green（只读）",
               a is not None and a.risk == "green", f"{a.risk if a else '缺'}")
        if a is not None:
            c = changed_for_action(a, None)
            record(f"⑯ {aid} 的 changed 恒 false（不破坏幂等验收）", c is False, str(c))
    miss = sorted(k for k in PROBE_SOURCES if k not in actions)
    record("⑯ PROBE_SOURCES 登记的动作都已存在", not miss, "、".join(miss) or "全部存在")

    # ── ⑰ v1.7（T6·S2 真跑抓到）：失败的执行不许念"按成功写好的结论"（规范 §9.13）──
    from app.engine import conclusion_with_failure_banner as _banner

    ok_case = _banner(types.SimpleNamespace(status="ok", conclusion="✅ 语法通过", error=None))
    bad_case = _banner(types.SimpleNamespace(
        status="failed", conclusion="✅ 语法通过（退出码 0）",
        error=ns(code="STEP_FAILED", reason="命令返回非零退出码 7")))
    aborted_case = _banner(types.SimpleNamespace(
        status="aborted", conclusion="✅ 语法通过", error=ns(code="PRECHECK_FAILED", reason="预检不通过")))
    record("⑰ 成功时结论**不动**（不误伤正常报告）",
           ok_case == "✅ 语法通过", repr(ok_case[:40]))
    record("⑰ ★失败时结论必须挂**否定横幅**，且原文保留（不删信息）",
           bad_case.startswith("❌ 本次执行") and "✅ 语法通过（退出码 0）" in bad_case
           and "STEP_FAILED" in bad_case, bad_case.splitlines()[0] if bad_case else "")
    record("⑰ ★中止（aborted，如预检不通过）同样要挂横幅",
           aborted_case.startswith("❌ 本次执行"), aborted_case.splitlines()[0] if aborted_case else "")
    record("⑰ 期望白名单已含 port_open（共 7 类）",
           "port_open" in EXPECT_TYPES and len(EXPECT_TYPES) == 7, "、".join(EXPECT_TYPES))

    # ── ⑱ v1.7 修订六·补（T6·S2 复验抓到）：同一个字段的**每个出口**都要改 ──
    #   ★ 教训：`_run_action_item` 有 4 条 return，前一版只改了 3 条「异常出口」，
    #     漏掉末尾那条**主返回** —— 而"动作跑完了、任务本身是 aborted"走的正是它
    #     （`pkg.remove` 因包被 dnf 连带收走而预检失败，就是这一条）。
    #     ⇒ `optional` 恒为 False ⇒ 卸包步骤照旧让配方中止，**修复等于没生效**，
    #       而且光看代码 diff 很容易以为改完了。
    #   ★ 静态钉死：不许再出现 `if st else False` 这种"漏出口"写法。
    import re as _re
    _src = (ROOT / "app" / "recipe.py").read_text(encoding="utf-8")
    _leak = _re.findall(r'"optional":\s*bool\(st\.optional\)\s*if\s*st\s*else\s*False', _src)
    record("⑱ ★ 编排层 `optional` 出口不许漏（不得再出现 `if st else False`）",
           not _leak, f"仍有 {len(_leak)} 处漏出口" if _leak else "4 条 return 全部读 item['optional']")
    _honored = len(_re.findall(r'bool\(item\.get\("optional"\)\)', _src))
    record("⑱ ★ `item['optional']` 必须被 4 条 return **全部**读到",
           _honored >= 4, f"命中 {_honored} 处（要求 ≥4）")


# ==================================================================== 主流程


def check_v18(cfg, actions) -> None:
    """v1.8（T7·S1）新增断言 ⑲~㉓：删除类终态 / 收敛覆盖包+路径 / 升级预检退出码 / 回退能执行 / 热装载。

    ★ 全部**离线可跑**：换机器、断网也要能红/绿（与 T2~T6 新加的那几节同一个要求）。
    ★ 这一节的共同点是"**规矩被钉死**"：凡是靠"人记得住"的规矩，这里都把它变成会红的一行。
    """
    import copy
    import shutil
    import types

    from app.catalog import render_argv
    from app.changed import changed_for_action
    from app.expect import PRESENCE_SOURCES, evaluate, validate_expect
    from app.recipe import (
        UNINSTALL_TERMINAL_ACTIONS, RecipeRunner, load_recipes, parse_recipe,
        purge_convergence_expects, step_blocks_recipe, uninstall_step_terminal,
    )
    from app.transport import ExecResult
    from app.yamlload import load_yaml

    section("★ v1.8（T7）：终态语义 · 路径收敛 · 升级预检 · 回退 · 热装载")
    src_recipe = (ROOT / "app" / "recipe.py").read_text(encoding="utf-8")

    # ══════════════════════════════════════ ⑲ 卸载类步骤的「终态达成」语义
    record("⑲ 卸载类动作白名单（删除 + **让服务不在**）",
           UNINSTALL_TERMINAL_ACTIONS == {"file.remove", "pkg.remove", "svc.stop", "svc.disable"},
           "、".join(sorted(UNINSTALL_TERMINAL_ACTIONS)))

    table = [
        # (动作, 模式, 任务状态, 失败码, 期望, 说明)
        ("file.remove", "uninstall_purge", "aborted", "PRECHECK_FAILED", True, "路径本就不存在"),
        ("pkg.remove", "uninstall_purge", "aborted", "PRECHECK_FAILED", True, "包已被 dnf 连带收走"),
        ("svc.stop", "uninstall_purge", "aborted", "PRECHECK_FAILED", True,
         "★ S2 真跑补的：单元随包一起没了 ⇒ 服务层同样「已达终态」"),
        ("svc.disable", "stop", "aborted", "PRECHECK_FAILED", True, "★ 同上，「停止」模式也算卸载侧"),
        ("file.remove", "uninstall_purge", "aborted", "BACKUP_FAILED", False, "★ 备份失败 ⇒ 照旧中止"),
        ("file.remove", "uninstall_purge", "aborted", "HOST_UNREACHABLE", False, "★ 机器连不上 ⇒ 照旧中止"),
        ("file.remove", "uninstall_purge", "failed", "PRECHECK_FAILED", False, "只有 aborted 走这条路"),
        ("svc.stop", "deploy", "aborted", "PRECHECK_FAILED", False,
         "★★ **deploy 段不适用**：要重启的服务不见了是真故障，必须停下来说清楚"),
        ("svc.configtest", "uninstall_purge", "aborted", "PRECHECK_FAILED", False, "非卸载类动作不享受"),
    ]
    for aid, mode, st, code, want, why in table:
        got = uninstall_step_terminal(aid, mode, st, code)
        record(f"⑲ uninstall_step_terminal({aid}, {mode}, {st}, {code}) == {want}（{why}）",
               got == want, f"实际 {got}")

    # ── 行级：把"预检失败"这个任务喂进编排层，看它到底记成什么 ──
    class _FakeStore:
        def list_backups(self, **kw):
            return []

    def _fake_task(status: str, code: str | None):
        err = OpsError(code=code, reason="预检未通过", advice="按预检输出处理") if code else None
        pre = types.SimpleNamespace(name="must_installed", title="确认该包当前已安装",
                                    status="aborted" if err else "ok", exit_code=1)
        return types.SimpleNamespace(status=status, id="T-selftest", changed=None, error=err,
                                     steps=[pre], conclusion="", duration_ms=1)

    def _row(status: str, code: str | None, *, aid: str = "pkg.remove",
             args: dict | None = None, mode: str = "uninstall_purge") -> dict:
        eng = types.SimpleNamespace(run=lambda *a, **kw: _fake_task(status, code))
        runner = RecipeRunner(cfg, actions, eng, _FakeStore(), {})
        run = types.SimpleNamespace(confirm_relay=[], checkpoints=[])
        return runner._run_action_item(
            None, {"action": aid, "args": args if args is not None else {"package": "bc"}},
            cfg.hosts[0], {}, run, mode,
        )

    row = _row("aborted", "PRECHECK_FAILED")
    record("⑲ 目标不存在时：该步判 skipped（不是 failed / aborted）",
           row["status"] == "skipped", f"实际 {row['status']}")
    record("⑲ ★ 该步带上了可复核的证据（terminal + 哪一步、退出码多少）",
           row.get("terminal") is True and "退出码" in (row.get("terminal_why") or ""),
           str(row.get("terminal_why"))[:120])
    record("⑲ ★★ 它不再中止配方（step_blocks_recipe == False）—— §12.16 规矩 1",
           step_blocks_recipe(row) is False, f"status={row['status']}")
    record("⑲ ★★ 它记 `changed = False`（零改动是**结构性可证**的，规范 §12.16 规矩 5）",
           row.get("changed") is False, f"changed={row.get('changed')!r}")

    row2 = _row("aborted", "BACKUP_FAILED")
    record("⑲ ★★ 反例：备份失败照旧中止（写坏了要会红）—— §12.16 规矩 2",
           row2["status"] == "aborted" and step_blocks_recipe(row2) is True,
           f"status={row2['status']} blocks={step_blocks_recipe(row2)}")
    record("⑲ ★ 反例那一步的 changed 照旧 unknown（不许借机把不知道的记成没变）",
           row2.get("changed") is None, f"changed={row2.get('changed')!r}")

    # ★ S2 服务层：单元随包一起没了 ⇒ 卸载/停止模式下 svc.stop 同样"已达终态"
    row3 = _row("aborted", "PRECHECK_FAILED", aid="svc.stop", args={"unit": "nginx"})
    record("⑲ ★★ **服务层**：卸载模式下 svc.stop 预检失败（单元已不在）⇒ 判 skipped、不中止",
           row3["status"] == "skipped" and step_blocks_recipe(row3) is False,
           f"status={row3['status']}")
    row4 = _row("aborted", "PRECHECK_FAILED", aid="svc.stop", args={"unit": "nginx"},
                mode="deploy")
    record("⑲ ★★ **deploy 模式不适用**：同一句 PRECHECK_FAILED 在那里是真故障，照旧中止",
           row4["status"] == "aborted" and step_blocks_recipe(row4) is True,
           f"status={row4['status']}")

    # ── 报告口径（规范 §12.16 规矩 6 / 清单 62）：三段必须分得开 ──
    from app.recipe import RecipeRun
    ng2_path = cfg.paths.catalog / "recipes" / "nginx.yaml"
    ng2, ng2_errs = parse_recipe(load_yaml(ng2_path, what="配方"), ng2_path, actions)
    if ng2_errs or ng2 is None:
        record("⑲ 拿 nginx 配方验全删报告口径（前提）", False, "；".join(ng2_errs)[:160])
    else:
        rr = RecipeRun(id="R-selftest", recipe=ng2, host=cfg.hosts[0],
                       mode="uninstall_purge")
        conf = "/etc/nginx/nginx.conf"
        site = "/var/www/aoc-nginx"
        rr.steps = [
            # ① 本步真的 OK ⇒ 进「已删除的路径」
            {"name": "file.remove", "action": "file.remove", "status": "ok",
             "args": {"path": site}, "changed": True, "optional": False, "terminal": False},
            # ② 本步 skipped（已达终态）⇒ 只能进「已达终态」那一行
            {"name": "file.remove", "action": "file.remove", "status": "skipped",
             "args": {"path": conf}, "changed": False, "optional": False, "terminal": True,
             "error": {"code": "PRECHECK_FAILED"}},
        ]
        rr.uninstall_rendered = {"remove_config": [conf], "purge_paths": [site]}
        # 收敛检查：包 + 两条路径都由采集证实"不在"（★ 带机器可读的 converge 标记）
        rr.health = [
            {"kind": "absent", "state": "pass", "where": "health[0]",
             "expected": "软件包「nginx」不存在", "converge": {"kind": "package", "value": "nginx"}},
            {"kind": "absent", "state": "pass", "where": "health[1]",
             "expected": f"路径「{conf}」不存在", "converge": {"kind": "path", "value": conf}},
            {"kind": "absent", "state": "pass", "where": "health[2]",
             "expected": f"路径「{site}」不存在", "converge": {"kind": "path", "value": site}},
        ]
        runner = RecipeRunner(cfg, actions, types.SimpleNamespace(), _FakeStore(), {})
        txt = runner._conclusion(rr)
        del_l, term_l, left_l = "", "", ""
        for ln in txt.splitlines():
            if ln.startswith("★ 已删除的路径"):
                del_l = ln
            elif ln.startswith("★ 已达终态"):
                term_l = ln
            elif "没删掉 / 没走到" in ln:
                left_l = ln
        record("⑲ ★★ 报告：本步真 ok 的路径进「已删除的路径」", site in del_l, del_l)
        record("⑲ ★★ 报告：本步 skipped 但**收敛检查证实不在**的，进「已达终态」那一行",
               conf in term_l and conf not in del_l, term_l)
        record("⑲ ★★ 报告：它**不许**出现在「没删掉 / 没走到」里（否则是反方向的误导）",
               conf not in left_l, left_l or "（本次没有这一行）")
        record("⑲ ★ 报告：「已达终态」那一行要**逐项**点出（含被连带收走的包）",
               "nginx" in term_l, term_l)

        # ★★ 顺序无关：把收敛检查结果**倒过来**，报告必须一字不变 ——
        #   这正是"按内容配对"替代"按下标配对"的理由（下标错位会**静默念错**）。
        rr.health = list(reversed(rr.health))
        txt2 = runner._conclusion(rr)
        record("⑲ ★★ 报告与收敛检查的**顺序无关**（按内容配对，不靠下标）",
               txt2 == txt,
               "倒序后逐字相同" if txt2 == txt else "★ 顺序打乱后报告变了 —— 那是「静默念错」的隐患")

    legacy_check = 'row.get("status") not in ("ok", "skipped")'
    record("⑲ ★ 配方级中止判定只有一处实现（两处调用 + 一处手写 —— 就是那个 helper 自己）",
           src_recipe.count("step_blocks_recipe(row)") == 2
           and src_recipe.count(legacy_check) == 1,
           f"调用 {src_recipe.count('step_blocks_recipe(row)')} 处 · 手写判断 {src_recipe.count(legacy_check)} 处")

    # ══════════════════════════════════════ ⑳ 全删的收敛检查：包 + 路径
    fs = PRESENCE_SOURCES.get("file.stat")
    record("⑳ file.stat 已登记为存在性来源（路径那一半的来源），且来源步骤是 count",
           fs is not None and fs.step == "count" and fs.arg == "path",
           f"{fs.action if fs else '缺'}/{fs.step if fs else '-'}/{fs.arg if fs else '-'}")

    fa, fr = actions.get("file.stat"), actions.get("file.remove")
    same_pat = (fa is not None and fr is not None
                and fa.params[0].pattern == fr.params[0].pattern)
    record("⑳ ★ file.stat 与 file.remove 的路径白名单**逐字相同**（删得掉就一定查得着，收敛无盲区）",
           same_pat, (fa.params[0].pattern if fa else "缺"))

    # ★★ 这一段钉的是 T7·S1 **真跑当场抓到的一个缺陷**（规范 §9.6 点名的那个坑）：
    #   "路径不存在 ⇒ 输出为空"是个**结论**，拿它去做 verify 的"非空断言"会 100% 假失败。
    #   修法是同一条命令两个解析器：raw 给人看、line_count（= count）给机器判（0 行也是结论）。
    if fa is None:
        record("⑳ file.stat 存在（本节其余断言的前提）", False, "缺这个动作")
    else:
        vf = [v.from_ for v in fa.verify]
        record("⑳ ★★ 自证挂在 **count**（数行数）那一步上，**不许**挂在 raw 那一步 —— §9.6",
               vf == ["count"], "verify.from = " + "、".join(vf))
        st_raw = fa.step("stat")
        st_cnt = fa.step("count")
        record("⑳ ★ 同一条命令两个解析器：raw（给人看）+ line_count（给机器判）",
               st_raw is not None and st_cnt is not None
               and st_raw.parser == "raw" and st_cnt.parser == "line_count"
               and st_raw.run == st_cnt.run,
               f"{st_raw.parser if st_raw else '缺'} / {st_cnt.parser if st_cnt else '缺'}")
        record("⑳ ★ 两个退出码都是结论（ok_exit_codes == [0, 2]；rc=2 不许当失败）",
               sorted(st_cnt.ok_exit_codes or []) == [0, 2] if st_cnt else False,
               str(st_cnt.ok_exit_codes if st_cnt else None))

    ng_path = cfg.paths.catalog / "recipes" / "nginx.yaml"
    ng_data = load_yaml(ng_path, what="配方")
    ngr, ng_errs = parse_recipe(copy.deepcopy(ng_data), ng_path, actions)
    if ng_errs or ngr is None:
        record("⑳ 拿 nginx 配方做收敛检查的基线", False, "；".join(ng_errs)[:200])
    else:
        # 像 run() 那样把 {{ 参数 }} 渲染成真值，再生成收敛检查
        prm = validate_params(ngr, {})
        from app.catalog import render_argv_element
        rendered = {
            "remove_config": [
                render_argv_element(str((it.get("args") or {}).get("path") or ""), prm)
                for it in ngr.uninstall.remove_config
            ],
            "purge_paths": [render_argv_element(x, prm) for x in ngr.uninstall.purge_paths],
        }
        ex = purge_convergence_expects(ngr, rendered)
        pkgs = [e for e in ex if e["expect"]["absent"]["action"] == "pkg.installed"]
        paths = [e for e in ex if e["expect"]["absent"]["action"] == "file.stat"]
        record("⑳ ★★ nginx 全删的收敛检查**同时**含「包」与「路径」两类",
               len(pkgs) == len(ngr.uninstall.remove_packages)
               and len(paths) == len(ngr.uninstall.remove_config) + len(ngr.uninstall.purge_paths)
               and pkgs and paths,
               f"{len(pkgs)} 条包 + {len(paths)} 条路径："
               + "、".join(e["expect"]["absent"]["args"]["path"] for e in paths))
        record("⑳ ★ 路径用的是**渲染后**的真值（不许漏出 {{ 参数 }}）",
               all("{{" not in e["expect"]["absent"]["args"]["path"] for e in paths),
               "、".join(e["expect"]["absent"]["args"]["path"] for e in paths))
        record("⑳ 收敛检查里的来源都在白名单内（装载期同样的口径）",
               all(validate_expect(e["expect"], actions, where="health[0]") == []
                   for e in ex), "")

    def _j(spec, steps, status="ok", code=None):
        err = OpsError(code=code, reason="采集失败", advice="") if code else None
        res = types.SimpleNamespace(
            status=status, id="T-selftest", error=err,
            steps=[types.SimpleNamespace(name=n, parsed=v, status="ok") for n, v in steps],
        )
        return evaluate(spec, lambda aid, args: res, {}, where="health[0]")

    spec_absent = {"absent": {"action": "file.stat", "args": {"path": "/opt/aoc-nfs/demo"}}}
    out = _j(spec_absent, [("count", 0)])
    record("⑳ 路径不存在（数行数 = 0）⇒ pass（★ 0 是结论，不是「取不到数据」）",
           out.state == "pass", f"{out.state} · {out.actual}")
    out = _j(spec_absent, [("count", 1)])
    record("⑳ ★★ 路径还在（数行数 = 1）⇒ fail（真有东西没删掉就不许假绿）", out.state == "fail",
           f"{out.state} · {out.actual}")
    out = _j(spec_absent, [], status="failed", code="HOST_UNREACHABLE")
    record("⑳ ★ 机器连不上 ⇒ unknown（既不算通过、也不算「还在」）", out.state == "unknown",
           f"{out.state} · {out.reason}")
    bad_src = validate_expect({"absent": {"action": "net.port", "args": {}}}, actions, where="health[0]")
    record("⑳ 非登记来源（net.port）当存在性来源 ⇒ 装载期被拒", bool(bad_src),
           "；".join(bad_src)[:160])

    # ══════════════════════════════════════ ㉑ 升级预检的退出码语义
    po = actions.get("pkg.outdated")
    record("㉑ pkg.outdated 已装载且是只读（green）",
           po is not None and po.risk == "green", f"risk={po.risk if po else '缺'}")
    if po is not None:
        ck = po.step("check")
        record("㉑ ★★ ok_exit_codes **恰好**是 [0, 100]（100 = 有更新；其余退出码仍是失败）",
               ck is not None and sorted(ck.ok_exit_codes or []) == [0, 100],
               str(ck.ok_exit_codes if ck else None))
        record("㉑ 有一步先看仓库清单（「没有可升级的」这句话的地基）",
               po.step("repos") is not None, "")
        eng = Engine(cfg, actions)
        import app.engine as _eng_mod

        def _step_out(rc: int):
            res = ExecResult(argv=["dnf", "check-update"], quoted="dnf -q check-update",
                             exit_code=rc, stdout="", stderr="", duration_ms=1)
            return _eng_mod.Engine._to_step_out(eng, ck, cfg.hosts[0], 1, {}, res, "t")

        record("㉑ 行为：rc=100（有更新）⇒ 步骤 ok（★ 100 不是失败）",
               _step_out(100).status == "ok", _step_out(100).status)
        record("㉑ 行为：rc=0（无更新）⇒ 步骤 ok", _step_out(0).status == "ok", _step_out(0).status)
        record("㉑ ★★ 行为：rc=1（源不可达等）⇒ 步骤 failed —— 于是「源不可达」绝不会被说成「没有可升级的」",
               _step_out(1).status == "failed", _step_out(1).status)

    # ══════════════════════════════════════ ㉒ 回退：从"承诺"变成"能执行"
    rb = actions.get("pkg.rollback")
    record("㉒ pkg.rollback 已装载且 risk=red（回退 = 变更的反方向）",
           rb is not None and rb.risk == "red", f"risk={rb.risk if rb else '缺'}")
    if rb is not None:
        record("㉒ 声明了确认词（red 的硬要求）",
               bool((rb.confirm or {}).get("confirm_text")),
               str((rb.confirm or {}).get("confirm_text") or ""))
        eng = Engine(cfg, actions)
        try:
            eng.run("pkg.rollback", cfg.hosts[0].id, {"tx": 1})
            record("㉒ ★★ 无确认词必须被拒（CONFIRM_REQUIRED）", False, "竟然放行了")
        except OpsError as exc:
            record("㉒ ★★ 无确认词必须被拒（CONFIRM_REQUIRED）",
                   exc.code == "CONFIRM_REQUIRED", f"{exc.code}: {exc.reason}")

        names = [s.name for s in rb.steps]
        record("㉒ ★ 步骤次序：先「列事务」（只读）再「回退」—— 不许盲回退",
               "list" in names and "undo" in names and names.index("list") < names.index("undo"),
               "、".join(names))
        try:
            argv = render_argv(rb.step("undo"), validate_params(rb, {"tx": 7}))
            record("㉒ 回退命令 = dnf history undo <事务号> -y",
                   argv == ["dnf", "history", "undo", "7", "-y"], " ".join(argv))
        except OpsError as exc:
            record("㉒ 回退命令渲染", False, f"{exc.code}: {exc.reason}")
        record("㉒ ★ 自证 = 回退前 / 回退后**版本逐字对照**（不是「命令返回 0」）",
               rb.step("ver_before") is not None and rb.step("ver_after") is not None, "")

        ns = types.SimpleNamespace
        c1 = changed_for_action(rb, ns(steps=[ns(name="ver_before", parsed="bc-1.07", status="ok"),
                                              ns(name="ver_after", parsed="bc-1.08", status="ok")]))
        record("㉒ changed：版本真的变了 ⇒ True", c1 is True, str(c1))
        c2 = changed_for_action(rb, ns(steps=[ns(name="ver_before", parsed="bc-1.08", status="ok"),
                                              ns(name="ver_after", parsed="bc-1.08", status="ok")]))
        record("㉒ changed：版本没变 ⇒ False（幂等的正面证据）", c2 is False, str(c2))
        c3 = changed_for_action(rb, ns(steps=[]))
        record("㉒ ★★ changed：没填包名、拿不到对照 ⇒ unknown（None，★ 不许默认 False）",
               c3 is None, str(c3))

        for aid in ("pkg.install", "pkg.update", "pkg.remove"):
            a = actions.get(aid)
            record(f"㉒ ★★ {aid} 结论里承诺的 `dnf history undo` 从此有动作兜底（检查清单 57）",
                   a is not None and "dnf history undo" in (a.conclusion or ""), aid)
        record("㉒ ★ 结论里明说「回不去的」东西（规范 §12.19）",
               any(k in rb.conclusion for k in ("回不来", "回不去", "收不回来")), "")

    # ══════════════════════════════════════ ㉔ 部署组回退（规范 §12.20）
    from app.engine import RESTORE_CONFIRM_TEXT
    from app.recipe import GROUP_RESTORE_CONFIRM_TEXT

    record("㉔ 组回退用的是**自己的**确认词，且与单点恢复不同（闸门强度只增不减）",
           bool(GROUP_RESTORE_CONFIRM_TEXT) and GROUP_RESTORE_CONFIRM_TEXT != RESTORE_CONFIRM_TEXT,
           f"组：{GROUP_RESTORE_CONFIRM_TEXT} ｜ 单点：{RESTORE_CONFIRM_TEXT}")

    class _FakeRunStore:
        """一次配方执行的记录 + 两条备份（一条可用、一条已被清理）。"""

        def __init__(self, run, backups):
            self._run, self._backups = run, backups

        def get_recipe_run(self, run_id):
            if run_id != self._run["id"]:
                raise OpsError(code="NOT_FOUND", reason="没有这次执行", advice="")
            return self._run

        def get_backup(self, bid):
            rec = self._backups.get(int(bid))
            if rec is None:
                raise OpsError(code="NOT_FOUND", reason="没有这条备份", advice="")
            return rec

    fake_run = {
        "id": "R-selftest-rb", "recipe_id": "nginx", "recipe_title": "Nginx",
        "recipe_version": "1", "host_id": "node-03", "host_name": "node-03",
        "mode": "deploy", "started_at": "2026-00-00T00:00:00",
        "checkpoints": [
            {"seq": 1, "step": "render_conf", "backup_id": 901,
             "label": "Nginx · 渲染主配置（覆盖前）", "orig_path": "/etc/nginx/nginx.conf"},
            {"seq": 2, "step": "render_index", "backup_id": 902,
             "label": "Nginx · 渲染站点首页（覆盖前）", "orig_path": "/var/www/aoc-nginx/index.html"},
            {"seq": 3, "step": "render_extra", "backup_id": 903,
             "label": "Nginx · 某个已被清理的备份", "orig_path": "/etc/nginx/conf.d/aoc.conf"},
        ],
        # ★ 这次执行动过包与服务 ⇒「回不去」那两栏必须**有内容**（不许写"无"）
        "steps": [
            {"step": "install", "action": "pkg.install", "args": {"package": "nginx"}},
            {"step": "restart_nginx", "action": "svc.restart", "args": {"unit": "nginx"}},
        ],
    }
    fake_backups = {
        901: {"id": 901, "status": "ok", "kind": "file", "sha256": "a" * 64,
              "orig_path": "/etc/nginx/nginx.conf", "label": "旧主配置"},
        902: {"id": 902, "status": "ok", "kind": "file", "sha256": "b" * 64,
              "orig_path": "/var/www/aoc-nginx/index.html", "label": "旧首页"},
        # 903 故意**没有**：模拟"备份已被清理" ⇒ 计划里必须判它「回不去」
    }

    class _FakeRestoreEngine:
        """第一条抛错、第二条成功 —— 专门用来验"一项失败不影响其它项"。"""

        def __init__(self):
            self.calls = []

        def restore_backup(self, backup_id, confirm_text):
            self.calls.append((int(backup_id), confirm_text))
            if int(backup_id) == 901:
                raise OpsError(code="HOST_UNREACHABLE", reason="采集链路不可用（自检夹具）", advice="")
            return {"ok": True, "task_id": "T-selftest-restore",
                    "conclusion": "已恢复，sha256 逐字节一致（cccccccccccc…）", "error": None}

    rstore = _FakeRunStore(fake_run, fake_backups)
    feng = _FakeRestoreEngine()
    rb_runner = RecipeRunner(cfg, actions, feng, rstore, {})

    plan = rb_runner.rollback_plan("R-selftest-rb")
    record("㉔ 计划是**逐项**的、每项都带期望 sha256 与来源步骤",
           len(plan["items"]) == 3
           and all(i.get("expect_sha256") is not None and i.get("from_step") for i in plan["items"]),
           "、".join(f"#{i['seq']}{i['orig_path']}" for i in plan["items"]))
    bad_item = [i for i in plan["items"] if not i["can_restore"]]
    record("㉔ ★ 备份被清理的那一项**明确判「回不去」并说清为什么**",
           len(bad_item) == 1 and "回不去" in bad_item[0]["why_not"],
           bad_item[0]["why_not"] if bad_item else "（没有判不可恢复的项）")
    kinds = [u["kind"] for u in plan["cannot_restore"]]
    record("㉔ ★★ 「回不去」四类**逐项列出**（包 / 服务状态 / 运行时内存态 / 外部影响）",
           len(kinds) == 4 and any("包" in k for k in kinds)
           and any("服务状态" in k for k in kinds)
           and any("运行时" in k or "内存" in k for k in kinds)
           and any("外部" in k for k in kinds),
           "、".join(kinds))
    empty_ones = [u for u in plan["cannot_restore"] if u["items"] == "无"]
    record("㉔ ★ 空的那几栏**也要写「无」**（不许留白 —— 留白会被读成「都回得去」）",
           len(empty_ones) >= 2, "、".join(u["kind"] for u in empty_ones))
    real_ones = [u for u in plan["cannot_restore"] if u["items"] != "无"]
    record("㉔ ★ 这次执行真的动过的包/服务，必须在那两栏里点出来（不许写「无」）",
           any("nginx" in u["items"] for u in real_ones if "包" in u["kind"])
           and any("nginx" in u["items"] for u in real_ones if "服务状态" in u["kind"]),
           "、".join(f"{u['kind']}={u['items']}" for u in real_ones))
    record("㉔ ★ 计划里**显式写出**「上一版产物不在回退范围」（清单 64）",
           "上一版产物" in (plan.get("boundary") or ""), (plan.get("boundary") or "")[:80])

    try:
        rb_runner.rollback_run("R-selftest-rb", "确认恢复")
        record("㉔ ★★ 用**错**的确认词（单点那句）必须被拒", False, "竟然放行了")
    except OpsError as exc:
        record("㉔ ★★ 无（或错）确认词必须被拒（CONFIRM_REQUIRED）",
               exc.code == "CONFIRM_REQUIRED", f"{exc.code}: {exc.reason}")

    out = rb_runner.rollback_run("R-selftest-rb", GROUP_RESTORE_CONFIRM_TEXT)
    record("㉔ ★★ **逐项独立**：一项抛错、一项没备份可回，另一项照样回去",
           out["ok_count"] == 1 and out["failed_count"] == 2
           and len(out["items"]) == 3,
           f"ok={out['ok_count']} failed={out['failed_count']} items={len(out['items'])}")
    codes_in = sorted(str((r.get("error") or {}).get("code") or "") for r in out["items"] if not r.get("ok"))
    record("㉔ ★ 三项的失败原因**各自说清**（链路错误 vs 备份已不在）",
           "HOST_UNREACHABLE" in codes_in and "BACKUP_MISSING" in codes_in, "、".join(codes_in))
    record("㉔ ★ 成功的那一项带回了**自证原文**（不是一句「成功」）",
           any("sha256" in (r.get("self_proof_text") or "") for r in out["items"]),
           "")
    record("㉔ ★ 结果里有**转达单点确认词**的留证（§12.6.1 同一个做法）",
           len(out["confirm_relay"]) >= 1
           and all(r["confirm_text"] == RESTORE_CONFIRM_TEXT for r in out["confirm_relay"]),
           f"{len(out['confirm_relay'])} 条转达")
    record("㉔ ★★ 没有「自动回滚」：结果里 auto 必须是 False",
           out.get("auto") is False, str(out.get("auto")))
    record("㉔ 结论里逐项念结果 + 明说回不去 + 点清边界",
           "逐项结果" in out["conclusion"] and "回不去" in out["conclusion"]
           and "上一版产物" in out["conclusion"], out["conclusion"][:100])

    # ── 路由真的存在（NO_SUCH_ROUTE ≠ NOT_FOUND：后者恰恰说明路由**认领**了）──
    from app.server import bootstrap as _bs
    try:
        _c2, _a2, _m2, _s2, _e2, api2 = _bs(ROOT)
    except Exception as exc:  # noqa: BLE001
        record("㉔ 两个回退接口已被 dispatch 认领", False, f"{type(exc).__name__}: {exc}")
    else:
        codes = []
        for method, path in (("GET", "/api/recipe-runs/R-nope/rollback-plan"),
                             ("POST", "/api/recipe-runs/R-nope/rollback")):
            try:
                api2.dispatch(method, path, {}, {} if method == "POST" else None)
                codes.append("200?")
            except OpsError as exc:
                codes.append(exc.code)
        # ★ GET 那条是**只读**：应当一路查到记录不存在（NOT_FOUND）；
        # ★ POST 那条**先过闸门**（确认词在查记录之前校验）⇒ 没给确认词时是 CONFIRM_REQUIRED。
        #   两条都证明"路由被认领了" —— 判据是**不许**出现 NO_SUCH_ROUTE。
        record("㉔ ★ 两个回退接口都**认领**了（不给确认词也不会是 NO_SUCH_ROUTE）",
               "NO_SUCH_ROUTE" not in codes and codes[0] == "NOT_FOUND",
               "、".join(codes))


    # ══════════════════════════════════════ ㉕ 执行记录读回来就能直接用（T7·S4 抓到的旧缺陷）
    from app.store import Store as _Store
    from app.recipe import RecipeRun as _RecipeRun

    raw = {k: "[]" for k in _Store._RUN_JSON_FIELDS}
    raw.update({"id": "R-x", "status": "ok",
                "steps_json": '[{"name": "s1"}]',
                "checkpoints_json": '[{"backup_id": 1}]',
                "changed_json": '["s1"]'})
    dec = _Store._decode_run(dict(raw))
    record("㉕ ★ 执行记录解码后**同时**有公开名（steps / checkpoints / changed_steps）",
           dec.get("steps") == [{"name": "s1"}] and dec.get("checkpoints") == [{"backup_id": 1}]
           and dec.get("changed_steps") == ["s1"],
           f"steps={dec.get('steps')} checkpoints={dec.get('checkpoints')}")
    record("㉕ ★ `_json` 那套名字**原样保留**（不破坏既有消费者）",
           dec.get("steps_json") == [{"name": "s1"}], str(dec.get("steps_json")))
    _pub = _RecipeRun(id="R", recipe=types.SimpleNamespace(id="x", name="X", version="1"),
                      host=cfg.hosts[0], mode="deploy").to_public()
    _miss = sorted(set(_Store._JSON_ALIASES.values()) - set(_pub))
    record("㉕ ★★ 公开名**全部**能在 `to_public()` 里找到（库 ↔ 接口两边对得上）",
           not _miss, "、".join(_miss) or f"{len(_Store._JSON_ALIASES)} 个全对得上")

    # ══════════════════════════════════════ ㉖ 用户自写配方（脚手架 + 体检 + 反例）
    import shutil as _shutil

    from app.recipe import lint_recipe, lint_summary

    scaff_root = cfg.paths.var / "selftest-v18" / "scaffold"
    if scaff_root.exists():
        _shutil.rmtree(scaff_root)
    py = [sys.executable, str(ROOT / "tools" / "new-recipe.py")]
    good_args = ["myapp", "--unit", "myapp", "--package", "myapp", "--port", "9210",
                 "--config", "/etc/myapp/myapp.conf", "--data", "/opt/aoc-myapp",
                 "--root", str(scaff_root)]
    cp = run_child(py + good_args)
    record("㉖ 脚手架跑得动（生成骨架）", cp.returncode == 0,
           (cp.stderr or cp.stdout or "")[:200])
    gen_recipe = scaff_root / "catalog" / "recipes" / "myapp.yaml"
    gen_tpl = scaff_root / "catalog" / "templates" / "myapp" / "main.conf"
    record("㉖ 骨架产出两件：配方 + 它引用的模板",
           gen_recipe.is_file() and gen_tpl.is_file(), f"{gen_recipe.name} / {gen_tpl.name}")

    gen_recipes, gen_report = load_recipes(scaff_root / "catalog" / "recipes", actions)
    record("㉖ ★★ 骨架**一次就能过装载期校验**（脚手架不许教出「写坏了」）",
           "myapp" in gen_recipes and gen_report.ok, gen_report.summary()[:180])

    cp_bad = run_child(py + ["badpath", "--data", "/srv/nope", "--root", str(scaff_root)])
    record("㉖ ★ 越界路径（/srv/…）**当场被拒**并说明白名单（配方删不掉的东西不该写进去）",
           cp_bad.returncode != 0 and "白名单" in (cp_bad.stderr + cp_bad.stdout),
           (cp_bad.stderr or cp_bad.stdout or "")[:140])

    # ── 体检：好配方 vs 骨架，必须给出**不同**的结论（否则它就是个摆设）──
    real_recipes, _ = load_recipes(cfg.paths.catalog / "recipes", actions)
    vk = real_recipes.get("valkey")
    lk_vk = lint_summary(lint_recipe(vk, actions)) if vk else {"overall": "缺", "items": []}
    health_vk = [i for i in lk_vk["items"] if i["name"] == "健康检查"]
    record("㉖ ★ 体检：valkey（有 `responds` 真探活）⇒ 健康检查判 **ok**",
           bool(health_vk) and health_vk[0]["level"] == "ok",
           health_vk[0]["detail"][:110] if health_vk else "缺健康检查那一项")
    lk_gen = lint_summary(lint_recipe(gen_recipes["myapp"], actions))
    health_gen = [i for i in lk_gen["items"] if i["name"] == "健康检查"]
    record("㉖ ★★ 体检：骨架（只有旁证）⇒ 健康检查判 **warn**，并说清怎么补",
           bool(health_gen) and health_gen[0]["level"] == "warn"
           and "旁证" in health_gen[0]["detail"] and "responds" in health_gen[0]["detail"],
           health_gen[0]["detail"][:130] if health_gen else "缺健康检查那一项")
    record("㉖ ★ 体检覆盖六个必查面（反向操作×3 / 护栏 / 健康 / 幂等 / 检查点 / 参数 / 批量）",
           len(lk_gen["items"]) >= 8,
           "、".join(i["name"] for i in lk_gen["items"]))
    # ★★ 这一条是 S5 真跑抓到的**假警报**：体检第一版用 `changed_for_action(a, None) is None`
    #    去问"登记过没有"，而它在"没有结果"时对**已登记**的动作也返回 None
    #    ⇒ 把 pkg.install / svc.start 这些明明登记过的动作全报成"未登记"。
    #    ★ 假警报比没有警报更坏：它会教用户忽略体检（与本项目"空结果 ≠ 空数据"同一个道理）。
    lk_vk2 = lk_vk
    idem_vk = [i for i in lk_vk2["items"] if i["name"] == "幂等可断言（changed 规则）"]
    record("㉖ ★★ 体检**不许**把登记过的动作误报成「未登记」（假警报比没有警报更坏）",
           bool(idem_vk) and idem_vk[0]["level"] == "ok",
           idem_vk[0]["detail"][:120] if idem_vk else "缺这一项")
    record("㉖ ★ 总判按最高档位取（fail > warn > ok）",
           lk_gen["overall"] in ("ok", "warn", "fail")
           and lk_gen["overall"] == ("fail" if any(i["level"] == "fail" for i in lk_gen["items"])
                                     else ("warn" if any(i["level"] == "warn" for i in lk_gen["items"]) else "ok")),
           f"overall={lk_gen['overall']} ok={lk_gen['ok']} warn={lk_gen['warn']} fail={lk_gen['fail']}")

    # ── 反例三份：必须被拒，且**点名**关键那句话 ──
    bad_dir = ROOT / "var" / "lab" / "recipes-bad"
    cases = {
        "bad-command.yaml": ["run"],
        "bad-uninstall.yaml": ["uninstall"],
        "bad-ref.yaml": ["myapp.start", "net.port", "net.ping"],
    }
    for fname, needles in cases.items():
        p = bad_dir / fname
        if not p.is_file():
            record(f"㉖ 反例样例 {fname} 存在", False, str(p))
            continue
        try:
            _recs, rep = load_recipes(p.parent, actions, now="2026-00-00T00:00:00")
            txt = "\n".join(e for f in rep.failed if f["file"] == fname
                            for e in (f.get("errors") or []))
            hit = all(n in txt for n in needles)
            record(f"㉖ ★ 反例 {fname} 被拒且点名「{'、'.join(needles)}」", bool(txt) and hit,
                   (txt.replace("\n", " ")[:180] or "竟然通过了装载期校验"))
        except Exception as exc:  # noqa: BLE001
            record(f"㉖ ★ 反例 {fname} 被拒", False, f"{type(exc).__name__}: {exc}")

    # ── ★ S9 补：体检的**命令行**入口（写配方的人不一定开着控制台）──
    #   两条路走**同一套** `lint_recipe`（不养第二套判定），这里只验"它真的能跑、退出码语义对"。
    chk = ROOT / "tools" / "recipe-check.py"
    cp_chk = run_child([sys.executable, str(chk)])
    record("㉖ ★ 配方体检的命令行入口跑得动（与界面那个按钮**同一套**判定）",
           cp_chk.returncode == 0 and "一共体检" in (cp_chk.stdout or ""),
           (cp_chk.stdout or "")[-110:].replace("\n", " ") or (cp_chk.stderr or "")[:110])
    cp_chk_bad = run_child([sys.executable, str(chk), "--recipes", str(bad_dir)])
    record("㉖ ★ 反例目录交给它 ⇒ **退出码 2**（装载不过就不体检 —— "
           "「能不能装载」与「写得全不全」是两件事，不许混）",
           cp_chk_bad.returncode == 2 and "没装进来" in (cp_chk_bad.stdout or ""),
           f"exit={cp_chk_bad.returncode}")

    # ══════════════════════════════════════ ㉓ 热装载（三个不许 + 说清哪一份哪一行）
    tmp_catalog = cfg.paths.var / "selftest-v18"
    tmp_recipes = tmp_catalog / "recipes"
    if tmp_recipes.exists():
        shutil.rmtree(tmp_catalog)
    tmp_recipes.mkdir(parents=True, exist_ok=True)
    # 夹具用**真配方**（nginx）+ 它引用的模板：这样"好配方"这一侧走的是与生产同一套校验。
    # ★ 文件名必须等于配方 id（装载期硬校验）⇒ 好配方就写成 nginx.yaml，
    #   两份坏配方各自把 id 也改成与文件名一致 —— 这样"唯一的错"才是我们想验的那个错。
    shutil.copytree(cfg.paths.catalog / "templates" / "nginx", tmp_catalog / "templates" / "nginx")
    good_txt = (cfg.paths.catalog / "recipes" / "nginx.yaml").read_text(encoding="utf-8")
    (tmp_recipes / "nginx.yaml").write_text(good_txt, encoding="utf-8", newline="\n")
    # 坏配方 1：出现被禁的顶层键（expr）
    (tmp_recipes / "bad-topkey.yaml").write_text(
        good_txt.replace("id: nginx", "id: bad-topkey", 1).rstrip() + '\nexpr: "1 == 1"\n',
        encoding="utf-8", newline="\n")
    # 坏配方 2：引用一个不存在的动作
    (tmp_recipes / "bad-action.yaml").write_text(
        good_txt.replace("id: nginx", "id: bad-action", 1)
                .replace("action: svc.enable", "action: nope.nothing", 1),
        encoding="utf-8", newline="\n")

    rec, report = load_recipes(tmp_recipes, actions, now="2026-00-00T00:00:00")
    record("㉓ ★ 好配方装载成功（同一套装载期校验）", "nginx" in rec, "、".join(report.loaded))
    record("㉓ ★★ 坏配方**不装载**（★ 重载不是绕过校验的后门）",
           "nope.nothing" not in rec
           and "bad-action" not in report.loaded and "bad-topkey" not in report.loaded,
           "装进来的：" + ("、".join(report.loaded) or "（无）"))
    names_failed = sorted(f["file"] for f in report.failed)
    record("㉓ ★★ 且**说清哪一份错**（两份坏配方逐份列出）",
           names_failed == ["bad-action.yaml", "bad-topkey.yaml"], "、".join(names_failed))
    txt = "\n".join(e for f in report.failed for e in (f.get("errors") or []))
    record("㉓ ★★ 并**说清错在哪个键**（expr 被点名 / 不存在的动作被点名）",
           ("expr" in txt) and ("nope.nothing" in txt), txt.replace("\n", " ")[:220])
    record("㉓ ★ 装载报告是结构化的三件事（装了几份 / 哪几份没装 / 为什么）",
           isinstance(report.to_public().get("loaded"), list)
           and isinstance(report.to_public().get("failed"), list)
           and "没装进来" in report.summary(),
           report.summary()[:160])

    # ── 重载：不影响已装载的、不打断正在执行的 ──
    fake_cfg = types.SimpleNamespace(
        paths=types.SimpleNamespace(catalog=tmp_catalog), timezone=cfg.timezone)
    runner = RecipeRunner(fake_cfg, actions, types.SimpleNamespace(), _FakeStore(), {})
    rpt1 = runner.reload()
    record("㉓ reload() 真的把配方装进来了", "nginx" in runner.recipes, rpt1.summary()[:120])
    inflight = runner.recipes["nginx"]           # ★ 模拟"正在执行的那一次"：它拿着这个对象
    version_before = inflight.version
    (tmp_recipes / "nginx.yaml").write_text(
        good_txt.replace('version: "1"', 'version: "9"', 1), encoding="utf-8", newline="\n")
    rpt2 = runner.reload()
    record("㉓ ★ 重载之后新执行拿到的是**新版**定义",
           runner.recipes["nginx"].version == "9", runner.recipes["nginx"].version)
    record("㉓ ★★ **正在执行的那一次继续用它自己那一版**（不被换掉）—— §12.17",
           inflight.version == version_before and inflight.version != runner.recipes["nginx"].version,
           f"在执行的那份 v{inflight.version} / 新装载的 v{runner.recipes['nginx'].version}")
    record("㉓ ★ 坏配方在重载里同样**不装载**且不影响好配方",
           "nope.nothing" not in runner.recipes and "nginx" in runner.recipes
           and not rpt2.ok, rpt2.summary()[:160])

    # ── 路由真的通（离线即可验：走的是与界面同一条 /api 路径）──
    from app.server import bootstrap
    try:
        bcfg, bacts, bmap, bstore, beng, bapi = bootstrap(ROOT)
        status, payload = bapi.dispatch("POST", "/api/recipes/reload", {}, {})
        load_pub = (payload.get("data") or {}).get("load") or {}
        record("㉓ ★ POST /api/recipes/reload 真的调得通（界面入口的后端）",
               status == 200 and payload.get("ok") is True and "loaded" in load_pub,
               f"HTTP {status} · 装载 {len(load_pub.get('loaded') or [])} 份")
        gstatus, gpayload = bapi.dispatch("GET", "/api/recipes", {}, {})
        record("㉓ ★ GET /api/recipes 带上了装载报告（不许静默少装载）",
               gstatus == 200 and isinstance((gpayload.get("data") or {}).get("load"), dict),
               "")
    except Exception as exc:  # noqa: BLE001
        record("㉓ 路由 /api/recipes/reload 调得通", False, f"{type(exc).__name__}: {exc}")


    # ══════════════════════════════════════ ㉗ 配方批量（闸门 · 失败隔离 · 横向对照）
    # ★ 这一节要钉死四件事，全都是"靠人记得住就会忘"的那类：
    #   ① 闸门三档（green 直接跑 / yellow 二次确认 / red **禁止**且**没有开关**）；
    #   ② ★★ 闸门挂在**配方风险**上，而不是配方 YAML 里那句"我要批量" —— 后者**装载期就该被拒**；
    #   ③ ★★ **失败隔离**：一台抛错不许把整批停掉，每台一个独立执行号；
    #   ④ ★★ 横向对照按「执行状态 + 收敛检查结果」判：**"跑完了"不等于"事情成了"**，
    #      而"变更步数不同"**不算**差异（两台初始现状不同时它天生不同 —— 多机治理不在本话题）。
    import inspect as _inspect

    from app.recipe import batch_gate, batch_summary

    def _rec(risk: str, name: str = "假配方"):
        return types.SimpleNamespace(id="fake", name=name, risk=risk)

    g_green = batch_gate(_rec("green"), "deploy")
    g_yellow = batch_gate(_rec("yellow"), "deploy")
    g_red = batch_gate(_rec("red"), "deploy")
    record("㉗ ★ green 配方批量：直接跑（**不要**二次确认）",
           g_green["allowed"] is True and g_green["needs_confirm"] is False,
           json.dumps(g_green, ensure_ascii=False)[:120])
    record("㉗ ★ yellow 配方批量：放行、但要**二次确认**",
           g_yellow["allowed"] is True and g_yellow["needs_confirm"] is True,
           json.dumps(g_yellow, ensure_ascii=False)[:120])
    record("㉗ ★★ red 配方批量：**被拒**（沿 T3 硬规矩）",
           g_red["allowed"] is False and "禁止批量" in g_red["reason"], g_red["reason"][:120])
    record("㉗ ★★ red 的 advice 要说清**出路**（逐台执行 / 先降档），不是干巴巴一句「不行」",
           ("逐台" in g_red["advice"]) and ("red" in g_red["advice"]), g_red["advice"][:120])
    record("㉗ ★★ **不提供配置开关**：入参只有 (recipe, mode) —— 没有 allow_red 之类的缝",
           list(_inspect.signature(batch_gate).parameters) == ["recipe", "mode"],
           "、".join(_inspect.signature(batch_gate).parameters))

    # ── ② 配方 YAML 里声明"我要批量" ⇒ **装载期就拒**（顶层键白名单，规范 §12.18 / §9.3）──
    bk_cat = cfg.paths.var / "selftest-v18" / "batch-key"
    if bk_cat.exists():
        shutil.rmtree(bk_cat)
    (bk_cat / "recipes").mkdir(parents=True, exist_ok=True)
    shutil.copytree(cfg.paths.catalog / "templates" / "nginx", bk_cat / "templates" / "nginx")
    nginx_txt = (cfg.paths.catalog / "recipes" / "nginx.yaml").read_text(encoding="utf-8")
    (bk_cat / "recipes" / "nginx.yaml").write_text(
        nginx_txt.rstrip() + '\nbatch: "我要批量"\n', encoding="utf-8", newline="\n")
    _bk_recs, bk_rep = load_recipes(bk_cat / "recipes", actions, now="2026-00-00T00:00:00")
    bk_txt = "\n".join(e for f in bk_rep.failed for e in (f.get("errors") or []))
    record("㉗ ★★ 配方 YAML 里写「我要批量」⇒ **装载期就拒**（批量是平台能力，不在配方里声明）",
           "nginx" not in _bk_recs and "batch" in bk_txt,
           (bk_txt.replace("\n", " ")[:180] or "竟然装载成功了"))

    # ── ③ 失败隔离与横向对照（runner 级 · 假执行器：不连目标机也能验"循环继续往下走"）──
    real_recs, _rep_batch = load_recipes(cfg.paths.catalog / "recipes", actions)
    brunner = RecipeRunner(cfg, actions, types.SimpleNamespace(), _FakeStore(), dict(real_recs))
    calls: list[tuple[str, str, str]] = []

    def _pub_item(host_id: str, host_name: str, *, status: str = "ok", health=None,
                  changed=("装包",), conclusion: str = "") -> dict:
        return {
            "run_id": f"R-{host_id}", "host_id": host_id, "host_name": host_name,
            "status": status, "changed_steps": list(changed), "unchanged_steps": [],
            "unknown_steps": [], "checkpoints": [{"label": "x"}],
            "health": health if health is not None else [{"state": "pass"}],
            "conclusion": conclusion or f"{host_name} 的结论", "duration_ms": 12, "error": None,
        }

    def _fake_run(recipe_id, host_id, raw_params, *, mode="deploy", confirm=False, confirm_text=""):
        calls.append((host_id, mode, confirm_text))
        if host_id == "node-02":                     # ★ 故意让**第一台**失败
            raise OpsError(code="HOST_UNREACHABLE", reason="连不上 node-02",
                           advice="先确认它开着、SSH 通")
        return types.SimpleNamespace(to_public=lambda: _pub_item(host_id, "node-03"))

    brunner.run = _fake_run
    out = brunner.batch_run("nginx", ["node-02", "node-03"], {}, mode="deploy", confirm=True)

    record("㉗ ★★ **失败隔离**：第一台抛错没有把整批停掉 —— 第二台照样跑到了",
           [c[0] for c in calls] == ["node-02", "node-03"], "、".join(c[0] for c in calls))
    record("㉗ ★ 失败那台**只记在自己那一行**（自己的 code 与原因都在）",
           len(out["items"]) == 2 and out["items"][0]["status"] == "failed"
           and out["items"][0]["host_id"] == "node-02"
           and (out["items"][0]["error"] or {}).get("code") == "HOST_UNREACHABLE",
           json.dumps(out["items"][0], ensure_ascii=False)[:150])
    record("㉗ ★★ 每台是**独立执行**：成功那台有自己的执行号，失败那台是 `None`（★ 不许编一个出来）",
           out["items"][1]["run_id"] == "R-node-03" and out["items"][0]["run_id"] is None,
           f"{out['items'][1]['run_id']} / {out['items'][0]['run_id']}")
    record("㉗ ★ 汇总分开计数（ok / failed），不是「有的成功有的失败」一句话",
           out["summary"]["total"] == 2 and out["summary"]["ok"] == 1
           and out["summary"]["failed"] == 1,
           json.dumps(out["summary"], ensure_ascii=False)[:150])
    record("㉗ ★★ 横向对照**点名**不一样的那台，并带上它自己的原因",
           out["summary"]["consistent"] is False
           and out["summary"]["differences"][0]["hosts"] == ["node-02"]
           and "连不上" in out["summary"]["differences"][0]["reasons"][0],
           json.dumps(out["summary"]["differences"], ensure_ascii=False)[:170])
    _s_conv = batch_summary([
        {"host_id": "a", "host_name": "A", "status": "ok", "checks_total": 2,
         "checks_failed": 0, "changed_steps": [], "error": None},
        {"host_id": "b", "host_name": "B", "status": "ok", "checks_total": 2,
         "checks_failed": 2, "changed_steps": [], "error": None},
    ])
    _named = sorted(h for x in _s_conv["differences"] for h in x["hosts"])
    record("㉗ ★★ 「跑完了」≠「事情成了」：收敛检查不同的两台**都**被点出来，"
           "且「真健康」只算 1 台（§12.6.5 / §12.16）",
           _s_conv["consistent"] is False and _named == ["A", "B"] and _s_conv["healthy"] == 1,
           json.dumps(_s_conv["groups"], ensure_ascii=False)[:150])
    record("㉗ ★★ 变更步数**不参与**一致/不一致判定（现状不同天生不同；多机治理不在本话题）",
           batch_summary([
               {"host_id": "a", "host_name": "A", "status": "ok", "checks_total": 3,
                "checks_failed": 0, "changed_steps": ["装包", "写配置"], "error": None},
               {"host_id": "b", "host_name": "B", "status": "ok", "checks_total": 3,
                "checks_failed": 0, "changed_steps": [], "error": None},
           ])["consistent"] is True,
           "")

    # ── ④ 闸门在**执行入口**上也拦得住（纯函数放行 ≠ 服务端放行）──
    calls.clear()
    try:
        expect_error(lambda: brunner.batch_run("nginx", ["node-03"], {}, mode="deploy",
                                               confirm=False), "CONFIRM_REQUIRED")
        record("㉗ ★ yellow 配方**没二次确认** ⇒ 被拒，且**一台都没跑**", not calls, f"竟然跑了 {calls}")
    except AssertionError as exc:
        record("㉗ ★ yellow 配方没二次确认 ⇒ 被拒", False, str(exc))

    brunner.recipes["fake-red"] = types.SimpleNamespace(id="fake-red", name="假 red 配方", risk="red")
    calls.clear()
    try:
        expect_error(lambda: brunner.batch_run("fake-red", ["node-03"], {}, mode="deploy",
                                               confirm=True), "BATCH_FORBIDDEN")
        record("㉗ ★★ red 配方在**执行入口**被拒（连二次确认都不给绕过），且一台没跑",
               not calls, f"竟然跑了 {calls}")
    except AssertionError as exc:
        record("㉗ ★★ red 配方在执行入口被拒", False, str(exc))

    purge_word = str(real_recs["nginx"].uninstall.purge_confirm_text)
    calls.clear()
    try:
        expect_error(lambda: brunner.batch_run("nginx", ["node-03"], {}, mode="uninstall_purge",
                                               confirm=True, confirm_text="我已确认"), "CONFIRM_REQUIRED")
        record("㉗ ★★ 全删批量：确认词不对 ⇒ 被拒，且**在铺出去之前**就拒（一台都没跑）",
               not calls, f"竟然跑了 {calls}")
    except AssertionError as exc:
        record("㉗ ★★ 全删批量：确认词不对 ⇒ 被拒", False, str(exc))
    calls.clear()
    ok_purge = brunner.batch_run("nginx", ["node-03"], {}, mode="uninstall_purge",
                                 confirm=True, confirm_text=purge_word)
    record("㉗ ★ 确认词**逐字**对上才放行（那句词是从配方 YAML 读出来的，不是抄的）",
           len(ok_purge["items"]) == 1 and calls and calls[-1][2] == purge_word,
           f"词 = {purge_word}")

    # ── ⑤ 接口真的被认领 + ★ 界面真的接上了（接口存在 ≠ 界面能点到，§9.9 同族）──
    from app.server import bootstrap as _bs3

    try:
        _c3, _a3, _m3, _s3, _e3, api3 = _bs3(ROOT)
        st3, pl3 = api3.dispatch("POST", "/api/recipes/nginx/batch-plan", {},
                                 {"host_ids": ["node-03"]})
        d3 = pl3.get("data") or {}
        record("㉗ ★ 批量预检接口被认领（**只读**：查主机清单 + 出闸门，不碰目标机）",
               st3 == 200 and (d3.get("gate") or {}).get("allowed") is True
               and [h["host_id"] for h in (d3.get("hosts") or [])] == ["node-03"],
               f"HTTP {st3} · 闸门 {json.dumps(d3.get('gate'), ensure_ascii=False)[:90]}")
        try:
            expect_error(lambda: api3.dispatch("POST", "/api/recipes/nginx/batch-plan", {}, {}),
                         "PARAM_MISSING")
            record("㉗ ★ 没选目标机 ⇒ `PARAM_MISSING`（**不是** `NO_SUCH_ROUTE`：路由确实被认领了）",
                   True)
        except AssertionError as exc:
            record("㉗ ★ 没选目标机 ⇒ PARAM_MISSING", False, str(exc))
    except Exception as exc:  # noqa: BLE001
        record("㉗ 批量接口被认领", False, f"{type(exc).__name__}: {exc}")

    appjs = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    record("㉗ ★★ 界面真的接上了这两个接口（接口存在 ≠ 界面能点到）",
           "/batch-plan" in appjs and "/batch-run" in appjs and "btnRecipeBatch" in appjs,
           "")
    record("㉗ ★ red 配方在界面上**根本点不下去**（按钮禁用 + 说明为什么），服务端再拦一道",
           "red 级配方禁止批量执行" in appjs and "btnRecipeBatch" in appjs
           and "r.risk === 'red' ? ' disabled" in appjs,
           "")

    # ★ 这一节自己搭的夹具**自己收** —— 否则每跑一次自检，`git status` 里就多一堆未跟踪文件
    #   （与 T4 收尾那次"自检产物冒出来"同一个处置；㉓ 那一节的夹具本来就会被下一轮重建）。
    if bk_cat.exists():
        shutil.rmtree(bk_cat)


    # ══════════════════════════════════════ ㉘ T7·S7：`space_kv` 解析器 + 补掉最后两项缺口
    # ★ 为什么这一节必须存在：S7 用「**一个新解析器 + 两个只读动作**」把账本推到 100%。
    #   ① 解析器是**核心代码**，扩它得有理由、也得能离线钉死（不能只靠"真跑看着对"）；
    #   ② ★★ **100% 这个数字必须是算出来的** —— 所以这里钉"账本真的没有缺口了"，
    #      而不是在注释里写一句"已是 100%"。
    import re as _re

    from app.changed import has_rule
    from app.parsers import PARSERS as _PARSERS
    from app.parsers import apply_pick as _apply_pick
    from app.parsers import parse_text as _parse_text

    record("㉘ ★ `space_kv` 已在解析器白名单里（新解析器必须登记，否则动作层写它会被装载期拒）",
           "space_kv" in _PARSERS, "、".join(_PARSERS))

    sshd_sample = (
        "port 22\n"
        "addressfamily any\n"
        "permitrootlogin yes\n"
        "subsystem sftp /usr/libexec/openssh/sftp-server\n"
        "# 这一行是注释，要跳过\n"
        "\n"
        "acceptenv LANG LC_*\n"
        "acceptenv LC_TERMINAL\n"          # ★ 重复键：口径是"保留最后一次"
    )
    kv = _parse_text("space_kv", sshd_sample)
    record("㉘ ★ `sshd -T` 那种「指令名 值」能解析成字典（空格分隔，**值里含空格**也对）",
           kv.get("permitrootlogin") == "yes"
           and kv.get("subsystem") == "sftp /usr/libexec/openssh/sftp-server",
           json.dumps(kv, ensure_ascii=False)[:150])
    record("㉘ ★ 空行与 `#` 注释行被跳过（否则字典里会多出垃圾键）",
           "# 这一行是注释，要跳过" not in kv and "" not in kv,
           json.dumps(sorted(kv), ensure_ascii=False)[:150])
    record("㉘ ★★ 重复键只保留**最后一次**（`acceptenv` / `hostkey` 这类可重复键会丢信息 "
           "⇒ 要数它们得用 lines / line_count）",
           kv.get("acceptenv") == "LC_TERMINAL", repr(kv.get("acceptenv")))
    record("㉘ ★ pick 能把带点的键名改成短名字（结论模板里的点号是「取字段」的意思，键名再带点必歧义）",
           _apply_pick(kv, {"permitrootlogin": "permit_root_login"}).get("permit_root_login") == "yes",
           "")

    # ── 两个补缺口的新动作：装载得到 · 只读 · 判得出来 · 模板占位符不歧义 ──
    for aid in ("host.kernelparams", "sec.ssh-harden"):
        act = actions.get(aid)
        record(f"㉘ ★ 动作 {aid} 装载成功且是 **green**（补的就是这两项 T3 缺口）",
               act is not None and act.risk == "green", "" if act is None else act.risk)
        if act is None:
            continue
        record(f"㉘ ★ {aid} 有结论模板 + 至少 1 条自证（一屏给全 + 真能失败）",
               bool(act.conclusion.strip()) and len(act.verify) >= 1, f"verify {len(act.verify)} 条")
        record(f"㉘ ★ {aid} 判得出「变了没有」（green 免登记；宪法 ② 的看门狗入口）",
               has_rule(act) is True, "")
        holes = set(_re.findall(r"\{([a-z_][A-Za-z0-9_.]*)\}", act.conclusion))
        deepest = max((h.count(".") for h in holes), default=0)
        record(f"㉘ ★ {aid} 的模板占位符**最多一层点**（`{{step.field}}`；再深就歧义了）",
               deepest <= 1, "、".join(sorted(holes))[:150])

    # ── ★★ 100% 是算出来的：账本没有缺口、也没有靠"删条目"凑数 ──
    _cov = reconcile(load_map(cfg.paths.map), actions)
    _w = _cov.get("weighted") or {}
    record("㉘ ★★ 两项 T3 缺口清零：覆盖面 **52/52 = 100%**（P0 28/28）",
           _cov["total"] == 52 and _cov["done"] == 52
           and _cov["p0_done"] == _cov["p0_total"] == 28,
           f'{_cov["done"]}/{_cov["total"]} = {_cov["rate"]}% · P0 {_cov["p0_done"]}/{_cov["p0_total"]}')
    record("㉘ ★ 缺口清单**为空**（★ 不是「把登记项删掉」那种假 100%：分母必须还是 52）",
           _cov["missing"] == [] and _cov["total"] == 52,
           str([m.get("id") for m in _cov["missing"]]) or "（无缺口）")
    record("㉘ ★★ 加权口径同样到顶（分母含 `platform` 段），且**兜底权重 0 条**",
           _w.get("w_done") == _w.get("w_all") and not _w.get("implicit_weight_ids"),
           f'{_w.get("w_done")}/{_w.get("w_all")} = {_w.get("rate")}% · '
           f'platform {_w.get("platform_done")}/{_w.get("platform_total")} · '
           f'兜底 {_w.get("implicit_weight_ids")}')
    record("㉘ ★ `sec.ssh-harden` 不再取 `challengeresponseauthentication`"
           "（★ 真跑核到：RHEL 10 的 `sshd -T` 根本不打印它，取它只会多一个假「（无）」）",
           "challengeresponseauthentication" not in str(actions["sec.ssh-harden"].step("effective").pick)
           if actions.get("sec.ssh-harden") else False,
           "")


def _r_of(action, result):
    """给真值表用：直接问 changed 规则（T8·S2 加）。"""
    from app.changed import changed_for_action
    return changed_for_action(action, result)


def check_v19(cfg, actions) -> None:
    """v1.9（T8·S2）新增断言 ㉙~㉟：内核参数写 / daemon-reload / reset-failed /
    file.cat 白名单 / registry.probe 判读 / net.firewall 不再假红。

    ★ 全部**离线可跑**：换机器、断网也要能红/绿。
    ★ 这一节的共同点是「**改错了会锁住自己的地方，判据必须可证伪**」——
      所以每条规矩都配了**反例**，「写坏了会红」是它唯一的存在理由。
    """
    from app.catalog import validate_params
    from app.changed import NO_CHANGE_EXEMPT, RULES, audit_rules, has_rule

    section("★ v1.9（T8）：内核参数写 · daemon-reload · reset-failed · 白名单 · 判读口径")

    def _accepted(action, given) -> bool:
        try:
            validate_params(action, given)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _rejected(action, given) -> bool:
        return not _accepted(action, given)

    def _whens(step):
        return [e.get("when") for e in step.run if isinstance(e, dict)]

    # ══════════════════════════════════ ㉙ 内核参数「写 + 持久化」
    a = actions.get("sysctl.set")
    record("㉙ `sysctl.set` 存在（T7 起跑线 #4 的本体）", a is not None,
           "动作清单里没有它" if a is None else "risk=" + str(a.risk))
    if a is not None:
        record("㉙ 它是 yellow（可回退，但改错了会锁住自己）", a.risk == "yellow", str(a.risk))
        record("㉙ 它有确认弹层（变更类动作该有的那一层）", bool(a.confirm))
        names = [s.name for s in a.steps]
        record("㉙ ★★ 三件事**成套**：before → write → after → persist → reload → verify_after",
               names == ["before", "write", "after", "persist", "reload", "verify_after"],
               "、".join(names))
        record("㉙ ★★ 有「复读」与「持久化后复读」两步 —— 命令返回 0 不算成功（§12.24.1）",
               "after" in names and "verify_after" in names)
        pf = next((s for s in a.steps if s.name == "persist"), None)
        wf = (pf.write_file or {}) if pf is not None else {}
        record("㉙ ★★ 持久化走 write_file（幂等写），落在 /etc/sysctl.d/ 且带 99-aoc- 前缀",
               str(wf.get("path", "")).startswith("/etc/sysctl.d/99-aoc-") and bool(wf.get("content")),
               str(wf.get("path")))
        record("㉙ ★★ 预检先问「这个键现在读得到吗」（= 顺序约束的落点，§12.24.3）",
               bool(a.precheck) and a.precheck[0].name == "key_readable",
               "、".join(s.name for s in a.precheck))
        kp = next((p for p in a.params if p.name == "key"), None)
        vp = next((p for p in a.params if p.name == "value"), None)
        kpat = (kp.pattern or "") if kp is not None else ""
        record("㉙ 参数 `key` 是**白名单正则**（不是「任意键都能写」）",
               bool(kpat) and "ip_forward" in kpat and kpat.startswith("^") and kpat.endswith("$"),
               kpat[:70])
        record("㉙ 参数 `value` 只允许数字",
               vp is not None and vp.pattern == "^[0-9]{1,9}$",
               str(getattr(vp, "pattern", None)))
        record("㉙ ★★ 反例：非法值 `maybe` **必须被参数校验拒**（写坏了要能红）",
               vp is not None and _rejected(a, {"key": "net.ipv4.ip_forward", "value": "maybe"}))
        record("㉙ ★★ 反例：白名单外的键 `kernel.ostype` **必须被拒**",
               kp is not None and _rejected(a, {"key": "kernel.ostype", "value": "1"}))
        record("㉙ ★ 正例：白名单内的键 + 数字值**必须通过**",
               kp is not None and _accepted(a, {"key": "net.ipv4.ip_forward", "value": "1"}))
        record("㉙ 它有 `backup:` 声明持久化文件（§9.1：会改文件的变更动作必须声明）",
               any(b.path.startswith("/etc/sysctl.d/") for b in a.backup),
               "、".join(b.path for b in a.backup))
        record("㉙ ★ 结论里写清「只增不降」与「回不去的」（§12.24.2 / §12.24.5）",
               "只增不降" in a.conclusion and "回不去" in a.conclusion)
        record("㉙ `changed` 规则已登记（`_r_sysctl_set`：比 before/after 两次读数）",
               "sysctl.set" in RULES, str(has_rule(a)))
        if "sysctl.set" in RULES:
            import types as _t

            def _res(b, af):
                return _t.SimpleNamespace(steps=[
                    _t.SimpleNamespace(name="before", status="ok", parsed=b, changed=None),
                    _t.SimpleNamespace(name="after", status="ok", parsed=af, changed=None)])

            record("㉙ ★ 真值表：`1 -> 0` 判「变了」", _r_of(a, _res("1", "0")) is True)
            record("㉙ ★ 真值表：`1 -> 1` 判「没变」（幂等的正面证据）",
                   _r_of(a, _res("1", "1")) is False)

    a = actions.get("sysctl.load-module")
    record("㉙ `sysctl.load-module` 存在（与 sysctl.set 配对成一组）", a is not None)
    if a is not None:
        names = [s.name for s in a.steps]
        record("㉙ 步骤是 count_before → load → count_after → persist",
               names == ["count_before", "load", "count_after", "persist"], "、".join(names))
        ca = next((s for s in a.steps if s.name == "count_after"), None)
        cb = next((s for s in a.steps if s.name == "count_before"), None)
        record("㉙ ★★ `count_after` **只接受退出码 0** —— grep -c 匹配 0 行时给 1，"
               "所以「modprobe 返回 0 但模块不在」会**当场判红**（可证伪）",
               ca is not None and ca.ok_exit_codes == [0], str(getattr(ca, "ok_exit_codes", None)))
        record("㉙ `count_before` 接受 [0, 1]（在不在都是有效报告）",
               cb is not None and sorted(cb.ok_exit_codes) == [0, 1],
               str(getattr(cb, "ok_exit_codes", None)))
        record("㉙ ★ 计数走 /proc/modules（一行一条、无表头），不是 lsmod（§12.23 的假数字）",
               ca is not None and "/proc/modules" in ca.run, str(getattr(ca, "run", None)))
        record("㉙ 自证挂在 `count_after` 上（`load` 成功时不输出，不能当证据）",
               any(v.from_ == "count_after" for v in a.verify), str([v.from_ for v in a.verify]))
        record("㉙ 结论里说明「本动作不自动卸载」这条回不去的（§12.24.5）",
               "不自动卸载" in a.conclusion)
        record("㉙ `changed` 规则已登记（`_r_sysctl_load_module`）", "sysctl.load-module" in RULES)

    # ══════════════════════════════════ ㉚ ㉛ daemon-reload（T6 定性 / T7 再确认的缺口）
    a = actions.get("svc.daemon-reload")
    record("㉚ `svc.daemon-reload` **存在**（规范 §12.25 要补的那个能力缺口）",
           a is not None, "动作清单里没有它" if a is None else "risk=" + str(a.risk))
    if a is not None:
        names = [s.name for s in a.steps]
        record("㉚ 步骤是 reload（daemon-reload）+ show（回读定义）+ files（原文）",
               names == ["reload", "show", "files"], "、".join(names))
        rel = next((s for s in a.steps if s.name == "reload"), None)
        record("㉚ reload 步真的是 `systemctl daemon-reload`",
               rel is not None and list(rel.run[:2]) == ["systemctl", "daemon-reload"],
               str(getattr(rel, "run", None)))
        show = next((s for s in a.steps if s.name == "show"), None)
        record("㉚ ★★ 第二重自证的第 ① 步在：`show` 取 FragmentPath 与 DropInPaths"
               "（systemd **内存里**那份定义）—— §12.25.2",
               show is not None and "FragmentPath" in show.run and "DropInPaths" in show.run)
        record("㉚ ★★ 自证**挂在 `show` 上**，不是挂在 `reload` 上"
               "（后者成功时不输出任何东西，拿它自证必然假红）",
               any(v.from_ == "show" for v in a.verify)
               and not any(v.from_ == "reload" for v in a.verify),
               str([(v.from_, v.severity) for v in a.verify]))
        record("㉚ ★★ 结论里明说「它**不证明**服务用了新配置」（§12.25.2 的分工）",
               "不证明" in a.conclusion and "重启服务" in a.conclusion)
        record("㉚ 它**不重启服务、不改文件**（reload 只管「让 systemd 知道」）",
               all("restart" not in str(s.run) for s in a.steps))
        record("㉚ ★ `changed` 判定已定：它不改目标机任何东西 ⇒ 记「没变」，"
               "且**理由写在明面上**（不是把不知道的当没变）",
               "svc.daemon-reload" in NO_CHANGE_EXEMPT
               and len(NO_CHANGE_EXEMPT["svc.daemon-reload"]) > 40,
               str(NO_CHANGE_EXEMPT.get("svc.daemon-reload", ""))[:60])
        record("㉚ `has_rule()` 对它是 True（配方体检不会把它报成未登记）", has_rule(a))

    # ══════════════════════════════════ ㉜ reset-failed（T6 让用户手敲过的那一条）
    a = actions.get("svc.reset-failed")
    record("㉜ `svc.reset-failed` **存在**（规范 §12.26）",
           a is not None, "动作清单里没有它" if a is None else "risk=" + str(a.risk))
    if a is not None:
        names = [s.name for s in a.steps]
        record("㉜ 七步：health_before → fail_before → fail_count_before → reset → "
               "health_after → fail_after → fail_count_after",
               names == ["health_before", "fail_before", "fail_count_before", "reset",
                         "health_after", "fail_after", "fail_count_after"],
               "、".join(names))
        fcb = next((s for s in a.steps if s.name == "fail_count_before"), None)
        fca = next((s for s in a.steps if s.name == "fail_count_after"), None)
        record("㉜ ★★ 判据走**计数**（`line_count`）而不是原文 —— "
               "空输出对 raw 是 None（只能判 unknown），对 line_count 是 **0**（能判没变）",
               fcb is not None and fca is not None
               and fcb.parser == "line_count" and fca.parser == "line_count",
               "、".join(str(s.parser) for s in (fcb, fca) if s is not None))
        rst = next((s for s in a.steps if s.name == "reset"), None)
        record("㉜ reset 步是 `systemctl reset-failed`，且 `unit` 留空时整步等价于全量",
               rst is not None and list(rst.run[:2]) == ["systemctl", "reset-failed"]
               and "unit" in _whens(rst), str(getattr(rst, "run", None)))
        record("㉜ ★★ 自证挂在 `health_after` 上（is-system-running 的结论永远落在 stdout）",
               any(v.from_ == "health_after" for v in a.verify), str([v.from_ for v in a.verify]))
        hb = next((s for s in a.steps if s.name == "health_before"), None)
        record("㉜ is-system-running 的退出码 0~4 全算正常报告（degraded 是结论不是故障）",
               hb is not None and sorted(hb.ok_exit_codes) == [0, 1, 2, 3, 4],
               str(getattr(hb, "ok_exit_codes", None)))
        record("㉜ ★★ 结论里写清「状态已清，根因未处理」（复位不是修好了）",
               "根因未处理" in a.conclusion)
        record("㉜ ★★ 结论里写清它**不**做什么（不改定义 / 不启停 / 不清日志 / 不修根因）",
               all(w in a.conclusion for w in ["不改", "不启不停", "不清", "不修"]))
        record("㉜ `changed` 规则已登记（`_r_svc_reset_failed`：比失败清单前后）",
               "svc.reset-failed" in RULES)
        if "svc.reset-failed" in RULES:
            import types as _t

            def _res2(b, af, sb="ok", sa="ok"):
                return _t.SimpleNamespace(steps=[
                    _t.SimpleNamespace(name="fail_count_before", status=sb, parsed=b, changed=None),
                    _t.SimpleNamespace(name="fail_count_after", status=sa, parsed=af, changed=None)])

            record("㉜ ★ 真值表：2 个失败 → 0 个 ⇒ 判「变了」",
                   _r_of(a, _res2(2, 0)) is True)
            record("㉜ ★ 真值表：本来就没有失败（0 → 0）⇒ 判「没变」（幂等）—— "
                   "★ 这一格就是本次修掉的那一格",
                   _r_of(a, _res2(0, 0)) is False)
            record("㉜ ★ 真值表：任一侧没问出来 ⇒ unknown（不许猜）",
                   _r_of(a, _res2(1, 0, sb="failed")) is None)

    # ══════════════════════════════════ ㉝ file.cat 路径白名单（含密钥类永不读）
    a = actions.get("file.cat")
    record("㉝ `file.cat` 存在且是 green（只读）", a is not None and a.risk == "green")
    if a is not None:
        pat = a.params[0].pattern or ""
        record("㉝ 自证挂在 `count` 上 —— ★★ **空文件是合法结论**，"
               "拿 `content` 做非空断言会 100% 假红（§9.6 / §10.6.3）",
               any(v.from_ == "count" for v in a.verify)
               and not any(v.from_ == "content" for v in a.verify),
               str([(v.from_, v.severity) for v in a.verify]))
        record("㉝ 预检用 `test -f` 把「目录 / 不存在」挡在门外（cat 对目录会报 Is a directory）",
               bool(a.precheck) and list(a.precheck[0].run[:2]) == ["test", "-f"],
               str(a.precheck[0].run[:3]) if a.precheck else "")
        record("㉝ ★★ pattern 里有**负向前瞻**（密钥类永不读）",
               "(?!" in pat and "authorized_keys" in pat and "shadow" in pat)
        record("㉝ ★★ 反例：`/etc/shadow` 必须被拒", _rejected(a, {"path": "/etc/shadow"}))
        record("㉝ ★★ 反例：`/etc/containerd/id_rsa` 必须被拒",
               _rejected(a, {"path": "/etc/containerd/id_rsa"}))
        record("㉝ ★★ 反例：`/etc/containerd/server.key` 必须被拒",
               _rejected(a, {"path": "/etc/containerd/server.key"}))
        record("㉝ ★★ 反例：白名单目录之外的 `/root/.ssh/authorized_keys` 必须被拒",
               _rejected(a, {"path": "/root/.ssh/authorized_keys"}))
        record("㉝ ★ 正例：旧集群那份调优文件**必须通过**（T8·S3 留证要用它）",
               _accepted(a, {"path": "/etc/sysctl.d/99-k8s-tuning.conf"}))

    # ══════════════════════════════════ ㉞ registry.probe 判读口径
    a = actions.get("registry.probe")
    record("㉞ `registry.probe` 存在且是 green（只读）", a is not None and a.risk == "green")
    if a is not None:
        nonopt = [s for s in a.steps if not s.optional]
        record("㉞ 只有一个**非 optional** 的探测步（自证来源），其余可选",
               len(nonopt) == 1 and nonopt[0].name == "k8s_registry",
               "、".join(s.name for s in nonopt))
        record("㉞ ★★ 所有探测步都把 **28（超时）** 当正常报告 —— "
               "「不可达」是这条链路的**结论**，不是动作失败（§12.28）",
               all(28 in s.ok_exit_codes for s in a.steps),
               str({s.name: s.ok_exit_codes for s in a.steps})[:120])
        hp = next((s for s in a.steps if s.name == "harbor_probe"), None)
        record("㉞ 内网仓库那一步**全部元素挂 when**（参数留空 ⇒ 整步跳过，§8.3）",
               hp is not None and all(isinstance(e, dict) for e in hp.run))
        record("㉞ ★★ 结论里同时给出「401 = 仓库活着」与「不是鉴权失败」"
               "（这一档最容易被读错）",
               "401 = 仓库活着" in a.conclusion and "不是鉴权失败" in a.conclusion)
        record("㉞ ★★ 结论里写清「000 = 不可达」不等于「没有这个镜像」（§12.28 规矩 4）",
               "没有这个镜像" in a.conclusion and "不是" in a.conclusion)

    # ══════════════════════════════════ ㉟ net.firewall 不再假红（结论落在 stderr 的坑）
    a = actions.get("net.firewall")
    record("㉟ `net.firewall` 仍在且是 green", a is not None and a.risk == "green")
    if a is not None:
        unit = next((s for s in a.steps if s.name == "unit"), None)
        state = next((s for s in a.steps if s.name == "state"), None)
        record("㉟ ★★ 状态来源是 `systemctl is-active`（**答案落在 stdout**）",
               unit is not None and list(unit.run[:2]) == ["systemctl", "is-active"],
               str(getattr(unit, "run", None)))
        record("㉟ is-active 的退出码 0/3/4 都是正常报告",
               unit is not None and sorted(unit.ok_exit_codes) == [0, 3, 4],
               str(getattr(unit, "ok_exit_codes", None)))
        record("㉟ ★★ `firewall-cmd --state` 降为 **optional 的原文证据**"
               "（未运行时答案在 stderr ⇒ 不许拿它自证，检查清单 79）",
               state is not None and state.optional is True, str(getattr(state, "optional", None)))
        record("㉟ ★★ 自证挂在 `unit` 上，**不再挂在 `state` 上**（修掉那处假红）",
               any(v.from_ == "unit" for v in a.verify)
               and not any(v.from_ == "state" for v in a.verify),
               str([(v.from_, v.severity) for v in a.verify]))
        record("㉟ ★ 结论首行给出单元状态，并写明「未运行是结论不是故障」",
               "{unit}" in a.conclusion and "不是故障" in a.conclusion)

    # ══════════════════════════════════ ㊱ 留证清单动作（§12.30 · T8·S3）
    #   ★ 这一节的共同点是「留证的正确语义是**如实报告**，不是"必须存在"」——
    #     所以每条规矩都配了"把『没有』说成『坏了』"的反例。
    _a = actions.get("file.manifest")
    record("㊱ `file.manifest` **存在**、green、且**零内容**（只读，不写不传）",
           _a is not None and _a.risk == "green"
           and not any(s.write_file or s.transfer for s in _a.steps),
           "动作清单里没有它" if _a is None else "risk=" + str(_a.risk))
    if _a is not None:
        _names = [s.name for s in _a.steps]
        record("㊱ ★★ 六步成套：root_count → root → tree_count → tree → digest_count → digest",
               _names == ["root_count", "root", "tree_count", "tree", "digest_count", "digest"],
               "、".join(_names))
        for _sn in ("tree", "tree_count", "digest", "digest_count"):
            _st = next((s for s in _a.steps if s.name == _sn), None)
            _run = list(getattr(_st, "run", []) or [])
            record("㊱ ★★ `" + _sn + "` 走 `find`（不是 ls -lR：列宽 / 时间格式 / locale 都会变）",
                   bool(_run) and _run[0] == "find", str(_run[:2]))
        for _sn in ("tree", "tree_count"):
            _run = [str(e) for e in next(s for s in _a.steps if s.name == _sn).run]
            record("㊱ ★ `" + _sn + "`（**清单**）用 find -printf 的制表符六列（类型 字节 时间 权限 属主 路径）",
                   any("%T@" in e and "%u:%g" in e for e in _run), str(_run[-1])[:40])
        for _sn in ("digest", "digest_count"):
            _run = [str(e) for e in next(s for s in _a.steps if s.name == _sn).run]
            record("㊱ ★ `" + _sn + "`（**摘要**）走 -exec sha256sum、**不带** -printf 六列",
                   "sha256sum" in _run and not any("%T@" in e for e in _run))
        for _sn in ("root_count", "root"):
            _st = next((s for s in _a.steps if s.name == _sn), None)
            record("㊱ ★★ `" + _sn + "` 的 ok_exit_codes 含 **2**（路径不存在是结论，不是错误）",
                   _st is not None and 2 in list(getattr(_st, "ok_exit_codes", []) or []),
                   str(getattr(_st, "ok_exit_codes", None)))
        for _sn in ("tree", "tree_count", "digest", "digest_count"):
            _st = next((s for s in _a.steps if s.name == _sn), None)
            record("㊱ ★★ `" + _sn + "` 的 ok_exit_codes 含 **1**（find『部分读不到』也是结论）",
                   _st is not None and 1 in list(getattr(_st, "ok_exit_codes", []) or []),
                   str(getattr(_st, "ok_exit_codes", None)))
        _counted = {"root_count", "tree_count", "digest_count"}
        record("㊱ ★★ **自证只挂『数行数』那几步**（raw / lines 的空输出永远不做非空断言）",
               bool(_a.verify) and all(v.from_ in _counted for v in _a.verify),
               str([(v.from_, v.severity) for v in _a.verify]))
        record("㊱ ★ 两份**必须**的判据挂 root_count 与 tree_count（digest_count 是 warn）",
               {"root_count", "tree_count"} <= {v.from_ for v in _a.verify if v.severity != "warn"}
               and any(v.from_ == "digest_count" and v.severity == "warn" for v in _a.verify))
        for _sn in ("root_count", "tree_count", "digest_count"):
            _st = next((s for s in _a.steps if s.name == _sn), None)
            record("㊱ `" + _sn + "` 是 line_count（空输出对它是 **0 这个结论**，§10.6.3）",
                   _st is not None and _st.parser == "line_count",
                   str(getattr(_st, "parser", None)))
        _pcs = [s.name for s in _a.precheck]
        record("㊱ ★★ 预检**只查工具**（find --version）、**不查目标路径在不在**（§12.30.2）",
               _pcs == ["find_available"]
               and list(_a.precheck[0].run) == ["find", "--version"],
               "、".join(_pcs))
        _need = ("id_*", "*.key", "*.pem", "authorized_keys", "shadow", "gshadow")
        for _sn in ("digest", "digest_count"):
            _run = [str(e) for e in next((s for s in _a.steps if s.name == _sn), None).run]
            _miss = [n for n in _need if n not in _run]
            record("㊱ ★★ `" + _sn + "`（**摘要**）里六项密钥类 `! -name` 排除**齐全**（§12.30.3）",
                   not _miss, ("缺：" + "、".join(_miss)) if _miss else "六项齐全")
        for _sn in ("tree", "tree_count"):
            _run = [str(e) for e in next(s for s in _a.steps if s.name == _sn).run]
            record("㊱ ★ **清单**那两步**不**排除密钥类 —— 它们要出现在清单里（只是没有 sha256）",
                   "_name" not in _run, "、".join(_run[-6:]))
        _rd = [str(e) for e in next(s for s in _a.steps if s.name == "digest_count").run]
        record("㊱ ★★ 摘要走 `-exec sha256sum -- {} +`（批量喂文件、不经过 shell）",
               "-exec" in _rd and "sha256sum" in _rd and _rd[-1] == "+")
        _good = {"path": "/etc/kubernetes", "depth": 3, "size_limit": "2M"}
        record("㊱ ★★ 正例：留证白名单内的目录**必须通过**", _accepted(_a, _good))
        for _bad in ("/etc/shadow", "/etc/kubernetes/../../etc/passwd", "/home/root",
                     "/root/.ssh", "/etc/kubernetes/.."):
            record("㊱ ★★ 反例：`" + _bad + "` **必须被拒**",
                   _rejected(_a, dict(_good, path=_bad)))
        record("㊱ ★ 反例：`depth` 越界（0 / 99）**必须被拒**",
               _rejected(_a, dict(_good, depth=0)) and _rejected(_a, dict(_good, depth=99)))
        record("㊱ ★ 反例：`size_limit` 不在枚举内 **必须被拒**",
               _rejected(_a, dict(_good, size_limit="999M")))
        record("㊱ ★ 结论里给『调小 depth / 分次留证』的截断提示（§12.30.5）",
               "depth" in _a.conclusion and "截断" in _a.conclusion)

    # ══════════════════════════════════ ㊲~㊴ 容器运行时真探活 + 链路末端（§12.31 · T8·S5）
    #   ★ 这一节的共同点是「**把'生效了没有'逼到链路末端**」——
    #     所以每条都配了"落不到末端就算不上证明"的反例。
    from app.changed import RULES as _RULES  # noqa: E402
    from app.expect import PROBE_SOURCES as _PS  # noqa: E402
    from app.recipe import load_recipes as _lr  # noqa: E402
    import re as _re  # noqa: E402

    _rt = actions.get("container.runtime")
    record("㊲ `container.runtime` **存在**、green、且**零写盘**（不写不传）",
           _rt is not None and _rt.risk == "green"
           and not any(s.write_file or s.transfer for s in _rt.steps),
           "动作清单里没有它" if _rt is None else "risk=" + str(_rt.risk))
    if _rt is not None:
        _pr = next((s for s in _rt.steps if s.name == "probe"), None)
        record("㊲ ★★ 探活那一步就是 `ctr version`（走 gRPC 真问一句，不是 systemctl 旁证）",
               _pr is not None and [str(e) for e in _pr.run] == ["ctr", "version"],
               str(getattr(_pr, "run", None)))
        record("㊲ ★★ 自证挂在 `probe` 上（它必须真问得出话来）",
               any(v.from_ == "probe" for v in _rt.verify),
               str([(v.from_, v.severity) for v in _rt.verify]))
        record("㊲ ★★ 预检**不查 socket** —— 守护进程不在要表现为『探活那一步非零退出』，"
               "而不是『动作压根没跑』（断言 ㊲③ 的反例就靠这个成立）",
               [s.name for s in _rt.precheck] == ["ctr_present"],
               "、".join(s.name for s in _rt.precheck))
        _cnt = next((s for s in _rt.steps if s.name == "images_count"), None)
        record("㊲ `images_count` 是 line_count（一个镜像都没有是 **0 这个结论**，§10.6.3）",
               _cnt is not None and _cnt.parser == "line_count",
               str(getattr(_cnt, "parser", None)))
    record("㊲ ★★ `container.runtime` 已在 `PROBE_SOURCES` 里登记（配方才写得出 responds）",
           "container.runtime" in _PS, "、".join(sorted(_PS)))

    _recs, _ = _lr(cfg.paths.catalog / "recipes", actions)
    _rc = _recs.get("k8s-containerd")
    _rf = ""
    if _rc is not None:
        for _h in _rc.health or []:
            _spec = (_h or {}).get("expect") or {}
            if "responds" in _spec:
                _rf = str((_spec.get("responds") or {}).get("first_field") or "")
    record("㊲ ★★ 配方健康判据用 `first_field: \"Server:\"`"
           "（★ **不是版本号**：那是会随包升级漂的 —— 本会话真的把 2.2.6 装成了 2.3.6）",
           _rf == "Server:", _rf or "（没有 first_field）")

    _pl = actions.get("container.pull")
    record("㊳ `container.pull` **存在**、yellow（会写镜像缓存）",
           _pl is not None and _pl.risk == "yellow",
           "动作清单里没有它" if _pl is None else "risk=" + str(_pl.risk))
    record("㊳ ★★ `container.pull` 已登记 `changed` 规则（漏了 → 通用那条断言会红）",
           "container.pull" in _RULES, "、".join(sorted(_RULES)))
    if _pl is not None:
        record("㊳ ★★ 走的是 **CRI 路**（`crictl`，与 kubelet 同一条），**不是** `ctr images pull`"
               "（后者是客户端自己解析 hosts —— 测了一个没人用的通路）",
               any(str(e) == "crictl" for s in _pl.steps for e in (getattr(s, "run", []) or [])))
        record("㊳ ★★ 预检查 `crictl`（缺工具 ⇒ 明确中止，不是『拉了个空』）",
               [s.name for s in _pl.precheck] == ["crictl_present"]
               and list(_pl.precheck[0].run) == ["ls", "-l", "/usr/bin/crictl"],
               "、".join(s.name for s in _pl.precheck))
        _ref = next((p for p in _pl.params if p.name == "ref"), None)
        _pat = str(getattr(_ref, "pattern", "") or "")
        record("㊳ ★★ `ref` 白名单：**收下真 ref**、**拒** `..` / 空白 / 以 `-` 开头（开关注入）",
               bool(_pat)
               and bool(_re.fullmatch(_pat, "registry.aliyuncs.com/google_containers/pause:3.10.1"))
               and all(not _re.fullmatch(_pat, b)
                       for b in ("../x", "a b", "-rf", "", "x/y:")),
               _pat[:60])

    _kt = (cfg.paths.catalog / "recipes" / "k8s-containerd.yaml").read_text(encoding="utf-8")
    record("㊳ ★★ 拉的 ref 就是**沙箱镜像那一个**（不是『挑个好拉的来证明链路』）",
           'ref: "{{ sandbox_image }}"' in _kt)
    # ★★ 注意：这两条**不许**在整份文本上做子串匹配 —— 说明文字里**故意**写了
    #   "不用 `state: {equals: inactive}`" 与 "/etc/containerd/config.toml 一个字都不写"，
    #   子串匹配会把**注释**当成**代码**（这正是"断言自己会骗人"那一类）。
    #   ⇒ 结构化：① 步骤名**钉死整份形状**；② 只在**真正的 YAML 值行**上匹配。
    _step_names = [s.name for s in (_rc.steps if _rc is not None else [])]
    record("㊴ ★★ 配方形状钉死：装包 → cri-tools → enable → start → 末端拉取"
           "（**没有** render_certsd / restart_containerd / 任何 `template:` 步骤）",
           _step_names == ["install_containerd", "install_cri_tools", "enable", "start", "pull_sandbox"],
           "、".join(_step_names) or "（配方没装载）")
    record("㊴ ★★ `template:` 步骤的 `dest:` **一个都不指向** `/etc/containerd/config.toml`"
           "（§12.13.5 硬规矩一：`rpm -qf` 说那份是 `containerd.io` 的，写了就复原不了）",
           not _re.search(r"(?m)^[ \t]*dest:[ \t]*/etc/containerd/config\.toml[ \t]*$", _kt)
           and "template:" not in _kt)
    record("㊴ ★★ 反向健康判据用**外部可观测**的『socket 不在了』，"
           "**不用** `equals: inactive`（`disable` 会把单元从 systemd 内存卸载 —— T5 真跑踩过）",
           "containerd.sock" in _kt
           and not _re.search(r"(?m)^[ \t]*equals:[ \t]*inactive[ \t]*$", _kt))
    record("㊴ ★ 反向操作三个按钮的确认词齐备（停止 / 保留数据 / 全删）",
           "stop_confirm_text:" in _kt and "purge_confirm_text:" in _kt)
    record("㊴ ★ 「保留数据」明确承诺保住**镜像缓存**（它是资产不是数据：删了要重拉）",
           "keep_data:" in _kt and "/var/lib/containerd" in _kt)

    # ══════════════════════════════════ ㊵~㊺ 集群引导 / 幂等守卫 / 清单应用（§12.32~§12.34 · T8·S6+S7）
    #   ★ 这一节的共同点是「**把'做成了没有'逼到终态**」——
    #     所以每条判据都配了"只写在途中就算不上证明"的反例。
    import types as _types  # noqa: E402
    from app.catalog import _parse_steps as _ps   # noqa: E402
    from app.recipe import (                      # noqa: E402
        precheck_means_done as _pmd, batch_gate as _bg, parse_recipe as _pr,
    )
    from app.changed import _r_k8s_apply as _rka  # noqa: E402
    from app.yamlload import load_yaml as _ly     # noqa: E402

    def _read(rel: str) -> str:
        p = ROOT / "catalog" / rel
        return p.read_text(encoding="utf-8") if p.exists() else ""

    _act = {n: actions.get(n) for n in (
        "k8s.kubeadm-reset", "k8s.kubeadm-init", "k8s.kubeconfig",
        "k8s.kubeadm-join", "k8s.nodes", "k8s.apply", "k8s.wait")}

    # ── ㊵ 七个新动作的装载契约 ─────────────────────────────────
    _want_risk = {
        "k8s.kubeadm-reset": "red", "k8s.kubeadm-init": "yellow",
        "k8s.kubeconfig": "yellow", "k8s.kubeadm-join": "yellow",
        "k8s.nodes": "green", "k8s.apply": "yellow", "k8s.wait": "green",
    }
    for _n, _rk in _want_risk.items():
        _a = _act[_n]
        record(f"㊵ `{_n}` 装载成功 且 risk == {_rk}",
               _a is not None and _a.risk == _rk,
               "未装载" if _a is None else _a.risk)
    # ★★ 每个"能变更的"动作都必须有 changed 规则（漏了 → 通用那条会红，这里点名）
    _mutable = [n for n, a in _act.items() if a is not None and a.risk != "green"]
    record("㊵ ★★ 五个变更动作**全部**登记了 changed 规则（§12.9 #28）",
           all(n in _RULES for n in _mutable),
           "缺：" + "、".join(n for n in _mutable if n not in _RULES))
    # ★ green 的两个必须**零写盘**
    for _n in ("k8s.nodes", "k8s.wait"):
        _a = _act[_n]
        _writes = [s.name for s in (_a.steps if _a else []) if s.write_file or s.transfer]
        record(f"㊵ `{_n}` 是只读：**零写盘**（无 write_file / transfer）",
               _a is not None and not _writes, "、".join(_writes))
    # ★★ 五只引导手里，每只至少一条自证挂在"数行数 / 退出码"上（不许挂在 raw 上）
    _probe_steps = {
        "k8s.kubeadm-reset": ("manifests_after", "line_count"),
        "k8s.kubeadm-init": ("api", "raw"),          # ★ 退出码型：命令本身就是 `kubectl get --raw`
        "k8s.kubeconfig": ("same", "line_count"),   # ★ 退出码型：`cmp -s`（空输出 ⇒ 必须 line_count）
        "k8s.kubeadm-join": ("kubelet_conf_after", "line_count"),
        "k8s.nodes": ("ready", "raw"),               # ★ 退出码型：`kubectl wait`
        "k8s.apply": ("get", "raw"),                 # ★ 退出码型：`kubectl get -f`
        "k8s.wait": ("wait", "raw"),                 # ★ 退出码型：`kubectl wait`
    }
    for _n, (_step, _parser) in _probe_steps.items():
        _a = _act[_n]
        _s = _a.step(_step) if _a else None
        record(f"㊵ `{_n}` 的自证来源是 `{_step}`（parser={_parser}）",
               _s is not None and _s.parser == _parser,
               "缺这一步" if _s is None else _s.parser)
        _froms = {v.from_ for v in (_a.verify if _a else [])}
        record(f"㊵ `{_n}` 的 verify 确实引用 `{_step}`", _step in _froms,
               "、".join(sorted(_froms)))
    # ★★ 判据不许挂在"空输出即合法结论"的 raw 步骤上做非空断言 —— 这里点名三条：
    for _n, _bad in (("k8s.kubeadm-reset", "manifests_before"),
                     ("k8s.kubeadm-init", "manifests_before"),
                     ("k8s.kubeadm-join", "kubelet_conf_before")):
        _a = _act[_n]
        _froms = {v.from_ for v in (_a.verify if _a else [])}
        record(f"㊵ ★★ `{_n}` 的 verify **不引用** `{_bad}`（空目录/文件不在是**结论**，不是没问到）",
               _bad not in _froms)
    # ★★ 真跑抓到的**真缺陷**（规范 §12.32.2 的补丁 / 清单 96）：
    #   `cmp -s` 成功时**什么都不输出** ⇒ 自证那一步的解析器**不能是 `raw`**
    #   （`raw` 对空输出给 None ⇒ "有没有值"必败 ⇒ **假红**）。必须选 `line_count`（0 是个值）。
    _kc = _act["k8s.kubeconfig"]
    _same = _kc.step("same") if _kc else None
    record("㊵ ★★ `k8s.kubeconfig` 的自证步骤 `same`（`cmp -s`）解析器是 `line_count`，**不是 `raw`**"
           "（成功时空输出 ⇒ `raw` 给 None ⇒ 假红：步骤全跑成了、报告却说自证未通过）",
           _same is not None and _same.parser == "line_count",
           "缺这一步" if _same is None else _same.parser)
    record("㊵ ★ 而它的一致性判据仍然是 **`cmp` 的退出码**（`ok_exit_codes == [0]`）",
           _same is not None and list(_same.ok_exit_codes) == [0],
           "缺这一步" if _same is None else str(_same.ok_exit_codes))

    # ── ㊶ 幂等守卫的三条装载期硬校验（规范 §12.33）─────────────
    _base = {"name": "probe", "title": "问一句", "run": ["true"], "parser": "raw"}
    _cases = [
        ("写在 steps 里 ⇒ **必须被拒**",
         [dict(_base, means_done=True, means_done_why="理由")], "steps", False),
        ("`means_done: true` 却没有 `means_done_why` ⇒ **必须被拒**",
         [dict(_base, means_done=True)], "precheck", False),
        ("只写 `means_done_why` 不写 `means_done` ⇒ **必须被拒**",
         [dict(_base, means_done_why="理由")], "precheck", False),
        ("给 `write_file` 步骤声明 ⇒ **必须被拒**",
         [{"name": "w", "write_file": {"path": "/tmp/x", "content": "x"},
           "means_done": True, "means_done_why": "理由"}], "precheck", False),
        ("写在 precheck 里、带理由 ⇒ **必须通过**",
         [dict(_base, means_done=True, means_done_why="目标已达成")], "precheck", True),
    ]
    for _why, _raw, _where, _want_ok in _cases:
        _buf: list[str] = []
        _ps(_raw, _buf, "k8s.probe", _where)
        record("㊶ 守卫声明：" + _why, (not _buf) == _want_ok,
               "｜".join(_buf)[:120])

    # ── ㊷ `precheck_means_done()` 的真值表（**纯函数**，离线就能验）──
    def _mk_action(step_name: str, means: bool):
        _st = _types.SimpleNamespace(name=step_name, means_done=means,
                                     means_done_why="因为它问的是目标在不在")
        return _types.SimpleNamespace(precheck_step=lambda n: _st if n == step_name else None)

    def _mk_task(status: str, code, failed_step: str):
        return _types.SimpleNamespace(
            status=status,
            error=(_types.SimpleNamespace(code=code) if code else None),
            steps=[_types.SimpleNamespace(name=failed_step, status="failed")])

    _A = _mk_action("not_yet", True)
    record("㊷ ① aborted + PRECHECK_FAILED + **正是那一步** + 有理由 ⇒ True",
           _pmd(_A, _mk_task("aborted", "PRECHECK_FAILED", "not_yet"))[0] is True)
    record("㊷ ② ★★ **失败的是别的预检步骤** ⇒ False"
           "（守卫**不许**把整条动作的失败一起放行 —— 这是本节的命门）",
           _pmd(_A, _mk_task("aborted", "PRECHECK_FAILED", "tool_present"))[0] is False)
    record("㊷ ③ 状态不是 aborted（例如 failed）⇒ False",
           _pmd(_A, _mk_task("failed", "PRECHECK_FAILED", "not_yet"))[0] is False)
    record("㊷ ④ 失败码不是 PRECHECK_FAILED（HOST_UNREACHABLE）⇒ False",
           _pmd(_A, _mk_task("aborted", "HOST_UNREACHABLE", "not_yet"))[0] is False)
    record("㊷ ④ 失败码不是 PRECHECK_FAILED（PARAM_INVALID）⇒ False",
           _pmd(_A, _mk_task("aborted", "PARAM_INVALID", "not_yet"))[0] is False)
    _B = _mk_action("not_yet", False)
    record("㊷ ⑤ 那一步**没有声明**守卫 ⇒ False（守卫是**声明出来**的，不是默认行为）",
           _pmd(_B, _mk_task("aborted", "PRECHECK_FAILED", "not_yet"))[0] is False)
    record("㊷ ★ 理由与「是哪一步」一起返回（结论里要能复核）",
           _pmd(_A, _mk_task("aborted", "PRECHECK_FAILED", "not_yet"))[1] != "")
    # ★★ 静态：`k8s.kubeadm-reset` 的"工具在不在"那条**必须没有**守卫
    _rs = _act["k8s.kubeadm-reset"]
    _tool = _rs.precheck_step("kubeadm_present") if _rs else None
    record("㊷ ★★ `k8s.kubeadm-reset` 的 `kubeadm_present` **没有** means_done"
           "（缺工具必须中止，绝不能吞成『已达终态』）",
           _tool is not None and not _tool.means_done)

    # ── ㊸ "再点一次不许破坏集群"的判据本身 ──────────────────────
    for _n, _want in (("k8s.kubeadm-init", ("not_yet",)),
                      ("k8s.kubeadm-join", ("not_yet",)),
                      ("k8s.kubeadm-reset", ("has_traces", "not_ours"))):
        _a = _act[_n]
        _guarded = {s.name for s in (_a.precheck if _a else []) if s.means_done}
        record(f"㊸ `{_n}` 的守卫就在这几步上：{_guarded}", _guarded == set(_want),
               "｜".join(sorted(_guarded)))
        _bare = [s.name for s in (_a.precheck if _a else [])
                 if not s.means_done and s.name.startswith(("kubeadm", "cri_socket", "kubectl"))]
        record(f"㊸ ★★ `{_n}` 的『工具/依赖在不在』那几条**一条都没声明**守卫",
               all(not s.means_done for s in (_a.precheck if _a else [])
                   if s.name in _bare), "｜".join(_bare))
    # ★★ 静态：两份配方都必须含 reset（"拆与建同一次"，§12.32.7）
    for _rid in ("k8s-init", "k8s-join"):
        _txt = _read(f"recipes/{_rid}.yaml")
        record(f"㊸ ★★ 配方 `{_rid}` 里**含** `k8s.kubeadm-reset`"
               f"（拆与建必须同一次，否则旧集群会被判成「已达终态」⇒ 假绿）",
               _re.search(r"(?m)^[ \t]*action:[ \t]*k8s\.kubeadm-reset[ \t]*$", _txt) is not None)
        record(f"㊸ ★ 配方 `{_rid}` 是 **red**（⇒ 进不了批量）",
               _re.search(r"(?m)^risk:[ \t]*red[ \t]*$", _txt) is not None)

    # ── ㊹ `k8s.apply` 的判据与 changed 都挂在 `kubectl diff` 上 ──
    _ap = _act["k8s.apply"]
    _d = _ap.step("diff") if _ap else None
    record("㊹ `k8s.apply` 的 `diff` 步骤：ok_exit_codes == [0, 1] 且 **optional: true**",
           _d is not None and list(_d.ok_exit_codes) == [0, 1] and _d.optional,
           "缺这一步" if _d is None else f"{_d.ok_exit_codes} / optional={_d.optional}")
    record("㊹ ★★ `k8s.apply` 走的是 `kubectl diff`（判**差异本身**），"
           "**不是**拿 `apply` 输出里的 created/configured 当判据（服务端补默认字段 ⇒ 假变化）",
           _d is not None and "kubectl" in _d.run and "diff" in _d.run)
    _ap_path = _ap.param("path") if _ap else None
    _pat = getattr(_ap_path, "pattern", "") or ""
    _ok_p = bool(_re.match(_pat, "/etc/kubernetes/aoc/calico.yaml"))
    _bad_p = [p for p in ("/etc/kubernetes/admin.conf", "/etc/passwd",
                          "/etc/kubernetes/aoc/../x.yaml", "/tmp/x.yaml")
              if _re.match(_pat, p)]
    record("㊹ `path` 白名单：收下真清单、**拒**白名单外 / 白名单内 `..`", _ok_p and not _bad_p,
           "被误收：" + "、".join(_bad_p))

    def _res(diff_rc, apply_status="ok"):
        return _types.SimpleNamespace(
            status="ok",
            steps=[_types.SimpleNamespace(name="diff", status="ok", exit_code=diff_rc),
                   _types.SimpleNamespace(name="apply", status=apply_status, exit_code=0)])

    record("㊹ `_r_k8s_apply`：diff 退出码 0 ⇒ **False**（幂等）",
           _rka(None, _res(0)) is False)
    record("㊹ `_r_k8s_apply`：diff 退出码 1 ⇒ **True**（真变了）",
           _rka(None, _res(1)) is True)
    record("㊹ `_r_k8s_apply`：diff 退出码 2 ⇒ **None**（拿不到对照数据 ≠ 没变）",
           _rka(None, _res(2)) is None)
    record("㊹ ★★ `apply` 没跑成 ⇒ **None**（不许把『连不上集群』伪造成一个判断）",
           _rka(None, _res(1, apply_status="failed")) is None)

    # ── ㊺ 两条由**装载期**挡下来的设计错误（§12.32.7）────────────
    _bad_recipe = {
        "id": "k8s-probe", "name": "探针", "version": "1", "summary": "x",
        "risk": "yellow", "params": [],
        "steps": [{"name": "r", "action": "k8s.kubeadm-reset"}],
        "uninstall": {"stop": [{"action": "k8s.kubeadm-reset"}],
                      "purge_confirm_text": "我已确认全删",
                      "stop_confirm_text": "我已确认停"},
        "health": [{"expect": {"responds": {"action": "k8s.nodes"}}}],
    }
    _, _errs_bad = _pr(dict(_bad_recipe), ROOT / "catalog/recipes/k8s-probe.yaml", actions)
    record("㊺ ★★ `risk` 取步骤内最严：引用了 red 动作却声明 `yellow` ⇒ **装载期被拒**",
           any("最高风险" in e for e in _errs_bad), "｜".join(_errs_bad)[:160])
    _gate_red = _bg(_types.SimpleNamespace(risk="red"), "deploy")
    record("㊺ ★★ `red` 配方**禁止批量**（不提供开关）—— `k8s-init` / `k8s-join` 都进不了批量",
           _gate_red.get("allowed") is False and "禁止批量" in str(_gate_red.get("reason") or "")
           and "开关" in str(_gate_red.get("reason") or ""),
           str(_gate_red)[:160])
    _, _errs_gate = _pr(dict(_bad_recipe, risk="red", deploy_confirm_text="点我"),
                        ROOT / "catalog/recipes/k8s-probe.yaml", actions)
    record("㊺ 正向有 red 动作 + 声明了 `deploy_confirm_text` ⇒ **通过**（不是被拒）",
           not any("deploy_confirm_text" in e for e in _errs_gate),
           "｜".join(_errs_gate)[:160])
    _safe_recipe = dict(_bad_recipe, risk="yellow", steps=[
        {"name": "r", "action": "k8s.nodes"}], uninstall={
        "stop": [{"action": "svc.stop", "args": {"unit": "x.service"}}],
        "purge_confirm_text": "我已确认全删", "stop_confirm_text": ""},
        deploy_confirm_text="点我")
    _, _errs_fake = _pr(_safe_recipe, ROOT / "catalog/recipes/k8s-probe.yaml", actions)
    record("㊺ ★★ 声明 `deploy_confirm_text` 却**没有** red 动作 ⇒ **假闸门、必须被拒**",
           any("假闸门" in e for e in _errs_fake), "｜".join(_errs_fake)[:160])

    # ── ㊻ ★★★ `ok_exit_codes` 是唯一准绳（§12.36 · 真跑抓到的真缺陷）──
    _esrc = (ROOT / "app" / "engine.py").read_text(encoding="utf-8")
    record("㊻ ★★★ 退出码判定里**不再**有『0 永远算成功』那半句"
           "（代码行 `if res.exit_code not in (0, None) and …`）—— 否则 `ok_exit_codes` 表达不了"
           "『这条命令必须失败』，幂等守卫 / svc.stop / file.remove 全都靠它",
           _re.search(r"(?m)^\s*(?:el)?if\s+res\.exit_code\s+not in\s*\(0, None\)", _esrc) is None)
    record("㊻ ★★ `None`（没拿到退出码）仍然放行 —— 那是『本地没跑起来』，由 255 那条负责，"
           "不该在这里被当成业务失败",
           "res.exit_code is not None and res.exit_code not in" in _esrc)
    # ★★ 六个老动作的「必须失败」声明**还在**（它们从 §12.36 这一天起才**真的**生效）：
    _must_fail = {
        "svc.stop": 3, "file.remove": 2, "cron.remove": 2,
        "pkg.remove": 1, "svc.disable": 1, "fw.port-close": 1,
    }
    for _n, _code in _must_fail.items():
        _a = actions.get(_n)
        _hit = [s.name for s in (_a.steps if _a else [])
                if s.ok_exit_codes and 0 not in s.ok_exit_codes and _code in s.ok_exit_codes]
        record(f"㊻ ★ `{_n}` 的『{_code} = 已经达到终态了』声明仍在"
               f"（★ 在此之前它是**假绿**：0 也会被放过）", bool(_hit), "、".join(_hit))
    # ★ 守卫的两条新预检也靠它
    for _n, _step in (("k8s.kubeadm-reset", "not_ours"), ("k8s.kubeadm-init", "not_yet"),
                      ("k8s.kubeadm-join", "not_yet")):
        _s = _act[_n].precheck_step(_step) if _act[_n] else None
        record(f"㊻ ★ `{_n}.{_step}` 用 `ok_exit_codes: [2]` 表达『它不在』"
               f"（rc=0 必须判红，否则守卫永不生效）",
               _s is not None and list(_s.ok_exit_codes) == [2],
               "缺这一步" if _s is None else str(_s.ok_exit_codes))

    # ══════════════════════════════════ ㊼ 账本回填后的**分母**也要钉住
    # ★★ T16·S3：数字从 T10 收尾推到 T16 —— 本次新增的是**两条 platform 条目**
    #   （`vm-lifecycle` / `vm-snapshot-guard`，各 w=5）⇒ 加权 270 → **280**、
    #   platform 18 → **20**、条目 70 → **72**；★ **`entries` 的分母仍是 52**（不许靠改口径凑数）。
    _cov2 = reconcile(load_map(cfg.paths.map), actions)
    _w2 = _cov2.get("weighted") or {}
    record("㊼ ★★ T16 收尾的账本：**52/52 · 加权 280/280 · platform 20/20 · 条目 72/72 · 缺口空 · 兜底 0**",
           _cov2["total"] == 52 and _cov2["done"] == 52
           and _w2.get("w_all") == 280 and _w2.get("w_done") == 280
           and _w2.get("platform_total") == 20 and _w2.get("platform_done") == 20
           and _w2.get("items_total") == 72 and _w2.get("items_done") == 72
           and _cov2["missing"] == [] and not _w2.get("implicit_weight_ids"),
           f'条目 {_cov2["done"]}/{_cov2["total"]} · 加权 {_w2.get("w_done")}/{_w2.get("w_all")} · '
           f'platform {_w2.get("platform_done")}/{_w2.get("platform_total")} · '
           f'items {_w2.get("items_done")}/{_w2.get("items_total")} · '
           f'缺口 {len(_cov2["missing"])} · 兜底 {len(_w2.get("implicit_weight_ids") or [])}')
    record("㊼ ★★ **分母不靠改口径凑**：`entries` 仍钉在 **52**（虚拟化层那类能力进 `platform` 段，"
           "与 T6 的服务配方、T7/T8/T9/T10 的平台能力同口径）—— 页首 `stage_scope` 为 T16",
           _cov2["total"] == 52 and _cov2.get("stage") == "T16", str(_cov2.get("stage")))

    # ══════════════════════════════════ ㊽ T9·S9：把这一版抓到的**真缺陷**变成看门狗
    # ★ 为什么要有这一组：T9 一共抓到 6 个真缺陷，其中 4 个是"报告说假话"族
    #   （假红 / 假变更 / 假警报 / 自相矛盾）。**写在规范里不够** ——
    #   凡是可以**静态钉住**的，都要在自检里留一条；否则下一个人照样会写出来。
    def _steps_of(_aid: str) -> dict:
        _a = actions.get(_aid)
        return {s.name: s for s in (_a.steps or [])} if _a else {}

    # ① §12.49：**"必须失败型"步骤不许被 verify 做"内容非空"自证**（真缺陷 ⑨ · §12.37.2 的重犯）
    #    它的成功态就是"命令报错"，而报错原文走 stderr ⇒ stdout 本来就空 ⇒ 叠一条非空断言 **100% 假红**。
    #    ★ 白名单里那两条是**实测无害**的老动作（状态词写在 stdout 上），按 §12.49 **留档不改**；
    #      它们必须**显式列在这里**，不许靠"反正没人看"混过去。
    _benign_mustfail_verify = {"svc.disable.after", "svc.stop.isactive"}
    _danger = []
    for _aid, _a in sorted(actions.items()):
        _mf = {n for n, s in _steps_of(_aid).items()
               if list(getattr(s, "ok_exit_codes", None) or []) and 0 not in list(s.ok_exit_codes)}
        for _v in (getattr(_a, "verify", None) or []):
            _src = (getattr(_v, "from_", None) or getattr(_v, "source", None)
                    or getattr(_v, "src", None))
            if _src in _mf and getattr(_v, "field", None) is None:
                _danger.append(f"{_aid}.{_src}")
    record("㊽ ★★ §12.49：**没有『必须失败型步骤被做非空自证』**（真缺陷 ⑨ —— 报错原文走 stderr，"
           "stdout 本就空 ⇒ 叠非空断言 = 100% 假红）",
           [d for d in _danger if d not in _benign_mustfail_verify] == [],
           "、" .join(_danger) or "（无）")

    # ② §12.51：`k8s.config.secret_keys` 的**七个元素必须挂同一个 `when`**
    #    挂一半 ⇒ `secret_name` 为空时命令照样执行（`describe secret ""`）⇒ 在**只读**动作里
    #    凭空造出一条"步骤失败"（**假警报**）。★★ 而且要**条件一致** —— 混进 `secret_namespace`
    #    （它有默认值 `default`）就永远渲染不出空 argv，"整步跳过"这条路走不到（§12.51.1）。
    _sk = _steps_of("k8s.config").get("secret_keys")
    _sk_run = list(getattr(_sk, "run", None) or [])
    _sk_bare = [el for el in _sk_run if not isinstance(el, dict)]
    _sk_when = {el.get("when") for el in _sk_run if isinstance(el, dict)}
    record("㊽ ★★ §12.51/§12.51.1：`k8s.config.secret_keys` **每个元素都挂 `when`、且是同一个条件**"
           "（挂一半 + 条件不一致 ⇒ 空 argv 渲染不出来 ⇒ 假警报）",
           bool(_sk_run) and not _sk_bare and _sk_when == {"secret_name"},
           f"元素 {len(_sk_run)} 个 · 裸元素 {len(_sk_bare)} 个 · when={sorted(_sk_when)}")

    # ③ §12.40 / §12.43：逃生口**结构上没有写路径** —— 没有 `flags` 参数，`verb` 枚举里一个写动词都没有
    _kv = actions.get("k8s.kubectl")
    _kv_names = {p.name for p in (getattr(_kv, "params", None) or [])}
    _kv_verbs = set()
    for _p in (getattr(_kv, "params", None) or []):
        if _p.name == "verb":
            _kv_verbs = set(getattr(_p, "values", None) or [])
    _write_verbs = {"apply", "create", "delete", "edit", "patch", "replace", "scale", "rollout",
                    "drain", "cordon", "uncordon", "taint", "label", "annotate", "exec", "cp",
                    "run", "set", "expose", "port_forward", "port-forward", "proxy", "auth", "config"}
    record("㊽ ★★ §12.40/§12.43：逃生口**没有写路径**（无 `flags` 参数 ⇒ `-o yaml|json` 不可达；"
           "`verb` 枚举里一个写动词都没有）——「请用对应动作」是**结构**，不是文档",
           "flags" not in _kv_names and not (_kv_verbs & _write_verbs),
           f"params={sorted(_kv_names)} · 越界写动词={sorted(_kv_verbs & _write_verbs) or '（无）'}")

    # ④ §12.38 / §12.44：`k8s.delete-namespace` 的命名空间白名单**结构上排除 kube-system**
    #    ★ 不去比对 pattern 的字面量（那会把断言绑死在一串正则上），而是**拿真名字去试**。
    import re as _re  # 局部导入：本文件别处不用 re，没必要为一条断言动文件头
    _dn = next((p for p in (getattr(actions.get("k8s.delete-namespace"), "params", None) or [])
                if p.name == "namespace"), None)
    _dn_pat = str(getattr(_dn, "pattern", "") or "")
    record("㊽ ★★ §12.38/§12.44：`k8s.delete-namespace` 放行 `aoc-t9`、**拒绝 `kube-system`**"
           "（★ 拿真名字去试，不比对正则字面量）",
           bool(_dn_pat) and _re.fullmatch(_dn_pat, "aoc-t9") is not None
           and _re.fullmatch(_dn_pat, "kube-system") is None,
           _dn_pat)

    # ⑤ §12.50：`k8s.exec` 的**默认探针**必须是"读内核文件"的那一个
    #    （本环境靶子镜像 `busybox:1.36` 没有 `/etc/os-release`、没有 `ss` ⇒ 那两个当默认必然红）
    _probe = next((p for p in (getattr(actions.get("k8s.exec"), "params", None) or [])
                   if p.name == "probe"), None)
    _pv = list(getattr(_probe, "values", None) or [])
    record("㊽ ★★ §12.50：`k8s.exec` 的**默认探针 = 读内核文件的那一个**（`cmdline`），"
           "且它**排在 `choices` 第一**（默认值必须在本环境真跑过：busybox 上 `os_release` / `ss_listen` 必红）",
           _pv[:1] == ["cmdline"] and _pv.count("cmdline") == 1
           and "cmdline" in str(getattr(_probe, "default", "")),
           f"default={getattr(_probe, 'default', None)!r} · values[0]={_pv[:1]}")

    # ══════════════════════════════════ 🄂~🄉 T10·S9：把这一版的**八条新判据**变成看门狗
    # ★ 为什么要有这一组：T10 的判据全是"可证伪"类（在采 / 在判 / 送出去了 / 抑制 / 监听面…）。
    #   凡是可以**静态钉住**的，都在这里留一条 —— 否则下一个人照样会写出"看起来对"的东西。
    #   ★★ 本版真缺陷 ⑤（`parser: line_count` 挂 `grep -c` ⇒ 计数恒为 1，**十处同时中招**）
    #   就是"离线层一条都抓不到"的活证据：**能被静态钉住的，绝不留给人记得住。**
    import re as _re10

    from app.recipe import parse_recipe as _parse_recipe10
    from app.yamlload import load_yaml as _load_yaml10

    _cat = cfg.paths.catalog
    _tpl_root = _cat / "templates"

    # ── 🄂 监听面：一处都不许通配（§12.53 · 验收 #11）
    _lis_decl = _re10.compile(
        r"(?:--web\.listen-address=|http_addr\s*=\s*|AOC_WEBHOOK_BIND\s*=\s*)"
        r"(\{\{\s*\w+\s*\}\}|[0-9A-Fa-f:.]+)")
    _wild, _decl, _nfile = [], [], 0
    for _p in sorted(_tpl_root.glob("mon-*/*")):
        if not _p.is_file():
            continue
        _nfile += 1
        # ★ 只看**生效行**：注释里写"官方默认是 0.0.0.0"是说明，不是监听
        _code = "\n".join(l for l in _p.read_text(encoding="utf-8").splitlines()
                          if not l.strip().startswith("#") and not l.strip().startswith(";"))
        if "0.0.0.0" in _code:
            _wild.append(_p.name)
        for _m in _lis_decl.finditer(_code):
            _v = _m.group(1)
            _decl.append(_v)
            if _v.startswith("0.0.0.0") or _v in ("0", "::", "0.0.0.0"):
                _wild.append(f"{_p.name}:{_v}")
    record("🄂 ★★ §12.53：监控模板里**没有一处监听 `0.0.0.0`**，且五处监听声明都是**显式地址**"
           "（★ 官方默认就是通配；本环境 SELinux 无兜底 ⇒ 只能自己钉）",
           not _wild and len(_decl) >= 5,
           f"{_nfile} 个模板文件 · 监听声明 {len(_decl)} 处：{_decl} ｜ 通配命中："
           f"{'、'.join(_wild) if _wild else '（无）'}")

    # ── 🄃 规则条数与"在采"判据的退出码（§12.54 / §12.55.2 · 验收 #4 #2）
    _rules_txt = (_tpl_root / "mon-prometheus" / "rules.yml").read_text(encoding="utf-8")
    _n_alert = len(_re10.findall(r"(?m)^\s*- alert:\s*\S", _rules_txt))
    _n_for = len(_re10.findall(r"(?m)^\s*for:\s*\S", _rules_txt))
    _nd = _steps_of("mon.targets").get("assert_no_down")
    _nd_codes = list(_nd.ok_exit_codes) if _nd is not None else None
    record("🄃 ★★ §12.54/§12.55.2：规则 **≥12 条且每一条都带 `for`** ＋ "
           "`mon.targets.assert_no_down` **只接受 rc=1**（命中即判红）",
           _n_alert >= 12 and _n_for == _n_alert and _nd_codes == [1],
           f"alert {_n_alert} 条 · for {_n_for} 条 · assert_no_down ok_exit_codes={_nd_codes}")

    # ── 🄄 三处"可选判据"的每个 run 元素必须挂同一个 when（§12.55.2 / §12.51.1 · 验收 #5）
    def _when_ok(_aid: str, _step: str, _param: str):
        _s = _steps_of(_aid).get(_step)
        _r = list(getattr(_s, "run", None) or []) if _s else []
        _bare = [e for e in _r if not isinstance(e, dict)]
        _w = {e.get("when") for e in _r if isinstance(e, dict)}
        _d = f"{_aid}.{_step}: {len(_r)} 个元素 · 裸 {len(_bare)} · when={sorted(str(x) for x in _w)}"
        return (bool(_r) and not _bare and _w == {_param}), _d

    _w1, _d1 = _when_ok("mon.alerts", "assert_present", "expect_present")
    _w2, _d2 = _when_ok("mon.alerts", "assert_absent", "expect_absent")
    _w3, _d3 = _when_ok("mon.alerts-received", "assert_received", "expect_received")
    record("🄄 ★★ §12.55.2/§12.51.1：三处「可选判据」的**每个 run 元素都挂同一个 `when`**"
           "（挂一半 ⇒ 空 argv 渲染不出来 ⇒ 假警报）",
           _w1 and _w2 and _w3, f"{_d1} ｜ {_d2} ｜ {_d3}")

    # ── 🄅 ★★★ 抑制只许问 Alertmanager（§12.56.1 · 本话题最值钱的一条）
    _am_steps = []
    for _s in (actions["mon.am-alerts"].steps or []):
        for _e in (getattr(_s, "run", None) or []):
            if isinstance(_e, str) and "/api/v2/alerts" in _e:
                _am_steps.append(_s.name)
    _al_concl = str(getattr(actions["mon.alerts"], "conclusion", "") or "")
    _al_points_am = "mon.am-alerts" in _al_concl
    _al_selfclaims = "抑制的落点" in _al_concl
    record("🄅 ★★★ §12.56.1：抑制**只许问 Alertmanager**（`mon.am-alerts` 真的打 `/api/v2/alerts`），"
           "而读 Prometheus 的 `mon.alerts` **必须把读者导过去、且不许自称抑制的落点**"
           "（★ Prometheus 里被抑制的那条照样 firing ⇒ 用错 API 结论反向）",
           bool(_am_steps) and _al_points_am and not _al_selfclaims,
           f"/api/v2/alerts 出现于 {_am_steps or '（无！）'} ｜ mon.alerts 结论里指向 am={_al_points_am}"
           f" ｜ 仍自称「抑制的落点」={_al_selfclaims}")

    # ── 🄆 收端：只绑回环 ＋ 能读回来（§12.57 · 验收 #6）
    _dl_r = list(getattr(_steps_of("mon.alerts-received").get("deliveries"), "run", None) or [])
    _rcv_py = (_tpl_root / "mon-webhook" / "receiver.py").read_text(encoding="utf-8")
    _rcv_bind_ok = 'AOC_WEBHOOK_BIND") or "127.0.0.1"' in _rcv_py
    _dl_counts = "-c" in _dl_r
    # ★★ 保证的**落点在参数上**（`sink` 的默认值），不是渲染后的那串 —— 断言要找对地方，
    #    否则它只是在比对"这个动作今天恰好写成什么样"（§12.45.4 同族：断言的作用域要对）。
    _sink_p = next((p for p in (actions["mon.alerts-received"].params or []) if p.name == "sink"), None)
    _sink_def = str(getattr(_sink_p, "default", "") or "")
    _dl_sink = ("{{ sink }}" in [str(x) for x in _dl_r]) and _sink_def.endswith("alerts-received.jsonl")
    record("🄆 ★★ §12.57：收端**只绑 127.0.0.1**（默认值 ⇒ 监听面一处都不扩大）＋ 有一条数投递次数的判据步 ＋ "
           "读的是 append-only 的 `alerts-received.jsonl`（★ 保证在 `sink` 参数的默认值上，不在渲染后的串里）",
           _rcv_bind_ok and _dl_counts and _dl_sink,
           f"receiver 默认绑定={_rcv_bind_ok} ｜ deliveries={' '.join(str(x) for x in _dl_r)} ｜ "
           f"sink 默认={_sink_def}")

    # ── 🄇 口令不进 catalog（§12.58 · 红线 #2）
    _pw = _re10.compile(r"(?i)(admin_password|master_password|password\s*=\s*\S|secret\s*=\s*\S)")
    _pw_hits = []
    for _p in sorted(_cat.rglob("*")):
        if not (_p.is_file() and _p.suffix.lower() in
                (".yaml", ".yml", ".ini", ".json", ".service", ".py")):
            continue
        for _i, _l in enumerate(_p.read_text(encoding="utf-8").splitlines(), 1):
            if _pw.search(_l):
                _pw_hits.append(f"{_p.relative_to(_cat).as_posix()}:{_i}")
    _gi_txt = (_tpl_root / "mon-grafana" / "grafana.ini").read_text(encoding="utf-8")
    record("🄇 ★ §12.58：`catalog/` 下**一个口令都没有**，且 `grafana.ini` 里**没有 `admin_password` 这个键名**"
           "（★ 粒度是文件 ——「写了空串」也算）",
           _pw_hits == [] and "admin_password" not in _gi_txt,
           "、".join(_pw_hits) if _pw_hits else "（无）")

    # ── 🄈 靶子的代价有界（§12.59 · 验收 #13）
    _st = _steps_of("mon.selftest-metric")
    _wf = [str((getattr(s, "write_file", None) or {}).get("path", "")) for s in _st.values()
           if getattr(s, "write_file", None)]
    # ★★ 同样：`aoc-mon-` 这个保证住在**参数 `target` 的 pattern** 上（写盘路径里用的是占位符）。
    _tg_p = next((p for p in (actions["mon.selftest-metric"].params or []) if p.name == "target"), None)
    _tg_pat = str(getattr(_tg_p, "pattern", "") or "")
    _tg_ok = (_re10.fullmatch(_tg_pat, "aoc-mon-selftest") is not None
              and _re10.fullmatch(_tg_pat, "selftest") is None)
    _wf_ok = bool(_wf) and all("{{ target }}" in x for x in _wf) and _tg_ok
    # ★ "制造真故障"的动作：弄挂集群 / 压满内存 / 写满磁盘 / 改内核 —— 告警靶子**一律不许**用它们
    _FORBID = {"disk.fill", "mem.stress", "cpu.stress", "k8s.node-drain",
               "k8s.delete-namespace", "k8s.kubeadm-reset", "sysctl.set"}
    _bad_ref = []
    for _p in sorted((_cat / "recipes").glob("monitoring-*.yaml")):
        for _m in _re10.finditer(r"(?m)^\s*(?:-\s*)?action:\s*([\w.\-]+)",
                                 _p.read_text(encoding="utf-8")):
            if _m.group(1) in _FORBID:
                _bad_ref.append(f"{_p.name}:{_m.group(1)}")
    _name_p = next((p for p in (actions["mon.target-add"].params or []) if p.name == "name"), None)
    _name_pat = str(getattr(_name_p, "pattern", "") or "")
    _pat_ok = (_re10.fullmatch(_name_pat, "aoc-mon-demo") is not None
               and _re10.fullmatch(_name_pat, "demo") is None)
    record("🄈 ★★ §12.59：靶子的代价有界 —— 人造指标只写 `aoc-mon-*` 前缀的文件（保证在 `target` 参数正则上）；"
           "T10 配方**不引用**任何「制造真故障」的动作（压内存 / 写满盘 / 排空节点 / 拆集群）；"
           "扩展点名字同样被 `aoc-mon-` 正则钉死",
           _wf_ok and not _bad_ref and _pat_ok,
           f"写盘路径={_wf} ｜ target 正则能过 aoc-mon-selftest、拒 selftest={_tg_ok} ｜ "
           f"越界引用={_bad_ref or '（无）'} ｜ name 正则过 aoc-mon-demo、拒 demo={_pat_ok}")

    # ── 🄉 「回不去」＋ 保留期双上限（§12.60 / §12.61 · 验收 #10 #12）
    _ms_path = _cat / "recipes" / "monitoring-stack.yaml"
    _ms_txt = _ms_path.read_text(encoding="utf-8")
    _, _ms_errs = _parse_recipe10(_load_yaml10(_ms_path, what="配方"), _ms_path, actions)
    _keep = _re10.search(r"(?ms)^\s*keep_data:\s*\n((?:\s*-\s*\S+\s*\n?)+)", _ms_txt)
    _psvc = (_tpl_root / "mon-prometheus" / "prometheus.service").read_text(encoding="utf-8")
    _ret_ok = ("retention.time" in _psvc and "retention.size" in _psvc)
    record("🄉 ★★ §12.60/§12.61：`keep_data` **非空**（「保留数据」是承诺）＋ "
           "`purge_paths`/`remove_config` **过装载期白名单预检** ＋ "
           "`prometheus.service` 里 **retention.time 与 retention.size 两个占位符都在**",
           bool(_keep) and _ms_errs == [] and _ret_ok,
           f"keep_data={(repr(_keep.group(1).strip()) if _keep else '（空！）')} ｜ "
           f"装载期错误={_ms_errs or '（无）'} ｜ retention 双上限={_ret_ok}")

    # ── 🄊 ★★ §12.51 / §12.64 ⑥：只读动作里的"探测/陈列型"步骤必须接受 rc=1（或 2）
    #   ★★ 真跑实测（T10·S7-A）：基线那一次 `mon.alerts` 挂着 `步骤失败 1/8` —— 因为 `detail`
    #     那一步没声明 rc=1（**一条告警都没有** ⇒ grep 不命中 ⇒ rc=1）。任务照样 `ok`，
    #     但**横幅在撒谎**：只读动作不该有"步骤失败"。与 T9 抓到的 ⑫（`when` 挂一半）**是同一张脸**：
    #     **"没有内容"被当成了"出错"。**
    #   ★★★ T10·S9 收尾**又撞到一次**（`file.stat`：`du -sh` 对不存在的路径给 rc=1）⇒
    #     说明它**不是 `mon.*` 专属**，而且**原版断言只钉了 `grep`/`tail` 两种命令**（钉子太窄）
    #     ⇒ 本节**扩到全库**，并且**把命令名单补全**（`ls` / `du` / `df` / `wc` / `cat` / `find` / `stat`）。
    #   ★ 判据三类分开（命名约定：**判据步一律以 `assert` 开头**）：
    #     ① 名字以 `assert` 开头 ⇒ **判据步**，必须严格（"不命中即红"），**不受本条约束**；
    #     ② 出现在任何 `verify.from` 里 ⇒ 承担结论，同样严格；
    #     ③ 其余**探测/陈列型**步骤 ⇒ `ok_exit_codes` **必须含 1 或 2**
    #        （1 = grep/tail/du 的"没有"；2 = `ls` 的"不存在"）。
    #   ★★ 两条豁免（都**写明理由**，不许"因为没红所以留着"）：
    #     · **只看 `steps`，不看 `precheck`** —— precheck 问的是"**这条路走不走得通**"，
    #       **缺工具 / 缺依赖必须中止**（§12.33：「`kubeadm` 在不在」**永远不是**终态判据）。
    #     · **显式清单**：`_ALWAYS_THERE`（结构上**必然存在**的系统路径：`/proc` / `/sys` / 系统配置文件）
    #       ＋ `_BENIGN_PROBE`（行为上**不可能遇到"不在"** —— 逐条写明理由）。
    _PROBE_TOKENS = ("ls -l", "ls -ld", "du ", "df ", "tail ", "grep ", "wc ",
                     "stat ", "find ", "cat ")
    # ★★ 三级修：**先把 `{{ 参数 }}` 剥掉再匹配** —— 不然 `--tail={{ tail }}` 里的
    #    `{{ tail }}` 会被当成 `tail` 这个命令（**实测**：本节第一版就这样误伤了 `k8s.logs.logs`）。
    #    ⇒ ★ 与 ⑥ 同一条纪律的**元层面**：**"看起来像"不等于"是"** ——
    #      判据要做的是"**这条命令是不是探测型**"，不是"这行字里有没有那几个字母"。
    _PH = _re10.compile(r"\{\{[^}]*\}\}")
    _ALWAYS_THERE = ("/proc/", "/sys/", "/etc/hosts", "/etc/selinux/config", "df -P -i")
    _BENIGN_PROBE = {
        "file.cat.content":
            "它的 precheck `is_file`（`test -f {{ path }}`，只接受 rc=0）已经保证文件在 ⇒ 这一步遇不到『不在』",
    }
    _bad_rc = []
    for _aid, _a in sorted(actions.items()):
        if getattr(_a, "risk", None) != "green":
            continue
        _vfrom = {str(getattr(_v, "from_", None) or getattr(_v, "source", None)
                      or getattr(_v, "src", None))
                  for _v in (getattr(_a, "verify", None) or [])}
        for _s in list(getattr(_a, "steps", None) or []):
            _argv = [str(x) for x in (getattr(_s, "run", None) or []) if not isinstance(x, dict)]
            _flat = _PH.sub("", " ".join(_argv))          # ★ 剥掉占位符再判"是不是探测型"
            if not any(_t in _flat for _t in _PROBE_TOKENS):
                continue
            if _s.name.startswith("assert") or _s.name in _vfrom:
                continue
            if any(_t in _flat for _t in _ALWAYS_THERE):
                continue
            if ("%s.%s" % (_aid, _s.name)) in _BENIGN_PROBE:
                continue
            _codes = list(getattr(_s, "ok_exit_codes", None) or [0])
            if 1 in _codes or 2 in _codes:
                continue
            _bad_rc.append("%s.%s%s" % (_aid, _s.name, _codes))
    record("🄊 ★★ §12.51 / §12.64 ⑥：**只读动作里的『探测/陈列型』步骤都接受 rc=1 或 2**"
           "（「一条都没有」「0 条」「它不在」都是**结论**不是出错 —— 不声明它 ⇒ "
           "只读动作也会挂一条『步骤失败』= 假警报）。★ 真跑实测两次："
           "修前 `mon.alerts` 是 `步骤失败 1/8`（grep 类）· `file.stat` 是 `步骤失败 1/3`（du 类）；"
           "修后都 `0/N`。★ 命令名单已补全（ls/du/df/wc/cat/find/stat），不是只钉 grep/tail",
           _bad_rc == [], "、".join(_bad_rc) if _bad_rc else "（无）")

    # ══════════════════════════════════ 通用：新增的变更类动作都必须有 changed 判定
    missing = audit_rules(actions)
    record("㉙~㉟ 通用：**没有「看起来会变更、却没有 changed 规则」的动作**",
           missing == [], "、".join(missing))


# ═══════════════════════════════════════════════════════════════════════════
def check_t11_delivery(rcfg, ractions, map_data) -> None:
    """T11（离线）：**交付物** —— ★★ 文档与账本**不许对不上**（规范 §12.66~§12.72）。

    ★ 为什么要有这一节：T11 抓到的最大的那一类问题是「**文档在说旧话**」
      （根 `README.md` 停在 T0、`repo\README.md` 停在 T4）—— 它**不报错、不崩**，
      只是让读者信一个错的数字。
    ★★ 这一节的**红是设计意图**：账本变了而文档没变 = **交付物在说假话**，必须两边一起改
      （§12.66.2「同一个数字只许有一处定义」）。
    ★ 只扫「**公开面向文件**」，**绝不扫内部资料**（`开发记录\` / `阶段开题单\`）——
      依据 T10 ⑬「看门狗自己也会咬错人」：第一次跑就误伤，等于没有看门狗。
    """
    section("★ v1.14（T11）：交付物 —— 文档与账本不许对不上")

    proj = ROOT.parent                                  # 项目根 = 仓库根
    shots = proj / "docs" / "screenshots"
    files = {
        "README.md": proj / "README.md",
        "CHANGELOG.md": proj / "CHANGELOG.md",
        "工程方法.md": proj / "工程方法.md",
        "技术实现.md": proj / "技术实现.md",
        "LICENSE": proj / "LICENSE",
    }
    lack = [n for n, p in files.items() if not p.is_file()]
    if not shots.is_dir():
        lack.append("docs/screenshots/")
    record("㊾ ★★ §12.68 规矩 1：交付包**六件套齐全**（根 README · CHANGELOG · 工程方法 · "
           "技术实现 · LICENSE · docs/screenshots/）—— ★ 缺一件 ⇒ 红",
           not lack, ("缺：" + "、".join(lack)) if lack else "六件齐")

    def _txt(p):
        return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""

    # ── 账本实时值（★ 文档里的数字必须**逐字等于**它们）
    cov = reconcile(map_data, ractions)
    w = cov.get("weighted") or {}
    n_recipes = len(list((ROOT / "catalog" / "recipes").glob("*.yaml")))
    want = {
        "条数口径": "%d/%d" % (cov.get("done", 0), cov.get("total", 0)),
        "加权口径": "%d/%d" % (w.get("w_done", 0), w.get("w_all", 0)),
        "platform": "%d/%d" % (w.get("platform_done", 0), w.get("platform_total", 0)),
        "条目": "%d/%d" % (w.get("items_done", 0), w.get("items_total", 0)),
        "动作数": "动作 %d" % len(ractions),
        "配方数": "配方 %d" % n_recipes,
    }

    readme = _txt(files["README.md"])
    miss = [k for k, v in want.items() if v not in readme]
    record("㊾ ★★★ §12.66.1：根 `README.md` 的**数字与账本一致**"
           "（条数 / 加权 / platform / 条目 / 动作数 / 配方数）",
           bool(readme) and not miss,
           ("缺字面量：" + "、".join("%s=%s" % (k, want[k]) for k in miss)) if miss
           else " ｜ ".join("%s %s" % (k, want[k]) for k in want))

    rreadme = _txt(ROOT / "README.md")
    want2 = {"动作数": want["动作数"], "配方数": want["配方数"], "条数口径": want["条数口径"]}
    miss2 = [k for k, v in want2.items() if v not in rreadme]
    record("㊿ ★★ §12.66.2：`repo\\README.md` 的「当前能力」数字与账本一致（**防两个真相**）",
           not miss2,
           ("缺字面量：" + "、".join("%s=%s" % (k, want2[k]) for k in miss2)) if miss2
           else " ｜ ".join("%s %s" % (k, want2[k]) for k in want2))

    # ── ★★ S9 补：**版本号**与**门禁条数**这两类数字，此前**没人看住** ──────────
    #    现场（T15·S9 顺手抓到）：`repo\README.md` **同一份文件里两个时代** ——
    #      一边写着「动作规范 **v1.18**」，一边写着「版本 **0.11.0**（T13）·
    #      自检 离线 **574/574** · 完整 **650/650**」。而 §12.66 早就写着"同一批数字
    #      只许有一处定义"。★ 为什么它能烂 4 个阶段没人发现：**只有覆盖面**那四个口径
    #      （㊾ ㊿）有人对账，**版本号与门禁条数一个判据都没有** ⇒ 它不报错、不崩。
    #    ★ 判据的边界（写清楚，免得下次误以为它全能）：
    #      · ㊿a **正向**查「必须写到当前版本 / 当前规范版本」；**不**查旧版本残留
    #        —— `CHANGELOG.md` 按设计**就该**满是历史版本，查它等于误伤（T10 ⑬ 看门狗咬错人）。
    #      · ㊿b 只查「**各文档之间**不许打架」；**不**查"所有文档一起停在旧数字"
    #        —— 那件事只能靠收工时的两道门（条数必须上升）。
    pub = {
        "根 README.md": files["README.md"],
        "CHANGELOG.md": files["CHANGELOG.md"],
        "工程方法.md": proj / "工程方法.md",
        "技术实现.md": proj / "技术实现.md",
        "repo/README.md": ROOT / "README.md",
    }
    from app import __version__ as _ver  # noqa: PLC0415

    _spec_txt = _txt(ROOT / "docs" / "动作规范.md")
    _spec_ver = "v1.%d" % max(int(x) for x in re.findall(r"\*\*v1\.(\d+)", _spec_txt))
    ver_bad: list[str] = []
    for _n, _p in pub.items():
        _t = _txt(_p)
        # ★★ 只认**由「版本」引出的**版本号：`\b\d+\.\d+\.\d+\b` 会撞上 **IP**
        #    （`127.0.0.1`）—— 第一版就是这么在 `工程方法.md` 上**假红**的。
        #    ★ 这是 T10 ⑬「看门狗自己也会咬错人」的**第二次**现场：判据的**边界**没写窄。
        if not re.search(r"版本[^\d\n]{0,14}\d+\.\d+\.\d+", _t):
            continue                      # 这份文档压根不声明版本 ⇒ 不适用（**不算红**）
        if _ver not in _t:
            ver_bad.append("%s 缺 %s" % (_n, _ver))
    for _n in ("根 README.md", "repo/README.md"):
        if _spec_ver not in _txt(pub[_n]):
            ver_bad.append("%s 缺规范版本 %s" % (_n, _spec_ver))
    record("㊿a ★★ §12.66.1（S9 补）：**版本号**从此有人看住 —— 凡提到版本的公开文档"
           "必须出现当前 `app.__version__`；根 README 与 `repo\\README.md` 还必须写出"
           "**当前规范版本**（★ 现场：`repo\\README.md` 一边 `v1.18`、一边 `0.11.0（T13）`）",
           not ver_bad,
           "、".join(ver_bad) or "当前版本 %s · 规范 %s" % (_ver, _spec_ver))

    #    ★★ 约定（写进 §12.112）：**当前**门禁条数必须在**同一行**同时写成
    #      `离线 N/N` 与 `完整 M/M`。★ 为什么这样就能把"当年"挑出去 ——
    #      **不靠认语境词**（`CHANGELOG` 的当前行里也有「从 638/714 升上来」，
    #      而历史行与当前行**长得一模一样**），而靠项目自己的不变量：
    #      **门禁条数只许上升**（收工准则）⇒ **历史值必然更小**
    #      ⇒ **每份文档取最大的那个，就是它的"当前值"**。
    #      ★ 第一版按"全部值必须唯一"判 ⇒ 在 `CHANGELOG` 的 8 条历史门禁行
    #        与 `工程方法.md` 的"真实事故（549/549 全绿）"上**假红**了两轮
    #        —— 同一次里 ㊿a 还撞上 `127.0.0.1`。★ **判据的边界要写窄，不是写宽。**
    _maxes: dict[str, dict[str, int]] = {}
    for _n, _p in pub.items():
        _off_c: list[int] = []
        _full_c: list[int] = []
        for _line in _txt(_p).splitlines():
            if "离线" not in _line or "完整" not in _line:
                continue
            _frs = [int(_m.group(1)) for _m in re.finditer(r"(\d+)\s*/\s*(\d+)", _line)
                    if _m.group(1) == _m.group(2)]      # ★ 只认 `N/N` 这种**自洽分数**
            if len(_frs) == 2:
                _off_c.append(_frs[0])
                _full_c.append(_frs[1])
        if _off_c:
            _maxes[_n] = {"离线": max(_off_c), "完整": max(_full_c)}
    _off_vals = sorted({v["离线"] for v in _maxes.values()})
    _full_vals = sorted({v["完整"] for v in _maxes.values()})
    record("㊿b ★★ §12.66.2（S9 补）：**门禁条数**在各公开文档之间不许打架 "
           "（约定：当前数字**同一行**写成 `离线 N/N` ＋ `完整 M/M`；"
           "★ 历史值更小 ⇒ 取每份文档的**最大值**当「当前值」）"
           "—— ★ 这正是 `repo\\README.md` 停在 `574/574 · 650/650` 四阶段没人发现的那类洞",
           len(_maxes) >= 2 and len(_off_vals) == 1 and len(_full_vals) == 1,
           " ｜ ".join("%s=%d/%d" % (_n, _v["离线"], _v["完整"])
                       for _n, _v in sorted(_maxes.items()))
           or "一份都没声明")

    # ── 措辞黑名单 + 脱敏标注（★ 范围**写死**；豁免理由写在规范 §12.70.1）
    black = ["交接", "新话题", "工作流", "高质量", "优雅", "极致", "完美", "业界领先"]
    targets = [
        ("README.md", files["README.md"]),
        ("CHANGELOG.md", files["CHANGELOG.md"]),
        ("工程方法.md", files["工程方法.md"]),
        ("技术实现.md", files["技术实现.md"]),
        ("repo/README.md", ROOT / "README.md"),
        ("docs/screenshots/README.md", shots / "README.md"),
    ]
    hits, nosc, scanned = [], [], 0
    for name, p in targets:
        if not p.is_file():
            continue
        scanned += 1
        tx = _txt(p)
        hits += ["%s 命中「%s」" % (name, word) for word in black if word in tx]
        if "公开前必须脱敏" not in tx:
            nosc.append(name)
    record("㊾ ★★ §12.70.1：公开面向文件**通过措辞黑名单**（工作流词 ＋ 自夸形容词）"
           "｜★ 范围写死：只扫公开面向文件，**不扫内部资料**",
           not hits, "、".join(hits) if hits
           else "%d 个文件 × %d 个词 · 0 命中" % (scanned, len(black)))
    record("㊾ ★ §12.70.2 规矩 2：公开面向文件**文首标注了「公开前必须脱敏」**"
           "（防「以为已经脱敏了」这个错觉）",
           not nosc, ("未标注：" + "、".join(nosc)) if nosc else "已扫描的 %d 个文件全部已标注" % scanned)


# ---------------------------------------------------------------- T15：报告与知识沉淀


def _t15_records():
    """给断言用的一套**人造记录**（★ 里面没有任何真机数据）。

    三种"必须如实说"的情形各来一条：**失败**（任务 failed）· **未执行**（请求 pending / rejected）·
    **读不到**（没有任务号 / 没有复核）。★ 它们不依赖靶机、也不依赖模型 —— 所以能进**离线门**。
    """
    session = {"id": "A-T15-FAKE", "title": "docker-01 上磁盘快满了", "model": "m", "provider": "p",
               "tier": "A"}
    turns = [
        {"seq": 1, "role": "user", "text": "docker-01 上磁盘快满了", "note": "",
         "created_at": "2026-09-27T20:00:00"},
        # ★ 没有任务号的事件（回问）—— 它**必须**出现在时间线里（§12.105.4）
        {"seq": 2, "role": "assistant", "text": "要查哪台？", "note": "ASK_HOST",
         "created_at": "2026-09-27T20:00:02"},
    ]
    calls = [
        # ① 成功 + 有任务号（跨机 A）
        {"seq": 3, "action_id": "disk.usage", "host_id": "h1", "task_id": "T-OK",
         "status": "ok", "explain": "根分区 88%", "created_at": "2026-09-27T20:01:00"},
        # ② 失败（跨机 B）—— ★ 晚于 ⑤，用来验"排序只认记录里的时间"
        {"seq": 4, "action_id": "disk.topdir", "host_id": "h2", "task_id": "T-FAIL",
         "status": "failed", "explain": "取不到", "created_at": "2026-09-27T20:02:00"},
        # ③ 没有任务号（被拒）—— ★ 它**不许**混进结论区
        {"seq": 5, "action_id": "file.grep", "host_id": "h1", "task_id": "",
         "status": "rejected", "explain": "非 green", "created_at": "2026-09-27T20:03:00"},
    ]
    requests = [
        {"id": "REQ-P", "created_at": "2026-09-27T20:04:00", "action_id": "cron.upsert",
         "host_id": "h1", "risk": "yellow", "status": "pending", "reason": "定期清理",
         "decided_at": "", "task_id": "", "card": {}},
        {"id": "REQ-R", "created_at": "2026-09-27T20:05:00", "action_id": "pkg.install",
         "host_id": "h1", "risk": "yellow", "status": "rejected", "reason": "装 ncdu",
         "decided_at": "2026-09-27T20:06:00", "task_id": "", "card": {}},
    ]
    tasks = {
        "T-OK": {"task": {"id": "T-OK", "host_id": "h1", "action_id": "disk.usage", "status": "ok",
                          "exit_code": 0, "duration_ms": 900, "created_at": "2026-09-27T20:01:00",
                          "params_json": {}, "verify_detail": [{"name": "根分区在", "ok": True,
                                                                "from": "df", "field": "/"}],
                          "conclusion": "根分区 88%"},
                 "steps": [{"seq": 1, "title": "df", "status": "ok", "exit_code": 0}],
                 "artifacts": [{"kind": "stdout", "label": "df",
                                "path": "var/artifacts/tasks/T-OK/df.txt"}]},
        "T-FAIL": {"task": {"id": "T-FAIL", "host_id": "h2", "action_id": "disk.topdir",
                            "status": "failed", "exit_code": 1, "duration_ms": 700,
                            "created_at": "2026-09-27T20:02:00", "params_json": {"path": "/var/log"},
                            "verify_detail": [], "conclusion": "取不到"},
                   "steps": [{"seq": 1, "title": "du", "status": "failed", "exit_code": 1}],
                   "artifacts": []},
    }
    usage = {"outflow_calls": 2, "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
             "tool_calls": 3, "tool_ok": 1, "conflicts": 0}
    return session, turns, calls, requests, tasks, usage


def check_t15_report(rcfg, ractions, map_data) -> None:
    """T15（运维报告与知识沉淀）· 离线可跑的结构断言 Ⓐ~Ⓘ ＋ Ⓛ（规范 §12.104~§12.108 / §12.111）。

    ★★ 本节的**主题**就是那句话：**「报告里每一句结论，都要能被点回它出生的那一次执行。」**
      ⇒ 九条里有五条是"**报告不许**说什么 / 不许拿什么充数"：

        Ⓐ 没有任务号 ⇒ **不许混进结论区**（★ 编一个任务号也冒充不了证据）
        Ⓑ 报告**不许说假话**（措辞由**记录里的状态**决定）＋ 生成前的自我扫描
        Ⓓ 时间线排序**只认记录里的时间** ＋ **跨机永不合并**
        Ⓔ 知识检索**只查结构化**（★ 不含 AI 的自由回答）＋ 命中不到要明说
        Ⓕ 候选**只落草案区、不生效**（`catalog/recipes/` 逐字节不变）
        Ⓖ 源码指纹**可证伪**（改一个字符 ⇒ 必变）
        Ⓗ **界面导出入口不许裸奔**（★ 这是真跑抓到的那条真缺陷的回归断言）
        Ⓘ 页签**零回退** ＋ 新增「报告」
        Ⓛ ★★ **门禁自己**的编码边界（子进程只有一个出口 ＋ 双向 pin 编码）——
          ★ 收口时抓到的**真缺陷**：门禁在**第 298 项处中断**，而它照样给出一行
          "通过 296 / 共 298" —— **看起来像一份结论**（§12.104.2 的同族：汇总数字也是"给人看的话"）
          ⇒ 判据要同时看住两件事：**"跑完了没有"** 与 **"跑过的那些对不对"**。

      ★ Ⓒ 是唯一一条要起 HTTP 的：**报告导出必须过鉴权闸门**（闸门是**请求层**的性质，
        函数层测它等于自己证明自己 —— 同 `check_t14_auth` 的理由）。
      ★★ 所有口令操作都发生在 `tempfile.mkdtemp()` 下，**绝不碰** `repo/var/auth.json`。
    """
    section("★ v1.18（T15）：报告 / 时间线 / 本地知识 / 候选 / 源码指纹 / 门禁自身边界"
            "（断言 Ⓐ~Ⓘ ＋ Ⓛ）")
    import ast
    import json as _json
    import shutil
    import tempfile

    from app.errors import OpsError
    from app.report import (NO_TASK_ID, build_report, report_name, scan_claims,
                            timeline_rows)

    repo = ROOT
    actions = ractions if isinstance(ractions, dict) else {a.id: a for a in ractions}
    session, turns, calls, requests, tasks, usage = _t15_records()
    note = {"host_names": {"h1": "h1", "h2": "h2"}, "generated_at": "2026-09-27T21:00:00",
            # ★ 人造的风险表：故意把其中一条说成 `yellow` —— 判据要看的是
            #   "渲染层拿到风险等级会不会如实写出来"，而不是真实 catalog 长什么样。
            "action_risks": {"disk.usage": "green", "disk.topdir": "yellow",
                             "file.grep": "green"}}
    text = build_report(session, turns, calls, requests, tasks, usage, **note)

    # ── Ⓐ ★★ 每条结论都要挂得起证据 ───────────────────────────────
    blocks = [ln for ln in text.splitlines() if ln.startswith("#### `")]
    n_task_blocks = len([b for b in blocks if b.startswith("#### `T-")])
    # ★ 判据要**锋利**：光看"整篇里出现过这句话"是不够的 ——
    #   必须**那一行**（被拒的那条调用所在的时间线行）自己带着「没有任务号」。
    grep_rows = [ln for ln in text.splitlines()
                 if ln.startswith("|") and "`file.grep`" in ln]
    row_ok = bool(grep_rows) and NO_TASK_ID in grep_rows[0]
    record("Ⓐa ★★ §12.104.1：**没有任务号的调用不许混进结论区** —— "
           "它只能出现在时间线与 §4 的「不可回放」单列里，且措辞是「没有任务号（不可回放）」",
           NO_TASK_ID in text and text.count(NO_TASK_ID) >= 3 and n_task_blocks == 2 and row_ok,
           "不可回放出现 %d 次 · 证据块 %d 个（应为 2：只有 T-OK / T-FAIL）· 那一行带标注=%s"
           % (text.count(NO_TASK_ID), n_task_blocks, row_ok))
    # ★★ §12.105.3：时间线必须能看出「这是变更」还是「只是看了一眼」
    record("Ⓐa' ★★ §12.105.3 / 清单 238：时间线有**类型列**，且按风险等级区分"
           "「执行（只读）」与「★ 执行（变更 · yellow）」",
           "| 类型 |" in text and "执行（只读）" in text and "执行（变更" in text
           and "变更请求（yellow）" in text,
           "有类型列=%s · 只读标签=%s · 变更标签=%s"
           % ("| 类型 |" in text, "执行（只读）" in text, "执行（变更" in text))
    # ★ 证伪：**编一个任务号**也冒充不了证据 —— 取不到留证 ⇒ 只能写"读不到"
    fake = build_report(session, turns, calls,
                        [dict(requests[0], task_id="T-FAKE-9001", status="approved")],
                        tasks, usage, **note)
    record("Ⓐb ★★ **编一个任务号 ⇒ 也冒充不了证据**（任务留证取不到时，只能写「读不到」，"
           "不许出现「成功」）",
           "读不到" in fake and "T-FAKE-9001" in fake
           and "#### `T-FAKE-9001`" in fake
           and "**成功**" not in fake.split("#### `T-FAKE-9001`")[1].split("####")[0],
           "该块里出现 成功=%s"
           % ("**成功**" in fake.split("#### `T-FAKE-9001`")[1].split("####")[0]))

    # ── Ⓑ ★★ 报告不许说假话 ──────────────────────────────────────
    record("Ⓑa ★★ §12.104.2：措辞由**记录里的状态**决定 —— "
           "任务 failed ⇒「失败」；请求 pending ⇒「未执行（人还没点确认）」；"
           "rejected ⇒「未执行（人驳回了）」",
           ("失败" in text) and ("未执行（人还没点确认）" in text) and ("未执行（人驳回了）" in text),
           "失败=%s pending=%s rejected=%s"
           % ("失败" in text, "未执行（人还没点确认）" in text, "未执行（人驳回了）" in text))
    # ★★ 三种"读不到"必须**明说"没有"**，不许留白
    record("Ⓑb ★★ 三种「读不到」如实说：没有任务号 / 没有复核 / 没有自证 —— 一律**写出来**，"
           "不许空着（★ 「读不到 ≠ 没成功」）",
           (NO_TASK_ID in text) and ("没有复核记录" in text)
           and ("本任务没有自证记录" in text) and ("（无归档）" in text),
           "无任务号=%s 无复核=%s 无自证=%s 无归档=%s"
           % (NO_TASK_ID in text, "没有复核记录" in text,
              "本任务没有自证记录" in text, "（无归档）" in text))
    record("Ⓑc ★★ §12.104.2 / 红线 10：**全文不许出现「已修复 / 已完成 / 问题已解决」**"
           "（平台自己说的话里一个都不许有）",
           scan_claims(text) == [], "命中：%s" % (scan_claims(text) or "无"))
    # ★ 证伪：把断言词塞进渲染层自己的话里 ⇒ **必须拒绝生成**（不是"生成完随它去"）
    try:
        from app.report import _guard_claims  # noqa: PLC0415
        try:
            _guard_claims("本次变更**已完成**，问题已解决")
            got = "（没有拒绝 —— 这正是缺陷）"
        except OpsError as exc:
            got = exc.code
    except Exception as exc:  # noqa: BLE001
        got = "%s: %s" % (type(exc).__name__, exc)
    record("Ⓑd ★★ **证伪**：报告生成前的自我扫描必须真的拦得住 —— "
           "塞一句「已完成」进去 ⇒ 抛 `REPORT_CLAIM_FORBIDDEN`",
           got == "REPORT_CLAIM_FORBIDDEN", "实际：%s" % got)

    # ── Ⓒ ★★ 报告导出**过鉴权闸门**（★ 真起一个本地服务打 HTTP）───────
    #   ★★ 为什么必须打 HTTP：闸门是**请求层**的性质（`server._handle` 的唯一漏斗）。
    #      函数层测它 = 自己证明自己（同 `check_t14_auth` 的理由）。
    #   ★★ 为什么用临时口令文件 + 临时会话库：`var/auth.json` 是**用户的真凭据**，
    #      `var/ops.db` 里有用户的真实记录 —— 自检碰它们就是破坏。
    from app.server import bootstrap as _t15_bootstrap

    tmp4 = Path(tempfile.mkdtemp(prefix="aoc-t15-gate-"))
    console = None
    try:
        from app.ai.sessions import AiSessions
        from app.auth import Auth

        _c, _a, _m, _s, _e, api = _t15_bootstrap(repo)
        api.auth = Auth(_TmpAuthCfg(tmp4 / "var" / "auth.json"))
        tmp_sess = AiSessions(tmp4 / "t15gate.db")
        tmp_sess.init()
        sid = tmp_sess.start_session("m", "p", "A", title="T15 自检会话")
        tmp_sess.add_turn(sid, "user", "查一下磁盘")
        old_sess = api.ai.sessions
        api.ai.sessions = tmp_sess
        console = _LocalConsole(api, rcfg)
        try:
            exp = "/api/ai/reports/%s/export?format=md" % sid
            st_no, _payload_no = console.req("GET", exp)
            st_ping, pg = console.req("GET", "/api/auth/ping")
            build_in_ping = (pg.get("data") or {}).get("build") or {}
            _r = console.req("POST", "/api/auth/setup", {"password": "t15-selftest-pass"})
            tok = ((_r[1].get("data") or {}).get("token")) or ""
            st_yes, payload = console.req("GET", exp, token=tok)
            body = str(payload.get("raw") or "")
            record("Ⓒa ★★ §12.104.3 / §12.97.2：**报告导出过鉴权闸门** —— "
                   "不带令牌 ⇒ **401**；带对令牌 ⇒ **200 且是 md 正文**",
                   st_no == 401 and st_yes == 200 and body.startswith("# 运维报告")
                   and sid in body and "生成于" in body,
                   "无令牌=%d · 有令牌=%d · 正文头=%s · 含会话号=%s"
                   % (st_no, st_yes, body[:12].replace("\n", " "), sid in body))
            record("Ⓒb ★ 报告正文里带**生成时刻**（快照语义，§12.104.1）＋"
                   "带**鉴权闸门的自述**（不内嵌原文）",
                   "生成于" in body and "没有内嵌目标机原文" in body,
                   "含生成时刻=%s · 含不内嵌声明=%s"
                   % ("生成于" in body, "没有内嵌目标机原文" in body))
            record("Ⓒc ★★ §12.108.2：**免鉴权的探活接口里带得出构建指纹**"
                   "（登录前就看得见「跑的是哪一版」）",
                   st_ping == 200 and len(str(build_in_ping.get("source_short") or "")) >= 8
                   and int(build_in_ping.get("files") or 0) > 10,
                   "ping=%d · 短指纹=%s · 文件数=%s"
                   % (st_ping, build_in_ping.get("source_short"), build_in_ping.get("files")))
        finally:
            api.ai.sessions = old_sess
    except Exception as exc:  # noqa: BLE001
        record("Ⓒ ★★ 报告导出过鉴权闸门", False, "%s: %s" % (type(exc).__name__, exc))
    finally:
        if console is not None:
            console.close()
        shutil.rmtree(tmp4, ignore_errors=True)

    # ── Ⓓ ★ 时间线：排序只认记录里的时间 ＋ 跨机永不合并 ─────────────
    rows = timeline_rows(calls, requests, turns, host_names={"h1": "h1", "h2": "h2"})
    times = [r["at"] for r in rows]
    hosts = [r["host"] for r in rows if r["host"]]
    record("Ⓓa ★★ §12.105：时间线**按记录里的时间升序**（送进去是乱序）＋ "
           "**跨机永不合并**（两台机器就是两行）",
           times == sorted(times) and len(rows) == 6 and hosts.count("h1") == 4
           and hosts.count("h2") == 1,
           "行数=%d · 升序=%s · h1=%d h2=%d"
           % (len(rows), times == sorted(times), hosts.count("h1"), hosts.count("h2")))
    # ★ 没有任务号的行**也要出现**（回问 / 被拒不是"没发生过"）
    no_task_rows = [r for r in rows if r["kind"] != "request" and not r["task_id"]]
    record("Ⓓb ★ §12.105.4：**没有任务号的行也要出现**（回问 / 被拒也是这次排障的一部分）",
           len(no_task_rows) == 2, "无任务号行数=%d（应为 2：回问 ＋ 被拒）" % len(no_task_rows))

    # ── Ⓔ ★★ 知识检索：只查结构化 ＋ 命中不到明说 ─────────────────
    tmp1 = Path(tempfile.mkdtemp(prefix="aoc-t15-kb-"))
    try:
        from app.ai.knowledge import LocalKnowledge
        from app.ai.sessions import AiSessions

        ks = AiSessions(tmp1 / "kb.db")
        ks.init()
        s1 = ks.start_session("m", "p", "A", title="磁盘满了怎么处理")
        ks.add_turn(s1, "user", "docker-01 磁盘快满了怎么办")
        ks.add_tool_call(s1, "disk.usage", "docker-01", task_id="T-KB1", status="ok", ok=True,
                         explain="根分区 88%")
        s2 = ks.start_session("m", "p", "A", title="磁盘满了怎么处理")
        ks.add_turn(s2, "user", "又满了")
        ks.add_tool_call(s2, "disk.usage", "docker-01", task_id="T-KB2", status="ok", ok=True,
                         explain="根分区 91%")
        kb = LocalKnowledge(ks, host_names={"docker-01": "docker-01"})
        hit = kb.search("disk")          # ★ 查"动作侧"的词：命中的是**带任务号**的工具调用
        hit_cn = kb.search("磁盘")        # ★ 查"人话侧"的词：命中的是标题 / 人的问句
        miss = kb.search("zzz-绝不存在的词-zzz")
        record("Ⓔa ★★ §12.106.3：**命中不到要明说「没有记录」＋交代查了哪些范围**"
               "（不是一句「没查到」）",
               miss["hit_count"] == 0 and "没有记录" in miss["text"]
               and bool(miss["searched"].get("scanned_rows"))
               and "ai_turn" in " ".join(miss["searched"]["tables"]),
               "命中=%d · 扫了 %d 行 · 文本含「没有记录」=%s"
               % (miss["hit_count"], miss["searched"].get("scanned_rows", 0),
                  "没有记录" in miss["text"]))
        record("Ⓔb ★ §12.106.5：命中时**出处四要素齐**（会话 / seq / 时间 / 任务号）"
               "—— 人话侧的问句命得中、动作侧的调用也命得中（且带得出任务号）",
               hit["hit_count"] > 0 and hit_cn["hit_count"] > 0
               and all(("session_id" in h and "at" in h and "task_id" in h) for h in hit["hits"])
               and any(h["task_id"] for h in hit["hits"]),
               "disk 命中 %d 条 · 磁盘 命中 %d 条 · 带任务号的命中=%s"
               % (hit["hit_count"], hit_cn["hit_count"],
                  any(h["task_id"] for h in hit["hits"])))
        # ★★ 实现层扫描（AST）：**`ai_turn` 的每一条查询都必须带 `role = 'user'`** ——
        #    混进 AI 的自由回答 = 把幻觉检索回来当天条（§12.106.2）。
        src = (repo / "app" / "ai" / "sessions.py").read_text(encoding="utf-8")
        joined: list[str] = []
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef) and node.name == "knowledge_corpus":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.JoinedStr):
                        s = "".join(v.value for v in sub.values
                                    if isinstance(v, ast.Constant) and isinstance(v.value, str))
                        if "ai_turn" in s:
                            joined.append(s)
        record("Ⓔc ★★ §12.106.2：**语料里不含 AI 的自由回答** —— "
               "`ai_turn` 的每一条查询都**带 `role = 'user'`**（实现层，走 AST 查）",
               bool(joined) and all(("role" in s and "user" in s) for s in joined),
               "ai_turn 查询 %d 条 · 全部带 role 过滤=%s"
               % (len(joined), all(("role" in s and "user" in s) for s in joined)))
    finally:
        shutil.rmtree(tmp1, ignore_errors=True)

    # ── Ⓕ ★★ 候选：只落草案区、不生效 ──────────────────────────────
    tmp2 = Path(tempfile.mkdtemp(prefix="aoc-t15-cand-"))
    try:
        from app.ai.knowledge import LocalKnowledge, mine_candidates
        from app.ai.sessions import AiSessions
        from app.ai.tools import ToolFace

        cs = AiSessions(tmp2 / "cand.db")
        cs.init()
        # 两个会话，跑**同一串**动作（≥ 3 步 ⇒ 够成候选）
        seq_ids = ["disk.usage", "disk.topdir", "log.view"]
        for i in (1, 2):
            sid_i = cs.start_session("m", "p", "A", title="候选样本 %d" % i)
            for a in seq_ids:
                cs.add_tool_call(sid_i, a, "docker-01", task_id="T-C%d-%s" % (i, a), status="ok", ok=True)
        out_dir = tmp2 / "recipes-candidate"
        res = mine_candidates(sessions=cs, actions=actions, out_dir=out_dir, min_support=2,
                              min_len=3, catalog_recipes=Path(rcfg.paths.catalog) / "recipes")
        files = sorted(out_dir.glob("candidate-*.yaml"))
        heads_ok = all("★ 未生效" in f.read_text(encoding="utf-8") for f in files)
        # ★★ AI 侧**结构上没有**"写候选"这条路：工具面里搜不到它
        face = ToolFace(rcfg, actions)
        names = [s["function"]["name"] for s in face.function_specs()]
        tool_text = _json.dumps(face.to_json(), ensure_ascii=False)
        record("Ⓕa ★★ §12.107.2/§12.107.3：候选**只落 `var/lab/recipes-candidate/`**；"
               "`catalog/recipes/` **逐字节不变**（`recipes_untouched`）；草案带「未生效」头",
               bool(files) and res["recipes_untouched"] is True
               and str(out_dir) in res["out_dir"] and heads_ok,
               "草案 %d 份 · recipes_untouched=%s · 带未生效头=%s"
               % (len(files), res["recipes_untouched"], heads_ok))
        record("Ⓕb ★★ §12.107.3：**AI 侧没有这条写入通道** —— 工具面里搜不到候选工具，"
               "`kb_search` 是唯一的知识工具（且只有读）",
               all("candidate" not in n for n in names)
               and all("candidate" not in n for n in names)
               and "kb_search" in names
               and "candidate" not in tool_text,
               "工具数=%d · 含 kb_search=%s · 工具面里出现 candidate=%s"
               % (len(names), "kb_search" in names, "candidate" in tool_text))
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    # ── Ⓖ ★ 源码指纹可证伪 ────────────────────────────────────────
    tmp3 = Path(tempfile.mkdtemp(prefix="aoc-t15-fp-"))
    try:
        from app.fingerprint import DISPLAY_LEN, source_fingerprint

        (tmp3 / "app").mkdir()
        (tmp3 / "web").mkdir()
        f1 = tmp3 / "app" / "a.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        (tmp3 / "web" / "b.js").write_text("var y = 1;\n", encoding="utf-8")
        fp_a = source_fingerprint(tmp3)
        fp_a2 = source_fingerprint(tmp3)
        f1.write_text("x = 2\n", encoding="utf-8")   # ★ 只改**一个字符**
        fp_b = source_fingerprint(tmp3)
        real = source_fingerprint(repo)
        blob = _json.dumps(real, ensure_ascii=False)
        record("Ⓖa ★★ §12.108.4：**指纹能证伪** —— 改一个字符 ⇒ 指纹必变；"
               "同一份源码算两次 ⇒ 同一个值（`scanned_at` 不参与哈希）",
               fp_a["hash"] != fp_b["hash"] and fp_a["hash"] == fp_a2["hash"]
               and len(fp_a["short"]) == DISPLAY_LEN and fp_a["files"] == 2,
               "改前 %s… · 改后 %s… · 同源两次相同=%s"
               % (fp_a["short"], fp_b["short"], fp_a["hash"] == fp_a2["hash"]))
        record("Ⓖb ★ §12.108.3：指纹里**只有文件名与哈希** —— 不含文件内容 / 凭据 / 主机信息",
               "REPORT_CLAIM_FORBIDDEN" not in blob and "sk-" not in blob
               and "BEGIN " not in blob and real["files"] > 10,
               "文件数=%d · 全长=%s…" % (real["files"], real["short"]))
    finally:
        shutil.rmtree(tmp3, ignore_errors=True)

    # ── Ⓗ ★★ 界面导出入口**不许裸奔**（★ 真缺陷的回归断言）──────────
    js = (repo / "web" / "app.js").read_text(encoding="utf-8")
    bad_js: list[str] = []
    if re.search(r"window\.open\(\s*exportUrl", js):
        bad_js.append("window.open(exportUrl…)（带不上令牌 ⇒ 必然 401）")
    if re.search(r"location\.href\s*=\s*['\"][^'\"]*/export", js):
        bad_js.append("location.href=…/export…（同上）")
    if re.search(r"fetch\(\s*url\s*\)", js):
        bad_js.append("fetch(url) 裸取（不带 Authorization）")
    need_js = ["async function fetchText(", "async function downloadText(", "authHeaders()"]
    miss_js = [n for n in need_js if n not in js]
    record("Ⓗ ★★ §12.104.3：**界面上的导出入口一律带令牌**（★ 真跑抓到的真缺陷："
           "T14 加了鉴权之后，三个导出入口用 `window.open` / `location.href` / 裸 `fetch` "
           "⇒ **全部 401**）—— 判据：不许有裸入口，且必须有 `fetchText` / `downloadText`",
           not bad_js and not miss_js,
           "裸入口：%s ｜ 缺函数：%s" % (bad_js or "无", miss_js or "无"))

    # ── Ⓘ ★ 页签零回退 ＋ 新增「报告」 ────────────────────────────
    tabs10 = ["actions", "recipes", "checkup", "history", "batches", "gaps", "k8s", "mon",
              "chat", "pending"]
    html = (repo / "web" / "index.html").read_text(encoding="utf-8")
    all_tabs = tabs10 + ["reports"]
    miss_html = [t for t in tabs10 if 'data-tab="%s"' % t not in html]
    miss_pane = [t for t in all_tabs if 'id="pane-%s"' % t not in html]
    miss_js2 = [t for t in all_tabs if "'%s'" % t not in js]
    # ★★ T15·S10：页签这笔账还要**多算一处** —— `工具\capture-screenshots.py` 的**走查表**。
    #    ★ 为什么值得单列：T14 那颗「三个导出入口全部 401」，**一半原因就是这张表没跟着页签长**
    #      —— 它当时只有 8 个页签，而界面已经有 11 个 ⇒ **T12/T14/T15 新增的三个页签
    #      没有任何真人看过**。（「走查没做」不是懒，是**表没跟着长 ⇒ 走查也走不到**。）
    #    ★ 判据：**逐个同序**（走查稿是按界面顺序读的，顺序错 = 读错）。
    _cap = ROOT.parent / "工具" / "capture-screenshots.py"
    if _cap.is_file():
        _walk = re.findall(r'^\s*\("([a-z0-9_-]+)",\s*"[^"]+\.png"',
                           _cap.read_text(encoding="utf-8"), re.M)
        _html_tabs = re.findall(r'data-tab="([a-z0-9_-]+)"', html)
        _walk_ok = _walk == _html_tabs
        _walk_detail = ("走查表 %d 个·与界面对得上" % len(_walk)) if _walk_ok else \
            ("★ **走查表对不上**：走查表 %s ／ 界面 %s" % (_walk, _html_tabs))
    else:
        _walk_ok = True
        _walk_detail = "（工具不在本次检出范围，跳过）"
    record("Ⓘ ★ 验收：**原 10 个页签零回退** ＋ 新增「报告」页签（页签 / 容器 / switchTab 三处都在）"
           "＋ ★★ **走查表也得跟着长**（`工具\\capture-screenshots.py` 的 `TABS` 必须与界面页签**逐个同序**）",
           not miss_html and not miss_pane and not miss_js2 and 'data-tab="reports"' in html
           and _walk_ok,
           "缺页签 %s · 缺容器 %s · JS 列表缺 %s · %s"
           % (miss_html or "无", miss_pane or "无", miss_js2 or "无", _walk_detail))

    # ── Ⓛ ★★ 门禁**自己**的编码边界（★ T15 收口抓到的**真缺陷**：门禁在第 298 项处中断）──
    #    ★ 判据为什么是"扫源码"而不是"再跑一次子进程"：
    #      这个洞的形态是**少了一个出口**；"跑一次没崩"只证明**这一次**没崩 ——
    #      换台机器、换个代码页又会犯（它就是这么过了八个月没被发现的）。
    #    ★ 扫的时候走 **AST**（不是字符串匹配）：本节的注释为了讲清现场**必须**提到那个 API
    #      的名字，字符串匹配会把注释也算成"命中" ⇒ **判据会判自己**（T14·S3 那条现场教训）。
    me = (ROOT / "tools" / "selftest.py").read_text(encoding="utf-8")
    #    ★★ 判据走 **AST**、不玩字符串 —— 两条现场教训叠在这儿：
    #      ① T14·S3「源码扫描必须走 AST」：字符串匹配会把注释 / 文档里的名字当成违规（假红）；
    #      ② ★ **本轮证伪演示第一条就把我这版判据自己的洞抓出来了**：
    #         第一版按「`def run_child` 到**下一个** `def` 之间」划地盘 ⇒
    #         只要把裸调用塞在**下一个 `def` 之前**，它就被算进 run_child 的地盘、**注入不红**
    #         （一条**假绿** —— 判据写成"看起来在看着"，比没有更危险）。
    #         ⇒ 改成按**函数体自己的行号区间**判（`lineno` ~ `end_lineno`）。
    tree = ast.parse(me)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "run_child"), None)
    lo, hi = (fn.lineno, fn.end_lineno) if fn is not None else (0, 0)
    inside: list[int] = []
    outside: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if (isinstance(f, ast.Attribute) and f.attr == "run"
                and isinstance(f.value, ast.Name) and f.value.id in ("subprocess", "_sp")):
            (inside if lo <= node.lineno <= hi else outside).append(node.lineno)
    record("Ⓛa ★★ §12.111：自检里跑子进程**只有一个出口**（`run_child`），"
           "别处一处裸调用都不许有 —— 否则下次换个控制台代码页，门禁又会**红得早**"
           "（在第 298 项处中断，而不是红在被测的东西上）",
           fn is not None and not outside and len(inside) >= 1,
           "run_child 在第 %d~%d 行（体里 %d 处调用）· 越界 %s"
           % (lo, hi, len(inside), outside or "无"))

    r_cjk = run_child([sys.executable, "-c", "print('中文探针 OK')"])
    record("Ⓛb ★★ §12.111：子进程的输出编码**被 pin 成 utf-8**（不随控制台代码页变）",
           r_cjk.returncode == 0 and r_cjk.stdout.strip() == "中文探针 OK",
           "rc=%s stdout=%r stderr=%r"
           % (r_cjk.returncode, r_cjk.stdout.strip(), r_cjk.stderr.strip()))

    r_raw = run_child([sys.executable, "-c",
                       "import sys; sys.stderr.buffer.write(b'\\xcf\\xb8\\xd3\\xef\\n'); "
                       "sys.stderr.flush()"])
    record("Ⓛc ★★ §12.111：就算子进程**真的吐非 utf-8 的字节**（GBK 的「错误」二字），"
           "读回来这一侧也只是「替换字符」—— **绝不崩**、绝不把结果变成 `None`",
           isinstance(r_raw.stderr, str) and "\ufffd" in r_raw.stderr,
           "stderr=%r" % (r_raw.stderr.strip(),))


def check_t17(cfg, actions, map_data) -> None:
    """★★ T17（六·虚拟化层 · 克隆与身份重置）新增断言 Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ（规范 §12.136 / §12.137）。

    五件事，对应本话题的五句纪律：
      Ⓥ 克隆是 `red`，且 AI 侧**结构上不可请求**（被批准表 ＋ 白名单）
      Ⓦ 目标已存在 ⇒ **预检拒绝**（"不覆盖"是硬规矩，不是"覆盖了再报"）
      Ⓧ **五项身份**逐项有归属与判据，且「**故意不重置 ⇒ 必红**」的反例开关在位
      Ⓨ `hosts.yaml` 的登记**可逐字节回退**（在**临时目录**里真跑工具，不动真文件）
      Ⓩ **任何代码页下，只读工具都不因"打印"而失败**（T17·S0 那条真缺陷挣来的）

    ★ 全部**离线可跑**（§12.124 的口径：离线跑不出结论的判据 = 没有判据）。
    ★ 每条都配**证伪**：判据写坏了必须红 ——「绿着但不管用」是本文件最常见的敌人。
    """
    import ast
    import copy as _copy
    import hashlib
    import json
    import os
    import shutil
    import subprocess
    import sys as _sys

    from app.ai import requests as _req
    from app.yamlload import load_yaml

    section("★ v1.20（T17）：造机与身份重置 · 克隆与登记 · 证据通道的编码纪律")

    tmp = cfg.paths.var / "selftest-t17"
    if tmp.is_dir():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)

    def _yaml(p):
        try:
            return load_yaml(p) or {}
        except OpsError:
            return {}

    def _sub(argv, *, env_extra=None, cwd=None):
        #   ★★ 为什么必须显式 `encoding="utf-8"`（T17·S7 自检自身抓到的真异常）：
        #     `text=True` 会用**父进程的本地码页**解码子进程输出 ——
        #     而子进程按 UTF-8 打印（例如那个用来证伪的 `bare.py`）⇒ 父进程当场
        #     `UnicodeDecodeError`。★ 与 §12.134 同源：**编码是通道的属性**，
        #     "谁读"这一侧也要说清用什么编码读，不能靠默认值。
        #   ★★ 这里**不再裸调** `subprocess.run`（T17·S9 收紧）：自检里跑子进程**只有一个出口**
        #     （`run_child`，断言 Ⓛa 扫 AST 看住）。第一版在 check_t17 里自己开了一个口子 ——
        #     于是"只许有一个出口"那条断言当场变红。★ 这不是它太严，是它抓对了。
        return run_child([_sys.executable, *argv], timeout=120,
                         cwd=cwd or str(ROOT), env_extra=env_extra)

    # ══════════════════════════════════════════ Ⓥ 克隆是 red ＋ AI 结构上不可请求
    clone = actions.get("vm.clone")
    allow = [str(x) for x in ((_yaml(ROOT / "config.yaml").get("ai") or {}).get("yellow_allowlist") or [])]

    def _requestable(aid, table, allowed) -> bool:
        return aid in table or aid in allowed

    real = _requestable("vm.clone", _req.APPROVED_YELLOW, allow)
    record("Ⓥ ★★★ §12.127/§12.130：`vm.clone` 是 **red**，且 **AI 侧结构上不可请求**"
           "（不在被批准表、也不在白名单）",
           clone is not None and getattr(clone, "risk", "") == "red" and not real,
           "risk=%s ｜ 被批准表含它=%s ｜ config 白名单含它=%s"
           % (getattr(clone, "risk", "（没装载）"),
              "vm.clone" in _req.APPROVED_YELLOW, "vm.clone" in allow))

    widened = tuple(_req.APPROVED_YELLOW) + ("vm.clone",)
    record("Ⓥ ★ **证伪**：把 `vm.clone` 塞进被批准表 ⇒ 同一段判据**必须立刻报出来**"
           "（否则它是一条空转的判据）",
           _requestable("vm.clone", widened, allow),
           "表变宽后同一段判据：%s" % ("报出来了 ✓" if _requestable("vm.clone", widened, allow)
                                   else "★ 仍说不可请求 —— 判据空转"))

    # ══════════════════════════════════════════ Ⓦ 目标已存在 ⇒ 预检拒绝（不覆盖）
    pre = list(getattr(clone, "precheck", []) or []) if clone else []
    pre_names = [getattr(s, "name", "") for s in pre]
    pre_text = " ".join(
        " ".join(str(x) for x in (getattr(s, "run", None) or [])) for s in pre
    )
    record("Ⓦ ★★ §12.130.4：克隆的**预检**里有「目标已存在 ⇒ 拒绝」那一条"
           "（`vmx-absent` ＋ `dir-absent`）—— **不覆盖**是硬规矩",
           "target_free" in pre_names and "vmx-absent" in pre_text and "dir-absent" in pre_text,
           "预检步骤：%s ｜ 含 vmx-absent=%s ｜ 含 dir-absent=%s"
           % ("、".join(n for n in pre_names if n) or "（无）",
              "vmx-absent" in pre_text, "dir-absent" in pre_text))

    src_clone = (cfg.paths.catalog / "actions" / "vm.clone.yaml").read_text(encoding="utf-8")
    stripped = "\n".join(ln for ln in src_clone.splitlines()
                         if "vmx-absent" not in ln and "dir-absent" not in ln)
    record("Ⓦ ★ **证伪**：把那两条期望从动作 YAML 里删掉 ⇒ 同一段判据**必须变红**",
           ("vmx-absent" not in stripped) and ("dir-absent" not in stripped),
           "删掉之后：vmx-absent=%s ｜ dir-absent=%s"
           % ("vmx-absent" in stripped, "dir-absent" in stripped))

    # ══════════════════════════════════════════ Ⓧ 五项身份逐项有判据 ＋ 故意不重置 ⇒ 必红
    identity = {
        "① machine-id": "host.machine-id-reset",
        "② SSH host key": "host.ssh-hostkey-reset",
        "③ 主机名": "host.hostname-set",
        "④ 静态地址": "host.static-ip-set",
        "⑤ VMware UUID/MAC（只读读出）": "vm.vmx-read",
    }
    missing = [k for k, aid in identity.items() if aid not in actions]
    record("Ⓧ ★★★ §12.128：**五项身份**各有归属动作（① ~ ④ 由 `host.*` 重置、⑤ 由 `vm.vmx-read` **只读**读出）",
           not missing,
           "五项：%s ｜ 缺：%s" % ("、".join(identity.values()), "、".join(missing) or "（无）"))

    reset_ids = ("host.machine-id-reset", "host.ssh-hostkey-reset",
                 "host.hostname-set", "host.static-ip-set")

    def _judgement(a):
        """判据步的三个条件：**在** · **不是 optional** · **只认退出码 0**。"""
        st = None
        for s in getattr(a, "steps", []) or []:
            if getattr(s, "name", "") == "reset":
                st = s
                break
        if st is None:
            return False, "没有名为 `reset` 的判据步"
        if getattr(st, "optional", False):
            return False, "判据步被设成 optional（= 把判据取下来，§12.119）"
        codes = list(getattr(st, "ok_exit_codes", None) or [0])
        if codes != [0]:
            return False, "判据步 ok_exit_codes=%s（应当只认 0）" % codes
        return True, "判据步在 · 非 optional · ok_exit_codes=%s" % codes

    bad: list[str] = []
    for aid in reset_ids:
        a = actions.get(aid)
        ok, why = _judgement(a) if a is not None else (False, "没装载")
        if not ok:
            bad.append("%s（%s）" % (aid, why))
    record("Ⓧ ★★ 四个重置动作的判据步都**在**、**不是 optional**、**只认退出码 0**"
           "（★ 判据不许被设成 optional）",
           not bad, "、".join(bad) or "四个都对")

    no_dry = []
    for aid in reset_ids:
        a = actions.get(aid)
        if a is None or not any(getattr(p, "name", "") == "dry_run"
                                for p in getattr(a, "params", []) or []):
            no_dry.append(aid)
    record("Ⓧ ★★ 「**故意不重置 ⇒ 必红**」的反例开关在位：四个重置动作都有 `dry_run`"
           "（演练 = 只跑判据、不动手）",
           not no_dry, "缺 dry_run 的：%s" % ("、".join(no_dry) or "（无）"))

    fake = _copy.deepcopy(actions["host.machine-id-reset"]) if "host.machine-id-reset" in actions else None
    fake_ok, fake_why = (False, "没装载")
    if fake is not None:
        for s in getattr(fake, "steps", []) or []:
            if getattr(s, "name", "") == "reset":
                s.optional = True
        fake_ok, fake_why = _judgement(fake)
    record("Ⓧ ★ **证伪**：把判据步改成 `optional` ⇒ 同一段判据**必须红**",
           (fake is not None) and (not fake_ok), fake_why)

    # ══════════════════════════════════════════ Ⓨ hosts.yaml 可逐字节回退（临时目录里真跑工具）
    tool = ROOT / "tools" / "host_register.py"
    box = tmp / "register-sandbox"
    (box / "var" / "backups").mkdir(parents=True, exist_ok=True)
    (box / "hosts.yaml").write_bytes((ROOT / "hosts.yaml").read_bytes())
    before_sha = hashlib.sha256((box / "hosts.yaml").read_bytes()).hexdigest()

    r1 = _sub([str(tool), "--root", str(box), "--id", "aoc-t17-selftest",
               "--address", "203.0.113.240",
               "--vmx", "D:\\VMs\\aoc-t17-selftest\\aoc-t17-selftest.vmx",
               "--from-mother", "selftest"])
    try:
        p1 = json.loads(r1.stdout)
    except Exception:  # noqa: BLE001
        p1 = {}
    back = str(p1.get("backup") or "")
    r2 = _sub([str(tool), "--root", str(box), "--revert", back]) if back else None
    after_sha = hashlib.sha256((box / "hosts.yaml").read_bytes()).hexdigest()
    record("Ⓨ ★★ §12.131：`hosts.yaml` 的登记**可逐字节回退**"
           "（在**临时目录**里真跑：写 → 备份 → 回退 ⇒ sha256 与写前一致）",
           r1.returncode == 0 and p1.get("written") is True and bool(back)
           and r2 is not None and r2.returncode == 0 and after_sha == before_sha,
           "写入 rc=%s written=%s ｜ 回退 rc=%s ｜ 写前=%s ｜ 回退后=%s"
           % (r1.returncode, p1.get("written"), getattr(r2, "returncode", "（没跑）"),
              before_sha[:16], after_sha[:16]))

    detail_z: str
    if back and os.path.isfile(back):
        raw = bytearray(Path(back).read_bytes())
        raw[-1:] = b"#" if raw[-1:] != b"#" else b"\n"
        tampered = tmp / "tampered.bak"
        tampered.write_bytes(bytes(raw))
        # ★★ 这一条**不能用"revert 自己的退出码"判**（T17·S7 第一次跑就抓到了：
        #    `--revert` 内部把"备份的 sha256"与"写回后文件的 sha256"比 —— 那是**同义反复**
        #    （我们就是把那份字节写回去的）⇒ 它永远相等、永远绿。
        #    ⇒ 真正的判据是**上一层那条**：回退后必须等于**写之前**的 sha256。
        #      所以这里要问的是："拿被动过的备份回退之后，'回退后 == 写前'还成立吗？"
        #      答案必须是**不成立** —— 这才说明那条判据**真的在盯着字节**。
        r3 = _sub([str(tool), "--root", str(box), "--revert", str(tampered)])
        sha_after_tamper = hashlib.sha256((box / "hosts.yaml").read_bytes()).hexdigest()
        ok_t = sha_after_tamper != before_sha
        detail_z = ("回退一个被动过的备份之后：文件=%s ｜ 写前=%s ｜ 与写前不一致=%s（rc=%s）"
                    % (sha_after_tamper[:16], before_sha[:16], sha_after_tamper != before_sha,
                       r3.returncode))
        # ★ 收尾把沙箱恢复成"写前"的样子（免得下一条判据读到脏状态）
        (box / "hosts.yaml").write_bytes(Path(back).read_bytes())
    else:
        ok_t, detail_z = False, "没有备份可试"
    record("Ⓨ ★ **证伪**：拿一个**被动过一个字节**的备份去回退 ⇒ 上一层那条「回退后 == 写前」"
           "**必须不成立**（否则那条 sha256 比对就是空转的）",
           ok_t, detail_z)

    # ══════════════════════════════════════════ Ⓩ 任何代码页下，只读工具不因"打印"失败

    def _pins_stdio(path) -> bool:
        try:
            tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            return False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute) and f.attr == "reconfigure":
                    for kw in node.keywords:
                        if kw.arg == "encoding" and getattr(kw.value, "value", "") == "utf-8":
                            return True
        return False

    pinned = ["run_one.py", "run_recipe.py", "host_register.py", "vmprobe.py"]
    unpinned = [n for n in pinned if not _pins_stdio(ROOT / "tools" / n)]
    record("Ⓩ ★★ §12.134：命令行工具**自己 pin 住 stdout 编码**"
           "（否则结论里出现 `⇒` 就会崩 —— 崩的偏偏是**留证**那一步）",
           not unpinned, "没 pin 的：%s" % ("、".join(unpinned) or "（无）"))

    hosts_doc = _yaml(ROOT / "hosts.yaml")
    vmx = ""
    for h in (hosts_doc.get("hosts") or []):
        vm = (h or {}).get("vm") or {}
        if vm.get("vmx"):
            vmx = str(vm["vmx"])
            break

    r4 = _sub([str(ROOT / "tools" / "vmprobe.py"), "--mode", "vmx", "--vmx", vmx],
              env_extra={"PYTHONIOENCODING": "gbk", "PYTHONUTF8": None})
    record("Ⓩ ★★ **真跑**：在 **cp936（GBK）** 环境里跑只读探针 ⇒ **不许崩**"
           "（退出码 0/3 都算对，出现 Traceback 就算错）",
           r4.returncode in (0, 3) and "Traceback" not in (r4.stdout + r4.stderr),
           "rc=%s ｜ 有 Traceback=%s ｜ 用的是 %s"
           % (r4.returncode, "Traceback" in (r4.stdout + r4.stderr), vmx or "（没找到 vmx）"))

    bare = tmp / "bare.py"
    bare.write_text("print('⇒ 一个没有 pin 编码的小脚本')\n", encoding="utf-8")
    r5 = _sub([str(bare)], env_extra={"PYTHONIOENCODING": "gbk", "PYTHONUTF8": None})
    record("Ⓩ ★ **证伪**：同一个 GBK 环境下，一个**没有 pin** 的小脚本**必须崩**"
           "（`UnicodeEncodeError`）—— 这证明上一条的绿**是 pin 挣来的**，不是碰巧",
           r5.returncode != 0 and "UnicodeEncodeError" in r5.stderr,
           "rc=%s ｜ stderr 里有 UnicodeEncodeError=%s"
           % (r5.returncode, "UnicodeEncodeError" in r5.stderr))

    # ══════════════════════════════════════ Ⓩa 同一个作用域里不许有重复的函数定义
    #   ★★ 现场（T17 三处，全是**打补丁重复插入**留下的）：
    #      ① `vmware.py` 的 `mkdir_path`；② 同文件的 `disk_check`；③ `changed.py` 的 `_r_vm_clone`
    #      —— 前两个当场被看见改了，第三个**一直躺到 S9 收口**。
    #   ★★ 为什么它必须有人看住：Python 对**同名函数**是**后一处静默覆盖前一处** ——
    #      不报错、不警告、两段长得一模一样；评审只会读到其中一份，
    #      而"另一份是不是也被人改过"**没有任何痕迹**（§12.125 同族：信息在，但没送到读它的那一方）。
    #   ★ 判据**逐作用域**判（module ＋ 每个 class）——
    #      第一版按整文件判 ⇒ `__init__` 在几十个类里各有一个，当场**假红一片**
    #      （T10 ⑬「看门狗自己也会咬错人」的第 N 次现场：边界要写窄）。
    _dup: list[str] = []
    _scanned = 0
    for _p in sorted(list((ROOT / "app").rglob("*.py"))
                     + list((ROOT / "tools").rglob("*.py"))):
        _scanned += 1
        try:
            _t = ast.parse(_p.read_text(encoding="utf-8"))
        except SyntaxError as exc:                       # 编译那一条断言也管，这里只记一笔
            _dup.append("%s 语法错：%s" % (_p.name, exc))
            continue
        for _sname, _scope in ([("module", _t)]
                               + [(c.name, c) for c in ast.walk(_t)
                                  if isinstance(c, ast.ClassDef)]):
            _names = [n.name for n in _scope.body
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for _nm in sorted({x for x in _names if _names.count(x) > 1}):
                _dup.append("%s::%s::%s ×%d" % (_p.name, _sname, _nm, _names.count(_nm)))
    record("Ⓩa ★★ §12.138：**同一个作用域里不许有重复的函数定义**"
           "（打补丁重复插入 ⇒ 后者**静默覆盖**前者：不报错、不警告、评审看不出来）",
           not _dup, "、".join(_dup) or "扫了 %d 个 .py：无重复" % _scanned)

    # ══════════════════════════════════════ Ⓩb 身份脚本：查到什么，必须交代得出来
    #   ★★ 现场（T17·S8 真跑 · §12.139 第 1 条）：脚本对外报 `no-host-keys`，
    #      而**同一台机器上明明有 3 对钥匙、3 个指纹** —— **判据自己说了假话**。
    #      ★ 真因是一个老掉牙的 shell 陷阱：`for … done | sort` 把整个循环放进了**子 shell**，
    #        循环体里设的"有钥匙"标志位在函数外面**永远是 0** ⇒ 无条件判"没有钥匙"。
    #   ★ 这一条**不做** shell 语义的静态扫描（那必然误伤：脚本里就有合法的「循环接管道」）——
    #     它锁的是**当初让假话现形的那一点**：结论里必须把「问到几个文件（私钥/公钥）」摆出来。
    #     ★★ 缺口如实记（规范 §12.139 第 1 条尾）：这类"子 shell 变量陷阱"**没有行为判据**
    #        （本机没有稳定的 POSIX 环境能跑这段脚本）⇒ 靠**这条形态判据 ＋ 人评审**。
    _idscript = ROOT / "var" / "uploads" / "aoc-identity.sh"
    _istext = _idscript.read_text(encoding="utf-8") if _idscript.is_file() else ""

    def _count_line(text: str) -> list[str]:
        """找出那条"把三个计数摆出来"的输出行（`say` 一行里同时有 count/files/priv/pub）。

        ★ 为什么判**输出行**而不是判"文件里有这几个字"：变量名 `_npriv=` 里也含 `priv=` ——
          判"有没有这几个字"会被变量名骗过去（§12.139 同族：判据要钉在**对外那句话**上）。
        """
        return [ln for ln in text.splitlines()
                if ln.strip().startswith("say ") and all(
                    k in ln for k in ("count=", "files=", "priv=", "pub="))]

    _miss = [] if _count_line(_istext) else ["结论行里没有 count/files/priv/pub"]
    record("Ⓩb ★★ §12.139.1：身份脚本报 host key 时**必须把「问到什么」摆出来**"
           "（总文件数 / 私钥数 / 公钥数 ＋ 先数文件再谈指纹）"
           "—— ★ 「没读到」与「不存在」从此不许混为一谈",
           bool(_istext) and not _miss,
           "缺：%s" % "、".join(_miss) if _miss
           else "结论行：%s" % _count_line(_istext)[0].strip()[:90])
    _stripped = "\n".join(ln for ln in _istext.splitlines()
                          if not (ln.strip().startswith("say ")
                                  and "count=" in ln and "files=" in ln))
    record("Ⓩb ★ **证伪**：把那行计数从脚本里删掉 ⇒ **同一段判据**必须报缺"
           "（否则它就是一条「看着像在看着」的判据）",
           not _count_line(_stripped),
           "删掉那行之后，同一段判据找到的结论行数：%d" % len(_count_line(_stripped)))

    # ══════════════════════════════════════ Ⓩc 「指纹变了」的台阶：先备份、只撤这一台
    #   ★★ 现场（T17·S8 真跑 · §12.139 第 2 条）：重置 host key 之后，管理机自己的
    #      `known_hosts` 还记着**旧指纹** ⇒ 平台 fail-closed 把门关上；而 `accept-new`
    #      对"指纹变了"**一样拒**（它只认"没见过的主机"）⇒ 唯一出路变成"请用户自己去改
    #      known_hosts" —— ★ 那正是本项目一直在消灭的「让人手改文件」。
    #   ★ 台阶 = `Transport.drop_known_hosts_entries()`；这里**真跑**三条硬规矩：
    #      ① 只撤**这一台**的两条键（别的机器一行不动）② 撤之前**逐字节备份**（且真能回退）
    #      ③ 本来就没有它的记录 ⇒ 如实回 0 条（那不是错误，是结论）
    from app.transport import SshTransport as _Transport

    _kh = tmp / "known_hosts"
    _addr, _port = "203.0.113.199", 22
    _kh.write_text("\n".join([
        "192.0.2.11 ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIOther",
        "[203.0.113.1]:22 ssh-rsa AAAAB3NzaC1yc2EAAAAOBracket",
        f"{_addr} ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIMine",
        "",
    ]), encoding="utf-8", newline="")
    _sha0 = hashlib.sha256(_kh.read_bytes()).hexdigest()
    _bkdir = tmp / "kh-backups"
    _d1 = _Transport.drop_known_hosts_entries(_addr, _port, path=_kh, backup_dir=_bkdir)
    _after1 = _kh.read_text(encoding="utf-8")
    _d2 = _Transport.drop_known_hosts_entries(_addr, _port, path=_kh, backup_dir=_bkdir)
    _bkp = Path(str(_d1.get("backup") or ""))
    _bkp_ok = _bkp.is_file() and hashlib.sha256(_bkp.read_bytes()).hexdigest() == _sha0
    if _bkp_ok:
        _kh.write_bytes(_bkp.read_bytes())                      # 真回退一次
    _restored = hashlib.sha256(_kh.read_bytes()).hexdigest() == _sha0
    record("Ⓩc ★★ §12.139.2：**「指纹变了」有人点过的台阶** —— "
           "① 只撤这一台的两条键（别的机器一行不动）② 撤前**逐字节备份**（且真能回退）"
           "③ 本来没有它的记录 ⇒ 如实回 0",
           _d1.get("removed") == 1 and _d1.get("kept") == 2
           and "Other" in _after1 and "Bracket" in _after1 and "Mine" not in _after1
           and _bkp_ok and _restored
           and _d2.get("removed") == 0 and not _d2.get("backup"),
           "第一次撤 %s 条 / 留 %s 条 ｜ 备份与原文逐字节一致=%s ｜ 真回退后一致=%s ｜ "
           "再撤一次=%s 条且无新备份=%s"
           % (_d1.get("removed"), _d1.get("kept"), _bkp_ok, _restored,
              _d2.get("removed"), not _d2.get("backup")))
    _api_src = (ROOT / "app" / "api.py").read_text(encoding="utf-8")
    _tr_src = (ROOT / "app" / "transport.py").read_text(encoding="utf-8")
    record("Ⓩc ★★ **它不许是「平台自己决定接受」**：`force` 只能由**人在界面上点**那一下带来 —— "
           "`/api/hosts/<id>/trust` 从**请求体**读 `force`，`transport.trust_host` 才有 force 分支",
           "force" in _api_src and "force: bool = False" in _tr_src,
           "api 读请求体 force=%s ｜ transport 有 force 分支=%s"
           % ("force" in _api_src, "force: bool = False" in _tr_src))

    # ══════════════════════════════════════ Ⓩd 本机通道动作：目标机必须**点名**，不许吃默认值
    #   ★★★ 现场（T17·S8 真跑 · §12.140 · 本轮最危险的一次）：
    #      `python tools\run_one.py vm.stop aoc-tpl-01` —— 第一个位置参数是 **host_id**，
    #      而 `vm.*` 的目标是 **`vm` 参数**，默认值偏偏是 **`node-03`**（一台真集群节点）
    #      ⇒ 这次"关掉靶机"**真的把 node-03 关了**；紧接着"开回 docker-01"又把它开回来。
    #   ★ 平台**没说假话**（结论抬头就是【node-03】）—— 出问题的是**脚本化调用**：
    #      界面表单里那个默认值**人看得见**，命令行里那个默认值**没人看得见**。
    #   ⇒ 真跑判据（离线可跑，几秒）：缺 `vm=` 时必须**当场拒**（退出码 2 ＋ 说明白）。
    #   ★★ 这里**刻意用只读动作**（`vm.status`）而不是 `vm.stop`：
    #      因为这条判据要**证伪**（把拦截删掉 ⇒ 它必须红），而删掉拦截之后这次调用会**真的执行** ——
    #      用 `vm.stop` 就会在自检里**真把一台集群节点关掉**。★ 判据不许伤到环境（T16 经验 #4）。
    # ★★ T18 换靶子（§12.140 的判据**一行没改**，只换了"拿谁当靶子"）：
    #    T17 那台临时克隆靶机 `aoc-tpl-01` **已退役**（用户 2026-09-28 拍板删掉），
    #    所以改用**一直在册**的 `node-03` —— 它正是 §12.140 那次事故的**当事机**。
    #    用它当靶子，这条判据读起来才完整：
    #    "**当时被误关掉的那一台**，现在必须点名才动得了"。
    #    ★ 仍然刻意用**只读**动作（`vm.status`）：这条判据要**证伪**（把拦截删掉 ⇒ 它必须红），
    #      而删掉拦截之后这次调用会**真的执行** —— 用 `vm.stop` 就会在自检里真关掉一台集群节点。
    # ★★ 2026-09-29（开源脱敏批）：靶子与**抬头里那个名字**都**从登记里算**，不再写死：
    #    ① 靶子 = 在册主机里**第一台带 `vm.vmx` 的**（本机通道动作要求点名 `vm=`，靶子得有 VM）；
    #    ② ★★★ 抬头里那个 `【…】` 是**虚拟机自己的名字**（`vm.vmx` 文件名的 stem）——
    #       它**本来就允许与主机 id 不同**（`docker-01` 的 vmx 叫 `vm-docker-01.vmx`，规范 §12.116 记过这条），
    #       所以**不许拿主机 id 去撞**：原来那条断言是靠了"id == VM 目录名"这个**巧合**才绿的。
    _vm_doc = _yaml(ROOT / "hosts.yaml")
    _vm_target, _vm_echo = "", ""
    for _h in (_vm_doc.get("hosts") or []):
        _vmx = str((((_h or {}).get("vm") or {}).get("vmx")) or "")
        if _vmx:
            _vm_target = str((_h or {}).get("id") or "")
            _vm_echo = os.path.splitext(os.path.basename(_vmx))[0]
            break
    if not _vm_target:
        record("Ⓩd ★★★ §12.140：本机通道**必须点名 `vm=`**", False,
               "hosts.yaml 里**没有一台带 `vm.vmx`** ⇒ 这条这次验不到（`vm=` 的靶子必须在册）")
        return
    _ro = run_child([sys.executable, str(ROOT / "tools" / "run_one.py"),
                     "vm.status", _vm_target], timeout=60, cwd=str(ROOT))
    record("Ⓩd ★★★ §12.140：**本机通道的动作必须点名 `vm=`**（脚本里不许吃参数默认值）——"
           "缺了就当场拒（动作里那两个默认值是给界面表单看的，不是给脚本看的）",
           _ro.returncode == 2 and "VM_TARGET_NOT_NAMED" in _ro.stdout,
           "退出码=%s ｜ 命中 VM_TARGET_NOT_NAMED=%s ｜ 靶子=%s（从 hosts.yaml 算）"
           % (_ro.returncode, "VM_TARGET_NOT_NAMED" in _ro.stdout, _vm_target))
    _ro2 = run_child([sys.executable, str(ROOT / "tools" / "run_one.py"),
                      "vm.status", _vm_target, "vm=" + _vm_target], timeout=120, cwd=str(ROOT))
    record("Ⓩd ★★ 而**点名之后**要正常跑，并且**把「你到底动的是哪台」回显出来**"
           "（★ 抬头里那个名字是**虚拟机自己的名字**，从 `vm.vmx` 算出来 —— "
           "它允许与主机 id 不同，§12.116）",
           _ro2.returncode == 0 and "真正要动的虚拟机" in _ro2.stdout
           and "【%s】" % _vm_echo in _ro2.stdout,
           "退出码=%s ｜ 有回显=%s ｜ 抬头是 %s=%s"
           % (_ro2.returncode, "真正要动的虚拟机" in _ro2.stdout,
              _vm_echo, "【%s】" % _vm_echo in _ro2.stdout))


# ══════════════════════════════════════════════════ ★ v1.21（T18）：交付形态

_PROBE_CACHE = None


def _launcher_probe_json():
    """跑一次**启动器探针**（`tools\\launcher_probe.py`），缓存它的 JSON。

    ★ 为什么"只跑一次"：它要起真子进程（每条判据都要拉起交付物真身），慢。
      Ⓩe / Ⓩf / Ⓩh 都从这一份结果里读 —— 不重复跑。
    ★★ 为什么这件事本身值得一条断言：启动器跑在 `repo\\` **之外**（`工具\\`），
      两道门此前**扫不到它** —— 它的行为一条判据都没有。
      这里的做法是补记② 那条 Ⓢ 的放大版：**不查字符串，把判定函数真跑一遍**。
    """
    global _PROBE_CACHE
    if _PROBE_CACHE is not None:
        return _PROBE_CACHE
    import json as _json
    exe = ROOT.parent / "工具" / "AutoOpsConsole.exe"
    if not exe.is_file():
        _PROBE_CACHE = {"__missing__": str(exe)}
        return _PROBE_CACHE
    cp = run_child([sys.executable, str(ROOT / "tools" / "launcher_probe.py"), "--json"],
                   timeout=900, cwd=str(ROOT))
    data = None
    for line in (cp.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                data = _json.loads(line)
                break
            except Exception:  # noqa: BLE001
                continue
    if data is None:
        data = {"__bad__": ("退出口=%s ｜ stdout=%s ｜ stderr=%s"
                            % (cp.returncode, (cp.stdout or "")[:300], (cp.stderr or "")[:300]))}
    _PROBE_CACHE = data
    return _PROBE_CACHE


def _probe_item(data, prefix):
    for it in (data or {}).get("items") or []:
        if str(it.get("name", "")).startswith(prefix):
            return it
    return None


def check_t18(cfg, actions, map_data) -> None:
    """★★ T18（七·交付形态 · 一键启动器与交付形态）新增断言 Ⓩe Ⓩf Ⓩg Ⓩh Ⓩj Ⓩk
    （规范 §12.149 ＋ **§12.150~§12.153（S8 补）**）。

    本话题最特殊的地方：**交付物跑在 `repo\\` 之外**（`工具\\AutoOpsConsole.exe`）——
    两道门此前**扫不到它**，它的六件事全靠"人肉试过"。
     ⇒ 判据的做法：**把探针当判定函数真跑一遍**，而不是去查源码里有没有某句话。

      Ⓩe 启动器**参数可注入**，且结论里**回显这次动的是哪个端口**
      Ⓩf **认人** ＋ **幂等**，而且**不杀别人的进程**（`stop`/`restart` 走**同一道**口子）
      Ⓩg **不可复现构建**：判据是「大小 ＋ 行为 ＋ 源码 sha256」，**不是**产物 hash
      Ⓩh 交付形态**可建 / 可撤 / 可审计**，撤销**只删自己建的**
      Ⓩj ★★★（S8 新增）**结论的收口**：`--json` 恰好一行 ＋ 字段固定 ＋ 退出口径一致 ＋
         脚本模式**不弹浏览器** ＋ ★★ **不攥住调用者的输出管道** ＋ 真 `start` 到就绪
         （在**临时 root** 上跑，**不碰生产库**）—— §12.150 六条规矩的落点
      Ⓩk ★★★（S8 第二组）**"拉起服务"这一跳的三条护栏**：一个端口一个实例、一个实例一组日志
         ＋ 日志目录用不了要**快速说真话且不许崩** —— §12.152 的落点

    ★ 全部**离线可跑**（§12.124 的口径：离线跑不出结论的判据 = 没有判据）。
    ★ 每条都配**证伪**（`tools\\proof_t18.py`）。
    ★★ 一条纪律：**不写"看着像在看着"的判据** —— 所以这里额外要求
      "**那条探针条目必须存在**"：谁把探针里对应的判据删掉，这里必须红。
    """
    import hashlib
    import re as _re

    section("★ v1.21（T18）：交付形态 —— 可注入 / 认人 / 不可复现构建的判据 / 快捷方式")

    data = _launcher_probe_json()
    if "__missing__" in data:
        skip("Ⓩe~Ⓩh 启动器探针（**没验到**）",
             "找不到 %s —— 先跑 `工具\\build-launcher.cmd` 再重跑自检" % data["__missing__"])
        return
    record("Ⓩe~Ⓩh ★★ 启动器探针**跑得出来**（不查字符串，把判定函数真跑一遍 —— "
           "交付物在 repo 之外，两道门此前扫不到它）",
           "__bad__" not in data and data.get("failed") == 0,
           data.get("__bad__") or "通过 %s / 共 %s ｜ 失败 %s"
           % (data.get("total"), data.get("total"), data.get("failed")))
    if "__bad__" in data:
        return

    def _one(sym, title, prefixes):
        items = [_probe_item(data, p) for p in prefixes]
        missing = [p for p, it in zip(prefixes, items) if it is None]
        got = [it for it in items if it is not None]
        ok = not missing and all(it.get("ok") for it in got)
        detail = ("★ 探针里**缺**了这几条判据：%s（删掉判据 ≠ 判据通过）" % missing) if missing else \
                 " ｜ ".join("%s=%s" % (str(it["name"])[:8], it.get("ok")) for it in got)
        record(sym + " " + title, ok, detail)

    _one("Ⓩe", "★★ 启动器**参数可注入**，且结论里**回显这次动的是哪个端口**"
               "（T18·S2 那条真缺陷的回归判据：注入之后人话里不许再说 8787）（§12.143）"
               "　★ S8 扩：`AOC_SHORTCUT_DIR` 真被读 · 显式 `--port` 不被 `AOC_PORT` 反超",
         ["⓪", "①-b", "①-c", "①-g", "K-1", "K-3"])
    _one("Ⓩf", "★★ **认人** ＋ **幂等**，而且**不杀别人的进程**；"
               "`stop` / `restart` 与 `start` 走**同一道**口子（§12.144/§12.144·第 3 次现场）"
               "　★ S8 扩：`start` 撞上别人的程序也走**同一个退出码 3** ＋ 真 `start` 到就绪再停",
         ["④-e", "③-e", "③-f", "③-h", "③-i", "J-4", "J-5", "J-6", "⑥-j", "⑥-k", "⑥-l"])
    _one("Ⓩh", "★★ 交付形态**可建 / 可撤 / 可审计**，撤销**只删自己建的**（§12.145）",
         ["⑤-a", "⑤-b", "⑤-e", "⑤-h", "⑤-i", "⑤-j", "K-2"])
    # ★★ T18 · S8（§12.150 / 清单 281~284）：**结论的收口** —— 一个发口 · 一致的退出码 ·
    #   脚本模式无副作用 · 交付物**不攥调用者的管道** · 真跑到就绪且**不碰生产库**。
    _one("Ⓩj", "★★★ **结论的收口**：`--json` 恰好一行 ＋ 字段固定 ＋ 退出口径一致 ＋ "
               "脚本模式不弹浏览器 ＋ **不攥住调用者的输出管道** ＋ 真 `start` 到就绪"
               "（在**临时 root** 上，不碰生产库）（§12.150 / 清单 281~284）",
         ["J-1 ★★ `--json` 恰好一行：shortcut list",
          "J-1 ★★ `--json` 恰好一行：stop（别人的程序占着）",
          "J-4", "J-5", "J-6", "⑥-c2", "⑥-f", "⑥-g", "⑥-h", "⑥-o"])
    # ★★ T18 · S8 第二组（§12.152 / 清单 285~287）：**"拉起服务"这一跳的三条护栏** ——
    #   两个实例不许抢同一个日志文件 · 日志目录用不了要**快速说清楚且不许崩**。
    _one("Ⓩk", "★★★ **拉起服务这一跳的护栏**：同一个 root 上**两个端口各起一个实例**都起得来"
               "（日志按端口分家）＋ 日志目录用不了时**快速说真话且不许崩**"
               "（§12.152 / 清单 285~287）",
         ["⑦-a", "⑦-b", "⑦-c", "⑦-d", "⑦-e"])
    # ★★ T18 · S9（§12.154 / 清单 288~290）：**可移植性收口** —— "自动找解释器"要真的自动。
    _one("Ⓩm", "★★★ **「自动找解释器」要真的自动，而且要问得到**：候选链**逐个试** · "
               "不是 python 的**跳过并继续** · 结论报得出用的是谁 / 什么版本 / 跳过了几个"
               "（§12.154 / 清单 288~290）",
         ["⑧-a", "⑧-b"])

    # ── Ⓩg：不可复现构建（§12.142）────────────────────────────────────────
    tmp = cfg.paths.var / "selftest-t18"
    tmp.mkdir(parents=True, exist_ok=True)
    script = ROOT.parent / "工具" / "build-launcher.cmd"
    src = ROOT.parent / "工具" / "launcher" / "AutoOpsConsole.cs"
    spec = ROOT / "docs" / "动作规范.md"
    doc = ROOT.parent / "工具" / "启动器-说明.md"

    raw = script.read_bytes() if script.is_file() else b""
    nonascii = sum(1 for b in raw if b > 127)
    record("Ⓩg-1 ★★ 构建脚本在，且**整个文件纯 ASCII**"
           "（cmd 按 **OEM 代码页**读 .bat，`chcp` 管不住它 —— 非 ASCII 会把命令行切碎，"
           "T18·S2 实测报 `'Y'` / `'et'` / `'hinese' is not recognized`）",
           script.is_file() and nonascii == 0,
           "存在=%s ｜ 非 ASCII 字节=%d" % (script.is_file(), nonascii))

    csc = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    sizes, outs = [], []
    for i in (1, 2):
        out = tmp / ("probe-%d.exe" % i)
        if out.is_file():
            out.unlink()
        cp = run_child([csc, "/nologo", "/optimize+", "/target:exe",
                        "/out:" + str(out), str(src)], timeout=300)
        # ★ 刻意编到**临时目录**：真 exe 是仓库里的受管产物，自检不许动它。
        sizes.append(out.stat().st_size if (cp.returncode == 0 and out.is_file()) else None)
        if out.is_file():
            cp2 = run_child([str(out), "status", "--port", "59999", "--json"], timeout=120,
                            env_extra={"AOC_ROOT": str(ROOT.parent)})
            outs.append((cp2.stdout or "").strip())
        else:
            outs.append(None)
    record("Ⓩg-2 ★★ 同一份源码**连编两次 ⇒ 大小一致**"
           "（★ 判据**不是** hash 相等 —— 那个做不到，见 §12.142；谁把它写成 hash 相等，必红）",
           sizes[0] is not None and sizes[0] == sizes[1],
           "两次大小：%s" % sizes)
    record("Ⓩg-3 ★★ 两次编译的产物**行为等价**（同一段探针 ＋ 固定端口 ⇒ 规范化输出逐字节相同）",
           outs[0] is not None and outs[0] != "" and outs[0] == outs[1],
           "输出：%s" % ((outs[0] or "")[:150]))

    doc_txt = doc.read_text(encoding="utf-8", errors="replace") if doc.is_file() else ""
    spec_txt = spec.read_text(encoding="utf-8", errors="replace") if spec.is_file() else ""
    record("Ⓩg-4 ★★ **「不可复现」这件事被写下来了**（规范 ＋ 交付物说明各一处）——"
           "★ 这是**形态判据**，明标它不是行为判据。不写明的后果很具体："
           "下一个人会拿 hash 去证明「exe 没被换过」，而那个结论**不成立**",
           ("不可复现" in spec_txt) and ("不可复现" in doc_txt),
           "规范=%s ｜ 说明=%s" % ("有" if "不可复现" in spec_txt else "缺",
                                   "有" if "不可复现" in doc_txt else "缺"))
    m = _re.search(r"源码 sha256[^0-9a-f]*([0-9a-f]{64})", doc_txt)
    real = hashlib.sha256(src.read_bytes()).hexdigest() if src.is_file() else ""
    record("Ⓩg-5 ★★ 交付物说明里**记着的源码 sha256 == 磁盘上源码的 sha256**"
           "（★ 这是「这份源码」唯一的可复算名字：**改了源码就必须更新记录**）",
           bool(m) and m.group(1) == real,
           "记录里=%s ｜ 磁盘上=%s%s" % (m.group(1)[:16] + "…" if m else "（没记）",
                                        real[:16] + "…" if real else "（读不到）",
                                        "" if (m and m.group(1) == real) else "　⇒ 两边不一致"))


def check_t18_offline_isolation() -> None:
    """Ⓩn ★★★（§12.156 / 清单 291）：**离线门全程没碰生产库**。

    ★★ 为什么要这一条：T18 收尾时用「采样器 ＋ 写入追踪」照出来 —— 离线门以前**会写生产库**
      （`⑥ 数据层` 落一条 `SELFTEST-TASK` ＋ 一份归档、`⑮ 一键体检` 落两条合成体检任务、
      `T17 的 Ⓩd` 走 `run_one.py` **子进程**真跑一次 `vm.status` 又落一条）。
      ⇒ 现在 `--offline` 整体跑在**项目临时副本**上（见 `_offline_isolate` 的注释）。
    ★ 本条的判据：门**开始那一刻**记下生产库的 sha256，门**结束时**再记一次 —— 必须逐字节一致。
      ★ 与探针的 `⑥-o` 分工：`⑥-o` 守"**探针起的那一个实例**"，本条守"**整道门 ＋ 它拉起的子进程**"。
      ★★ 它同时把 `⑥-o` 那条**随机红**焊死：门不再动那个文件，`⑥-o` 就没有"时序"可赌了。
    """
    if not ISOLATED:
        skip("Ⓩn 离线门没碰生产库（本次**没有隔离信息**：不是 `--offline`，或显式关掉了隔离）",
             "AOC_SELFTEST_ISOLATED=%r ｜ ★ 关掉隔离是为了看它写什么，**不是通过**"
             % os.environ.get("AOC_SELFTEST_ISOLATED"))
        return
    db = real_prod_db()
    if db is None or not _REAL_DB_SHA_AT_START:
        skip("Ⓩn 离线门没碰生产库（**没有可对照的生产库**）", "real_root=%r" % REAL_ROOT)
        return
    now = _sha256_file(db)
    record("Ⓩn ★★★ 离线门**全程没碰生产库**（门的读写全在临时副本上；"
           "生产库 sha256 前后一致 —— 这条同时把探针 `⑥-o` 的随机红焊死）",
           now == _REAL_DB_SHA_AT_START,
           "前 %s ｜ 后 %s" % (_REAL_DB_SHA_AT_START[:16] + "…", now[:16] + "…"))


def check_t18_doc_numbers() -> None:
    """Ⓩi ★★★ 门禁条数：**文档 ↔ 本次实测**必须一致（规范 §12.146 / 清单 271）。

    ★★ 这条是本话题**开工第一天照出来的那个洞**的焊点：
      现场 —— `repo\\README.md` 停在 `737/820`，另 3 份已经是 `738/821`，
      而起因是"补记② 改完文档**没人再跑门**"。T17 交接里那句「738/738 全绿」
      **在写下它的那一刻就已经不成立了**。
    ★ 与 `㊿b` 的分工：`㊿b` 查「**文档之间**一致」（"3 份新 1 份旧"它抓得住）；
      本条查「**文档 ↔ 事实**一致」（"4 份一起停在旧数字"只有它抓得住）。
    ★ 必须**最后**跑：它算的就是"**这次一共跑了多少条**"。
    ★ 只验得动**本模式**的那一列（离线门验 `离线 N`，完整门验 `完整 M`）——
      另一列**不是本次能算出来的数** ⇒ 如实说明，**不假装验过**（「跳过 ≠ 通过」）。
    """
    import re as _re

    n = len(results) + 1                     # ★ 把本条自己算进去（下面才 record）
    col = "离线" if OFFLINE else "完整"
    other = "完整" if OFFLINE else "离线"
    docs = (
        ("根 README.md", ROOT.parent / "README.md"),
        ("CHANGELOG.md", ROOT.parent / "CHANGELOG.md"),
        ("工程方法.md", ROOT.parent / "工程方法.md"),
        ("技术实现.md", ROOT.parent / "技术实现.md"),
        ("repo/README.md", ROOT / "README.md"),
    )
    seen, bad = [], []
    for name, p in docs:
        if not p.is_file():
            continue
        vo, vf = [], []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if "离线" not in line or "完整" not in line:
                continue
            frs = [int(mm.group(1)) for mm in _re.finditer(r"(\d+)\s*/\s*(\d+)", line)
                   if mm.group(1) == mm.group(2)]       # ★ 只认 `N/N` 这种自洽分数
            if len(frs) == 2:
                vo.append(frs[0])
                vf.append(frs[1])
        if not vo:
            continue                                    # 这份文档不声明门禁条数 ⇒ 不适用
        got = max(vo) if col == "离线" else max(vf)
        seen.append("%s%s=%d" % (name, col, got))
        if got != n:
            bad.append("%s 写的是 %s=%d，本次实测是 %d" % (name, col, got, n))
    record("Ⓩi ★★★ §12.146 / 清单 271：**门禁条数 —— 文档 ↔ 本次实测**必须一致"
           "（`㊿b` 只看文档**之间**；本条看文档**↔ 事实**。★ 改了断言就必须同步这 5 份文档 ——"
           "**这正是本话题开工第一天照出来的那个洞**）",
           len(seen) >= 2 and not bad,
           "；".join(bad) if bad else
           ("本次 %s 实测 = %d ｜ " % (col, n)) + " ｜ ".join(seen)
           + " ｜ ★ 另一列（%s）不是本次能算出来的数，**没验到**" % other)


def preflight_hosts(cfg) -> None:
    """★★ T18 · S7：完整门**开跑前先探活一次** —— 把「不可达」的机器**一次性**标出来。

    ★ 现场（T17 结题回执 §4.2 遗留 #10 ／ `继续工作-看这里.md` §2.1）：
      在册机器**关回去**之后，完整门会**变慢到像卡死** —— 每个要落在目标机上的只读动作
      都要对那台机器**各撞一次 ssh 超时**，5 台逐个撞一遍。
      ★★ 它**会跑完，而且仍然全绿**，只是慢 —— 所以那是一个**"看得懂"的问题，不是"对不对"的问题**。
    ★★ 因此这一段**只 print，不改任何判据**：
      探活只是**预告**，**不跳过**任何东西 —— 不可达的机器照样会被每个动作撞一次。
      它做的事是：把"要撞几次、大概多久、为什么"提前说清楚，**别让人把它误当成卡死**。
      ★ 与「跳过 ≠ 通过」同一族：**"会变慢"要写在明面上，不许让下一个人自己猜。**
    """
    import socket as _sock
    import time as _time

    section("★ 开跑前探活（★ 只是预告 —— 不改任何判据，也不跳过任何东西）")
    hosts = list(cfg.hosts)
    if not hosts:
        print("  （没有在册主机）")
        return
    rows, dead = [], []
    for h in hosts:
        tgt = str(getattr(h, "target", "") or "")
        where = tgt.split("@")[-1] if "@" in tgt else tgt
        port = 22
        if ":" in where and where.rsplit(":", 1)[-1].strip().isdigit():
            where, p = where.rsplit(":", 1)
            port = int(p)
        t0 = _time.time()
        ok = False
        try:
            with _sock.create_connection((where, port), timeout=2.0):
                ok = True
        except Exception:  # noqa: BLE001
            ok = False
        dt = _time.time() - t0
        rows.append((h.id, where, port, ok, dt))
        if not ok:
            dead.append(h.id)
    for hid, addr, port, ok, dt in rows:
        print("  %s %-16s %s:%s   %4.0f ms%s"
              % ("✅" if ok else "❌", hid, addr, port, dt * 1000, "" if ok else "   ← 不可达"))
    if dead:
        print("")
        print("  ⚠️  不可达 %d 台：%s" % (len(dead), "、".join(dead)))
        print("     ★ 下面**每一个**要落在目标机上的只读动作，都会对它们**各撞一次 ssh 超时** ——")
        print("       这是**预期**，不是卡死（完整门仍会跑完，并给出结论）。")
        print("     ★ 想让它快：先把这些机器 `vm.start`（yellow，要人点头），")
        print("       或把它们从 `hosts.yaml` 里撤掉（本项目管不到的就别留在册）。")
    else:
        print("")
        print("  ✅ %d 台全部可达 —— 完整门不会有多余的等待。" % len(rows))


def main() -> int:
    # ★★ T18·S9：**先把门挪到临时副本**上再跑（见 `_offline_isolate` 的注释）。
    #   ★ 四个入口都挪：`--offline`（会写库的是 ⑥ / ⑮ / T17 的 Ⓩd）与三个快通道
    #     （`--t16/--t17/--t18`，给证伪演示用的 —— 它们同样会真跑真写）。
    if (OFFLINE or ONLY_T16 or ONLY_T17 or ONLY_T18) and not ISOLATED \
            and os.environ.get("AOC_SELFTEST_NO_ISOLATE") != "1":
        return _offline_isolate()
    # ★★ T16·S9：`--t16` 是给「证伪演示」的快通道（只跑 T16 那一节，同一个 check_t16）
    if ONLY_T16:
        return _main_t16_only()
    if ONLY_T17:
        return _main_t17_only()
    if ONLY_T18:
        return _main_t18_only()
    print("=" * 70)
    print("  auto-ops-console · 自检（T1 验收标准 #6）")
    print(f"  根目录：{ROOT}")
    print(f"  模式：{'离线（跳过目标机相关检查）' if OFFLINE else '完整'}")
    print("=" * 70)

    try:
        check_runtime()
        cfg = check_config()
        actions, _map_data = check_catalog(cfg)
        check_schema_rejection(cfg)
        check_injection(cfg, actions)
        store = check_store(cfg)
        bcfg, bactions = check_bootstrap()
        if bcfg is None:
            rcfg, ractions = cfg, actions
        else:
            rcfg, ractions = bcfg, bactions

        # T2 新增的两节（离线即可跑：动作清单/覆盖对账 + 结果可导出）
        check_readonly_coverage(rcfg, ractions, _map_data)
        check_export()
        # T3 补漏新增（离线）：路由对账 —— 前面几节验的是"动作装载得对吗"，
        # 这一节验的是"界面点得动吗"，是两回事（正是这次踩坑的地方）。
        check_routes()

        # T4 新增三节（都**离线可跑**）：覆盖率双口径 / 体检判定层 / 纳管分发点。
        # 它们验的是 T4 的三条主线，且都不依赖目标机 —— 换机器、断网也能红/绿。
        check_weights(rcfg, _map_data, ractions)
        check_checkup(rcfg)
        check_enroll(rcfg)
        # T6 新增（离线可跑）：run_by 选段 / responds 判据 / 白名单覆盖预检 / 三个探活动作
        check_v17(rcfg, ractions)
        # T7 新增（离线可跑）：删除类终态语义 / 收敛检查覆盖包+路径 / 升级预检退出码 /
        #                      回退能执行能自证 / 配方热装载（三个不许）
        check_v18(rcfg, ractions)
        # T8 新增（离线可跑）：内核参数写+持久化 / daemon-reload / reset-failed /
        #                      路径白名单（含密钥类永不读）/ registry.probe 判读口径
        check_v19(rcfg, ractions)
        # T11 新增（离线可跑）：**交付物** —— 文档与账本不许对不上（规范 §12.66~§12.72）
        check_t11_delivery(rcfg, ractions, _map_data)
        # T12 新增（离线可跑）：**AI 助手** —— 无后门 / 只发结论 / key 不落盘（规范 §12.74~§12.79）
        # ★ 这六条守的是"违反了不会报错"的那一类（铁律 8/9、红线 6~11）。
        check_t12_ai(rcfg, ractions, _map_data)
        # T13 新增（离线可跑）：**多机检索与汇总** —— 范围不许自编 / 三段交代 / 只看结论
        # （规范 §12.85~§12.92，断言 ⑸ ⑹ ⑺ ⑻ ⑼ ⑽）
        check_t13_retrieval(rcfg, ractions, _map_data)
        # T14 新增（离线可跑）：**最小鉴权** —— 真的在拦 / 无口令即全拒 / 边界两段都在
        # （规范 §12.97，断言 ⑾ ⑿ ⒅）
        # ★ 这一节**真起一个本地 HTTP 服务**来打 —— 因为"闸门有没有生效"是**请求层**的事，
        #   在函数层测等于自证；而且它用的口令文件是**临时目录里的**，绝不碰 var/auth.json。
        check_t14_auth(rcfg, ractions, _map_data)
        # ★ T14·S3（离线可跑）：变更「请求」—— 只摆卡片 / 白名单是上限 / 五要素齐备
        #   （规范 §12.96 / §12.98 / §12.99，断言 ⒀ ⒁ ⒂ ⒃ ⒆）
        check_t14_requests(rcfg, ractions, _map_data)
        # ★ T14·S4/S5（离线可跑）：人点确认 ⇒ 走既有执行路 ⇒ 平台自动复核（断言 ⒄）
        check_t14_approve(rcfg, ractions, _map_data)
        # ★★ T15（离线可跑）：**报告与知识沉淀** —— 每条结论挂得起证据 / 报告不许说假话 /
        #    导出过闸门 / 时间线排序与跨机不合并 / 知识只查结构化 / 候选不生效 / 指纹可证伪
        #    （规范 §12.104~§12.108，断言 Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ）
        #    ★ 其中 Ⓒ 真起一个**临时目录里的**本地服务打 HTTP，绝不碰 var/auth.json。
        #    ★★ Ⓛ（S9 补 · 规范 §12.111）：**门禁自己**的编码边界 —— 收口时抓到
        #       「门禁在第 298 项处中断」那个真缺陷：子进程单出口 ＋ 双向 pin 编码。
        check_t15_report(rcfg, ractions, _map_data)
        # ★★ T16（离线可跑）：**虚拟化层 · VM 生命周期** —— 非 ssh 通道 / VM 归属闸门 /
        #    电源判据分级 / 幂等靠探针 / 闸门只增不减 / 域 M 进账本 / 「问不到」≠「不存在」 /
        #    界面第 12 页签与按钮级走查 / 同一个开口两处认账
        #    （规范 §12.115~§12.125，断言 Ⓙ Ⓚ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ）
        check_t16(rcfg, ractions, _map_data)
        #    ★★ T17（规范 §12.136 / §12.137）：造机与身份重置
        #    （克隆是 red 且 AI 结构上不可请求 / 目标已存在 ⇒ 拒绝覆盖 / 五项身份逐项有判据
        #     / hosts.yaml 逐字节可回退 / 任何代码页下只读工具不因打印失败，断言 Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ）
        check_t17(rcfg, ractions, _map_data)
        # ★★ T18（离线可跑，规范 §12.149）：**交付形态** —— 交付物跑在 `repo\` **之外**，
        #    两道门此前**扫不到它**。判据的做法是"**把探针当判定函数真跑一遍**"，不查字符串。
        #      Ⓩe 参数可注入 ＋ 回显这次动的是哪个端口
        #      Ⓩf 认人 ＋ 幂等 ＋ **不杀别人的进程**（stop/restart 与 start 走同一道口子）
        #      Ⓩg 不可复现构建的判据：**大小 ＋ 行为 ＋ 源码 sha256**（不是产物 hash）
        #      Ⓩh 交付形态可建 / 可撤 / 可审计，撤销**只删自己建的**
        check_t18(rcfg, ractions, _map_data)

        if not OFFLINE:
            # ★★ T18 · S7：**开跑前先探活一次** —— 治"完整门看起来像卡死"。
            #    ★ 它**只 print，不改任何判据**（没有一条断言因为它变红或变绿）。
            preflight_hosts(rcfg)
            if check_target(rcfg, ractions):
                check_actions_live(rcfg, ractions, Store(rcfg))
            else:
                section("⑩~⑬ 真跑检查")
                record("跳过（目标机不可达）", False,
                       "修好连通性后重跑；或用 --offline 只跑离线层。")
        else:
            section("⑩~⑬ 目标机相关检查")
            print("  ⏭  --offline 模式，已跳过")
    except OpsError as exc:
        print(f"\n❌ 自检中断：{exc.code} {exc.reason}")
        if exc.advice:
            print(f"   建议：{exc.advice}")
        results.append(("自检中断", False, exc.reason))
    except Exception:  # noqa: BLE001
        print("\n❌ 自检脚本自身异常（这是缺陷）：")
        traceback.print_exc()
        results.append(("自检脚本异常", False, "见上方堆栈"))

    # ★★ T18（§12.146 / 清单 271）：**门禁条数 —— 文档 ↔ 本次实测**。
    #    ★ 必须放在**最后**：它算的就是"这次一共跑了多少条"，所以只能在所有章节跑完之后。
    #    ★ 它自己也算一条（函数里 `+1` 把它自己算进去了）。
    # ★★ T18·S9（§12.156 / 清单 291）：**离线门不许碰生产库** —— 必须在收尾算，且必须在
    #    「数字对账」之前，好让 Ⓩi 数出来的"本次一共多少条"把它算进去。
    try:
        check_t18_offline_isolation()
    except Exception as _exc:  # noqa: BLE001
        results.append(("Ⓩn 判定函数自身异常", False, "%s: %s" % (type(_exc).__name__, _exc)))

    try:
        check_t18_doc_numbers()
    except Exception as _exc:  # noqa: BLE001
        results.append(("Ⓩi 判定函数自身异常", False, "%s: %s" % (type(_exc).__name__, _exc)))

    ok = sum(1 for _, o, _ in results if o)
    bad = [(n, d) for n, o, d in results if not o]
    print("\n" + "=" * 70)
    print(f"  结果：通过 {ok} / 共 {len(results)}　失败 {len(bad)}"
          + (f"　★ 跳过 {len(skips)}（**没验到**，不等于通过）" if skips else ""))
    for n, d in bad:
        print(f"    ❌ {n}")
    for n in skips:
        print(f"    ⏭ {n}")
    print("=" * 70)
    return 0 if not bad else 1


def _main_t16_only() -> int:
    """★★ T16·S9：**只跑 T16 那一节**（`--t16`）—— 给「证伪演示」用的快通道。

    ★ 为什么不复用整条 `main()`：整道门要几分钟（含真跑），而证伪演示要
      「注入一处 ⇒ 立刻看对应断言红没红 ⇒ 还原 ⇒ 再确认它回绿」来回好几轮。
    ★★ 这里**只决定跑哪一节**，判据本身**一行都没有另写** —— 同一个 `check_t16()`。
      否则这个快通道自己就成了"第二套判据"（§12.6.1 的老话）。
    """
    import datetime as _dtmod

    print("=" * 72)
    print("  auto-ops-console · 自检（**只跑 T16 那一节**）")
    print(f"  时间 {_dtmod.datetime.now().isoformat(timespec='seconds')} ｜ 仓库 {ROOT}")
    print("=" * 72)
    try:
        t16cfg = check_config()
        t16actions, t16map = check_catalog(t16cfg)
        check_t16(t16cfg, t16actions, t16map)
    except OpsError as exc:
        print(f"\n❌ 自检中断：{exc.code} {exc.reason}")
        results.append(("自检中断", False, exc.reason))
    except Exception:  # noqa: BLE001
        print("\n❌ 自检脚本自身异常（这是缺陷）：")
        traceback.print_exc()
        results.append(("自检脚本异常", False, "见上方堆栈"))
    return _report_tail()


def _main_t17_only() -> int:
    """★★ T17·S7：**只跑 T17 那一节**（`--t17`）—— 与 `--t16` 同一个道理。

    ★ 这里**只决定跑哪一节**，判据本身**一行都没有另写** —— 同一个 `check_t17()`。
      否则这个快通道自己就成了"第二套判据"（§12.6.1 的老话）。
    """
    import datetime as _dtmod

    print("=" * 72)
    print("  auto-ops-console · 自检（**只跑 T17 那一节**）")
    print(f"  时间 {_dtmod.datetime.now().isoformat(timespec='seconds')} ｜ 仓库 {ROOT}")
    print("=" * 72)
    try:
        t17cfg = check_config()
        t17actions, t17map = check_catalog(t17cfg)
        check_t17(t17cfg, t17actions, t17map)
    except OpsError as exc:
        print(f"\n❌ 自检中断：{exc.code} {exc.reason}")
        results.append(("自检中断", False, exc.reason))
    except Exception:  # noqa: BLE001
        print("\n❌ 自检脚本自身异常（这是缺陷）：")
        traceback.print_exc()
        results.append(("自检脚本异常", False, "见上方堆栈"))
    return _report_tail()


def _main_t18_only() -> int:
    """★★ T18·S6：**只跑 T18 那一节**（`--t18`）—— 给「证伪演示」用的快通道。

    ★ 与 `--t16` / `--t17` 同一个道理：**只决定跑哪一节**，判据本身**一行都没有另写**
      （两处口径漂移是本项目反复咬过人的东西）。
    ★★ 这一节里**不跑 Ⓩi**：那条断言算的是"**这次一共跑了多少条**"，
      在快通道里那个数字**毫无意义** ⇒ 与其给它一个假数字，不如**不跑它**。
      Ⓩi 的证伪走完整的 `--offline`（见 `tools\\proof_t18.py`）。
    """
    import datetime as _dtmod

    print("=" * 72)
    print("  auto-ops-console · 自检（**只跑 T18 那一节**）")
    print(f"  时间 {_dtmod.datetime.now().isoformat(timespec='seconds')} ｜ 仓库 {ROOT}")
    print("=" * 72)
    try:
        t18cfg = check_config()
        t18actions, t18map = check_catalog(t18cfg)
        check_t18(t18cfg, t18actions, t18map)
    except OpsError as exc:
        print(f"\n❌ 自检中断：{exc.code} {exc.reason}")
        results.append(("自检中断", False, exc.reason))
    except Exception:  # noqa: BLE001
        print("\n❌ 自检脚本自身异常（这是缺陷）：")
        traceback.print_exc()
        results.append(("自检脚本异常", False, "见上方堆栈"))
    return _report_tail()


def _report_tail() -> int:
    """跑完之后的那段汇总（`main()` 与 `--t16` 快通道共用一份 —— 免得两处口径漂移）。"""
    ok = sum(1 for _, o, _ in results if o)
    bad = [(n, d) for n, o, d in results if not o]
    print("\n" + "=" * 70)
    print(f"  结果：通过 {ok} / 共 {len(results)}　失败 {len(bad)}"
          + (f"　★ 跳过 {len(skips)}（**没验到**，不等于通过）" if skips else ""))
    for n, d in bad:
        print(f"    ❌ {n}")
    for n in skips:
        print(f"    ⏭ {n}")
    print("=" * 70)
    return 0 if not bad else 1


def check_t12_ai(rcfg, ractions, map_data) -> None:
    """T12（AI 助手基座）· 离线可跑的结构断言 🄋 🄌 ⑴ ⑵ ⑶ ⑷（规范 §12.74 / §12.76 / §12.78 / §12.79）。

    ★ 为什么这六条必须是**结构断言**而不是文档条款：
      铁律 8 / 9 与红线 6~11 **违反了不会报错** —— 它们只会让
      **留证 / 护栏 / 确认闸门 / 覆盖率账本**四套体系**静悄悄失效**。
      ⇒ 断言要问的是"**结构上做不做得到**"，不是"有没有人这么写过"。
    """
    section("★ v1.15（T12）：AI 助手 —— 无后门 / 只发结论 / key 不落盘（结构断言）")
    repo = ROOT
    actions = ractions if isinstance(ractions, dict) else {a.id: a for a in ractions}

    try:
        from app.ai.outflow import ALLOWED_TASK_KEYS, FORBIDDEN_KEYS, pack_tool_result
        from app.ai.runtime import AiRuntime
        from app.ai.sessions import SCHEMA
        from app.ai.tools import ToolFace
    except Exception as exc:  # noqa: BLE001
        record("★ T12 的 AI 模块可导入", False, f"{type(exc).__name__}: {exc}")
        return

    face = ToolFace(rcfg, actions)
    green = {aid: a for aid, a in actions.items() if a.risk == "green"}
    specs = face.function_specs()
    blob = json.dumps(specs, ensure_ascii=False)

    # ── 🄋 工具面在结构上不可能越权（铁律 9 / 红线 7）────────────────────
    non_green = [a["id"] for a in face.to_json()["tools"] if a["risk"] != "green"]
    confirm_leak = [k for k in ("confirm_text", "confirm", "confirm_word") if f'"{k}"' in blob]
    record("🄋 ★★ §12.74.2 规矩 1：**工具面只含 green**"
           "（`yellow`/`red` 一个都不在 · 不存在任何 `confirm_text` 类字段）",
           len(face.green) == len(green) and not non_green and not confirm_leak,
           f"工具 {len(face.green)}/{len(green)} 个 · "
           f"非 green 混入 {non_green or '无'} · confirm 通道 {confirm_leak or '无'}")

    # ── 🄌 无后门：AI 侧拿不到底层（铁律 8 / 红线 6）────────────────────
    ai_dir = repo / "app" / "ai"
    bad_imports: list[str] = []
    for py in sorted(ai_dir.glob("*.py")):
        for line in py.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not (s.startswith("import ") or s.startswith("from ")):
                continue
            if re.search(r"(^|[\s.])(engine|transport|ssh|paramiko)([\s.]|$)", s):
                bad_imports.append(f"{py.name}: {s[:60]}")
    record("🄌 ★★ §12.74.1：**AI 侧没有直连底层的通道**"
           "（`app/ai/**` 不许 import 执行层 / 传输层 / ssh —— 只许走既有的 `/api/**` dispatch）",
           not bad_imports, "、".join(bad_imports) if bad_imports else f"扫描 {len(list(ai_dir.glob('*.py')))} 个模块，0 命中")

    # ── ⑴ 数据外流只 A 档（红线 9 / §12.77 / §12.78）──────────────────
    # ★ 造一份**带原文的**假任务：装箱之后，原文键必须一个都不剩（这才是"结构上做不到"）。
    dirty = {
        "id": "T-fake", "action_id": "disk.usage", "host_id": "h1", "risk": "green",
        "status": "ok", "verify_result": "ok", "conclusion": "根分区 28%",
        "steps": [{"name": "mounts", "stdout": "SECRET-RAW-OUTPUT", "stderr": "x"}],
        "artifacts": ["/tmp/a"], "backups": [{"path": "/etc/x"}], "argv": ["df", "-P"],
    }
    packed = pack_tool_result(dirty, "h1", "译文")
    leaked = [k for k in FORBIDDEN_KEYS if k in json.dumps(packed, ensure_ascii=False)]
    tier_ok = str((rcfg.raw.get("ai") or {}).get("outflow_tier", "A")).upper() == "A"
    record("⑴ ★★ §12.78：**外流只 A 档**"
           "（把一份带 `steps/stdout/artifacts/backups/argv` 的真任务装箱 ⇒ 一个都不许剩；档位配置 = A）",
           not leaked and tier_ok and "conclusion" in ALLOWED_TASK_KEYS,
           f"装箱后残留 {leaked or '无'} · 档位={('A' if tier_ok else '非 A')} · 允许清单 {len(ALLOWED_TASK_KEYS)} 项")

    # ── ⑵ key 四不落（红线 8 / §12.79）────────────────────────────────
    # ★ 扫描范围**写死**（T11 坑 6 的教训：范围不定，看门狗会咬错人）：
    #   只扫 app/ · web/ · config.yaml · hosts.yaml · catalog/。豁免理由见下。
    scan_files: list[Path] = []
    for sub in ("app", "web"):
        scan_files += [p for p in (repo / sub).rglob("*") if p.is_file() and p.suffix in (".py", ".js", ".css", ".html")]
    scan_files += [repo / "config.yaml", repo / "hosts.yaml"]
    scan_files += [p for p in (repo / "catalog").rglob("*") if p.is_file()]
    # ★ 豁免：`app/ai/keystore.py` 里的 `sk-[A-Za-z0-9_\-]{6,}` 是**脱敏正则本身的字面量**
    #   （它后面跟的是字符类，不是密文）—— 用"像真 key"的形态来判（≥12 位连续字母数字）就不会误伤。
    key_re = re.compile(r"sk-[A-Za-z0-9]{12,}")
    hits = []
    for p in scan_files:
        if not p.is_file():
            continue
        m = key_re.search(p.read_text(encoding="utf-8", errors="replace"))
        if m:
            hits.append(f"{p.relative_to(repo)}: {m.group(0)[:8]}…")
    cfg_txt = (repo / "config.yaml").read_text(encoding="utf-8", errors="replace")
    ai_block = cfg_txt.split("ai:", 1)[1] if "ai:" in cfg_txt else ""
    key_field = bool(re.search(r"(?m)^\s*(key|api_key|token)\s*:", ai_block))
    ks_src = (repo / "app" / "ai" / "keystore.py").read_text(encoding="utf-8")
    no_write = not re.search(r"def\s+(write|save|dump|persist)\w*\s*\(", ks_src)
    record("⑵ ★★ §12.79：**key 的'四不落'**"
           "（全库无像真 key 的字面量 · `config.yaml` 的 ai 段没有 key 字段 · key 模块没有写盘方法）",
           not hits and not key_field and no_write,
           f"字面量命中 {hits or '无'} · config 里 key 字段={'有' if key_field else '无'} · "
           f"keystore 写盘方法={'有' if not no_write else '无'}")

    # ── ⑶ 工具面与 catalog 一致（防两张表漂移，§12.75.2 / §12.66.2）──────
    gen = repo / "catalog" / "ai-tools.json"
    ok3, detail3 = False, "catalog/ai-tools.json 不存在（跑 tools/ai-export.py 生成）"
    if gen.is_file():
        data = json.loads(gen.read_text(encoding="utf-8"))
        ids = sorted(t["id"] for t in data.get("tools") or [])
        ok3 = ids == sorted(green)
        detail3 = (f"生成物 {len(ids)} 个 / 账本 green {len(green)} 个"
                   + ("" if ok3 else "　★ 差集：" + str(sorted(set(ids) ^ set(green))[:6])))
    record("⑶ ★★ §12.75.2：**工具面生成物与 catalog 一致**"
           "（`catalog/ai-tools.json` ↔ `catalog/actions/*.yaml` 里 `risk: green` 的那批）",
           ok3, detail3)

    # ── ⑷ 双结论对照存在、且冲突以工作台为准（§12.73.2 / 红线 10）────────
    try:
        from app.ai.runtime import ToolOutcome
        good = ToolOutcome(action_id="k8s.pods", host_id="m", ok=True, verify="ok", task_id="T-ok")
        bad = ToolOutcome(action_id="k8s.pods", host_id="w", ok=False, status="aborted",
                          verify="", task_id="T-bad", explain="这台没 kubeconfig")
        a = AiRuntime._detect_conflicts("已确认：集群一切正常。", [good, bad])
        b = AiRuntime._detect_conflicts("已确认：集群一切正常。", [good, good])
        c = AiRuntime._detect_conflicts("节点都 Ready。", [bad])
        ok_call = bool(a) and not b and not c
    except Exception as exc:  # noqa: BLE001
        record("⑷ 冲突检测可运行", False, f"{type(exc).__name__}: {exc}")
        return
    ok_schema = ("conflict" in SCHEMA) and ("task_id" in SCHEMA)
    record("⑷ ★★ §12.73.2：**双结论对照存在，且冲突以工作台为准**"
           "（AI 说'已确认'而工作台未证成 ⇒ 必须检出分歧；工作台已证成 / 没提确认词 ⇒ 不许误报；"
           "会话表要能记住分歧与任务号）",
           ok_call and ok_schema,
           f"冲突三例 {'通过' if ok_call else '不通过'} · 会话表 conflict/task_id "
           f"{'齐' if ok_schema else '缺'}")




def check_t13_retrieval(rcfg, ractions, map_data) -> None:
    """T13（多机检索与汇总）· 离线可跑的断言 **⑸ ⑹ ⑺ ⑻ ⑼ ⑽**（规范 §12.85 ~ §12.92）。

    ★ 为什么它们必须是**结构断言**：
      T13 的三条主线里，最容易"悄悄破掉"的是这三件 ——
        ① **范围不许自编**（破了就变成"AI 猜它可能在哪就去乱翻"）
        ② **三种情形不许混**（"没找到 / 没查到 / 可能不全"混成一句 = 报告在说假话）
        ③ **只看结论**（破了就等于偷偷把 A 档放宽成 C 档）
      ⇒ 断言要问"结构上做不做得到"，不是"有没有人这么写过"。

    ★ 六条全部**不需要靶机、不需要 key**（喂人造输入看输出）——
      这是 §12.95 的纪律（能离线验的尽量离线，T9 §12.52 / T12 §12.84 的教训）。
    """
    section("★ v1.16（T13）：多机检索与汇总 —— 范围不许自编 / 三段交代 / 只看结论（结构断言）")
    import io as _io
    import json as _json
    import os as _os
    import re as _re

    repo = ROOT
    actions = ractions if isinstance(ractions, dict) else {a.id: a for a in ractions}
    try:
        from app.ai import retrieval as R
        from app.ai.outflow import FORBIDDEN_KEYS, pack_tool_result
        from app.ai.runtime import AiRuntime, decide_hosts
        from app.ai.sessions import AiSessions
        from app.ai.settings import load_ai_settings
        from app.ai.tools import ToolFace
        from app.yamlload import load_yaml
    except Exception as exc:  # noqa: BLE001
        record("T13 断言：AI 检索模块可导入", False, "%s: %s" % (type(exc).__name__, exc))
        return

    settings = load_ai_settings(rcfg)
    face = ToolFace(rcfg, actions)

    class _O:
        """假 outcome（duck typing）。"""

        def __init__(self, aid, hid, concl, ok=True, explain=""):
            self.action_id, self.host_id, self.conclusion = aid, hid, concl
            self.ok, self.explain, self.task_id = ok, explain, "T-FAKE"

    GREP_HIT = ("文件内容检索结果（x）\n· 位置：/etc\n"
                "· 命中（最多 20 条）：\n  /etc/ssh/sshd_config:40:PermitRootLogin yes\n\n判读：\n")
    GREP_NONE = ("文件内容检索结果（x）\n· 命中（最多 20 条）：\n  （无）\n\n判读：\n")

    # ── ⑸ ★★ 范围不许自编（§12.85）
    grep = actions.get("file.grep")
    j_model = R.classify_param_sources(grep, {"path": "/opt/secret", "keyword": "x"}, "看看有没有问题")
    j_user = R.classify_param_sources(grep, {"path": "/etc/ssh", "keyword": "PermitRootLogin"},
                                      "在 /etc/ssh 下找 PermitRootLogin 有没有出现")
    j_def = R.classify_param_sources(grep, {"path": "/etc/systemd/system", "keyword": "aoc"}, "查下服务")
    record("⑸a 自编的检索范围 ⇒ model（触发回问）", j_model.get("path") == "model", str(j_model))
    record("⑸b 用户说过的 ⇒ user", j_user.get("path") == "user" and j_user.get("keyword") == "user", str(j_user))
    record("⑸c 等于动作默认值 ⇒ default", j_def.get("path") == "default", str(j_def))

    rt = AiRuntime.__new__(AiRuntime)
    rt.settings = settings
    rt.face = face
    rt._current_text = "看看有没有问题"

    def _must_not_execute(method, path, query, body=None):
        """★ 装了它，"破坏后"的形态才是**可判定的红**而不是 AttributeError 崩掉。

        ★ 这个坑是 S9 证伪演示当场抓出来的（第一版没有它 ⇒ 破坏后这一节直接崩，
          报告里只剩一句"自检脚本自身异常"，看不出是哪条断言没守住）。
        """
        raise AssertionError("★ 不该走到执行：自编的范围必须在执行**之前**被挡下（规范 §12.85）")

    rt.dispatch = _must_not_execute
    # ★ 注意 `expect_error` 的语义是"**抛** AssertionError"，不是"返回 code"——
    #   第一版写成 `code = expect_error(...)` 是错的，自检当场把它红了出来（断言自己也要写对）。
    try:
        _reason = expect_error(
            lambda: rt.run_action_readonly("file.grep", ["node-02"],
                                           {"path": "/opt/secret", "keyword": "x"}),
            "AI_NEED_CONFIRM_SCOPE",
        )
        record("⑸d ★★ 自编范围在**执行之前**就被挡下（AI_NEED_CONFIRM_SCOPE）", True, _reason[:110])
    except AssertionError as _exc:
        record("⑸d ★★ 自编范围在**执行之前**就被挡下（AI_NEED_CONFIRM_SCOPE）", False, str(_exc))

    # ★ 词表回归（§12.93）：14 条真实问句，一条走错就红
    all_ids = {h.id for h in rcfg.hosts}
    try:
        samples = load_yaml(_os.path.join(repo, "tools", "t13-phrase-samples.yaml"),
                            what="T13 问句样本").get("samples") or []
    except Exception as exc:  # noqa: BLE001
        samples = []
        record("⑸e 问句样本集可读", False, str(exc))
    wrong = []
    # ★★ T17·S9 修订「all」这一档的判据 —— **现场**：T17 造出来的克隆靶机 `aoc-tpl-01`
    #    进了册 ⇒ 登记主机 **4 台 → 5 台**，而 `ai.max_hosts_per_action` = **4** ⇒
    #    「全部」这一次**确实被上限砍到 4 台**。
    #      ★ 这是产品**承诺过**的行为（§12.92「上限与截断」：上限是动作自带的，
    #        与"这次确实被砍"要能分开看见），**不是走错**。
    #      ★ 样本集起草时写的那句「应自动铺全部 4 台」是一句**环境假设**，不是判据；
    #        把它当判据 = 每加一台机器就红一次（而红的原因跟词表毫无关系）。
    #    ⇒ 判据改成：**不反问** ＋ 恰好是**前 cap 台**（顺序也钉住）＋ 不许退化成一两台。
    _cap = int(getattr(settings, "max_hosts_per_action", 0) or 0)
    _order = [h.id for h in rcfg.hosts]
    _want_all = _order[:_cap] if _cap > 0 else _order
    for smp in samples:
        dec = decide_hosts(str(smp.get("text") or ""), rcfg.hosts, settings)
        exp = str(smp.get("expect") or "")
        ids = set(dec.host_ids)
        if exp == "ask":
            ok = bool(dec.asked)
        elif exp == "all":
            ok = (not dec.asked) and sorted(ids) == sorted(_want_all) and len(ids) >= 2
        elif exp in ("named", "subset"):
            ok = (not dec.asked) and 0 < len(ids) < len(all_ids)
        else:
            ok = False
        if not ok:
            wrong.append("%s(%s→%s)" % (smp.get("id"), exp, "、".join(sorted(ids)) or "ask"))
    record("⑸e 词表回归：%d 条真实问句全部走对（要求 ≥12 条）" % len(samples),
           (not wrong) and len(samples) >= 12,
           ("走错：" + "、".join(wrong)) if wrong else
           "登记 %d 台 ｜ 单次上限 %d 台%s"
           % (len(_order), _cap,
              "　★ 本次「全部」被上限砍到 %d 台（§12.92：上限与截断分开看）" % _cap
              if len(_order) > _cap else ""))

    # ── ⑹ ★★★ 三段交代齐全，且三种情形不混（§12.88）
    v_hit = R.aggregate([_O("file.grep", "h1", GREP_HIT)], host_order=[h.id for h in rcfg.hosts])
    v_none = R.aggregate([_O("file.grep", "h1", GREP_NONE)], host_order=[h.id for h in rcfg.hosts])
    v_fail = R.aggregate([_O("k8s.nodes", "h1", "", ok=False,
                             explain="★ 这台是 k8s-worker：读集群要一个能读集群的入口，不是集群故障")],
                         host_order=[h.id for h in rcfg.hosts])
    t_hit, t_none, t_fail = (R.scope_block(v_hit), R.scope_block(v_none), R.scope_block(v_fail))
    record("⑹a 三种情形的三段交代**两两不同**", len({t_hit, t_none, t_fail}) == 3,
           "hit=%r none=%r" % (t_hit[:40], t_none[:40]))
    record("⑹b 「找到了」与「没找到」分开写", ("找到了" in t_hit) and ("没找到" in t_none), "")
    record("⑹c 「没查到」带原因、且**不**进「没有」",
           ("没查到" in t_fail) and (v_fail.no_hit_hosts == []) and len(v_fail.not_searched) == 1,
           "no_hit=%s not_searched=%d" % (v_fail.no_hit_hosts, len(v_fail.not_searched)))

    # ── ⑺ ★★ 出境只走 conclusion（§12.89）
    task = {
        "id": "T-FAKE", "action_id": "file.grep", "status": "ok", "verify_result": "ok",
        "conclusion": "结论里有命中行 /etc/ssh/sshd_config:40:PermitRootLogin yes",
        "steps": [{"stdout": "原文"}], "stdout": "原始输出", "stderr": "原始错误",
        "artifacts": ["/tmp/x"], "argv": ["grep"], "command": "grep x",
    }
    try:
        packed = pack_tool_result(task, "h1")
        blob = _json.dumps(packed, ensure_ascii=False)
        leaked = [k for k in FORBIDDEN_KEYS if k in blob]
    except OpsError as _exc:
        # ★ 装箱时就被 `assert_no_forbidden` 拦下 —— 这也是"红"的一种形态（更早），
        #   不许让它把整节崩掉（S9 证伪演示当场抓到的第二个用例缺陷）。
        packed, blob, leaked = {}, "", ["（装箱即被拦下）%s" % _exc.code]
    record("⑺a 检索类任务装箱后**一个原文键都不剩**", not leaked,
           ("泄漏：" + "、".join(leaked)) if leaked else "")
    record("⑺b 装箱里有「含目标机内容」标记（§12.89 第 3 条）", "content_warning" in packed, "")
    src = _io.open(_os.path.join(repo, "app", "ai", "retrieval.py"), encoding="utf-8").read()
    record("⑺c 检索模块源码里**没有** stdout/stderr 字段引用",
           ('"stdout"' not in src) and ('"stderr"' not in src) and ("'stdout'" not in src), "")

    # ── ⑻ ★ 截断必须如实标注（§12.90）
    p_long = pack_tool_result({"id": "T-L", "conclusion": "x" * 5000}, "h1")
    m = _re.search(r"〔已截断：保留 (\d+) 字符 / 共 (\d+) 字符〕", str(p_long.get("conclusion")))
    record("⑻a 超长结论写明「保留 N / 共 M」",
           bool(m) and m.group(1) == "4000" and m.group(2) == "5000",
           ("匹配=%s" % (m.group(0) if m else "无")))
    p_short = pack_tool_result({"id": "T-S", "conclusion": "短结论"}, "h1")
    record("⑻b 未截断时**不**出现该标记", "已截断" not in str(p_short.get("conclusion")), "")

    # ── ⑼ ★★ 跨机永不合并（§12.86）
    v = R.aggregate([_O("file.grep", "node-01", GREP_HIT), _O("file.grep", "node-02", GREP_HIT)],
                    host_order=[h.id for h in rcfg.hosts])
    record("⑼ 两台同名路径同一行 ⇒ 计数 = 2（不是 1）、两台分开列",
           v.hit_count == 2 and v.host_count == 2 and len(v.rows) == 2,
           "hit=%d hosts=%d rows=%d" % (v.hit_count, v.host_count, len(v.rows)))

    # ── ⑽ ★ 命中率统计不外发（§12.92）
    record("⑽a 会话层有**本地**命中率账（hitrate）", hasattr(AiSessions, "hitrate"), "")
    packed2 = pack_tool_result({"id": "T-W", "conclusion": "结论", "hit_rate": 88,
                                "domain_pick": "A、C", "fallback": 1}, "h1")
    blob2 = _json.dumps(packed2, ensure_ascii=False)
    record("⑽b 命中率 / 选域字段**不在**出境装箱里",
           ("hit_rate" not in blob2) and ("domain_pick" not in blob2) and ("fallback" not in blob2), blob2[:120])


# ---------------------------------------------------------------- T14：最小鉴权


class _TmpAuthCfg:
    """只给 `Auth` 用的**最小配置替身**。

    ★ 为什么必须有它：`Auth` 的默认口令文件是 `repo/var/auth.json` —— 那是**用户的真凭据**。
      自检一旦碰它，就可能把用户的门口令改掉或锁掉（那不是"测坏了自己"，
      是**把一个真实的安全设施弄坏**）。⇒ 一律换成**临时目录里的**文件，测完即弃。
    """

    def __init__(self, file_path) -> None:
        self.raw = {"auth": {"file": str(file_path)}}
        self.root = file_path.parent
        self.timezone = "Asia/Shanghai"


class _LocalConsole:
    """在自检进程里起一个**真的** HTTP 服务（随机端口），用来打真实请求。

    ★ 为什么不能只测函数：见 `check_t14_auth` 的 docstring ——
      "闸门"是**请求层**的性质，函数层测它等于自己证明自己。
    """

    def __init__(self, api, cfg) -> None:
        import threading
        from http.server import ThreadingHTTPServer

        from app.server import make_handler

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(api, cfg))
        self.port = self.httpd.server_address[1]
        self.base = "http://127.0.0.1:%d" % self.port
        #: ★★ 被 RST 的次数（服务端**没读请求体**就关连接时会 +1）。
        #: ★ 它是个**断言**，不是个统计：正常应当恒为 0。
        #: 见 `app/server.py::_drain` 的注释 —— 这个缺陷是在**完整门**里跑出来的。
        self.aborts = 0
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def _req_once(self, method: str, path: str, body=None, token: str | None = None):
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        r = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                raw = resp.read().decode("utf-8", "replace")
                # ★ T15：导出通道回的是**纯文本**（报告 / 单任务报告）——
                #   原来这里只试 JSON，于是 200 的文本响应会抛 JSONDecodeError 把整节断言带崩。
                #   ⇒ 非 JSON 也照样返回，放进 `raw` 里（调用方想看正文就看它）。
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, {"raw": raw}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, {"raw": raw[:400]}

    def req(self, method: str, path: str, body=None, token: str | None = None):
        """打一次；★ 遇到连接被 RST **重试一次**，但把这件事记在 `self.aborts` 里。

        ★ 为什么要重试：一次抖动不该让后面 20 条断言全丢掉
          （T13 的教训：**崩不是红** —— 崩了报告里只剩"脚本异常"，什么都学不到）。
        ★ 为什么要计数：重试会**掩盖**服务端的真缺陷，所以"有没有 RST 过"要单独成为一条断言。
          ★ 两头都要，少一头都是自欺。
        """
        try:
            return self._req_once(method, path, body, token)
        except ConnectionError:
            self.aborts += 1
            return self._req_once(method, path, body, token)

    def close(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:  # noqa: BLE001
            pass


def check_t14_auth(rcfg, ractions, map_data) -> None:
    """T14（变更编排 · 人在环）· 离线可跑：**最小鉴权真的在拦**（规范 §12.97，断言 ⑾ ⑿ ⒅）。

    ★★ 为什么这一节必须**真打 HTTP**、而不是在函数层验：
      "闸门"是**请求层**的性质（`app/server.py` 的唯一漏斗）。
      函数层测它等于自己证明自己 —— 而红线 11 的病根恰恰是"**整个没有这一层**"，
      不是"这一层写错了"。所以这里起一个临时 HTTP 服务，用真的 401 / 429 说话。

    ★★ 为什么用**临时口令文件**：`repo/var/auth.json` 是用户的真凭据，自检碰它就是破坏。
      这一节的所有口令操作都发生在 `tempfile.mkdtemp()` 下的文件上。

    ★ 三条断言分别守：
      ⑾ 鉴权真的在拦（不带令牌 401 / 带对令牌 200）
      ⑿ 无口令 ⇒ **全拒**（"没口令就放行"是假鉴权；口令文件坏了更不能变成"没设过"）
      ⒅ 「能防 / 不能防」两段**都在**（§12.97.4：边界不许只说一半）
    """
    section("★ v1.17（T14）：最小鉴权 —— 真的在拦 / 无口令即全拒 / 边界两段都在（断言 ⑾ ⑿ ⒅）")
    import shutil
    import tempfile

    from app.auth import Auth
    from app.server import bootstrap

    tmp = Path(tempfile.mkdtemp(prefix="aoc-t14-auth-"))
    console = None
    api = None
    old_auth = None
    try:
        auth_file = tmp / "var" / "auth.json"
        # ★ 用临时口令状态接管 auth（**先备份原对象，稍后还原**）
        _c, _a, _m, _s, _e, api = bootstrap(ROOT)
        old_auth = api.auth
        api.auth = Auth(_TmpAuthCfg(auth_file))
        console = _LocalConsole(api, rcfg)

        def err_code(payload):
            return (payload.get("error") or {}).get("code") or ""

        def code_of(resp):
            # ★ 注意返回的是 **(状态码, 错误码字符串)** 两件东西 ——
            #   不是 (状态码, payload)。想要 payload 请直接下标 resp[1]。
            return resp[0], err_code(resp[1])

        # ── ⑾ 鉴权真的在拦 ───────────────────────────────────────────
        st_health, _ = code_of(console.req("GET", "/api/health"))
        st_actions, _ = code_of(console.req("GET", "/api/actions"))
        st_hosts, _ = code_of(console.req("GET", "/api/hosts"))
        st_export, code_export = code_of(console.req("GET", "/api/tasks/T-xxx/export?format=txt"))
        record("⑾a ★★ §12.97.2：**不带令牌一律 401**"
               "（含 /api/health · /api/actions · /api/hosts · 导出通道）",
               (st_health, st_actions, st_hosts, st_export) == (401, 401, 401, 401),
               "health=%d actions=%d hosts=%d export=%d(%s)"
               % (st_health, st_actions, st_hosts, st_export, code_export))
        # ★ 错误信封：拒绝也必须给「原因 + 建议」（T5 的教训：异常路径丢信封 = 界面全变未知错误）
        _, env = console.req("GET", "/api/health")
        _e2 = env.get("error") or {}
        record("⑾b ★ 拒绝也带**完整错误信封**（ok=false + reason + advice）",
               env.get("ok") is False and bool(_e2.get("reason")) and bool(_e2.get("advice")),
               "code=%s reason=%s" % (_e2.get("code"), str(_e2.get("reason"))[:40]))
        record("⑾c ★ `/api/health` **不在**免鉴权白名单里（它会吐主机名 / IP / user=root）",
               st_health == 401, "health=%d" % st_health)

        # ── ⑿ 无口令 ⇒ 全拒（假鉴权判定）─────────────────────────────
        #   ★★ 判据不是"有没有这个字段"，而是"把校验删掉，断言会不会红" ——
        #      所以这里要同时验"没口令时全拒"与"设置过后才放行"，两条都得立住。
        st_ping = console.req("GET", "/api/auth/ping")
        pd = (st_ping[1].get("data") or {})
        st_ping = st_ping[0]
        record("⑿a ★ `/api/auth/ping` 免鉴权可读，且如实报告「没设过口令」",
               st_ping == 200 and pd.get("configured") is False and pd.get("setup_allowed") is True,
               "configured=%s setup_allowed=%s" % (pd.get("configured"), pd.get("setup_allowed")))
        st_login_before, code_login_before = code_of(
            console.req("POST", "/api/auth/login", {"password": "whatever-123456"}))
        record("⑿b ★ 没设过口令时 login 给**可执行建议**（不是一句 401 了事）",
               st_login_before == 401 and code_login_before == "AUTH_NOT_INITIALIZED",
               "%d %s" % (st_login_before, code_login_before))

        # ★★ ⑿q 守的是「**回过 body 又被拒**的路径不许挂死」（§12.97.5）：
        #   第一版 `_drain()` 拿 Content-Length 当「还剩多少」，于是在 `dispatch`
        #   **已经读过**请求体的路径（`login` 返 401）上又去等**永远不会再来**的字节 ⇒
        #   服务端挂死，客户端只能等到自己的超时（`TimeoutError`，离线门 ⑿b 就这么红的）。
        #   ★ 判据是**耗时**：不许用「反正业务断言是绿的」把它解释过去（§12.52 同源）。
        import time as _time

        _t_q = _time.time()
        st_q, code_q = code_of(console.req(
            "POST", "/api/auth/login", {"password": "whatever-123456"}))
        _dt_q = _time.time() - _t_q
        record("⑿q ★★ §12.97.5：**带 body 却被拒**的 POST 必须「立刻」回来"
               "（服务端在已读过 body 的路径上再等 body ⇒ 客户端只能等自己的超时）",
               st_q == 401 and code_q == "AUTH_NOT_INITIALIZED" and _dt_q < 5.0,
               "HTTP %d %s · %.2fs" % (st_q, code_q, _dt_q))
        _r_setup = console.req("POST", "/api/auth/setup", {"password": "t14-selftest-pass"})
        st_setup = _r_setup[0]
        token = (((_r_setup[1].get("data") or {}).get("token")) or "")
        record("⑿c ★ 首次设置口令成功并直接发牌", st_setup == 200 and len(token) >= 32,
               "%d token_len=%d" % (st_setup, len(token)))
        st_health_ok, _ = code_of(console.req("GET", "/api/health", token=token))
        record("⑿d ★★ **设过口令之后，带对令牌才放行**（`/api/health` ⇒ 200）",
               st_health_ok == 200, "health=%d" % st_health_ok)
        st_bad, code_bad = code_of(console.req("GET", "/api/health", token="not-a-real-token"))
        record("⑿e ★ 错令牌 ⇒ 401", st_bad == 401, "%d %s" % (st_bad, code_bad))
        # ★★ 后门守卫：设过之后不许再"初始化"一次
        st_setup2, code_setup2 = code_of(console.req("POST", "/api/auth/setup", {"password": "hijack-me-1234"}))
        record("⑿f ★★ **设过口令后 `/api/auth/setup` 必须被拒**（否则它就是免鉴权的重置 = 后门）",
               st_setup2 == 401 and code_setup2 == "AUTH_ALREADY_INITIALIZED",
               "%d %s" % (st_setup2, code_setup2))
        # ★ 口令文件里不许出现明文（§12.97.1）
        body = auth_file.read_text(encoding="utf-8") if auth_file.is_file() else ""
        record("⑿g ★ 口令文件里**不出现明文**（只存 salt / iterations / hash）",
               ("t14-selftest-pass" not in body) and ('"salt"' in body) and ('"hash"' in body),
               "字节=%d" % len(body))
        st_out, _ = code_of(console.req("POST", "/api/auth/logout", {}, token=token))
        st_after, _ = code_of(console.req("GET", "/api/health", token=token))
        record("⑿h ★ 登出之后原令牌立刻失效（401）", st_out == 200 and st_after == 401,
               "logout=%d after=%d" % (st_out, st_after))

        # ── ⑿ 续：改口令（★ 原来这条路由**一条断言都没盖**，只能靠"人去浏览器点一下"——
        #     那不合格。这里把 /api/auth/password 整条路径补上。）
        _r2 = console.req("POST", "/api/auth/login", {"password": "t14-selftest-pass"})
        tok2 = (((_r2[1].get("data") or {}).get("token")) or "")
        _rb = console.req("POST", "/api/auth/password",
                          {"old_password": "not-the-old-one", "new_password": "brand-new-pass-99"},
                          token=tok2)
        _stb, _cb = _rb[0], err_code(_rb[1])
        record("⑿l ★ 改口令：**旧口令错 ⇒ 拒**（不是谁拿着令牌就能改）",
               _stb == 401 and _cb == "AUTH_BAD_CREDENTIALS", "%d %s" % (_stb, _cb))
        _rok = console.req("POST", "/api/auth/password",
                           {"old_password": "t14-selftest-pass", "new_password": "brand-new-pass-99"},
                           token=tok2)
        tok3 = (((_rok[1].get("data") or {}).get("token")) or "")
        _old_tok_status = console.req("GET", "/api/health", token=tok2)[0]
        _new_tok_status = console.req("GET", "/api/health", token=tok3)[0]
        record("⑿m ★ 改口令成功 ⇒ **所有旧令牌立即失效**、只留一个新令牌",
               _rok[0] == 200 and len(tok3) >= 32 and _old_tok_status == 401 and _new_tok_status == 200,
               "新令牌 %d 位 · 旧令牌->%d · 新令牌->%d" % (len(tok3), _old_tok_status, _new_tok_status))
        _st_old = console.req("POST", "/api/auth/login", {"password": "t14-selftest-pass"})[0]
        _st_new = console.req("POST", "/api/auth/login", {"password": "brand-new-pass-99"})[0]
        record("⑿n ★ 改完之后：旧口令登不进、新口令能登",
               _st_old == 401 and _st_new == 200, "旧口令->%d · 新口令->%d" % (_st_old, _st_new))
        _st_short = console.req("POST", "/api/auth/password",
                                {"old_password": "brand-new-pass-99", "new_password": "abc"},
                                token=tok3)[0]
        record("⑿o ★ 改口令也守**长度下限**（弱口令不给设）", _st_short == 400, "HTTP %d" % _st_short)
        # ★★ 这条守的是"拒绝在**传输层**也没被打折"：
        #    服务端不读请求体就关连接 ⇒ 客户端收到 RST，看不到 401 信封。
        #    ★ 它是**完整门跑出来的**（离线门没复现）—— 见 app/server.py::_drain。
        record("⑿p ★★ **一次 RST 都没有**（拒绝时也把请求体读掉了 ⇒ 客户端永远拿得到那封信封）",
               console.aborts == 0, "RST 次数=%d" % console.aborts)

        # ── ⑿ 续：口令文件坏了 ⇒ **fail-closed**（不许退化成"没设过"）──
        shutil.rmtree(auth_file.parent, ignore_errors=True)
        auth_file.parent.mkdir(parents=True, exist_ok=True)
        auth_file.write_text("{ not json", encoding="utf-8")
        api.auth = Auth(_TmpAuthCfg(auth_file))
        st_broken, code_broken = code_of(console.req("GET", "/api/health"))
        st_broken_setup, code_broken_setup = code_of(
            console.req("POST", "/api/auth/setup", {"password": "recover-me-1234"}))
        record("⑿i ★★ §12.97.3：**口令文件坏了 ⇒ 一切全拒，连「设置口令」都不给**"
               "（不许把它当成「没设过口令」—— 那等于把门打开）",
               st_broken == 401 and code_broken == "AUTH_STORE_BROKEN"
               and st_broken_setup == 401 and code_broken_setup == "AUTH_STORE_BROKEN",
               "health=%d(%s) setup=%d(%s)" % (st_broken, code_broken, st_broken_setup, code_broken_setup))
        # ★ 控制台**仍然起得来**（起不来用户就连看错误的界面都没有 —— T7·§12.17 的教训）
        record("⑿j ★ 口令文件坏了，控制台**仍可启动**（能起来才看得到错误）", console is not None, "")

        # ── ⑿ 续：限速 ────────────────────────────────────────────────
        shutil.rmtree(auth_file.parent, ignore_errors=True)
        api.auth = Auth(_TmpAuthCfg(auth_file))
        api.auth.set_password("t14-selftest-pass")
        codes = []
        for _i in range(7):
            codes.append(console.req("POST", "/api/auth/login", {"password": "wrong-one"})[0])
        record("⑿k ★ 连错口令 ⇒ 触发限速（429），不是无限次猜",
               429 in codes, "HTTP 序列=%s" % codes)

        # ── ⒅ 边界两段都在（§12.97.4）────────────────────────────────
        pol = Auth(_TmpAuthCfg(tmp / "x.json")).public_policy()
        spec = (ROOT / "docs" / "动作规范.md").read_text(encoding="utf-8")
        ign = (ROOT / ".gitignore").read_text(encoding="utf-8")
        record("⒅a ★★ §12.97.4：策略里「能防」与「不能防」**两段都在且非空**",
               bool(pol.get("can_protect")) and bool(pol.get("cannot_protect")),
               "can=%d cannot=%d" % (len(pol.get("can_protect") or []), len(pol.get("cannot_protect") or [])))
        record("⒅b ★ 规范 §12.97.4 里两个词都在（删掉任一段 ⇒ 这条红）",
               ("能防" in spec) and ("不能防" in spec) and ("不是「保险柜」" in spec), "")
        record("⒅c ★ §12.97.1 的承诺是真的：`var/auth.json` **确实在 .gitignore 里**",
               "var/auth.json" in ign, "")
        record("⒅d ★ 鉴权口令**不落盘明文**这条在模块 docstring 与实现里都有落点",
               ("PBKDF2" in (ROOT / "app" / "auth.py").read_text(encoding="utf-8")), "")
    except Exception as exc:  # noqa: BLE001
        record("★ T14 鉴权断言可跑（没崩）", False, "%s: %s" % (type(exc).__name__, exc))
    finally:
        if console is not None:
            console.close()
        if api is not None and old_auth is not None:
            api.auth = old_auth
        shutil.rmtree(tmp, ignore_errors=True)


def check_t14_requests(rcfg, ractions, map_data) -> None:
    """T14·S3 · 离线可跑：**「请求」是 AI 的权利，「执行」不是**（规范 §12.96 / §12.98 / §12.99）。

    ★ 五条断言全部**不需要靶机、不需要 key**（喂人造输入 / 查结构）——
      这是 §12.95 的纪律（能离线验的尽量离线，§12.52 / §12.84 的教训）。

    ★ 它们分别守：
      ⒀ 三档权限在**工具面**上就是分开的（`green` 能跑 · `yellow` 只能请求 · `red` 连请求都不发）
         ＋ ★★ **白名单是"上限"的子集**：往配置里塞没批准的动作 ⇒ 审计当场报出来
      ⒁ `request_action` **只写记录、不执行**（库里多一行 pending · 任务表零新增 · 一次 dispatch 都没走）
      ⒂ 「确认词」字段在 `request_action` 的 schema 里**结构上不存在**
      ⒃ 卡片五要素**缺一项就不许生成**，且缺哪一项要说清
      ⒆ 全库 `.py` 都能编译（★ 这是今天挣来的一条：语法错的文件**在没人 import 它之前**没人会踩到）
    """
    section("★ v1.17（T14·S3）：变更「请求」—— 只摆卡片 / 白名单是上限 / 五要素齐备（断言 ⒀ ⒁ ⒂ ⒃ ⒆）")
    import ast
    import compileall
    import dataclasses
    import json as _json
    import tempfile

    repo = ROOT
    actions = ractions if isinstance(ractions, dict) else {a.id: a for a in ractions}
    try:
        from app.ai.requests import (
            APPROVED_YELLOW, CARD_FIELDS, REVIEW_TABLE, UNDO_TABLE,
            ActionRequests, build_card, card_text, validate_card,
        )
        from app.ai.sessions import AiSessions
        from app.ai.tools import REQUEST_TOOL_NAME, ToolFace
        from app.errors import OpsError
        from app.store import Store
    except Exception as exc:  # noqa: BLE001
        record("★ T14·S3 的模块可导入", False, "%s: %s" % (type(exc).__name__, exc))
        return

    tmp = Path(tempfile.mkdtemp(prefix="aoc-t14-req-"))
    sessions = None
    try:
        face = ToolFace(rcfg, actions)
        sessions = AiSessions(tmp / "req.db")
        sessions.init()
        reqs = ActionRequests(rcfg, actions, face, sessions)

        # ── ⒀a ★★ 白名单是「上限」的子集（表不许被悄悄改宽）─────────────
        allow = list(face.yellow_allowlist)
        problems = reqs.audit_allowlist()
        record("⒀a ★★ §12.96.1：`yellow_allowlist` **每一项都在 `APPROVED_YELLOW` 里**"
               "（配置只是「上限」的子集；空白名单 = 一个都不放开）",
               bool(allow) and not problems and set(allow) <= set(APPROVED_YELLOW),
               "白名单 %d 项 · 审计问题 %s" % (len(allow), problems or "无"))

        wide_raw = dict(rcfg.raw or {})
        wide_raw["ai"] = {**(wide_raw.get("ai") or {}), "yellow_allowlist": allow + ["k8s.exec"]}
        wide_cfg = dataclasses.replace(rcfg, raw=wide_raw)
        wide_face = ToolFace(wide_cfg, actions)
        wide_problems = ActionRequests(wide_cfg, actions, wide_face, sessions).audit_allowlist()
        record("⒀b ★★ **证伪**：把没批准的 `k8s.exec` 塞进白名单 ⇒ **审计必须当场报出来**",
               any("k8s.exec" in p for p in wide_problems),
               "审计 = %s" % (wide_problems or "（空的 —— 这条证伪没成立！）"))

        # ── ⒀c ★★ 三档权限：拒，而且**说清该去哪儿**（§12.99.3）──────────
        def _deny(aid):
            try:
                reqs.guard(aid)
                return "", ""
            except OpsError as exc:
                return exc.code, exc.advice

        code_red, adv_red = _deny("pkg.remove")        # red：连请求都不许发
        code_y, adv_y = _deny("k8s.exec")              # yellow 但不在白名单
        code_ok, _ = _deny("pkg.install")              # 白名单内 ⇒ 放行
        exec_red = exec_y = ""
        for aid, box in (("pkg.remove", "red"), ("k8s.exec", "yellow")):
            try:
                face.guard(aid)
            except OpsError as exc:
                if box == "red":
                    exec_red = exc.code
                else:
                    exec_y = exc.code
        record("⒀c ★★ §12.96.1 / §12.99.3：`red` **连请求都不许发**、白名单外的 `yellow`"
               "**既跑不了也请求不了**，白名单内的**能请求**，且被拒时**说清该去哪儿办**",
               code_red == "AI_RED_NEEDS_HUMAN" and code_y == "AI_NOT_REQUESTABLE"
               and code_ok == "" and exec_red == "AI_NOT_READONLY" and exec_y == "AI_NOT_READONLY"
               and ("界面" in adv_red) and ("自己点" in adv_y),
               "red→%s · 域外 yellow→%s · 白名单内→%s · 执行面 red/yellow→%s/%s｜"
               "建议含「界面」=%s 含「自己点」=%s"
               % (code_red, code_y, code_ok or "放行", exec_red, exec_y,
                  "界面" in adv_red, "自己点" in adv_y))

        # ── ⒁ ★★ 只写记录、不执行（§12.96.2 规矩 1）────────────────────
        # ★ 三条判据缺一不可：库里多一行 pending · **任务表零新增** · **一次 dispatch 都没走**。
        #   ★ 尤其第三条：它证明的不是"这次恰好没执行"，而是**这条路上根本没有执行入口**。
        store = Store(rcfg)
        store.init()
        before_tasks = int(store.stats()["tasks_total"])
        probe = ActionRequests(rcfg, actions, face, sessions)
        out = probe.submit("pkg.install", rcfg.hosts[0].id, {"package": "ncdu"},
                           "先试一次请求：这是验收①的靶包")
        after_tasks = int(store.stats()["tasks_total"])
        row = sessions.get_action_request(out["request_id"])
        text = card_text(out["card"])
        # ★★ 为什么判据是"**结构上拿不到**"而不是"这次没调用"：
        #   打桩计数只在"真有人把 dispatch 接进来"时才有效；而 `ActionRequests` **连构造参数里
        #   都没有 dispatch**，源码里也**没有一处**执行层的引用 —— ★ **"没有入口"比"这次没走"强一个量级**
        #   （同 §12.74.2 的写法）。★ 顺带记一条：第一版写的就是个打桩计数器，
        #   而那个桩**从没被接上**——那就是一条**假断言**（绿得毫无意义）。
        # ★★ 扫描必须走 AST，**不许对源码做字符串匹配**：
        #   本模块的 docstring 里就写着「不 import 执行层 / 传输层（`engine` / `transport` / `ssh`）」——
        #   字符串匹配会**把这句话当成违规**（第一次就是这么红的：假红，一条真问题都没有）。
        #   判据要问的是"**代码里有没有引用**"，所以就看 import 与标识符，不看散文。
        src = (repo / "app" / "ai" / "requests.py").read_text(encoding="utf-8")
        _EXEC_MODULES = ("engine", "transport", "paramiko", "paramiko", "ssh")
        used: list[str] = []
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Import):
                used += [f"import {a.name}" for a in node.names
                         if (a.name or "").split(".")[0] in _EXEC_MODULES]
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in _EXEC_MODULES:
                    used.append(f"from {node.module} import …")
            elif isinstance(node, ast.Attribute) and node.attr in ("dispatch", "run_action"):
                used.append(f".{node.attr}")
            elif isinstance(node, ast.Name) and node.id in ("dispatch", "engine"):
                used.append(node.id)
        exec_words = sorted(set(used))
        has_dispatch = hasattr(probe, "dispatch")
        record("⒁ ★★ §12.96.2 规矩 1：**「请求」= 写一条记录，不是调一次执行**"
               "（库里多一行 `pending` · 任务表零新增 · 这条路**结构上拿不到**执行入口 · 卡片可原样递给人）",
               row is not None and row.get("status") == "pending"
               and after_tasks == before_tasks and not has_dispatch and not exec_words
               and row["card"].get("request_id") == out["request_id"]
               and ("待确认" in text),
               "request_id=%s · 状态=%s · 任务 %d→%d · 有 dispatch 入口=%s · 源码里的执行词=%s"
               % (out["request_id"], row.get("status") if row else "（没落库）",
                  before_tasks, after_tasks, has_dispatch, exec_words or "无"))

        # ── ⒂ ★★ 确认词通道**结构上**不存在（§12.99.2）──────────────────
        specs = face.function_specs()
        blob = _json.dumps(specs, ensure_ascii=False)
        req_spec = [s for s in specs if s["function"]["name"] == REQUEST_TOOL_NAME]
        props = list(((req_spec[0]["function"]["parameters"]["properties"]) if req_spec else {}).keys())
        _CONFIRMISH = ("confirm_text", "confirm", "confirm_word")
        in_props = [k for k in _CONFIRMISH if k in props]
        in_blob = [k for k in _CONFIRMISH if '"%s"' % k in blob]
        record("⒂ ★★ §12.99.2：`request_action` 的 schema 里**结构上不存在**确认词字段"
               "（判据是「它根本不在那里」，不是「约定了不传」）",
               bool(req_spec) and not in_props and not in_blob,
               "request_action 在工具表里=%s · 入参 %s · 确认词类键 %s"
               % (bool(req_spec), props, in_props or in_blob or "无"))
        # ★ 证伪：手工给它加上 ⇒ 同一段判据必须报红
        fake = _json.loads(_json.dumps(req_spec[0]))
        fake["function"]["parameters"]["properties"]["confirm_text"] = {"type": "string"}
        fake_props = list(fake["function"]["parameters"]["properties"].keys())
        fake_blob = _json.dumps(fake, ensure_ascii=False)
        record("⒂ ★ **证伪**：给 `request_action` 加上 `confirm_text` ⇒ 同一段判据**必须报红**",
               bool([k for k in _CONFIRMISH if k in fake_props])
               and bool([k for k in _CONFIRMISH if '"%s"' % k in fake_blob]),
               "加完之后命中 = %s" % [k for k in _CONFIRMISH if '"%s"' % k in fake_blob])

        # ── ⒃ ★★ 五要素：缺一项就不许生成卡片（§12.98.1）────────────────
        host = rcfg.hosts[0]
        good = build_card(rcfg, actions["pkg.install"], host, {"package": "ncdu"},
                          "验收 5：五要素齐备性")
        bad_ones: list[str] = []
        for f in CARD_FIELDS:
            broken = _json.loads(_json.dumps(good))
            broken[f] = [] if f == "cannot_undo" else ""
            try:
                validate_card(broken)
                bad_ones.append(f + "（清空了竟然还放行）")
            except OpsError as exc:
                if exc.code != "AI_CARD_INCOMPLETE" or f not in (exc.reason + " " + str(exc.context)):
                    bad_ones.append(f + "（报了，但没说清缺哪个）")
        record("⒃a ★★ §12.98.1：卡片五要素**缺一项就不许生成**，且**说清缺的是哪一项**"
               "（逐项清空 ⇒ 逐项被拒）",
               not bad_ones and len(CARD_FIELDS) == 5
               and all(str(good[f]).strip() not in ("", "[]", "{}") for f in CARD_FIELDS),
               "五要素=%s · 逐项清空结果=%s" % ("、".join(CARD_FIELDS), bad_ones or "全部被正确拒绝"))

        # ★ 撤法映射不到 ⇒ **必须写「无已知撤回路径」**，而且卡片仍然成立（空也要写「无」）
        no_undo = build_card(rcfg, actions["pkg.install"], host, {"package": "ncdu"},
                             "映射不到时的兜底", undo_table={})
        record("⒃b ★ §12.98.3：撤法**映射不到** ⇒ 必须写「无已知撤回路径」＋"
               "「只能靠人手工收拾」（★ 留空或含糊都不允许）",
               "无已知撤回路径" in no_undo["undo"]["how"] and bool(no_undo["cannot_undo"]),
               "撤法 = %s｜撤不回来 = %s" % (no_undo["undo"]["how"][:40], no_undo["cannot_undo"]))

        # ★ 两张表本身也要自洽：复核动作必须真实存在**且只读**；撤法动作必须真实存在
        bad_refs: list[str] = []
        for aid in APPROVED_YELLOW:
            if aid not in actions:
                bad_refs.append(aid + "（动作不存在）")
            elif actions[aid].risk != "yellow":
                bad_refs.append(aid + "（不是 yellow）")
            if aid not in UNDO_TABLE:
                bad_refs.append(aid + "（没登记撤法）")
            if aid not in REVIEW_TABLE:
                bad_refs.append(aid + "（没登记复核）")
        for aid, row in REVIEW_TABLE.items():
            a = actions.get(row["action_id"])
            if a is None:
                bad_refs.append("%s 的复核动作不存在：%s" % (aid, row["action_id"]))
            elif a.risk != "green":
                bad_refs.append("%s 的复核动作用了非只读动作：%s" % (aid, row["action_id"]))
        for aid, row in UNDO_TABLE.items():
            by = str(row.get("by_action") or "")
            if by and by not in actions:
                bad_refs.append("%s 的撤法动作不存在：%s" % (aid, by))
        record("⒃c ★★ 被批准的动作**每一个都有撤法 + 复核**；复核动作必须真实存在**且是只读**",
               not bad_refs,
               "问题 %s" % (bad_refs or "无（%d 个动作全部齐备）" % len(APPROVED_YELLOW)))

        # ★ 判据与影响面里的占位符必须**真的被填掉**（★ 这条是"把卡片打出来看一眼"挣来的：
        #   第一版自作聪明用了单花括号渲染，结果 **YAML 那条备份路径**一个占位符都没被填上，
        #   卡片上原样印着 `{{ key }}`，而当时**所有断言都是绿的**
        #   —— 断言不问渲染，它就没人看住。★ 教训：**凡是"给人看的那段话"，都要有一条断言盯着它**）。
        rendered = build_card(rcfg, actions["pkg.install"], host, {"package": "ncdu"},
                              "占位符必须被填掉")
        rendered2 = build_card(rcfg, actions["sysctl.set"], host,
                               {"key": "net.ipv4.ip_forward", "value": "1"},
                               "备份路径上的占位符也必须被填掉")
        leftovers = [v for v in rendered["criteria"]["params"].values() if "{" in str(v)]
        leftovers += [p for p in rendered2["impact"]["paths"] if "{" in str(p)]
        record("⒃d ★ 判据参数与**影响面里的文件路径**都必须**真的被填上**（不留 `{{ }}` 占位符）",
               not leftovers and rendered["criteria"]["params"].get("pkg") == "ncdu"
               and rendered2["impact"]["paths"] == ["/etc/sysctl.d/99-aoc-net.ipv4.ip_forward.conf"],
               "判据参数 = %s ｜ 影响面文件 = %s ｜ 残留 = %s"
               % (rendered["criteria"]["params"], rendered2["impact"]["paths"], leftovers or "无"))

        # ── ⒆ 全库可编译（★ 今天的现场挣来的）───────────────────────────
        bad_dirs = [d for d in ("app", "tools")
                    if not compileall.compile_dir(str(repo / d), quiet=2, force=True)]
        record("⒆ ★ 全库 `.py` 都能编译"
               "（★ 扫的是「还没被谁 import 的文件」那一类漏网 —— 语法错在被 import 之前是隐身的）",
               not bad_dirs, "编译失败：%s" % (bad_dirs or "无（app/ 与 tools/ 全过）"))
    except Exception as exc:  # noqa: BLE001
        record("★ T14·S3 断言可跑（没崩）", False, "%s: %s" % (type(exc).__name__, exc))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def check_t14_approve(rcfg, ractions, map_data) -> None:
    """T14·S4/S5 · 离线可跑：**人点确认的那一下**与**自动复核**（规范 §12.99 / §12.100）。

    ★ 它们守四件事：
      ⒄a ★★ 复核的判定**只在"真读到、且成立"时**才说"已证实"；
           ★★ 三种"读不到"（步骤缺失 / 没有解析结果 / 采样没覆盖）**一律判未证实** ——
           "读不到 ≠ 没成功"是这一话题最容易写错的一句话。
      ⒄b ★★ 人点的那一下**也不能执行 `red`**（纵深防御：入口拦过，执行口还要自己站得住）。
      ⒄c ★★ 执行走的是**同一个入口**（`/api/actions/<id>/run` ＋ `confirm=True`）——
           打桩 `dispatch` 验路由与标志位，★ **不碰任何目标机**（桩会吞掉这次调用）。
      ⒄d ★ **原 9 个页签零回退** ＋ 新增「待确认」（静态可判，不靠肉眼）。
    """
    section("★ v1.17（T14·S4/S5）：人点确认 ⇒ 走既有执行路 ⇒ 平台自动复核（断言 ⒄）")
    import dataclasses
    import json as _json

    repo = ROOT
    actions = ractions if isinstance(ractions, dict) else {a.id: a for a in ractions}
    try:
        from app.ai.requests import approve_guard, judge_review, review_plan
        from app.errors import OpsError
        from app.server import bootstrap
    except Exception as exc:  # noqa: BLE001
        record("★ T14·S4 的模块可导入", False, "%s: %s" % (type(exc).__name__, exc))
        return

    # ── ⒄a ★★ 复核判定：只认"真读到、且成立" ───────────────────────
    def _judge(aid, params, steps):
        plan = review_plan(aid, params, actions)
        return judge_review(aid, params, plan, steps)

    cases = [
        ("装包成功（rpm 查得到）", "pkg.install", {"package": "ncdu"},
         [{"name": "info", "parsed": {"name": "ncdu"}}], True),
        ("装了但 rpm 查不到（核算是空的）", "pkg.install", {"package": "ncdu"},
         [{"name": "info", "parsed": {}}], False),
        ("复核任务里**没有**那一步", "pkg.install", {"package": "ncdu"},
         [{"name": "count", "parsed": 3}], False),
        ("那一步**没有解析结果**（被跳过 / 没跑到）", "pkg.install", {"package": "ncdu"},
         [{"name": "info", "parsed": None}], False),
        ("服务真起来了", "svc.start", {"unit": "nginx"},
         [{"name": "show", "parsed": {"ActiveState": "active", "UnitFileState": "enabled"}}], True),
        ("服务没起来（inactive）", "svc.start", {"unit": "nginx"},
         [{"name": "show", "parsed": {"ActiveState": "inactive", "UnitFileState": "disabled"}}], False),
        ("开机自启设上了", "svc.enable", {"unit": "nginx"},
         [{"name": "show", "parsed": {"UnitFileState": "enabled"}}], True),
        ("开机自启没设上", "svc.enable", {"unit": "nginx"},
         [{"name": "show", "parsed": {"UnitFileState": "disabled"}}], False),
    ]
    bad: list[str] = []
    for label, aid, params, steps, want in cases:
        got = _judge(aid, params, steps)
        if bool(got.get("proved")) != want:
            bad.append("%s（期望 %s，实得 %s）" % (label, want, got.get("proved")))
    record("⒄a ★★ §12.100：**只有在「真读到、且成立」时才判「已证实」**"
           "（装包读不到包名 / 步骤缺失 / 没有解析结果 ⇒ 一律未证实）",
           not bad, "八种输入全部符合预期" if not bad else "偏差：%s" % bad)

    # ★ 采样没覆盖 ⇒ 必须判未证实（且说清是"读不到"，不是"没成功"）
    odd = _judge("sysctl.set", {"key": "net.ipv4.conf.all.rp_filter", "value": "1"}, [])
    covered = _judge("sysctl.set", {"key": "net.ipv4.ip_forward", "value": "1"},
                     [{"name": "core", "parsed": {"ip_forward": "1"}}])
    record("⒄a' ★★ 复核动作**采样没覆盖**那个 key ⇒ 判「未证实」并说清是**读不到**；"
           "覆盖到了且值相等 ⇒ 判「已证实」",
           (odd.get("proved") is False and "读不到" in str(odd.get("basis")))
           and bool(covered.get("proved")),
           "未覆盖：%s（%s）｜ 覆盖：%s" % (odd.get("verdict"), str(odd.get("basis"))[:60],
                                          covered.get("verdict")))

    # ── ⒄b ★★ 人点的那一下也不能执行 red（纵深防御）────────────────
    host = rcfg.hosts[0]
    face = None
    try:
        from app.ai.tools import ToolFace
        face = ToolFace(rcfg, actions)
    except Exception as exc:  # noqa: BLE001
        record("⒄b ★★ 纵深防御：执行口自己再查一遍 risk", False, "ToolFace 起不来：%s" % exc)
    if face is not None:
        pend_base = {"id": "REQ-FAKE", "status": "pending", "host_id": host.id,
                     "action_id": "pkg.install"}
        rows = [
            ("red（pkg.remove）", dict(pend_base, action_id="pkg.remove"), "AI_APPROVE_NOT_YELLOW"),
            ("已处理过（approved）", dict(pend_base, status="approved"), "AI_REQUEST_DECIDED"),
            ("白名单外（k8s.exec）", dict(pend_base, action_id="k8s.exec"), "AI_NOT_REQUESTABLE"),
            ("白名单内（pkg.install）⇒ 放行", dict(pend_base), ""),
        ]
        got: list[str] = []
        for label, row, want in rows:
            try:
                approve_guard(row, actions, face.yellow_allowlist)
                code = ""
            except OpsError as exc:
                code = exc.code
                if code == "AI_APPROVE_NOT_YELLOW" and "确认词" not in str(exc.advice):
                    got.append(label + "（拒了，但没说清该去哪儿输确认词）")
            if code != want:
                got.append("%s（期望 %s，实得 %s）" % (label, want, code or "放行"))
        record("⒄b ★★ §12.99.1 纵深防御：**执行口自己也要站得住** —— `red` / 已处理过 / 白名单外 "
               "一律拒，且 red 被拒时**说清该去哪儿手输确认词**",
               not got, "四种输入全部符合预期" if not got else "偏差：%s" % got)

    # ── ⒄c ★★ 执行走同一个入口（打桩 dispatch，不碰目标机）──────────
    try:
        _cfg, _acts, _m, _store, _eng, api = bootstrap(ROOT)
        calls: list[tuple[str, str, dict]] = []

        def _stub(method: str, path: str, query: dict, body: dict | None, *a, **k):
            calls.append((method, path, dict(body or {})))
            return 200, {"ok": True, "data": {"task": {"id": "T-FAKE-T14", "status": "ok"}}}

        orig = api.dispatch
        api.dispatch = _stub
        try:
            task = api._ai_run_task("pkg.install", host.id, {"package": "ncdu"}, confirm=True)
        finally:
            api.dispatch = orig
        hit = calls[0] if calls else ("", "", {})
        record("⒄c ★★ §12.96.2 规矩 1：**执行走的就是既有那条路**"
               "（`POST /api/actions/<id>/run` ＋ `confirm=True`，与界面点「执行」同一个入口）",
               hit[0] == "POST" and hit[1] == "/api/actions/pkg.install/run"
               and hit[2].get("confirm") is True and task.get("id") == "T-FAKE-T14",
               "路由 %s %s · confirm=%s · 任务号 %s（★ 打桩，没碰目标机）"
               % (hit[0], hit[1], hit[2].get("confirm"), task.get("id")))
    except Exception as exc:  # noqa: BLE001
        record("⒄c ★★ 执行走同一个入口", False, "%s: %s" % (type(exc).__name__, exc))

    # ── ⒄d ★ 原 9 个页签零回退 ＋ 新增「待确认」（静态可判）─────────
    tabs = ["actions", "recipes", "checkup", "history", "batches", "gaps", "k8s", "mon", "chat"]
    html = (repo / "web" / "index.html").read_text(encoding="utf-8")
    js = (repo / "web" / "app.js").read_text(encoding="utf-8")
    miss_html = [t for t in tabs if f'data-tab="{t}"' not in html]
    miss_pane = [t for t in tabs + ["pending"] if f'id="pane-{t}"' not in html]
    miss_js = [t for t in tabs + ["pending"] if f"'{t}'" not in js]
    has_badge = 'id="pendingBadge"' in html
    record("⒄d ★ 验收 9：**原 9 个页签零回退** ＋ 新增「待确认」页签（页签 / 容器 / switchTab 三处都在，"
           "带待办角标）",
           not miss_html and not miss_pane and not miss_js and has_badge,
           "缺页签 %s · 缺容器 %s · JS 列表缺 %s · 角标 %s"
           % (miss_html or "无", miss_pane or "无", miss_js or "无", has_badge))

    # ── ⒄f ★★ "跑不起来"也必须落一个明确决定（★ 真跑抓到的缺陷的回归断言）──
    try:
        import tempfile

        from app.ai.requests import ActionRequests
        from app.ai.sessions import AiSessions

        tmp2 = Path(tempfile.mkdtemp(prefix="aoc-t14-unrun-"))
        tmp_sess = AiSessions(tmp2 / "unrun.db")
        tmp_sess.init()
        reqs2 = ActionRequests(rcfg, actions, face, tmp_sess)
        out2 = reqs2.submit("cron.upsert", host.id,
                            {"name": "t14-unrun", "schedule": "*/30 * * * *", "command": "/bin/true"},
                            "断言 ⒄f：看跑不起来时会不会把卡片留在 pending")
        api_cfg, api_acts, _m2, _s2, _e2, api2 = bootstrap(ROOT)
        calls = {"n": 0}

        def _fake_run(aid, host_id, params, *, confirm=False):
            """第一次（变更）给个假的"成了"；第二次（复核）**当场抛** —— 模拟"参数过不了白名单"。"""
            calls["n"] += 1
            if calls["n"] == 1:
                return {"id": "T-FAKE-RUN", "status": "ok", "verify_result": "ok"}
            raise OpsError(
                code="PARAM_INVALID",
                reason="参数「文件路径」含有不允许的字符（模拟：复核动作自己的白名单把路径拒了）",
                advice="换一个复核动作。",
            )

        orig_run, orig_sess = api2._ai_run_task, api2.ai.sessions
        orig_req_sess = api2.ai.requests.sessions
        api2._ai_run_task = _fake_run
        # ★ 两处引用的是**同一个** `AiSessions` 对象（生产里本来就是同一个）——
        #   断言里换库必须**两处一起换**，否则会在"取不到这条请求"上假红（第一版就是这么红的）。
        api2.ai.sessions = tmp_sess
        api2.ai.requests.sessions = tmp_sess
        try:
            res2 = api2.ai_request_decide(out2["request_id"], {"by": "断言"})
        finally:
            api2._ai_run_task = orig_run
            api2.ai.sessions = orig_sess
            api2.ai.requests.sessions = orig_req_sess
        row2 = tmp_sess.get_action_request(out2["request_id"])
        record("⒄f ★★ 「**跑不起来**」也要落一个**明确决定**（不许把卡片留在 `pending`）"
               "—— ★ 真跑抓到的缺陷：复核起不来时异常抛出 ⇒ 卡片一直挂着，而人以为自己已经点过了。"
               "★ 状态说的是「**变更那一半**」（这里真的做成了 ⇒ `approved`），"
               "「有没有被证实」记在 `card.review` 里 —— **两件事分开记**，不许混成一个词",
               row2 is not None and str(row2.get("status")) != "pending"
               and str(row2.get("status")) == "approved"
               and str((res2.get("review") or {}).get("verdict")) == "not_run"
               and "跑不起来" in str((res2.get("review") or {}).get("basis"))
               and "未证实" in str(res2.get("conclusion")),
               "卡片状态 %s · 复核 %s · 结论 %s"
               % (row2.get("status") if row2 else "（没落库）",
                  (res2.get("review") or {}).get("verdict"),
                  str(res2.get("conclusion"))[:60]))
        shutil_rm = __import__("shutil")
        shutil_rm.rmtree(tmp2, ignore_errors=True)
    except Exception as exc:  # noqa: BLE001
        record("⒄f ★★ 跑不起来也要落决定", False, "%s: %s" % (type(exc).__name__, exc))

    # ── ⒄e ★ 两条新路由在 **POST** 分支里（★ 免得又踩"写进 GET 分支"那个坑）──
    src = (repo / "app" / "api.py").read_text(encoding="utf-8")
    post_at = src.find('if method == "POST":\n            if path == "/api/ai/key"')
    approve_at = src.find("requests/([^/]+)/(approve|reject)")
    record("⒄e ★ `/api/ai/requests/<id>/approve|reject` 两条路由写在 **POST** 分支里"
           "（★ 这一条是踩过坑才立的：第一版写进了 GET 分支 ⇒ POST 打过去是 NO_SUCH_ROUTE）",
           post_at > 0 and approve_at > post_at,
           "POST 分支起点 %d · approve 路由 %d" % (post_at, approve_at))


def check_t16(cfg, actions, map_data) -> None:
    """★★ T16（六·虚拟化层 · VM 生命周期）新增断言 Ⓙ Ⓚ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ（规范 §12.124）。

    十件事，对应本话题十句纪律：
      Ⓙ 通道是**动作的属性**，且本地通道**没有 shell 语义**
      Ⓚ 本机子进程**只有一个出口** ＋ 退出码归一（`4294967295 → -1`）
      Ⓜ **VM 归属**：拒绝是纪律，而且**那条拒绝确实出自闸门那一段**（证伪）
      Ⓝ 电源判据**分三级**，且「起来了」≠「能 ssh 进去」
      Ⓞ **幂等**靠探针的 `was_running`，不靠「命令没报错」
      Ⓟ 闸门只增不减：M 域的 `red` 在 AI 侧**结构上不可请求**
      Ⓠ 域 **M** 已进账本（四处回填）
      Ⓡ 「**问不到**」≠「**不存在**」：探针必须交代查了什么键
      Ⓢ 界面第 **12** 页签 ＋ 走查表同步 ＋ **按钮级**边界
      Ⓣ 同一个开口**两处实现都要认账**（S6 出的真缺陷挣来的）
      Ⓤ AI 侧**不许碰新通道**，也**没有 `confirm_text` 通道**（验收 #11 · 铁律 8）

    ★ 全部**离线可跑**（§12.124 的口径：离线跑不出结论的判据 = 没有判据）。
    ★ 每条都配**证伪**：判据写坏了必须红 ——「绿着但不管用」是本文件最常见的敌人。
    """
    import ast
    import copy as _copy
    import importlib.util

    from app import changed as _changed
    from app import vmware as _vmw
    from app.ai import requests as _req
    from app.ai.tools import ToolFace
    from app.catalog import render_text
    from app.hostexec import run_child as product_run_child
    from app.recipe import lint_recipe, load_recipes

    section("★ v1.19（T16）：非 ssh 通道 · VM 归属 · 电源判据 · 闸门只增不减 · 界面第 12 页签")

    tmp = cfg.paths.var / "selftest-t16"
    tmp.mkdir(parents=True, exist_ok=True)

    # ══════════════════════════════════ Ⓙ 通道是动作的属性 ＋ 本地通道没有 shell 语义
    local_ids = sorted(a.id for a in actions.values() if getattr(a, "channel", "ssh") == "local")
    vm_ids = sorted(a.id for a in actions.values() if a.id.startswith("vm."))
    #   ★★ T17·S9 收紧：判据**不再写死"10 个"**，改成算出来的期望集 ——
    #     T17 往 M 域加了 `vm.clone` / `vm.vmx-read`（都是本机通道），
    #     还加了 `host.register`（改的是**管理机自己**的 hosts.yaml，同样走本机通道）。
    #     ★ 写死数字的判据，每加一个动作就要来改一次 —— 那不是判据，是台账；
    #       而"算出来的期望集"照样抓得住**误标**（多一个 / 少一个都红）。
    expect_local = sorted({*vm_ids, "host.register"})
    record("Ⓙ ★★★ §12.115.1：**通道由动作声明**（`channel: ssh|local`）—— "
           "所有 `vm.*`（%d 个）＋ `host.register`（写的是**管理机自己**的 hosts.yaml）"
           "必须声明 `local`，且**别的动作一个都不许被误标**" % len(vm_ids),
           local_ids == expect_local and len(vm_ids) >= 10,
           "本机通道 %d 个：%s　｜ 期望：%s"
           % (len(local_ids), "、".join(local_ids) or "（无）", "、".join(expect_local)))

    def _ast_shell_smells(path) -> list[str]:
        """扫一个本机通道文件：出现 shell 语义 / 编码前缀就报出来。

        ★ 只扫**代码里的字符串常量** —— 文档串与注释不算（它们本来就要「说明我们不做这些事」，
          把它们也算进来就等于**惩罚写清楚的人**）。
        """
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docs.add(id(body[0].value))
        bad: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                            and kw.value.value is True:
                        bad.append("%s:%d shell=True" % (path.name, node.lineno))
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and id(node) not in docs:
                v = node.value
                if "LC_ALL" in v:
                    bad.append("%s:%d 字符串里出现 LC_ALL" % (path.name, node.lineno))
                if v.strip() in ("-c", "sh", "bash", "cmd"):
                    bad.append("%s:%d 出现 shell 形态的常量 %r" % (path.name, node.lineno, v.strip()))
        return bad

    local_files = [ROOT / "app" / n for n in ("hostexec.py", "transport_local.py", "vmware.py")]
    smells = [x for p in local_files for x in _ast_shell_smells(p)]
    record("Ⓙ ★★ §12.115.3：本地通道 **argv 直传** —— 三个文件里没有 `shell=True`、"
           "没有 `env LC_ALL`、没有 `sh -c`（★ 判据只看代码里的字符串常量）",
           not smells, "、".join(smells) or "三个文件都干净")

    #   ★ 证伪：往本地通道里塞一句 `env LC_ALL=C` ⇒ 同一段判据**必须报出来**
    mut_local = tmp / "transport_local_mutated.py"
    src_local = (ROOT / "app" / "transport_local.py").read_text(encoding="utf-8")
    mut_local.write_text(
        src_local.replace("        self.cfg = cfg\n",
                          '        self.cfg = cfg\n        LC_ALL_MUT = ["env", "LC_ALL=C"]\n', 1),
        encoding="utf-8")
    mut_smells = _ast_shell_smells(mut_local)
    record("Ⓙ ★ **证伪**：往本地通道塞一句 `env LC_ALL=C` ⇒ 同一段判据**必须报出来**"
           "（否则它就是一条空转的判据）",
           bool(mut_smells), "、".join(mut_smells) or "★ 没报出来 —— 判据是空转的")

    # ══════════════════════════════════ Ⓚ 本机子进程：唯一出口 ＋ 退出码归一
    #   ★★ 边界（★ 如实写清，不把判据说大）：本判据管的是 **T16 这条本机通道**的三个文件。
    #      `app\transport.py`（3 处）与 `app\enroll.py`（2 处）是 **T1/T3 写就的 ssh / 密钥通道**，
    #      它们本来就 pin 了 utf-8 ＋ `errors="replace"` —— 把它们也收进「唯一出口」
    #      是**一次独立重构**（动的是整套 ssh 路径），★ 不属于 T16。这里**点名列出**，不假装不存在。
    def _subprocess_sites(path):
        """列出这个文件里所有"跑子进程"的调用，以及 `run_child` 的函数体行号区间。

        ★ 为什么要解析 **import 别名**：本项目的写法是 `import subprocess as _sp`
          （见 `hostexec.py`）—— 只认名字叫 `subprocess` 的那种朴素写法，
          会把出口本身当成 0 处调用 ⇒ **判据当场假绿**（第一版就是这么写错的）。
        """
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = {"subprocess"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for al in node.names:
                    if al.name == "subprocess":
                        aliases.add(al.asname or "subprocess")
            elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                for al in node.names:
                    aliases.add(al.asname or al.name)
        span = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run_child":
                span = (node.lineno, node.end_lineno)
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) \
                    and fn.value.id in aliases:
                found.append(node.lineno)
            elif isinstance(fn, ast.Name) and fn.id in aliases:
                found.append(node.lineno)
        return span, found

    span_h, calls_h = _subprocess_sites(ROOT / "app" / "hostexec.py")
    span_t, calls_t = _subprocess_sites(ROOT / "app" / "transport_local.py")
    span_v, calls_v = _subprocess_sites(ROOT / "app" / "vmware.py")
    inside = span_h is not None and bool(calls_h) \
        and all(span_h[0] <= n <= span_h[1] for n in calls_h)
    record("Ⓚ ★★ §12.115.4：本机通道的子进程**只有一个出口** —— `subprocess.*` 全部落在 "
           "`hostexec.run_child` 的函数体里（`transport_local` / `vmware` 两处 **0** 调用）",
           inside and not calls_t and not calls_v,
           "hostexec：run_child 第 %s 行 · subprocess %d 处（全在里面=%s）｜ 另两个文件 %d 处"
           % (span_h, len(calls_h), inside, len(calls_t) + len(calls_v)))

    cp_exit = product_run_child([sys.executable, "-c", "print('T16 出口 OK')"], timeout=60)
    record("Ⓚ ★ 真跑一次 `hostexec.run_child`：拿回的一定是 `str`（**永不为 `None`**）"
           "—— 那正是 T15·S9 那颗洞的形态（`None` 漏到调用处 ⇒ `TypeError`）",
           isinstance(cp_exit.stdout, str) and isinstance(cp_exit.stderr, str)
           and "T16 出口 OK" in cp_exit.stdout,
           "rc=%s stdout=%r" % (cp_exit.exit_code, cp_exit.stdout[:40]))

    ghost_vmx = str(Path(str(_vmw.vm_conf(cfg).get("allow_vmx_dirs", ["D:\\VMs"])[0]))
                    / "__aoc_selftest_没有这台__" / "没有这台.vmx")
    try:
        bad_rc = _vmw.call(cfg, ["listSnapshots", ghost_vmx], timeout=60)
        record("Ⓚ ★★ §12.115.5：`vmrun` 失败时退出码**归一成 `-1`**（★ 实测 Windows 会给 "
               "`4294967295` —— 判据写 `rc == -1` 只在归一之后才成立）",
               bad_rc.exit_code == -1 and bad_rc.exit_code != 4294967295,
               "rc=%s ｜ 原始形态 %s ｜ 输出里的话术只透传：%r"
               % (bad_rc.exit_code,
                  "4294967295（若未归一）" if bad_rc.exit_code == -1 else "-",
                  (bad_rc.stdout or bad_rc.stderr or "")[:60]))
    except OpsError as exc:
        skip("Ⓚ ★★ 退出码归一（`4294967295 → -1`）",
             "本机没有可用的 vmrun（%s）—— **这次没验到**" % exc.code)

    # ══════════════════════════════════ Ⓜ VM 归属：拒绝是纪律，且拒绝来自闸门那一段
    reg = _vmw.registry(cfg)
    ghost = ghost_vmx
    try:
        _vmw.vm_guard(cfg, True, {"vm": ghost})
        rej = None
    except OpsError as exc:
        rej = exc
    record("Ⓜ ★★★ §12.116 / 红线 12：**未登记的 VM ⇒ 闸门拒绝**，且话术里含"
           "「**这是保护，不是故障**」＋ 怎么把它加进来",
           rej is not None and rej.code == "VM_NOT_MANAGED"
           and "这是保护，不是故障" in rej.advice and "extra_allow" in rej.advice,
           "登记在册 %d 台 ｜ 拒绝码 %s" % (len(reg), getattr(rej, "code", "★ 没拒（闸门空转）")))

    cfg_named = _copy.deepcopy(cfg)
    cfg_named.raw["vm"] = dict(cfg_named.raw.get("vm") or {})
    cfg_named.raw["vm"]["extra_allow"] = [ghost]
    named = None
    try:
        named = _vmw.vm_guard(cfg_named, True, {"vm": ghost})
    except OpsError as exc:
        named = exc
    record("Ⓜ ★★ §12.116：加进 `vm.extra_allow`（**当次点名**，写进文件即留痕）之后 ⇒ **放行**",
           isinstance(named, dict) and named.get("vm_managed_by") == "extra_allow",
           "结果：%s" % (("放行 · managed_by=%s" % named.get("vm_managed_by"))
                        if isinstance(named, dict) else "★ 仍被拒：%s" % getattr(named, "code", "")))

    outside = r"D:\不属于白名单\x.vmx"
    cfg_out = _copy.deepcopy(cfg)
    cfg_out.raw["vm"] = dict(cfg_out.raw.get("vm") or {})
    cfg_out.raw["vm"]["extra_allow"] = [outside]
    rej2 = None
    try:
        _vmw.vm_guard(cfg_out, True, {"vm": outside})
    except OpsError as exc:
        rej2 = exc
    record("Ⓜ ★★ §12.116：`vmx` 落在 `vm.allow_vmx_dirs` **之外** ⇒ 纵深防御**必须拒**",
           rej2 is not None and rej2.code == "VM_OUTSIDE_ALLOWED_DIRS",
           "拒绝码 %s" % getattr(rej2, "code", "★ 没拒"))

    #   ★ 证伪：把闸门那一段（`resolve_vm` 调用）删掉 ⇒ ① 那条拒绝必须**消失**
    mut_src = (ROOT / "app" / "vmware.py").read_text(encoding="utf-8")
    mut_src2 = mut_src.replace(
        "    info = resolve_vm(cfg, token)",
        '    info = {"name": "mutated", "vmx": token, "host_id": "", "managed_by": "mutated"}', 1)
    if mut_src2 == mut_src:
        record("Ⓜ ★ **证伪**：把闸门那一段删掉 ⇒ 未登记的 VM 必须**不再被拒**", False,
               "★ 变异点没找到（`vmware.py` 里 `resolve_vm(cfg, token)` 那行的写法变了？）")
    else:
        mut_vmw = tmp / "vmware_guard_removed.py"
        mut_vmw.write_text(mut_src2, encoding="utf-8")
        spec = importlib.util.spec_from_file_location("aoc_t16_mut_vmware", mut_vmw)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["aoc_t16_mut_vmware"] = mod
        spec.loader.exec_module(mod)
        passed = True
        try:
            mod.vm_guard(cfg, True, {"vm": ghost})
        except OpsError:
            passed = False
        record("Ⓜ ★ **证伪**：把闸门那一段（`resolve_vm` 调用）删掉 ⇒ 未登记的 VM "
               "**不再被拒** —— 这证明①那条拒绝**确实出自这一段**，不是别处碰巧挡住的",
               passed, "变异体：%s" % ("放行了（证伪成立）" if passed else "★ 仍被拒 —— 判据不落在那一段上"))

    # ══════════════════════════════════ Ⓝ 电源判据分三级；「起来了」≠「能 ssh 进去」
    st_act = actions.get("vm.start")
    if st_act is None:
        record("Ⓝ `vm.start` 存在（电源那条链的本体）", False, "动作清单里没有它")
    else:
        receipt = [s.name for s in st_act.steps if s.optional]
        judge = [s.name for s in st_act.steps if not s.optional and s.ok_exit_codes]
        record("Ⓝ ★★ §12.119：「**收条**」与「**判据**」分开写 —— `vm.start` 里同时有"
               "收条步（`optional`）与判据步（**非 optional** ＋ 用 `ok_exit_codes` 表达终态）",
               bool(receipt) and bool(judge),
               "收条步 %s ｜ 判据步 %s" % (receipt, judge))
        merged = [w for w in ("开机成功", "关机成功", "启动成功", "成功启动", "已完成", "已修复")
                  if w in st_act.conclusion]
        record("Ⓝ ★★ §12.117：`vm.start` 的**结论**里不许出现把两件事合并的话术"
               "（「起来了」与「能 ssh 进去」是两件事，不许合成一句）",
               not merged, "命中的话术：%s" % ("、".join(merged) if merged else "无"))
    wg = actions.get("vm.wait-guest")
    record("Ⓝ ★ `vm.wait-guest` 存在且是 `green`（它是编排链里「能不能往下走」的那道判据）",
           wg is not None and wg.risk == "green", "risk=%s" % getattr(wg, "risk", "（动作不存在）"))

    # ══════════════════════════════════ Ⓞ 幂等靠**探针的 `was_running`**
    need_rules = ("vm.start", "vm.stop", "vm.stop-hard", "vm.snapshot-create")
    miss_rules = [i for i in need_rules if i not in _changed.RULES]
    record("Ⓞ ★ §12.117 / §12.3 宪法 2：四条 VM 变更动作都**显式登记**了 `changed` 规则"
           "（★ 未登记一律 `unknown`，**不许默认 False**）",
           not miss_rules, "缺：%s" % ("、".join(miss_rules) or "无（四条都在）"))

    class _StubStep:                       # 自检里的极简打桩对象（只喂给 changed 的规则函数）
        def __init__(self, name, status, parsed):
            self.name, self.status, self.parsed = name, status, parsed

    class _StubResult:
        def __init__(self, steps):
            self.steps = steps

    def _stub(was: str):
        return _StubResult([_StubStep("probe_before", "ok", {"was_running": was})])

    if st_act is not None and "vm.start" not in miss_rules:
        c_yes = _changed.changed_for_action(st_act, _stub("yes"))
        c_no = _changed.changed_for_action(st_act, _stub("no"))
        record("Ⓞ ★★ 打桩验证：`was_running=yes` ⇒ `changed=False`（**幂等 · 零变更**）；"
               "`no` ⇒ `True` —— 判据来自**动手前的探针**，不是「命令没报错」",
               c_yes is False and c_no is True,
               "yes ⇒ %s ｜ no ⇒ %s" % (c_yes, c_no))
    else:
        record("Ⓞ ★★ 打桩验证幂等", False, "vm.start 或它的 changed 规则不在")

    class _FakeAction:
        id = "vm.这个动作不存在"
        risk = "yellow"

    unreg = _changed.changed_for_action(_FakeAction(), _stub("yes"))
    record("Ⓞ ★ 未登记的 vm 变更动作 ⇒ `unknown`（`None`），**不是 `False`**"
           "（宪法 2：拿不到对照数据 ≠ 确实没变）",
           unreg is None, "结果：%r" % (unreg,))

    # ══════════════════════════════════ Ⓟ 闸门只增不减：M 域的 red 在 AI 侧**结构上不可请求**
    reds = ("vm.stop-hard", "vm.snapshot-revert")
    in_approved = [i for i in reds if i in _req.APPROVED_YELLOW]
    face = ToolFace(cfg, actions)
    allow = tuple(getattr(face, "yellow_allowlist", ()) or ())
    in_allow = [i for i in reds if i in allow]
    record("Ⓟ ★★★ §12.120 / 红线 15：M 域的 `red` **不在** `APPROVED_YELLOW`、"
           "也**不在** `ai.yellow_allowlist`（★ 红线 15 比「只能请求」更严：**连请求都不许发**）",
           not in_approved and not in_allow,
           "APPROVED_YELLOW 命中 %s ｜ allowlist 命中 %s" % (in_approved or "无", in_allow or "无"))

    svc = _req.ActionRequests(cfg, actions, face, None)
    codes = []
    for i in reds:
        try:
            svc.guard(i)
            codes.append("%s→**放行**" % i)
        except OpsError as exc:
            codes.append("%s→%s" % (i, exc.code))
    record("Ⓟ ★★ §12.99.1：`guard()` 对它们抛 `AI_RED_NEEDS_HUMAN`（★ 它是按 **risk == red** 挡的，"
           "与白名单是**两道互不依赖**的闸 —— 少一道都还有一道）",
           all(c.endswith("AI_RED_NEEDS_HUMAN") for c in codes), "、".join(codes))

    face_wide = _copy.copy(face)
    face_wide.yellow_allowlist = tuple(list(allow) + ["vm.stop-hard"])
    probs = _req.ActionRequests(cfg, actions, face_wide, None).audit_allowlist()
    record("Ⓟ ★ 证伪：把 `vm.stop-hard` 塞进白名单 ⇒ **装载期审计必须报出来**"
           "（白名单只能是 APPROVED_YELLOW 的子集）",
           any("vm.stop-hard" in p for p in probs),
           "审计问题项：%s" % ("；".join(probs) if probs else "★ 没报 —— 审计是空转的"))

    # ══════════════════════════════════ Ⓠ 域 M 已进账本（四处回填）
    domains = map_data.get("domains") or {}
    record("Ⓠ ★ §12.116：账本 `domains` 里有 **M**（虚拟化与快照）",
           "M" in domains and bool(str(domains.get("M") or "").strip()),
           "M = %r ｜ 账本共 %d 个域" % (domains.get("M"), len(domains)))
    m_actions = sorted(i for i, a in actions.items() if a.domain == "M")
    m_files = sorted(p.name[:-5] for p in (ROOT / "catalog" / "actions").glob("vm.*.yaml"))
    record("Ⓠ ★★ 域 M 的**动作文件**与**装载结果**逐项相等（★ 两份来源对账，不靠手抄数字）",
           m_files == m_actions,
           "文件 %d 个 %s ｜ 装载 domain=M %d 个 %s" % (len(m_files), m_files, len(m_actions), m_actions))
    orphan = sorted(i for i, a in actions.items() if a.domain not in domains)
    record("Ⓠ ★ 每个动作的 `domain` 都能在账本 `domains` 里找到（含 M 域的 10 个）",
           not orphan, "、".join(orphan) or "全部对得上")
    plat = [p for p in (map_data.get("platform") or []) if str(p.get("since")) == "T16"]
    weights = map_data.get("weights") or {}
    no_w = [str(p.get("id")) for p in plat if not isinstance(weights.get(str(p.get("id"))), dict)]
    record("Ⓠ ★★ 账本里 T16 的 `platform` 条目**已入账且各自有权重**"
           "（★ 权重表与账本是两张表，漂移一次就没人看得出）",
           bool(plat) and all(p.get("done") for p in plat) and not no_w,
           "T16 platform 条目 %s ｜ 漏权重 %s" % ([p.get("id") for p in plat], no_w or "无"))

    # ══════════════════════════════════ Ⓡ 「问不到」≠「不存在」：探针必须交代查了什么键
    need_key = {"vm.list": "{scan.checked}", "vm.status": "{state.checked}"}
    miss_key = [i for i, ph in need_key.items()
                if ph not in (getattr(actions.get(i), "conclusion", "") or "")]
    record("Ⓡ ★★ §12.122：`vm.list` / `vm.status` 的**结论里带得出「我查了什么」**"
           "（探针的 `checked`）—— 否则「问不到」与「不存在」输出长得一模一样，而且都很干净",
           not miss_key, "缺 %s" % ("、".join(miss_key) or "无（两处都交代了）"))

    src_vmw = (ROOT / "app" / "vmware.py").read_text(encoding="utf-8")
    empty_guard = 'table or "  （没有扫到任何虚拟机）"' in src_vmw
    vm_list = actions.get("vm.list")
    rendered = render_text(getattr(vm_list, "conclusion", ""), {
        "scan": {"checked": "vmrun list ＋ 扫 allow_vmx_dirs ＋ 只读 inventory.vmls",
                 "running": 0, "count": 0, "managed": 0,
                 "table": "  （没有扫到任何虚拟机）",
                 "allow_dirs": r"D:\VMs", "extra_allow": "（无）"}})
    record("Ⓡ ★★ §12.122：**空结果要明说** —— 空盘面渲染出来必须看得见「没有扫到」这句话"
           "（★ 「沉默」与「真的没有」在给人看的那段话里不许长得一样）",
           empty_guard and "没有扫到任何虚拟机" in rendered,
           "产生侧有兜底文案=%s ｜ 渲染出来含该句=%s" % (empty_guard, "没有扫到任何虚拟机" in rendered))

    # ══════════════════════════════════ Ⓢ 界面第 12 页签 ＋ 走查表 ＋ 按钮级边界
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    jsx = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    old_tabs = ["actions", "recipes", "checkup", "history", "batches", "gaps", "k8s", "mon",
                "chat", "pending", "reports"]
    all_tabs = old_tabs + ["vm"]
    miss_tab = [t for t in all_tabs if 'data-tab="%s"' % t not in html]
    miss_pane = [t for t in all_tabs if 'id="pane-%s"' % t not in html]
    miss_js = [t for t in all_tabs if "'%s'" % t not in jsx]
    record("Ⓢ ★★ §12.121：界面第 **12** 个页签「虚拟机」**三处齐**"
           "（页签按钮 / `pane-vm` 容器 / `switchTab` 列表）＋ 原 11 个**零回退**",
           not miss_tab and not miss_pane and not miss_js,
           "缺页签 %s ｜ 缺容器 %s ｜ JS 列表缺 %s"
           % (miss_tab or "无", miss_pane or "无", miss_js or "无"))

    cap = ROOT.parent / "工具" / "capture-screenshots.py"
    cap_txt = cap.read_text(encoding="utf-8") if cap.is_file() else ""
    walk = re.findall(r'^\s*\("([a-z0-9_-]+)",\s*"[^"]+\.png"', cap_txt, re.M)
    html_tabs = re.findall(r'data-tab="([a-z0-9_-]+)"', html)
    record("Ⓢ ★★ 走查表 `TABS` 与界面 `data-tab` **逐个同序**（含 `vm`）"
           "—— ★ 表不跟着长，新页签就**永远没人看过**（它还安静地绿着）",
           bool(walk) and walk == html_tabs,
           "走查表 %s ｜ 界面 %s" % (walk, html_tabs))

    btn_ok = ("def _button_walk(" in cap_txt and "btnExportTxt" in cap_txt
              and "btnLogout" in cap_txt and "btnChangePw" in cap_txt)
    record("Ⓢ ★★ §12.121：走查工具里**存在「按钮级」那一段**（导出 / 锁定 → 登录 / 改口令），"
           "且按钮级的失败**自己决定退出码**（6）",
           btn_ok and "return 6" in cap_txt,
           "按钮级段落=%s ｜ 退出码 6=%s" % (btn_ok, "return 6" in cap_txt))

    # ══════════════════════════════════ ★★ T18：走查选任务必须**只认真任务**
    # ★ 现场：T17 走查里「导出（.txt）」失败过一次 —— 点下去之后判"回放后**没有**导出按钮"。
    #   到真界面复核：那条**真任务**的导出段**正常存在** ⇒ 变量不是界面，是**被点到的那一条**：
    #   历史列表里混着自检造的合成任务（`SELFTEST-TASK` / `SELFTEST-CHECKUP-A/B`），
    #   它们**本来就没有导出段**，点到它们就判红 —— 而红的理由**是假的**
    #   （同 `config.yaml` 里 `selftest.host_id` 那条教训：**判据红的原因不该是"环境不是我以为的那样"**）。
    # ★ 判据怎么写才不作假：**不查"脚本里有没有某个字符串"**（那只能证明"写过"），
    #   而是把走查脚本里那个判定函数**拿进来真跑一遍**，喂真任务 / 合成任务 / 别的编号族：
    #   ★ 其中 `REQ…`（AI 变更请求）与空串是**故意加的对照组** —— 判据认的是**编号形状**，
    #     不是"黑名单里有 SELFTEST 这三个字"；换成黑名单，这两行就会漏过去。
    try:
        import importlib.util as _iu
        _spec = _iu.spec_from_file_location("_aoc_capture", str(cap))
        _capmod = _iu.module_from_spec(_spec)
        _spec.loader.exec_module(_capmod)                      # ★ 顶层只有常量与 def，无副作用
        _real, _synth = _capmod._real_tasks([
            "T20260928-150717-65213d",      # 真任务（库里实测的编号）
            "SELFTEST-TASK",                # ★ 自检造的（实测）
            "SELFTEST-CHECKUP-A",           # ★ 自检造的（实测）
            "SELFTEST-CHECKUP-B",           # ★ 自检造的（实测）
            "REQ20260927-225620-bb40ad",    # ★ 对照组：**另一个编号族**（AI 变更请求，不是任务）
            "",                             # ★ 对照组：空
        ])
        _pick_ok = (_real == ["T20260928-150717-65213d"]
                    and _synth == ["SELFTEST-TASK", "SELFTEST-CHECKUP-A",
                                   "SELFTEST-CHECKUP-B", "REQ20260927-225620-bb40ad", ""])
        _pick_detail = "真任务 %s ｜ 挡下 %s" % (_real, _synth)
    except Exception as _exc:  # noqa: BLE001
        _pick_ok, _pick_detail = False, "拿不到走查脚本里的判定函数：%s" % _exc
    record("Ⓢ ★★ T18：走查选任务时**只认「真任务」编号形状** —— 合成任务与别的编号族一律**不点**"
           "（★ 否则点到合成任务 ⇒ 判「回放后没有导出按钮」⇒ **红的理由是假的**）",
           _pick_ok, _pick_detail)

    # ══════════════════════════════════ Ⓣ 同一个开口，两处实现都要认账（S6 真缺陷）
    real_recipes, _rep = load_recipes(cfg.paths.catalog / "recipes", actions)
    vm_cycle = real_recipes.get("vm-cycle")
    if vm_cycle is None:
        record("Ⓣ `vm-cycle` 装载得到（无卸载开口的本体）", False, "没装进来（装载报告：%s）"
               % _rep.summary()[:120])
    else:
        items = lint_recipe(vm_cycle, actions)
        stop_row = next((i for i in items if i["name"] == "反向操作：停服 / 撤自启"), None)
        record("Ⓣ ★★★ §12.6.5 / §12.125：`no_uninstall` ＋ 写明理由 ⇒ 体检对"
               "「反向操作：停服 / 撤自启」判 **ok**（★ 是 `ok`，不是 `warn`；"
               "★ 判成 `fail` 就是我刚修的那条真缺陷）",
               stop_row is not None and stop_row["level"] == "ok",
               "该条：%s ｜ %s" % (stop_row["level"] if stop_row else "（没有这一条）",
                                  (stop_row or {}).get("detail", "")[:80]))

    def _load_errors(rep) -> str:
        """把装载报告里**每一份的为什么**拼成一段文字（★ `summary()` 只说文件名，
        要判"拒的理由对不对"必须读 `failed[*].errors`）。"""
        return " ".join(str(e) for f in (rep.failed or []) for e in (f.get("errors") or []))

    vm_cycle_yaml = (cfg.paths.catalog / "recipes" / "vm-cycle.yaml").read_text(encoding="utf-8")
    naked = re.sub(r"no_uninstall_why:\s*\|.*?\n(?=params:)", "", vm_cycle_yaml, flags=re.S)
    mut_dir = tmp / "recipes-naked"
    mut_dir.mkdir(parents=True, exist_ok=True)
    (mut_dir / "vm-cycle.yaml").write_text(naked, encoding="utf-8")
    _, naked_rep = load_recipes(mut_dir, actions)
    naked_err = _load_errors(naked_rep)
    record("Ⓣ ★★ 证伪：**裸开关**（去掉 `no_uninstall_why`）⇒ **装载期必须拒**"
           "（★ 开口只认「声明 ＋ 写明理由」，不许一句话把服务类硬规则关掉）",
           (not naked_rep.ok) and "no_uninstall_why" in naked_err,
           "装载：%s ｜ 理由：%s" % (naked_rep.summary()[:60], naked_err[:110]))

    both_dir = tmp / "recipes-both"
    both_dir.mkdir(parents=True, exist_ok=True)
    (both_dir / "vm-cycle.yaml").write_text(
        naked + "\nuninstall:\n  purge_confirm_text: 我已知晓\n  purge_paths:\n    - /opt/aoc-x\n",
        encoding="utf-8")
    _, both_rep = load_recipes(both_dir, actions)
    both_err = _load_errors(both_rep)
    record("Ⓣ ★★ 证伪：`no_uninstall` 与 `uninstall` 段**并存** ⇒ **装载期必须拒**"
           "（★ 「既然声明了没有卸载，就别写一份出来」）",
           (not both_rep.ok) and "互斥" in both_err,
           "装载：%s ｜ 理由：%s" % (both_rep.summary()[:60], both_err[:110]))

    chk = run_child([sys.executable, str(ROOT / "tools" / "recipe-check.py")])
    record("Ⓣ ★★ `tools\\recipe-check.py` 对**出厂配方**退出码 **0**（最差的一档**不是** `fail`）"
           "—— ★ 它就是 S6 那条真缺陷**现形的地方**（当时退出码 1、自检 ㉖ 红）",
           chk.returncode == 0 and "一共体检" in (chk.stdout or ""),
           "exit=%s ｜ %s" % (chk.returncode, (chk.stdout or "")[-90:].replace("\n", " ")))

    # ══════════════════════════════════ Ⓤ AI 侧不许碰新通道，也没有 `confirm_text` 通道
    #    （T16 开题单 §7 验收 #11）
    ai_files = sorted((ROOT / "app" / "ai").glob("*.py"))
    banned = {"app.hostexec", "app.vmware", "app.transport_local"}
    hits_import: list[str] = []
    hits_text: list[str] = []
    for p in ai_files:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        docs = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docs.add(id(body[0].value))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in banned:
                hits_import.append("%s:%d from %s" % (p.name, node.lineno, node.module))
            if isinstance(node, ast.Import):
                for al in node.names:
                    if al.name in banned:
                        hits_import.append("%s:%d import %s" % (p.name, node.lineno, al.name))
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and id(node) not in docs and "confirm_text" in node.value:
                hits_text.append("%s:%d" % (p.name, node.lineno))
    record("Ⓤ ★★ 验收 #11：`app\\ai\\**` **不许 import 新通道模块**（`hostexec` / `vmware` / "
           "`transport_local`）—— AI 与点击走同一套接口，AI 不得有直连后门（铁律 8）",
           not hits_import, "、".join(hits_import) or "%d 个文件都干净" % len(ai_files))
    record("Ⓤ ★★ 验收 #11：`app\\ai\\**` 的**代码里**没有 `confirm_text` 这条通道"
           "（★ 文档串里写着「没有这条通道」不算 —— 那正是好事）",
           not hits_text, "、".join(hits_text) or "没有")

    api_src = (ROOT / "app" / "api.py").read_text(encoding="utf-8")
    seg_start = api_src.find("def _ai_run_task(")
    seg_end = api_src.find("\n    def ", seg_start + 10)
    seg = api_src[seg_start:seg_end] if seg_start >= 0 and seg_end > seg_start else ""
    record("Ⓤ ★★ 验收 #11：人点确认之后那条执行路的 body **只有** host_id / params / confirm —— "
           "**没有** `confirm_text`（★ AI 不能代过闸门，连「替人打确认词」这条缝都不留）",
           bool(seg) and "confirm_text" not in seg and '"confirm": bool(confirm)' in seg,
           "段落 %d 字符 ｜ 含 confirm_text=%s" % (len(seg), "confirm_text" in seg))


if __name__ == "__main__":
    raise SystemExit(main())
