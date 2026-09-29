"""输出解析器。

设计口径（开题单技术要求 #3「不要解析人类可读输出」）：
  优先用**结构化来源**：`--output=json`、`-p KEY`（属性）、`/proc/*`、`KEY=VALUE` 契约文件。
  只有当输出格式被发行版版本锁死、且无结构化替代时，才写专用解析器（如 free_m），
  并必须在动作 YAML 的 note 里写明理由。

  反例：RHEL/Rocky 10 的 dnf 已换成 DNF5，**人读**输出格式变过 —— 所以 dnf 一律用
  `--json` / `rpm -qa` 之类的结构化源，绝不解析它的表格输出。
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any

from app.errors import OpsError

PARSERS = (
    "raw", "lines", "line_count",
    "shell_kv", "colon_kv", "space_list", "json", "free_m",
    # ↓ T2 新增（规范 v1.1）：动作层**禁止管道**，于是"排序 / 展平 / 取 TOP N"无处可放 ——
    #   若不收进解析器，「目录体积排行」「大文件排行」「端口→进程→归属服务」只能给原始表格，
    #   违背 T2 的核心验收「一次给全结论」。故按 §3 的判断标准（格式是否被版本锁死 +
    #   是否有结构化替代）逐条评估后加入，理由写在每个函数上方。
    "df_rows", "du_rows", "find_rows", "ss_rows", "ip_addr", "head_lines",
    # ↓ T7·S7 新增（规范 §12.23）：`sshd -T` 那份「指令名 值」（**空格分隔**）的输出 ——
    #   三条判定同时成立才加它，理由见 `_space_kv` 的 docstring 与规范 §12.23。
    "space_kv",
    # ↓ T9·S2/S3 新增（规范 §12.39.5）：把 `kubectl get pods -A -o json` 变成**成因清单** ——
    #   ★ 本话题唯一一处平台代码扩展，三条判定（格式锁死 / 无结构化替代 / 换命令绕不开）
    #   写在 `app/k8s_diag.py` 的模块 docstring 与规范 §12.39.5 里。
    #   ★ 它**不是第二个判定中心**：只做"解释"，动作成败仍由 `verify` 决定。
    "k8s_diag",
)


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def _shell_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = _strip_quotes(v)
    return out


def _colon_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def _space_kv(text: str) -> dict[str, str]:
    """`指令名 值`（**空格分隔**）的契约型输出 —— 目前唯一的使用者是 `sshd -T`（T7·S7 · 规范 §12.23）。

    ★ 为什么**必须**为它单独写一个解析器（§5 的三条判定，逐条对照）：
      ① **格式被版本锁死**：`sshd -T` 打的就是 OpenSSH 自己那套「指令名 + 值」，
         从 7.x 到 10.x 没变过，并且它**没有** `--json` 之类的结构化替代；
      ② **没有更结构化的来源**：`/etc/ssh/sshd_config` 是"**写没写**"，
         而我们要判的是"**最终生效什么**"（OpenSSH 的默认值 + `Include` 进来的那些文件
         合起来才是生效值）—— 只有 `sshd -T` 能回答；
      ③ **动作层禁止管道** ⇒ "把关心的那几行 grep 出来"这条路走不通，只能在解析器里挑。
      ⇒ 三条同时成立，属于 §5 说的"**格式被锁死且无结构化替代**"的少数合理例外。

    ★ 口径（写清楚，免得后人误用）：
      · **第一个空白之前是键**，之后（**含空格**）是值 ——
        例：`subsystem sftp /usr/libexec/openssh/sftp-server` ⇒ 键 `subsystem`、值 `sftp /usr/...`；
      · 空行、以 `#` 开头的行**跳过**；
      · ★ **重复键只保留最后一次**出现的值。`sshd -T` 里绝大多数键唯一，但
        `acceptenv` / `hostkey` 这类**可重复**的键会因此丢信息
        ⇒ **不要拿它去数这种键**（要数就用 `lines` / `line_count`）。
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        out[parts[0]] = parts[1].strip() if len(parts) > 1 else ""
    return out


def _free_m(text: str) -> dict[str, Any]:
    """`free -m` 专用解析器。

    存在的理由：free 属 procps-ng，其输出列在 RHEL 8/9/10 上稳定且被大量脚本依赖；
    单位固定为 MB（因为加了 -m）。这是"格式被版本锁死"的少数合理例外。
    """
    rows: dict[str, dict[str, int]] = {}
    header: list[str] = []
    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        if parts[0].lower() == "total":          # 表头行
            # ★ 表头要包含 parts[0]（就是 "total" 列本身）。
            #   T1 期间这里写成 parts[1:]，把 total 列吃掉了，
            #   导致 Mem/Swap 的每一列整体左移一格（已用显示成总量、总量变成（无））。
            header = [p.lower().replace("/", "_") for p in parts]
            continue
        if not header:
            continue
        # ★ 标签**保持原样大小写**（Mem / Swap），只去掉行尾冒号。
        #   T1 期间这里曾多写了一个 .lower()，导致产出 key 变成 "mem"，
        #   而动作 YAML 引用的是 {mem.Mem.total} —— 全部取不到值，
        #   又一次被 verify 断言拦下（"必须读到内存"不通过）。
        label = parts[0].rstrip(":")
        vals: dict[str, int] = {}
        for i, cell in enumerate(parts[1:]):
            if i >= len(header):
                break
            try:
                vals[header[i]] = int(cell)
            except ValueError:
                continue
        rows[label] = vals
    if not rows:
        raise OpsError(
            code="STEP_FAILED",
            reason="free -m 的输出无法解析（未识别到 Mem/Swap 行）",
            advice="在目标机手工执行 free -m，确认输出格式；若发行版差异导致格式变化，请反馈以调整解析器。",
        )
    return {"unit": "MB", **rows}


# ==================================================================== T2 新增（规范 v1.1）
#
# 共同约定：
#   · 输入**空文本**（一行都没有）→ 返回空列表。语义是"命令正常跑完，但没有匹配项"
#     （例：过滤某个没人监听的端口、没有超过阈值的文件），这是**结论**，不是故障。
#   · 输入**有行但一行都解析不出来** → 抛 STEP_FAILED（格式变了，必须让人知道）。

TOP_N = 20          # 排行类解析器的默认条数上限
TOP_N_MAX = 500     # 上限：防"把 5000 行糊一屏"（真实需求都是几十行）


def _resolve_top(arg: Any) -> int:
    """把动作层传来的 `parser_arg` 变成一个可用的条数（T4 · 规范 §10.5）。

    ★ 起因：`TOP_N` 原本写死 20，用户"看不见第 21 个"。现在动作 YAML 可以声明
      `parser_arg: "{{ top_n }}"`，把显示条数变成参数；不声明就仍是默认 20。
      非法值**不报错、退回默认** —— 它只影响显示条数，不值得让整个动作失败。
    """
    if arg is None or arg == "":
        return TOP_N
    try:
        return max(1, min(int(str(arg).strip()), TOP_N_MAX))
    except (TypeError, ValueError):
        return TOP_N


# ss 行的结构校验（防止"任意 6 个词"被当成套接字）
_SS_PROTO_RE = re.compile(r"^(tcp|udp|sctp|raw|icmp|icmp6|u_str|netlink)[0-9]?$")
_SS_LOCAL_RE = re.compile(r"^.+:(\d+|\*)$")


def _rows_from_lines(text: str, build, what: str, advice: str) -> list[dict[str, Any]]:
    """逐行转换；空输入 → 空列表；有行却全解析失败 → 抛错。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    rows = [r for r in (build(ln) for ln in lines) if r]
    if not rows:
        raise OpsError(code="STEP_FAILED", reason=f"{what} 有输出，但一行都没解析出来", advice=advice)
    return rows


def _top(rows: list[dict[str, Any]], key: str, top: int = TOP_N) -> list[dict[str, Any]]:
    rows.sort(key=lambda r: -int(r.get(key, 0)))
    return rows[:top]


def _df_rows(text: str) -> list[dict[str, Any]]:
    """`df -P` / `df -P -i` → 每个挂载点一条记录。

    存在的理由：df 属 coreutils，`-P` 是 POSIX 规定的**可移植输出格式**（固定 6 列、不折行），
    比默认格式稳定（默认格式会为长设备名折行，那才是真正的"人读格式"）；且 df 没有 JSON 替代。
    两种表头通过首行的 `Inodes` 区分（普通用量 / inode 用量），产出不同字段名。
    容量列单位随 `-P` 固定为 1024 字节块 → 换算 MB 时除 1024。

    尾部处理：`Mounted on` 可能含空格（如 /mnt/my disk），故按 `split(None, 5)` 切前 5 列，
    剩下的整段就是挂载点。
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise OpsError(
            code="STEP_FAILED",
            reason="df 没有任何输出",
            advice="手工执行 df -P 对照；若命令不存在，用「包搜索」查哪个包提供它（coreutils）。",
        )
    inode_mode = "Inodes" in lines[0].split()
    rows: list[dict[str, Any]] = []
    for raw in lines[1:]:
        parts = raw.split(None, 5)
        if len(parts) < 6:
            continue
        fs, c1, c2, c3, pcent, mount = parts
        try:
            n1, n2, n3 = int(c1), int(c2), int(c3)
        except ValueError:
            continue
        if inode_mode:
            rows.append({"fs": fs, "inodes": n1, "iused": n2, "ifree": n3,
                         "ipcent": pcent, "mount": mount})
        else:
            rows.append({"fs": fs, "size_mb": n1 // 1024, "used_mb": n2 // 1024,
                         "avail_mb": n3 // 1024, "pcent": pcent, "mount": mount})
    if not rows:
        raise OpsError(
            code="STEP_FAILED",
            reason="df 输出无法解析（未识别到任何文件系统行）",
            advice="手工执行 df -P，确认输出仍是 POSIX 的固定 6 列格式。",
        )
    return rows


def _du_rows(text: str, top: int = TOP_N) -> list[dict[str, Any]]:
    """`du -m` 输出（`SIZE<TAB>PATH`）→ 按体积**降序**、取前 top 条。

    ★ 为什么排序放在解析器里：规范 §4 禁止 run 里出现管道，`du | sort -rn | head` 无处可放；
      而"体积排行"正是这条动作的价值（不给排行就只是又一张原始表格）。
      排序属于**格式转换的收尾**，不是业务判断，故收敛在此，并在动作 note 里标注。
      单位由 `-m` 固定为 MB。
    """
    def build(line: str) -> dict[str, Any] | None:
        size, _, path = line.partition("\t")
        if not path:
            parts = line.split(None, 1)
            if len(parts) < 2:
                return None
            size, path = parts
        try:
            mb = int(size)
        except ValueError:
            return None
        return {"size_mb": mb, "path": path.strip()}

    rows = _rows_from_lines(
        text, build, "du",
        "手工执行 du -x -m --max-depth=1 <路径> 对照；确认用了 -m（MB 单位）与制表符分隔。",
    )
    # 丢掉 0MB 的行：`du -m` 是整数 MB，空目录/微小目录一律算 0 ——
    # 在"体积排行"里这些行没有信息量（实测 /var 下 18 行里有 11 行是 0），
    # 会把真正的大户挤下去。想连空目录一起看，用 depth=2 往下钻。
    rows = [r for r in rows if int(r.get("size_mb", 0)) > 0]
    return _top(rows, "size_mb", top)


def _find_rows(text: str, top: int = TOP_N) -> list[dict[str, Any]]:
    """`find -printf '%s\\t%p\\n'` 输出（`字节<TAB>路径`）→ 按体积**降序**、取前 top 条。

    存在的理由同 `du_rows`（排序无处可放）。字节 → MB 在此换算。
    """
    def build(line: str) -> dict[str, Any] | None:
        size, _, path = line.partition("\t")
        if not path:
            parts = line.split(None, 1)
            if len(parts) < 2:
                return None
            size, path = parts
        try:
            nbytes = int(size)
        except ValueError:
            return None
        return {"size_mb": round(nbytes / 1048576, 1), "path": path.strip()}

    rows = _rows_from_lines(
        text, build, "find",
        "手工执行 find <路径> -xdev -type f -size +50M -printf '%s\\t%p\\n' 对照。",
    )
    return _top(rows, "size_mb", top)


def _ss_rows(text: str) -> list[dict[str, Any]]:
    """`ss -H -tulnp` → 每个套接字一条记录（含**进程名 + PID**，这是"端口 → 进程"的落点）。

    存在的理由：ss 没有 JSON / 属性式输出，其 `-H` 列布局（proto state recvq sendq local peer process）
    在 iproute2 中稳定。`-H` 去掉表头正是为了解析。
    进程列形如 `users:(("sshd",pid=1800,fd=7),("systemd",pid=1,fd=173))` —— 取**第一个**（真正的属主进程）。

    ★ 结构校验：只靠"能切出 6 列"不足以判定是套接字行（任意句子都能切成 6 个词）。
      所以额外要求 ① 第一列是已知协议 ② local 列形如 `地址:端口`。
      校验不过的行直接跳过；整段都校验不过 → 报错（说明格式变了）。
    """
    def build(line: str) -> dict[str, Any] | None:
        parts = line.split(None, 6)
        if len(parts) < 6:
            return None
        proto, state, recvq, sendq, local, peer = parts[:6]
        if not _SS_PROTO_RE.match(proto) or not _SS_LOCAL_RE.match(local):
            return None
        rest = parts[6] if len(parts) > 6 else ""
        comm, pid = "", ""
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', rest)
        if m:
            comm, pid = m.group(1), m.group(2)
        else:
            m2 = re.search(r'users:\(\("([^"]+)"', rest)
            if m2:
                comm = m2.group(1)
        return {
            "proto": proto, "state": state, "local": local, "peer": peer,
            "port": local.rsplit(":", 1)[-1],
            "proc": comm or "（无进程信息）",
            "pid": pid,
        }

    return _rows_from_lines(
        text, build, "ss",
        "确认命令带了 -H（不打印表头）与 -t/-u；手工执行 ss -H -tulnp 对照列布局。",
    )


def _ip_addr(text: str) -> list[dict[str, Any]]:
    """`ip -j addr` 的 JSON → 每张网卡一条记录（地址/状态/MTU/MAC 展平）。

    存在的理由：`ip -j` 已经是结构化源（首选），但它的 `addr_info` 是**嵌套列表**，
    直接渲染会变成 Python 字典字面量（不可读）。此解析器只负责"展平 + 拼接"，
    把一张网卡的 IPv4/IPv6 拼成一行，满足「一屏给全」。
    """
    try:
        payload = json.loads(text or "[]")
    except json.JSONDecodeError as exc:
        raise OpsError(
            code="STEP_FAILED",
            reason="期望 JSON 输出，但实际内容不是合法 JSON",
            advice="确认命令带了 -j（ip -j addr）。手工执行对照。",
            detail=str(exc),
        ) from exc
    if not isinstance(payload, list):
        raise OpsError(
            code="STEP_FAILED",
            reason="ip -j addr 的输出不是数组",
            advice="确认目标机 iproute2 版本支持 -j；否则改用 nmcli。",
        )
    rows: list[dict[str, Any]] = []
    for iface in payload:
        if not isinstance(iface, dict):
            continue
        info = iface.get("addr_info") or []
        v4 = [f"{a.get('local')}/{a.get('prefixlen')}"
              for a in info if isinstance(a, dict) and a.get("family") == "inet"]
        v6 = [f"{a.get('local')}/{a.get('prefixlen')}"
              for a in info if isinstance(a, dict) and a.get("family") == "inet6"]
        rows.append({
            "ifname": iface.get("ifname"),
            "state": iface.get("operstate"),
            "mtu": iface.get("mtu"),
            "mac": iface.get("address"),
            "ipv4": "、".join(v4) or "（无）",
            "ipv6": "、".join(v6) or "（无）",
        })
    return rows


_NO_ENTRIES_HINT = "-- No entries --"


def _lines(text: str) -> list[str]:
    """逐行结果（去空行）—— 顺带剔除 journalctl 的 `-- No entries --` 提示行。

    ★ T4 实测：`journalctl -o short-iso` 无匹配时 rc=0，stdout 就是这一行提示；
      它是**提示**不是日志行。不剔除的话，"没有日志"会变成结论里的一行假日志
      （`log.view` 的收窄区实测踩到过）。与 `_line_count` 的剔除是同一条理由。
    """
    return [ln.rstrip() for ln in text.splitlines() if ln.strip() and ln.strip() != _NO_ENTRIES_HINT]


def _line_count(text: str) -> int:
    """数**有意义的**行数。

    ★ T4 修正：`journalctl` 在"没有匹配项"时会往 **stdout** 打一行 `-- No entries --`
      （实测：`journalctl -k -g oom` 无匹配 → rc=1 且 stdout 就是这一行）。
      它是**提示**，不是日志行 —— 直接数行数会把"这段时间没有错误日志"报成"有 1 行"，
      正好把结论说反。所以这里把它排除掉（只在整行等于该提示时排除，不做模糊匹配）。
    """
    return len([ln for ln in text.splitlines() if ln.strip() and ln.strip() != _NO_ENTRIES_HINT])


def _head_lines(text: str, top: int = TOP_N) -> list[str]:
    """取前 top 行非空行；★ **被砍掉时追加一行可判定的截断标记**（T13 · 规范 §12.90.1）。

    存在的理由：`ps` / `pstree` 这类命令**没有**"只输出前 N 条"的选项，而动作层禁止管道
    （`| head` 写不了），于是"截断"无处可放。此解析器**只做截断**，排序交给命令自身的
    `--sort`（如 `ps --sort -pcpu`），不越界做业务判断。

    ★★ T13 改动（**只加可观测性，不改命令、不改判据**）：
      原来被砍掉时**一个字都不说** —— 于是上位（人 / AI / 配方）读到的是「这些就是全部」。
      现在若 `len(lines) > top`，会在末尾追加一条固定形态的标记：
          〔输出已截断：仅显示前 N 行／共 M 行〕
      ⇒ 让"被砍了"这件事**可被观测**（同 §12.45.3「这一屏没有内容 ≠ 这一步没取到」）。
      ★ 副作用（已知、可接受）：凡用 `head_lines` 的动作，被截断时结论会多这一行；
        断言里凡是"非空/条数"类的都不受影响（自检会当场复核）。
    """
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if len(lines) > top:
        shown = lines[:top]
        shown.append("〔输出已截断：仅显示前 %d 行／共 %d 行〕" % (top, len(lines)))
        return shown
    return lines


# ==================================================================== 入口


def parse_text(kind: str, text: str, arg: Any = None) -> Any:
    """按解析器名解析 stdout 文本。

    `arg` 是动作层可选传下来的**解析器参数**（T4 · 规范 §10.5），目前只有"排行/截断类"
    解析器（du_rows / find_rows / head_lines）用它来表示"取前几条"，默认 20。
    其余解析器**忽略**它 —— 这样动作 YAML 多写一个 parser_arg 不会把别的解析器弄坏。
    """
    kind = kind or "raw"
    top = _resolve_top(arg)
    if kind == "raw":
        return text.strip()
    if kind == "lines":
        return _lines(text)
    if kind == "line_count":
        return _line_count(text)
    if kind == "shell_kv":
        return _shell_kv(text)
    if kind == "colon_kv":
        return _colon_kv(text)
    if kind == "space_kv":
        return _space_kv(text)
    if kind == "k8s_diag":
        # ★ 局部导入：解析器层与"成因推导"解耦（规范 §12.39.5 边界 1：它不碰 ssh / 引擎）；
        #   也让 `app.k8s_diag` 能被**离线单独导入**做纯函数断言。
        # ★ `arg`（动作里的 `parser_arg`）用来**选模式**：`pods`（默认）/ `pending`（§12.39.4）。
        from app.k8s_diag import diagnose

        return diagnose(text, arg if isinstance(arg, str) else None)
    if kind == "space_list":
        first = next((l for l in text.splitlines() if l.strip()), "")
        return shlex.split(first)
    if kind == "json":
        s = text.strip()
        if not s:
            return []
        try:
            return json.loads(s)
        except json.JSONDecodeError as exc:
            raise OpsError(
                code="STEP_FAILED",
                reason="期望 JSON 输出，但实际内容不是合法 JSON",
                advice="确认该命令带了 --output=json（或 --json）参数，且目标机版本支持它。",
                detail=f"{exc}\n--- 前 300 字符 ---\n{text[:300]}",
            ) from exc
    if kind == "free_m":
        return _free_m(text)
    if kind == "df_rows":
        return _df_rows(text)
    if kind == "du_rows":
        return _du_rows(text, top)
    if kind == "find_rows":
        return _find_rows(text, top)
    if kind == "ss_rows":
        return _ss_rows(text)
    if kind == "ip_addr":
        return _ip_addr(text)
    if kind == "head_lines":
        return _head_lines(text, top)
    raise OpsError(
        code="CATALOG_INVALID",
        reason=f"未知的解析器：{kind}",
        advice=f"可选值：{', '.join(PARSERS)}",
    )


def apply_pick(value: Any, pick: dict[str, str] | None) -> Any:
    """按 `pick` 从字典里挑字段并改名（避免结论模板里出现带空格/括号的键）。"""
    if not pick or not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for src, dst in pick.items():
        if src in value:
            out[str(dst)] = value[src]
    return out
