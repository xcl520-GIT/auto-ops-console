"""期望判定层（规范 §12.2）：**配方只声明"要什么"，判定只在这里**。

三条硬约束（规范 §12.2，缺一不可）
----------------------------------
1. `expect` 是**恰好一个键**的映射（键 = 本模块白名单里的类型名）；
2. ★ **采集只能引用已登记的动作，不许出现裸命令** ——
   这样 §4 的三层安全契约对配方**依然生效**（配方没法绕过参数白名单去跑命令）；
3. ★ **判定结果三态**：`pass` / `fail` / **`unknown`**。
   `unknown` 既不等于通过、也不等于不通过；`preflight` 里按不通过处理（宁可不做），
   `health` 里判配方 `failed` 并说清"为什么判不了"。

这一层与 `checkup`（§10.2）是同一条路：**采集走动作、判定走平台**。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from app.catalog import ParamValue, render_argv_element
from app.errors import OpsError

#: 采集器协议：(动作 id, 参数) → TaskResult（由配方的编排层注入）
Collector = Callable[[str, dict[str, Any]], Any]

#: ★ 采集链路本身的故障码 —— 这些一律判 `unknown`（不是"期望不成立"，而是"这次问不出来"）。
#:   判据来自 app/transport.py / store.py / errors.py 实际会抛的码。
INFRA_CODES = {
    "HOST_UNREACHABLE", "SSH_AUTH_FAILED", "SSH_HOSTKEY_UNKNOWN", "SSH_TIMEOUT",
    "TOOL_MISSING", "STORE_ERROR", "INTERNAL", "CONFIG_INVALID", "CATALOG_INVALID",
    "PARAM_INVALID", "PARAM_MISSING", "NOT_FOUND",
}

#: 期望类型白名单（规范 §12.2 的表 + v1.7 §12.11 新增 `responds` / `port_open`）
EXPECT_TYPES = ("present", "absent", "free_port", "state", "http_status", "responds", "port_open")


@dataclass(frozen=True)
class PresenceSource:
    """「某物存在吗」这类期望的采集来源（★ 只登记**已登记的动作**）。

    语义：该动作的 `step` 步骤解析结果**非空** ⇔ 这个「东西」存在。
    要加新来源，**先升规范**（规范 §12.2 约束 2），不许在配方里就地发明。
    """

    action: str
    step: str
    arg: str          # 该动作里代表"这个东西"的参数名
    subject: str      # 人话（"软件包"）


#: ★ 存在性来源白名单（规范 §12.2；v1.8 §12.16 增补第二条）。
#:
#:   ① `pkg.installed`：**软件包**在不在（rpm -q 的本地数据库查询）；
#:   ② `file.stat`（T7 新增）：**路径**在不在（ls -ld）。
#:      ★ 为什么必须补这一条：全删的收敛检查要覆盖"包 **和** 路径"两类（规范 §12.16 规矩 3），
#:        而在此之前**没有任何只读动作能回答"这个目录还在不在"** ⇒ 路径那一半只能靠
#:        "删除命令返回 0"来判 —— 那正是 §12.6.5 点名要杜绝的**假绿**。
#:      ★ 它的参数白名单与 `file.remove` **逐字相同**：删得掉的路径一定查得着，
#:        于是"删了没删"不存在盲区。
PRESENCE_SOURCES: dict[str, PresenceSource] = {
    "pkg.installed": PresenceSource(
        action="pkg.installed", step="info", arg="pkg", subject="软件包",
    ),
    "file.stat": PresenceSource(
        # ★ 来源步骤是 `count`（`line_count`：1 = 在、0 = 不在），**不是** `stat`（`raw`）——
        #   因为 `raw` 在"路径不存在"时给的是**空字符串**，而这里判"存在吗"要的正是那个 0。
        #   （T7·S1 真跑抓到的缺陷：拿 `raw` 那一步既当来源又当自证 ⇒ "不存在"被判成 VERIFY_FAILED。）
        action="file.stat", step="count", arg="path", subject="路径",
    ),
}


@dataclass(frozen=True)
class ProbeSource:
    """「**真问一句它活着吗**」这类期望的采集来源（★ 只登记**已登记的动作**）。

    语义：该动作 `step` 步骤的输出，与参照值**精确匹配** ⇔ 这个服务在应答。
    ★ 为什么必须有这一层：`state: active`（单元在跑）与 `free_port`（端口没人听）都只是**旁证**；
      Nginx 有 `http_status` 这个"真问一句"，MariaDB / Valkey / NFS 需要一个等价物（规范 §12.11）。
    要加新来源，**先升规范**（§12.11.3），不许在配方里就地发明。
    """

    action: str
    step: str
    arg: str          # 该动作里代表"问谁"的参数名（用来生成人话）
    subject: str      # 人话（"MariaDB"）


#: ★ 探活动作白名单（规范 §12.11.3）：本话题三个服务各一个，**全部 green（只读）**。
#:   green ⇒ `changed` 恒 false（`app/changed.py` 按 risk 自动判定，不需要逐条登记规则）。
PROBE_SOURCES: dict[str, ProbeSource] = {
    "db.mariadb-ping": ProbeSource(
        action="db.mariadb-ping", step="probe", arg="", subject="MariaDB",
    ),
    "db.valkey-ping": ProbeSource(
        action="db.valkey-ping", step="probe", arg="port", subject="Valkey",
    ),
    "nfs.export-check": ProbeSource(
        action="nfs.export-check", step="probe", arg="", subject="NFS 导出",
    ),
    # ── T8·S5 新增（规范 §12.31.6）：容器运行时的"真探活" ──
    # ★★ 参照值在配方里写的是 `first_field: "Server:"`，**不是版本号** ——
    #   `ctr version` 只有在**守护进程真的应答**时才会多出 `Server:` 段，
    #   那是"API 通了"的结构性事实；而写死版本号就是"包一升级就假红"。
    # ★ 本动作**不判**"我们那份配置被读了没有" —— 那件事落不到链路末端（§12.31.2），
    #   所以本话题压根不去改主配置。镜像来源的验证走 `container.pull`（真拉一次）。
    "container.runtime": ProbeSource(
        action="container.runtime", step="probe", arg="", subject="containerd 运行时",
    ),
    # ── T8·S6 新增（规范 §12.32.5）：集群就绪 —— "判据的家" ──
    # ★★ 参照值**不给算子**（§12.11.2 的第三种形态）：判据由**动作自己的 verify** 承担 ——
    #   `kubectl wait --for=condition=Ready nodes --all` 的**退出码**就是"Ready 了没有"。
    # ★ 为什么这里**不用** `first_field`：`kubectl wait` 的输出形如
    #   `node/node-01 condition met`（多节点时多行），**行首字段是节点名**，
    #   不构成"所有节点都 Ready"的判据 —— 一个 Ready 就够撑起一行。
    #   而**退出码**天然等价于"全部就绪"。★ 又一次：判据选与实现细节无关的那一个。
    "k8s.nodes": ProbeSource(
        action="k8s.nodes", step="ready", arg="", subject="K8s 集群",
    ),
}


@dataclass
class ExpectOutcome:
    kind: str
    state: str                      # pass / fail / unknown
    expected: str
    actual: str = ""
    collect_action: str = ""
    collect_task: str | None = None
    reason: str = ""
    advice: str = ""
    where: str = ""

    @property
    def ok(self) -> bool:
        return self.state == "pass"

    def to_public(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "where": self.where,
            "state": self.state,
            "expected": self.expected,
            "actual": self.actual,
            "collect_action": self.collect_action,
            "collect_task": self.collect_task,
            "reason": self.reason,
            "advice": self.advice,
        }


# ------------------------------------------------------------------ 工具


def _collect(collect: Collector, action_id: str, args: dict[str, Any]) -> tuple[Any, OpsError | None]:
    """跑一次采集动作。异常**不外抛** —— 采集失败要变成 `unknown` 的判据，而不是把配方打崩。"""
    try:
        return collect(action_id, args), None
    except OpsError as exc:
        return None, exc


def _val(result: Any, step: str) -> Any:
    for s in getattr(result, "steps", None) or []:
        if getattr(s, "name", None) == step:
            return getattr(s, "parsed", None)
    return None


def _step(result: Any, step: str) -> Any:
    found = None
    for s in getattr(result, "steps", None) or []:
        if getattr(s, "name", None) == step:
            found = s
    return found


def _task_id(result: Any) -> str | None:
    return getattr(result, "id", None)


def _failed_code(result: Any) -> str | None:
    err = getattr(result, "error", None)
    return getattr(err, "code", None) if err else None


def _failed_reason(result: Any) -> str:
    err = getattr(result, "error", None)
    if not err:
        return ""
    return str(getattr(err, "reason", "") or "")


def _infra_failure(result: Any) -> str | None:
    """采集动作是不是"链路层失败"（→ unknown）？是则返回原因。"""
    if getattr(result, "status", "") == "ok":
        return None
    code = _failed_code(result)
    if code in INFRA_CODES:
        return f"采集链路不可用：{_failed_reason(result) or code}"
    return None


def _render(value: Any, params: dict[str, ParamValue]) -> Any:
    """把期望里的 `{{ 参数 }}` 渲染成实际值（复用与动作层同一个替换实现）。"""
    if isinstance(value, str):
        if "{{" not in value:
            return value
        try:
            return render_argv_element(value, params)
        except OpsError as exc:
            raise OpsError(
                code="RECIPE_INVALID",
                reason=f"期望里引用了未定义的参数：{exc.reason}",
                advice="在配方 params 里定义它，或改正占位符拼写。",
            ) from None
    if isinstance(value, dict):
        return {k: _render(v, params) for k, v in value.items()}
    return value


def _ssh_ok(result: Any) -> bool:
    return getattr(result, "status", "") != "aborted"


# ------------------------------------------------------------------ 各类型判定


def _j_presence(kind: str, value: Any, collect: Collector,
                params: dict[str, ParamValue], where: str) -> ExpectOutcome:
    """`present` / `absent` —— 引用一个**已登记的存在性来源动作**。"""
    want_present = kind == "present"
    spec = _render(value, params)
    action_id = str(spec.get("action") or "")
    src = PRESENCE_SOURCES.get(action_id)
    if src is None:  # 加载期已拦，这里是兜底
        raise OpsError(
            code="RECIPE_INVALID",
            reason=f"「{action_id}」不是已登记的存在性来源",
            advice=f"目前只支持：{'、'.join(PRESENCE_SOURCES)}（要加来源先升规范 §12.2）。",
        )
    args = spec.get("args") or {}
    subject = f"{src.subject}「{args.get(src.arg, '')}」"
    expected = f"{subject} {'存在' if want_present else '不存在'}"

    result, err = _collect(collect, src.action, args)
    task = _task_id(result) if result is not None else None
    if result is None:
        return ExpectOutcome(
            kind=kind, state="unknown", expected=expected,
            collect_action=src.action, collect_task=task, where=where,
            reason=f"采集动作没能执行：{err.reason if err else '未知原因'}",
            advice=err.advice if err else "",
        )
    infra = _infra_failure(result)
    if infra:
        return ExpectOutcome(
            kind=kind, state="unknown", expected=expected, collect_action=src.action,
            collect_task=task, where=where, reason=infra,
            advice="先确认目标机可达、这一步的采集命令可用，再重跑配方。",
        )
    step = _step(result, src.step)
    got = getattr(step, "parsed", None) if step is not None else None
    exists = bool(got)
    detail = ""
    if isinstance(got, dict):
        detail = "、".join(f"{k}={v}" for k, v in list(got.items())[:4])
    actual = ("存在" + (f"（{detail}）" if detail else "")) if exists else "不存在"
    state = "pass" if exists == want_present else "fail"
    return ExpectOutcome(
        kind=kind, state=state, expected=expected, actual=actual,
        collect_action=src.action, collect_task=task, where=where,
        reason="" if state == "pass" else (
            f"{subject}{'已经装过' if want_present else '仍然存在'} —— 与期望{'相反' if want_present else '不符'}"
        ),
        advice="" if state == "pass" else (
            "若这是「不该重复部署」的护栏，说明目标机不是干净状态：先卸载再跑；"
            "若这是「卸载·全删」的收敛检查，说明**还有东西没删掉**，看该步骤对应任务的原始输出。"
        ),
    )


def _j_free_port(kind: str, value: Any, collect: Collector,
                 params: dict[str, ParamValue], where: str) -> ExpectOutcome:
    port = str(_render(value, params)).strip()
    expected = f"端口 {port} 空闲（没有进程在监听）"
    result, err = _collect(collect, "net.port", {"port": port})
    task = _task_id(result) if result is not None else None
    if result is None:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.port", collect_task=task, where=where,
                             reason=f"采集动作没能执行：{err.reason if err else '未知原因'}",
                             advice=err.advice if err else "")
    infra = _infra_failure(result)
    if infra:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.port", collect_task=task, where=where,
                             reason=infra, advice="先确认目标机可达、ss 可用。")
    # ★ 关键区分（规范 §10.6.3「空结果 ≠ 空数据」）：
    #   `ss` 在端口**没人监听**时输出为空（parsed 是 None）—— 那是**结论**（端口空闲），
    #   不是"取不到数据"。所以判据只能是**步骤状态**，绝不能是"值非空"。
    #   （这条是 T5 实地探针在 node-03 上当场撞出来的：8080 明明空闲，却被判成"无法判定"。）
    sstep = _step(result, "sockets")
    if sstep is None or getattr(sstep, "status", None) not in ("ok", "skipped"):
        return ExpectOutcome(
            kind=kind, state="unknown", expected=expected, collect_action="net.port",
            collect_task=task, where=where,
            reason="拿不到监听套接字列表（ss 可能不存在或输出无法解析）",
            advice="先看任务里 sockets 步骤的原始输出。",
        )
    sockets = getattr(sstep, "parsed", None)
    if not sockets:
        return ExpectOutcome(kind=kind, state="pass", expected=expected,
                             actual="没人监听这个端口", collect_action="net.port",
                             collect_task=task, where=where)
    who = []
    for it in (sockets or [])[:5]:
        if isinstance(it, dict):
            who.append(f"{it.get('proto', '?')} {it.get('local', '')} 进程 {it.get('proc') or '?'}(PID {it.get('pid') or '?'})")
    return ExpectOutcome(
        kind=kind, state="fail", expected=expected,
        actual="；".join(who) or "端口已被占用",
        collect_action="net.port", collect_task=task, where=where,
        reason=f"端口 {port} 已被占用 —— 继续部署会撞端口",
        advice="换一个端口，或先停掉占用它的服务（可在「端口占用」动作里看归属服务）。",
    )


def _j_state(kind: str, value: Any, collect: Collector,
             params: dict[str, ParamValue], where: str) -> ExpectOutcome:
    spec = _render(value, params)
    unit = str(spec.get("unit") or "").strip()
    if "." not in unit:
        unit = unit + ".service"
    equals = str(spec.get("equals") or "").strip()
    expected = f"服务 {unit} 处于 {equals}"

    result, err = _collect(collect, "svc.list", {})
    task = _task_id(result) if result is not None else None
    if result is None:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="svc.list", collect_task=task, where=where,
                             reason=f"采集动作没能执行：{err.reason if err else '未知原因'}",
                             advice=err.advice if err else "")
    infra = _infra_failure(result)
    if infra:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="svc.list", collect_task=task, where=where,
                             reason=infra, advice="先确认目标机可达、systemd 可用。")
    loaded = _val(result, "loaded")
    if not isinstance(loaded, list) or not loaded:
        return ExpectOutcome(
            kind=kind, state="unknown", expected=expected, collect_action="svc.list",
            collect_task=task, where=where,
            reason="拿不到 systemd 单元列表（输出为空或无法解析）",
            advice="先看任务里 loaded 步骤的原始输出。",
        )
    hit = None
    for it in loaded:
        if not isinstance(it, dict):
            continue
        name = str(it.get("unit") or it.get("Unit") or it.get("name") or "")
        if name == unit:
            hit = it
            break
    if hit is None:
        return ExpectOutcome(
            kind=kind, state="fail", expected=expected, actual="系统里没有这个服务",
            collect_action="svc.list", collect_task=task, where=where,
            reason=f"单元列表里找不到 {unit}",
            advice="确认服务名拼写（别名/模板单元需要写全名）。",
        )
    actual_state = str(hit.get("active") or hit.get("ActiveState") or hit.get("activestate") or "")
    sub = str(hit.get("sub") or hit.get("SubState") or "")
    state = "pass" if actual_state == equals else "fail"
    return ExpectOutcome(
        kind=kind, state=state, expected=expected,
        actual=f"{actual_state or '（未知）'}" + (f"（{sub}）" if sub else ""),
        collect_action="svc.list", collect_task=task, where=where,
        reason="" if state == "pass" else f"服务 {unit} 当前是 {actual_state or '未知状态'}，不是 {equals}",
        advice="" if state == "pass" else f"先看这个服务的原始状态与日志（可在「服务列表」动作里查 {unit}）。",
    )


def _j_http_status(kind: str, value: Any, collect: Collector,
                   params: dict[str, ParamValue], where: str) -> ExpectOutcome:
    spec = _render(value, params)
    url = str(spec.get("url") or "").strip()
    try:
        equals = int(spec.get("equals"))
    except (TypeError, ValueError):
        raise OpsError(
            code="RECIPE_INVALID",
            reason=f"http_status 的 equals 必须是整数：{spec.get('equals')!r}",
            advice="写 200 这样的响应码。",
        ) from None
    args = {"url": url}
    if spec.get("timeout") is not None:
        args["timeout"] = spec["timeout"]
    expected = f"HTTP 探测 {url} 返回 {equals}"

    result, err = _collect(collect, "net.http", args)
    task = _task_id(result) if result is not None else None
    if result is None:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.http", collect_task=task, where=where,
                             reason=f"采集动作没能执行：{err.reason if err else '未知原因'}",
                             advice=err.advice if err else "")
    if not _ssh_ok(result):
        infra = _infra_failure(result) or "目标机不可达"
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.http", collect_task=task, where=where,
                             reason=infra, advice="先确认目标机可达。")
    # ★ 关键区分：net.http 失败既可能是"工具/链路不行"（unknown），
    #   也可能是"**连不上这个服务**"（那正是健康检查要判的 fail）。
    #   只把链路层故障算 unknown，其余算 fail 并附 curl 的原文。
    infra = _infra_failure(result)
    if infra:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.http", collect_task=task, where=where,
                             reason=infra, advice="先看任务里 probe 步骤的原始输出。")
    probe = _val(result, "probe")
    m = re.search(r"HTTP\s+(\d{3})", str(probe or ""))
    if m:
        code = int(m.group(1))
        # ★ curl 的 `-w %{http_code}` 在**连不上**时给 `000` —— 那不是"HTTP 响应码 0"，
        #   而是"根本没建起连接"。分开说，否则人会去查一个不存在的响应码
        #   （T5 实地探针在 node-03 上看到的正是 "HTTP 000"）。
        if code == 0:
            return ExpectOutcome(
                kind=kind, state="fail", expected=expected,
                actual="连接失败（curl 没能建立连接，http_code=000）",
                collect_action="net.http", collect_task=task, where=where,
                reason="这个端口上没有服务在监听（连接被拒绝 / 超时）",
                advice="先确认服务是否已启动、是否真的在监听该端口（看「服务列表」与「端口占用」）。",
            )
        state = "pass" if code == equals else "fail"
        return ExpectOutcome(
            kind=kind, state=state, expected=expected, actual=f"HTTP {code}",
            collect_action="net.http", collect_task=task, where=where,
            reason="" if state == "pass" else f"响应码 {code} ≠ {equals}",
            advice="" if state == "pass" else "看服务日志与配置（列表页里有「服务状态」与「配置校验」入口）。",
        )
    # 取不到响应码：分两种情况 —— 动作失败（连不上）→ fail；动作成功却没指标 → unknown
    if getattr(result, "status", "") != "ok":
        return ExpectOutcome(
            kind=kind, state="fail", expected=expected,
            actual=f"探测失败：{_failed_reason(result) or '（无原文）'}",
            collect_action="net.http", collect_task=task, where=where,
            reason="服务没有响应（连接被拒绝 / 超时 / 端口没在监听）",
            advice="这一项不通过通常意味着服务没起来或没监听该端口；先看服务状态与端口占用。",
        )
    return ExpectOutcome(
        kind=kind, state="unknown", expected=expected, collect_action="net.http",
        collect_task=task, where=where,
        reason="curl 跑完了，但输出里取不到响应码（格式不符）",
        advice="先看任务里 probe 步骤的原始输出。",
    )


def _lines_of(value: Any) -> list[str]:
    """把探活动作的输出归一成"行列表"（`parser: lines` 给 list，`parser: raw` 给 str）。"""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    return str(value).splitlines()


def _j_responds(kind: str, value: Any, collect: Collector,
                params: dict[str, ParamValue], where: str) -> ExpectOutcome:
    """`responds` —— "真问一句这个服务活着吗"（规范 §12.11）。

    ★ 采集**只允许引用已登记的探活动作**（`PROBE_SOURCES`），所以配方里依然**没有命令**。
    ★ 算子只有两个，且都是**精确匹配**：
      · `equals`      —— 输出（`strip` 后）**整体全等**
      · `first_field` —— 输出中**存在一行**，其按空白切分的**第一个字段全等**
    ★ **明确不做子串匹配**：`"active" in "inactive"` 为真 —— 那叫假绿，不叫通过。
      （两个都不给 ⇒ 只要求"该探活动作报告可用"，判据由动作自己的 `verify` 承担。）
    """
    spec = _render(value, params)
    action_id = str(spec.get("action") or "")
    src = PROBE_SOURCES.get(action_id)
    if src is None:  # 加载期已拦，这里是兜底
        raise OpsError(
            code="RECIPE_INVALID",
            reason=f"「{action_id}」不是已登记的探活动作",
            advice=f"目前只支持：{'、'.join(PROBE_SOURCES)}（要加来源先升规范 §12.11）。",
        )
    args = spec.get("args") or {}
    equals = spec.get("equals")
    first_field = spec.get("first_field")
    if equals is not None and first_field is not None:
        raise OpsError(
            code="RECIPE_INVALID",
            reason=f"{where} 的 responds 只能给 equals 或 first_field 之一（「问一句」只该有一个判据）",
            advice="两个都要判 → 写成两条期望。",
        )
    if equals is not None:
        ref = str(equals).strip()
        expected = f"{src.subject} 的应答等于「{ref}」"
    elif first_field is not None:
        ref = str(first_field).strip()
        expected = f"{src.subject} 的应答里有一行以「{ref}」开头（按字段全等，不是子串）"
    else:
        ref = ""
        expected = f"{src.subject} 应答正常"

    result, err = _collect(collect, src.action, args)
    task = _task_id(result) if result is not None else None
    if result is None:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action=src.action, collect_task=task, where=where,
                             reason=f"采集动作没能执行：{err.reason if err else '未知原因'}",
                             advice=err.advice if err else "")
    infra = _infra_failure(result)
    if infra:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected, collect_action=src.action,
                             collect_task=task, where=where, reason=infra,
                             advice="先确认目标机可达；★ 缺工具（探活程序没装）会降级成「无法判定」，不是通过。")
    if _step(result, src.step) is None:
        return ExpectOutcome(
            kind=kind, state="unknown", expected=expected, collect_action=src.action,
            collect_task=task, where=where,
            reason=f"拿不到探活步骤「{src.step}」的输出",
            advice=f"先看任务 {task or '—'} 里这一步的原始输出。",
        )
    # ★ 与 http_status 同一条规矩：**链路/工具故障 → unknown；探活本身"问不到" → fail**。
    #   探活动作失败（命令非 0）通常就是"这个服务没应答"—— 那正是健康检查要判的 fail。
    if getattr(result, "status", "") != "ok":
        return ExpectOutcome(
            kind=kind, state="fail", expected=expected,
            actual=f"探活失败：{_failed_reason(result) or '（无原文）'}",
            collect_action=src.action, collect_task=task, where=where,
            reason=f"{src.subject} 没有应答",
            advice=f"先确认服务在跑、端口在听；任务 {task or '—'} 里有原始输出。",
        )
    raw_lines = _lines_of(_val(result, src.step))
    raw_text = "\n".join(raw_lines).strip()

    if equals is not None:
        state = "pass" if raw_text == ref else "fail"
        return ExpectOutcome(
            kind=kind, state=state, expected=expected, actual=raw_text or "（无输出）",
            collect_action=src.action, collect_task=task, where=where,
            reason="" if state == "pass" else f"应答「{raw_text or '（无输出）'}」≠ 期望「{ref}」",
            advice="" if state == "pass" else "看这个服务的日志与配置（界面「服务列表」里有状态入口）。",
        )
    if first_field is not None:
        hit = next((ln for ln in raw_lines if ln.split() and ln.split()[0] == ref), None)
        state = "pass" if hit else "fail"
        return ExpectOutcome(
            kind=kind, state=state, expected=expected,
            actual="；".join(ln.strip() for ln in raw_lines[:5]) or "（无输出）",
            collect_action=src.action, collect_task=task, where=where,
            reason="" if state == "pass" else f"应答里没有第一个字段是「{ref}」的那一行",
            advice="" if state == "pass" else "确认它确实已生效（不只是把配置写进了文件）。",
        )
    return ExpectOutcome(kind=kind, state="pass", expected=expected,
                         actual=raw_text or "（无输出）",
                         collect_action=src.action, collect_task=task, where=where)


def _j_port_open(kind: str, value: Any, collect: Collector,
                 params: dict[str, ParamValue], where: str) -> ExpectOutcome:
    """`port_open` —— 这个端口上**有人在听**吗？（`free_port` 的镜像 · 规范 §12.11）

    ★ 为什么需要它（T6·S2 真机时发现的**假绿缺口**）：
      `responds` 证明的是"服务答话了"，但它走 **UNIX socket**（本机套接字）——
      **完全不看 TCP 端口**。于是"参数里填的 `port` 到底生效了没有"没人验：
      配置写错端口、或我们的配置压根没被应用，健康检查**照样全绿**。
      Nginx 那边 `http_status` 顺带把端口钉住了（它走 127.0.0.1:port）；
      `port_open` 就是数据库 / 缓存这类"没有 HTTP 可探"的服务的等价物。
    ★ 采集走**已登记动作** `net.port`（只读）—— 配方里依旧没有命令。
    """
    port = str(_render(value, params)).strip()
    expected = f"端口 {port} 上有人在监听"
    result, err = _collect(collect, "net.port", {"port": port})
    task = _task_id(result) if result is not None else None
    if result is None:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.port", collect_task=task, where=where,
                             reason=f"采集动作没能执行：{err.reason if err else '未知原因'}",
                             advice=err.advice if err else "")
    infra = _infra_failure(result)
    if infra:
        return ExpectOutcome(kind=kind, state="unknown", expected=expected,
                             collect_action="net.port", collect_task=task, where=where,
                             reason=infra, advice="先确认目标机可达、ss 可用。")
    # ★ 与 free_port 同一条纪律（规范 §10.6.3）：判据看**步骤状态**，不看"值非空" ——
    #   "没人监听"时 ss 的输出本来就是空的，那是**结论**，不是"取不到数据"。
    sstep = _step(result, "sockets")
    if sstep is None or getattr(sstep, "status", None) not in ("ok", "skipped"):
        return ExpectOutcome(
            kind=kind, state="unknown", expected=expected, collect_action="net.port",
            collect_task=task, where=where,
            reason="拿不到监听套接字列表（ss 可能不存在或输出无法解析）",
            advice="先看任务里 sockets 步骤的原始输出。",
        )
    sockets = getattr(sstep, "parsed", None)
    if sockets:
        who = []
        for it in (sockets or [])[:5]:
            if isinstance(it, dict):
                who.append(
                    f"{it.get('proto', '?')} {it.get('local', '')} "
                    f"进程 {it.get('proc') or '?'}(PID {it.get('pid') or '?'})"
                )
        return ExpectOutcome(
            kind=kind, state="pass", expected=expected,
            actual="；".join(who) or "有人在监听", collect_action="net.port",
            collect_task=task, where=where,
        )
    return ExpectOutcome(
        kind=kind, state="fail", expected=expected, actual="没人监听这个端口",
        collect_action="net.port", collect_task=task, where=where,
        reason=f"端口 {port} 上没有进程在监听 —— 服务可能没起来，或者配置里填的端口没生效",
        advice="先看「服务列表」里这个服务的状态，再对照配置里实际写的端口（配置没被应用也会这样）。",
    )


JUDGES: dict[str, Callable[..., ExpectOutcome]] = {
    "present": _j_presence,
    "absent": _j_presence,
    "free_port": _j_free_port,
    "state": _j_state,
    "http_status": _j_http_status,
    "responds": _j_responds,
    "port_open": _j_port_open,
}


# ------------------------------------------------------------------ 对外入口


def render_spec(value: Any, params: dict[str, ParamValue]) -> Any:
    """公开入口：把期望里的 `{{ 参数 }}` 渲染成实际值（规范 §12.2）。

    ★ 为什么需要它：**计划预览**也得给人看真值。
      预览里若显示 `http://127.0.0.1:{{ port }}/`，人就得自己在脑子里替换一遍 ——
      预览的意义（"执行前看见它会拿什么去判"）就打了折。
      判定与预览共用同一个 `_render`，不会出现"预览一套、判定另一套"。
    """
    return _render(value, params)


def evaluate(expect_spec: Any, collect: Collector, params: dict[str, ParamValue],
             *, where: str = "期望") -> ExpectOutcome:
    """判定一条期望。`where` 是给人看的出处（"preflight[0]" / "health[1]"）。"""
    if not isinstance(expect_spec, dict) or len(expect_spec) != 1:
        raise OpsError(
            code="RECIPE_INVALID",
            reason=f"{where} 必须是**恰好一个键**的期望（当前：{expect_spec!r}）",
            advice=f"写法：expect: {{ free_port: \"{{{{ port }}}}\" }}。允许的类型：{'、'.join(EXPECT_TYPES)}。",
        )
    kind, value = next(iter(expect_spec.items()))
    fn = JUDGES.get(str(kind))
    if fn is None:
        raise OpsError(
            code="RECIPE_INVALID",
            reason=f"{where} 用了未登记的期望类型「{kind}」",
            advice=f"允许的类型：{'、'.join(EXPECT_TYPES)}。要加新类型，先升规范 §12.2。",
        )
    return fn(str(kind), value, collect, params, where)


def validate_expect(expect_spec: Any, actions: dict[str, Any], *, where: str) -> list[str]:
    """加载期静态校验（不连目标机）：结构 / 白名单 / 引用的动作存在且参数名对得上。"""
    errs: list[str] = []
    if not isinstance(expect_spec, dict) or len(expect_spec) != 1:
        return [f"{where} 必须是恰好一个键的映射（键 = 期望类型）"]
    kind, value = next(iter(expect_spec.items()))
    kind = str(kind)
    if kind not in EXPECT_TYPES:
        return [f"{where} 期望类型「{kind}」不在白名单内（允许：{'、'.join(EXPECT_TYPES)}）"]

    if kind in ("present", "absent"):
        if not isinstance(value, dict) or not value.get("action"):
            return [f"{where} {kind} 必须写成 {{action: <已登记动作>, args: {{…}}}}"]
        aid = str(value.get("action"))
        if aid not in PRESENCE_SOURCES:
            return [
                f"{where} 「{aid}」不是已登记的存在性来源"
                f"（目前支持：{'、'.join(PRESENCE_SOURCES)}；要加来源先升规范 §12.2）"
            ]
        if aid not in actions:
            return [f"{where} 引用的动作不存在：{aid}"]
        src = PRESENCE_SOURCES[aid]
        args = value.get("args") or {}
        if not isinstance(args, dict):
            return [f"{where} args 必须是映射"]
        allowed = {p.name for p in actions[aid].params}
        for k in args:
            if k not in allowed:
                errs.append(
                    f"{where} 动作 {aid} 没有参数「{k}」（可用：{'、'.join(sorted(allowed)) or '无'}）"
                    f" —— 顺带提一句：{aid} 的包名参数叫「{src.arg}」，不是 package"
                )

    elif kind == "free_port":
        if not isinstance(value, str) or not value.strip():
            errs.append(f"{where} free_port 的值应是一个端口（可写 {{{{ port }}}}）")

    elif kind == "port_open":
        # ── v1.7 新增（规范 §12.11）：free_port 的镜像 —— 端口上**有人在听**吗
        if not isinstance(value, str) or not value.strip():
            errs.append(f"{where} port_open 的值应是一个端口（可写 {{{{ port }}}}）")

    elif kind == "state":
        if not isinstance(value, dict) or not value.get("unit") or not value.get("equals"):
            errs.append(f"{where} state 必须写成 {{unit: <服务名>, equals: <active/inactive/failed>}}")

    elif kind == "http_status":
        if not isinstance(value, dict) or not value.get("url"):
            errs.append(f"{where} http_status 必须写成 {{url: <完整 URL>, equals: <响应码>}}")
        else:
            try:
                int(value.get("equals"))
            except (TypeError, ValueError):
                errs.append(f"{where} http_status 的 equals 必须是整数（如 200）")
            if isinstance(value.get("url"), str) and not re.match(r"^https?://", value["url"]):
                errs.append(f"{where} http_status 的 url 必须带 http:// 或 https:// 前缀")

    elif kind == "responds":
        # ── v1.7 新增（规范 §12.11）：命令类判据 ──
        allowed_keys = {"action", "args", "equals", "first_field"}
        if not isinstance(value, dict) or not value.get("action"):
            return [f"{where} responds 必须写成 {{action: <已登记的探活动作>, args: {{…}}}}"]
        extra_keys = sorted(set(value) - allowed_keys)
        if extra_keys:
            errs.append(
                f"{where} responds 不支持这些键：{'、'.join(extra_keys)}"
                f"（只允许 action / args / equals / first_field —— ★ 没有 contains：本项目禁止子串判据）"
            )
        if value.get("equals") is not None and value.get("first_field") is not None:
            errs.append(f"{where} responds 的 equals 与 first_field 只能给一个（两个都要判 → 写成两条期望）")
        aid = str(value.get("action"))
        if aid not in PROBE_SOURCES:
            errs.append(
                f"{where} 「{aid}」不是已登记的探活动作"
                f"（目前支持：{'、'.join(PROBE_SOURCES)}；要加来源先升规范 §12.11.3）"
            )
        elif aid not in actions:
            errs.append(f"{where} 引用的动作不存在：{aid}")
        else:
            args = value.get("args") or {}
            if not isinstance(args, dict):
                errs.append(f"{where} args 必须是映射")
            else:
                allowed = {p.name for p in actions[aid].params}
                for k in args:
                    if k not in allowed:
                        errs.append(
                            f"{where} 动作 {aid} 没有参数「{k}」"
                            f"（可用：{'、'.join(sorted(allowed)) or '无'}）"
                        )
    return errs


def describe_types() -> str:
    return "、".join(EXPECT_TYPES)
