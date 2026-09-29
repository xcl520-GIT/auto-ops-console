"""动作定义：YAML 加载 + schema 校验 + argv 渲染。

★ 安全契约（三层防线的前两层，见 docs/动作规范.md §4）：

  第一层  参数定义即契约：required + pattern（完整匹配）+ min/max + choices/values
  第二层  渲染 argv 时**逐元素**取值，元素之间不合并、不拼接
  第三层  在 transport.py：传给 ssh 前每个元素 shlex.quote() 兜底

  禁止事项在**加载时**即拒绝（不是运行时才报错）：
    · run 元素里出现管道/重定向/命令分隔符（除非该元素是参数模板）
    · run 为空、引用未定义参数、foreach 引用不存在或缺少 item_pattern
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import Host
from app.errors import OpsError
from app.parsers import PARSERS, apply_pick
from app.yamlload import load_yaml

# ------------------------------------------------------------------ 正则

ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9-]*$")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
PARAM_REF_RE = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}")
TEXT_REF_RE = re.compile(r"\{([A-Za-z0-9_]+(?:\.[A-Za-z0-9_-]+)*)\}")

RISKS = ("green", "yellow", "red")
PRIORITIES = ("P0", "P1", "P2", "P3")
# ★★ T16（规范 §12.115 规矩 1）：**执行通道** —— 由动作声明，不由主机声明。
#    判据只有一句：这条命令在**哪台机器**上跑。
#      · ssh   （默认）= 经系统 ssh 到目标 Linux 机（本项目此前唯一的执行面）
#      · local        = 宿主机上的**本机 Windows 进程**（vmrun.exe）
CHANNELS = ("ssh", "local")

# run 元素里禁止出现的 shell 元字符（防"偷偷写管道"）
_FORBIDDEN_IN_ARGV = ("|", ">", "<", "&&", ";", "$(", "`", "\n", "||")

_DOMAIN_DEFAULT = {"host": ".service"}

# ★★ T16（规范 §12.115）：**引擎注入**的渲染变量 —— 由平台（`engine` + `app\vmware.py`）
#   在渲染前放进 `extra`，动作 YAML 直接用 `{{ vm_vmx }}` 这种写法引用它们。
#   ★ 它们**不是**动作参数（不该出现在界面表单里），所以加载期的"引用必须已定义"要放行这几个名字；
#     反过来说：这份名单是**白名单**，往里加名字 = 平台多承诺一个变量，必须有出处（规范 §12.115）。
ENGINE_EXTRA_NAMES = (
    # 由 VM 闸门（app\vmware.py::vm_guard）解析后注入
    "vm", "vm_name", "vm_vmx", "vm_host_id", "vm_managed_by",
    # ★ T17（规范 §12.130 第 6 条）：**新机的落盘位置** —— 由 vm_guard 调 new_vm_paths() 注入
    #   （唯一来源是 config.yaml 的 vm.allow_vmx_dirs；★ 动作 YAML 里**不许**自己拼路径）
    "vm_new_id", "vm_new_dir", "vm_new_vmx",
    # 由本通道的"工具坐标"注入（app\vmware.py::probe_extra）
    "vmrun", "vm_type", "vm_probe_py", "vm_probe_script",
    # ★ T17·S4：登记那条动作的工具坐标（hosts.yaml 的写前备份 / 可回退在它里面，规范 §12.131）
    "host_register_script",
)

# ── 备份路径校验（规范 §9.1）──────────────────────────────────────
# 渲染后（{{ 参数 }} 替换掉之后）必须完整匹配；禁 `..`，禁危险根路径。
BACKUP_PATH_RE = re.compile(r"^/[A-Za-z0-9._@/+-]*$")
BACKUP_FORBIDDEN = ("/", "/proc", "/sys", "/dev", "/run")


# ------------------------------------------------------------------ 数据模型


@dataclass
class Param:
    name: str
    label: str
    type: str = "str"
    required: bool = False
    default: Any = None
    pattern: str | None = None
    min: int | None = None
    max: int | None = None
    choices: list[str] = field(default_factory=list)
    values: list[str] = field(default_factory=list)
    placeholder: str = ""
    help: str = ""
    normalize: str | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "type": self.type,
            "required": self.required,
            "default": self.display_default(),
            "pattern": self.pattern,
            "min": self.min,
            "max": self.max,
            "choices": self.choices,
            "placeholder": self.placeholder,
            "help": self.help,
        }

    def display_default(self) -> Any:
        """界面上应预填的值。enum 用显示文本。"""
        if self.default is None:
            return None
        if self.type == "enum" and self.values and self.default in self.values:
            return self.choices[self.values.index(self.default)]
        return self.default


@dataclass
class ParamValue:
    name: str
    value: str          # 最终传给命令的值
    display: str        # 界面上/结论里展示的值
    raw: Any = None


@dataclass
class BackupItem:
    """变更动作声明的「改动前必须备份」的路径（规范 §9.1）。

    引擎在**执行任何变更步骤之前**逐项备份；任一 required 项失败 → 变更步骤一律不执行。
    语义与限制见 docs/动作规范.md §9.1。
    """

    path: str                    # 绝对路径；可含 {{ 参数 }}；不做 glob（要目录就写目录）
    label: str = ""              # 给人看的名字（默认取 path）
    required: bool = False       # False=不存在时记 missing 继续；True=失败并中止动作
    allow_large: bool = False    # 超过 config.yaml 的 backup.max_file_mb 时必须显式声明

    def to_public(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "label": self.label or self.path,
            "required": self.required,
            "allow_large": self.allow_large,
        }


@dataclass
class Step:
    name: str
    title: str
    run: list[Any]
    parser: str = "raw"
    pick: dict[str, str] | None = None
    optional: bool = False
    silent: bool = False
    timeout: int | None = None
    note: str = ""
    foreach: str | None = None
    as_: str | None = None
    item_pattern: str | None = None
    ok_exit_codes: list[int] = field(default_factory=lambda: [0])
    # ── T4 新增（规范 §10.5）：解析器参数 ──
    # 给"排行/截断类"解析器（du_rows / find_rows / head_lines）传"取前几条"。
    # 不声明就沿用默认 20；其余解析器忽略它。写 {{ 参数 }}，加载期校验引用必须已定义。
    parser_arg: str | None = None
    # ── T6 新增（规范 §12.10）：`run_by` 枚举选段 ──
    # {"param": <enum 参数名>, "cases": {<取值>: [argv…]}}；与 `run` **互斥、必居其一**。
    # ★ 参数只用来"选段"：命令本身是写死在这里的静态数组，**永远不由参数拼出来**。
    # ★ 键名是 `param` 而**不是** `on`：YAML 1.1 会把裸 `on`/`off`/`yes`/`no` 解析成布尔
    #   （PyYAML 实测：`on: binary` 的键是 True）—— 见规范 §12.10。
    run_by: dict[str, Any] | None = None
    # ── T3 新增（规范 §9.5）：两种**非 run** 的步骤 —— 平台能力，不是动作层开后门 ──
    # write_file: 写远端文件（{path, content, mode}）—— `run` 禁重定向，写文件必须走这里
    # transfer:   put（本地→远端）/ get（远端→本地），配合 src / dst
    write_file: dict[str, Any] | None = None
    transfer: str | None = None
    src: str | None = None
    dst: str | None = None
    # ── T8 新增（规范 §12.33）：幂等守卫 —— ★★ **只许写在 precheck 步骤上** ──
    # 语义：**这一步不成立 ⇒ 目标已经是我想要的样子了**（已达终态，不是失败）。
    # ★ 为什么挂在"步骤"而不是"动作"上：一个动作有多条预检，它们的语义**各不相同** ——
    #   「这台机器上有没有旧集群」可以是终态判据，「kubeadm 这个工具在不在」**永远不是**
    #   （缺工具必须中止，绝不能吞成"已达终态"）。动作级声明会把这二者一起放行。
    means_done: bool = False
    # ★ 声明必须配一段人读的理由（装载期必填）——
    #   它是一句**承诺**，没有理由的承诺就是谁也无法证伪的托词（规范 §12.33 规矩 2）。
    means_done_why: str = ""


@dataclass
class Verify:
    name: str
    from_: str
    field: str | None = None
    severity: str = "fail"
    on_missing: str = ""


@dataclass
class Action:
    id: str
    title: str
    summary: str
    domain: str
    risk: str
    priority: str
    tags: list[str] = field(default_factory=list)
    note: str = ""
    confirm: dict[str, Any] | None = None
    params: list[Param] = field(default_factory=list)
    backup: list[BackupItem] = field(default_factory=list)
    precheck: list[Step] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    verify: list[Verify] = field(default_factory=list)
    conclusion: str = ""
    source: str = ""
    # ★★ T16（规范 §12.115）：执行通道。缺省 `ssh`；`local` = 宿主机上的本机进程。
    channel: str = "ssh"

    def param(self, name: str) -> Param | None:
        return next((p for p in self.params if p.name == name), None)

    def step(self, name: str) -> Step | None:
        return next((s for s in self.steps + self.precheck if s.name == name), None)

    def precheck_step(self, name: str) -> Step | None:
        """按名字取**预检**步骤（规范 §12.33 的幂等守卫要靠它判"是哪一步不成立"）。"""
        return next((s for s in self.precheck if s.name == name), None)

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "domain": self.domain,
            "risk": self.risk,
            "priority": self.priority,
            "tags": self.tags,
            "note": self.note,
            "confirm": self.confirm,
            "params": [p.to_public() for p in self.params],
            "backup": [b.to_public() for b in self.backup],
            "step_count": len(self.steps),
            "verify_count": len(self.verify),
            "source": self.source,
            # ★ T16：通道要让界面看得见（"为什么这条要在本机跑"必须能被人读到）
            "channel": self.channel,
        }

    def to_detail(self) -> dict[str, Any]:
        d = self.to_public()
        d["steps"] = [
            {
                "name": s.name,
                "title": s.title,
                "optional": s.optional,
                "silent": s.silent,
                "note": s.note,
                "foreach": s.foreach,
            }
            for s in self.steps
        ]
        d["conclusion"] = self.conclusion
        # ★ T8（规范 §12.33）：预检步骤也进详情 —— 幂等守卫是**一条对外可见的承诺**，
        #   界面上要能读到"哪一步不成立时算已达终态、为什么"。
        d["precheck"] = [
            {
                "name": s.name,
                "title": s.title,
                "optional": s.optional,
                "note": s.note,
                "means_done": s.means_done,
                "means_done_why": s.means_done_why,
            }
            for s in self.precheck
        ]
        d["verify"] = [
            {"name": v.name, "from": v.from_, "field": v.field, "severity": v.severity}
            for v in self.verify
        ]
        return d


# ------------------------------------------------------------------ 渲染


def render_argv_element(
    element: str, params: dict[str, ParamValue], extra: dict[str, str] | None = None
) -> str:
    """把 `{{ 名字 }}` 替换成取值。

    查找顺序：**循环变量（extra）优先，其次参数**。
    原因：`svc.list` 里 `{{ unit }}` 是 foreach 的循环变量，而 `log.view` 里 `{{ unit }}`
    是普通参数 —— 同一个占位符名在不同动作里有不同来源，所以必须让调用方显式区分，
    不能因为"参数表里没有"就报未定义。
    """
    extra = extra or {}

    def _sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name in extra:
            return str(extra[name])
        pv = params.get(name)
        if pv is None:
            raise OpsError(
                code="CATALOG_INVALID",
                reason=f"命令里引用了未定义的参数或循环变量：{name}",
                advice="在动作 YAML 的 params 里定义它，或检查 foreach 的 as 名字。",
            )
        return pv.value

    return PARAM_REF_RE.sub(_sub, element)


def select_run_elements(step: Step, params: dict[str, ParamValue]) -> list[Any]:
    """取这一步要跑的 argv 元素：`run` 原样，或 `run_by` 按 enum 取值**选段**（规范 §12.10）。

    ★ 为什么要有它：动作层的 `run` 只能"逐个元素替换 `{{ 参数 }}`"或"参数有值才出现"，
    **表达不了"按参数的取值选一条命令"**。而"把命令片段做成参数"等于把动作层变成命令通道
    （违反安全契约 §4）。`run_by` 把差异写在**静态 argv 表**里，参数只用来**选段**。
    """
    if not step.run_by:
        return step.run
    pname = str(step.run_by.get("param") or "")
    cases = step.run_by.get("cases") or {}
    pv = params.get(pname)
    key = "" if pv is None else str(pv.value)
    if key not in cases:
        raise OpsError(
            code="CATALOG_INVALID",
            reason=f"步骤 {step.name} 的 run_by 里没有取值「{key}」对应的预设（参数：{pname}）",
            advice=f"可选取值：{'、'.join(sorted(cases))}",
        )
    return list(cases[key])


def render_argv(
    step: Step, params: dict[str, ParamValue], extra: dict[str, str] | None = None
) -> list[str]:
    """把一个步骤的 run 渲染成最终 argv 数组。

    `run` 元素两种形态：
      · 字符串          → 总是出现（可用 {{ 参数 }}）
      · {when, value}   → 仅当 when 指向的参数有值时出现（用于可选参数）
    """
    extra = extra or {}
    argv: list[str] = []
    for element in select_run_elements(step, params):
        if isinstance(element, dict):
            when = str(element.get("when", ""))
            value = element.get("value", "")
            pv = params.get(when)
            # 循环变量也算"有值"
            has = (pv is not None and str(pv.value) != "") or (
                when in extra and str(extra[when]) != ""
            )
            if not has:
                continue
            text = str(value)
        else:
            text = str(element)

        text = render_argv_element(text, params, extra)
        argv.append(text)
    return argv


def render_text(template: str, ctx: dict[str, Any]) -> str:
    """渲染结论/确认文本里的 `{步骤.字段}` 占位符。

    取不到的占位符渲染成「（无）」，**不报错** ——
    否则一个 optional 步骤失败就会把整个结论毁掉。
    """

    def _sub(m: re.Match[str]) -> str:
        path = m.group(1).split(".")
        cur: Any = ctx.get(path[0])
        for seg in path[1:]:
            if isinstance(cur, dict):
                cur = cur.get(seg)
            elif isinstance(cur, (list, tuple)):
                if seg.isdigit() and int(seg) < len(cur):
                    cur = cur[int(seg)]
                elif seg in ("count", "len") and not seg.isdigit():
                    cur = len(cur)
                else:
                    cur = None
            else:
                cur = None
            if cur is None:
                break
        if cur is None or cur == "" or cur == [] or cur == {}:
            return "（无）"
        return format_value(cur)

    return TEXT_REF_RE.sub(_sub, template)


def _cell(value: Any) -> str:
    """字典里的单元格渲染。

    ★ T2 新增：JSON 源（`ip -j route` / `ip -j neigh`）里常见**列表值**
      （route 的 `flags: []`、neigh 的 `state: ["DELAY"]`）。
      直接 f-string 会渲染成 Python 字面量 `['DELAY']`，在结论里很难看。
      列表一律用「、」连接。
    """
    if isinstance(value, list):
        return "、".join(_cell(v) for v in value) if value else "（空）"
    return str(value)


def format_value(value: Any) -> str:
    """把解析结果渲染成可读文本。结论区靠它实现「一屏给全」。"""
    if value is None or value == "" or value == [] or value == {}:
        return "（无）"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict) and "iter" in item and "value" in item:
                # foreach 步骤产出的结构：{"iter": 循环项, "value": 该项的解析结果}
                body = format_value(item["value"])
                head = f"  · {item['iter']}："
                if "\n" in body:
                    parts.append(head + "\n" + "\n".join("      " + ln for ln in body.splitlines()))
                else:
                    parts.append(head + body.strip())
            elif isinstance(item, dict):
                label = item.get("iter") or item.get("unit")
                body = " ｜ ".join(
                    f"{k}={_cell(v)}" for k, v in item.items() if k not in ("iter", "raw")
                )
                parts.append(f"  · {label}：{body}" if label else f"  · {body}")
            else:
                parts.append(f"  {item}")
        return "\n".join(parts) if parts else "（无）"
    if isinstance(value, dict):
        return "\n".join(f"  {k}: {_cell(v)}" for k, v in value.items())
    return str(value)


# ------------------------------------------------------------------ 参数校验


def _with_help(advice: str, p: Any) -> str:
    """★ 规范 §12.47：把作者写在参数上的 `help` 接进**拒绝信息**。

    只列"可选值" / "填个整数"回答的是「**我能填什么**」，
    ★ 它没有回答「**我想要的那个为什么在这里不行、该去哪儿**」——
    而"该去哪儿"这类指引（逃生口的"写命令请走对应动作"就是唯一一处）**只能写在 help 里**。
    ⇒ 话没到用户手里，闸门就只做了一半（错误信息是这道闸门唯一的出口）。

    ★★ 为什么抽成一个函数：同一个 `PARAM_INVALID` 下有**多条 raise 出口**，
      分散地各自拼字符串必然出现"**改了一处、以为改完了**"
      （v1.7 修订六·补漏 `optional` 主返回 · §12.47 漏 enum 分支 —— **同一族缺陷的第 2 次现形**）。
      抽出来之后，自检可以静态断言"这个错误码下每条出口都调了它"。
    """
    h = getattr(p, "help", None)
    return advice + (f"\n{h}" if h else "")


def validate_params(action: Action, given: dict[str, Any] | None) -> dict[str, ParamValue]:
    """按参数定义校验并归一化用户输入。

    这是安全契约的**第一层**：只放行白名单内的值。
    """
    given = given or {}
    out: dict[str, ParamValue] = {}

    unknown = set(given) - {p.name for p in action.params}
    if unknown:
        raise OpsError(
            code="PARAM_INVALID",
            reason=f"动作「{action.title}」不认识这些参数：{', '.join(sorted(unknown))}",
            advice="界面按定义生成表单，出现多余参数通常是前端缓存旧版本，刷新页面即可。",
        )

    for p in action.params:
        raw = given.get(p.name, None)
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            raw = p.default

        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            if p.required:
                raise OpsError(
                    code="PARAM_MISSING",
                    reason=f"缺少必填参数「{p.label}」",
                    advice="填上该字段后再执行。",
                    context={"param": p.name},
                )
            out[p.name] = ParamValue(name=p.name, value="", display="", raw=raw)
            continue

        if p.type == "enum":
            if p.choices and p.values and len(p.choices) != len(p.values):
                raise OpsError(
                    code="CATALOG_INVALID",
                    reason=f"参数 {p.name} 的 choices 与 values 长度不一致",
                    advice="两者必须一一对应。",
                )
            sval = str(raw)
            if p.choices and sval in p.choices:
                idx = p.choices.index(sval)
                out[p.name] = ParamValue(p.name, p.values[idx], p.choices[idx], raw)
                continue
            if sval in p.values:
                idx = p.values.index(sval)
                disp = p.choices[idx] if p.choices else sval
                out[p.name] = ParamValue(p.name, sval, disp, raw)
                continue
            raise OpsError(
                code="PARAM_INVALID",
                reason=f"参数「{p.label}」的值不在允许范围内：{sval}",
                # ★ §12.47：作者写在 help 里的"该去哪儿"必须跟着错误走出去（长 help 用换行接，不套 `（）`）。
                advice=_with_help(f"可选值：{'、'.join(p.choices or p.values)}", p),
                context={"param": p.name},
            )

        if p.type == "int":
            try:
                ival = int(str(raw).strip())
            except ValueError:
                raise OpsError(
                    code="PARAM_INVALID",
                    reason=f"参数「{p.label}」必须是整数，实际是：{raw}",
                    advice=_with_help("填一个整数。", p),
                    context={"param": p.name},
                ) from None
            if p.min is not None and ival < p.min:
                raise OpsError(
                    code="PARAM_INVALID",
                    reason=f"参数「{p.label}」不能小于 {p.min}",
                    advice=_with_help(f"允许范围 {p.min} ~ {p.max}。", p),
                    context={"param": p.name},
                )
            if p.max is not None and ival > p.max:
                raise OpsError(
                    code="PARAM_INVALID",
                    reason=f"参数「{p.label}」不能大于 {p.max}",
                    advice=_with_help(f"允许范围 {p.min} ~ {p.max}。", p),
                    context={"param": p.name},
                )
            out[p.name] = ParamValue(p.name, str(ival), str(ival), raw)
            continue

        # type == str
        sval = str(raw)
        if p.pattern and not re.fullmatch(p.pattern, sval):
            raise OpsError(
                code="PARAM_INVALID",
                reason=f"参数「{p.label}」含有不允许的字符：{sval}",
                advice=(
                    "参数只允许白名单内的字符。"
                    + (f"（{p.help}）" if p.help else "")
                ),
                context={"param": p.name, "pattern": p.pattern},
            )
        if p.normalize == "systemd_unit" and "." not in sval:
            sval = sval + _DOMAIN_DEFAULT["host"]
            if p.pattern and not re.fullmatch(p.pattern, sval):
                raise OpsError(
                    code="PARAM_INVALID",
                    reason=f"参数「{p.label}」规范化后仍不合法：{sval}",
                    advice=_with_help("检查参数值。", p),
                    context={"param": p.name},
                )
        out[p.name] = ParamValue(p.name, sval, sval, raw)

    return out


# ------------------------------------------------------------------ 加载与校验


def _errs(buf: list[str], msg: str) -> None:
    buf.append(msg)


def _parse_params(raw: Any, buf: list[str], aid: str) -> list[Param]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        _errs(buf, f"[{aid}] params 必须是列表")
        return []
    out: list[Param] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        where = f"[{aid}] params[{i}]"
        if not isinstance(item, dict):
            _errs(buf, f"{where} 必须是映射")
            continue
        name = str(item.get("name", ""))
        if not NAME_RE.match(name):
            _errs(buf, f"{where} name「{name}」不合法（应为 ^[a-z][a-z0-9_]*$）")
            continue
        if name in seen:
            _errs(buf, f"{where} 参数名重复：{name}")
        seen.add(name)
        ptype = str(item.get("type", "str"))
        if ptype not in ("str", "int", "enum"):
            _errs(buf, f"{where} type「{ptype}」不合法（str/int/enum）")
            continue
        choices = [str(c) for c in (item.get("choices") or [])]
        values = [str(v) for v in (item.get("values") or [])]
        if ptype == "enum":
            if not choices or not values:
                _errs(buf, f"{where} enum 必须同时给 choices 与 values")
            elif len(choices) != len(values):
                _errs(buf, f"{where} choices({len(choices)}) 与 values({len(values)}) 长度不一致")
        pattern = item.get("pattern")
        if pattern is not None:
            try:
                re.compile(str(pattern))
            except re.error as exc:
                _errs(buf, f"{where} pattern 不是合法正则：{exc}")
                pattern = None
        out.append(
            Param(
                name=name,
                label=str(item.get("label") or name),
                type=ptype,
                required=bool(item.get("required", False)),
                default=item.get("default"),
                pattern=str(pattern) if pattern else None,
                min=item.get("min"),
                max=item.get("max"),
                choices=choices,
                values=values,
                placeholder=str(item.get("placeholder") or ""),
                help=str(item.get("help") or ""),
                normalize=item.get("normalize"),
            )
        )
    return out


def _parse_backup(raw: Any, buf: list[str], aid: str, defined: set[str]) -> list[BackupItem]:
    """解析 `backup:` 段（规范 §9.1）。

    加载期做**静态**校验：把 `{{ 参数 }}` 先替换成占位字符再检查路径形状
    （参数的最终取值由 validate_params 的白名单把关，运行时还会再校验一次）。
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        _errs(buf, f"[{aid}] backup 必须是列表")
        return []
    out: list[BackupItem] = []
    for i, item in enumerate(raw):
        at = f"[{aid}] backup[{i}]"
        if not isinstance(item, dict):
            _errs(buf, f"{at} 必须是映射（path / label / required / allow_large）")
            continue
        path = str(item.get("path", "")).strip()
        if not path:
            _errs(buf, f"{at} 缺少 path")
            continue
        for ref in PARAM_REF_RE.findall(path):
            if ref not in defined:
                _errs(buf, f"{at} path 引用了未定义的参数：{ref}")
        # ★ 若整个 path 就是一个 {{ 参数 }} 模板（典型：file.push 的 "{{ remote_path }}"），
        #   加载期无从判断它的形状 —— 交给**运行时**校验（BackupRunner.validate_path）。
        #   不做这个豁免，"路径完全由参数决定"这种完全合理的写法会被加载期误杀。
        if not PARAM_REF_RE.fullmatch(path.strip()):
            static = PARAM_REF_RE.sub("x", path)
            if not static.startswith("/"):
                _errs(buf, f"{at} path 必须是绝对路径：{path}")
            if ".." in static:
                _errs(buf, f"{at} path 不得包含 ..（防止越权备份）：{path}")
            if not BACKUP_PATH_RE.match(static):
                _errs(buf, f"{at} path 含不允许的字符（只允许 A-Za-z0-9 . _ @ / + -）：{path}")
            if static.rstrip("/") in BACKUP_FORBIDDEN:
                _errs(buf, f"{at} 不允许备份「{static}」（防灾难性递归复制）")
        out.append(
            BackupItem(
                path=path,
                label=str(item.get("label") or ""),
                required=bool(item.get("required", False)),
                allow_large=bool(item.get("allow_large", False)),
            )
        )
    return out


def _parse_run_by(raw: Any, buf: list[str], at: str) -> tuple[dict[str, Any] | None, list[Any]]:
    """解析并校验 `run_by`（规范 §12.10）。返回 (规范化后的 run_by, 所有 case 的 argv 元素合集)。

    这里只做**结构**校验；★ "`on` 必须是 enum 参数"与"**双向全覆盖**"在 `_parse_action` 里做
    （那里才有完整的参数表）。argv 元素的合规校验与 `run` **同一套规则**。
    """
    if not isinstance(raw, dict):
        _errs(buf, f"{at} run_by 必须是映射（param / cases）")
        return None, []
    keys = set(raw)
    if keys != {"param", "cases"}:
        shown = "、".join(str(k) for k in sorted(keys, key=str)) or "空"
        hint = ""
        if any(isinstance(k, bool) for k in keys):
            # ★ 实测坑：PyYAML 按 YAML 1.1 把裸 `on` / `off` / `yes` / `no` 解析成布尔。
            hint = "（★ YAML 1.1 会把裸 `on` / `off` / `yes` / `no` 解析成布尔 —— 键名用 `param`，不要用 `on`）"
        _errs(buf, f"{at} run_by 只允许 param 与 cases 两个键（当前：{shown}）{hint}")
        return None, []
    pname = str(raw.get("param") or "")
    if not NAME_RE.match(pname):
        _errs(buf, f"{at} run_by.param「{pname}」不像参数名（应为 ^[a-z][a-z0-9_]*$）")
    cases = raw.get("cases")
    if not isinstance(cases, dict) or not cases:
        _errs(buf, f"{at} run_by.cases 必须是非空映射（取值 → argv）")
        return None, []

    norm: dict[str, list[Any]] = {}
    flat: list[Any] = []
    for key, argv in cases.items():
        k = str(key)
        if not k:
            _errs(buf, f"{at} run_by.cases 里有空取值")
            continue
        if not isinstance(argv, list) or not argv:
            _errs(buf, f"{at} run_by.cases[{k}] 必须是非空 argv 数组")
            continue
        for element in argv:
            if isinstance(element, dict):
                if not {"when", "value"} <= set(element):
                    _errs(buf, f"{at} run_by.cases[{k}] 的字典元素必须同时有 when 与 value")
                    continue
                when = str(element.get("when", ""))
                if when and not NAME_RE.match(when):
                    _errs(buf, f"{at} run_by.cases[{k}] 的 when「{when}」不像参数名")
                continue
            text = str(element)
            if PARAM_REF_RE.search(text):
                continue          # 参数模板：值由参数白名单把关
            for bad in _FORBIDDEN_IN_ARGV:
                if bad in text:
                    _errs(
                        buf,
                        f"{at} run_by.cases[{k}] 的元素「{text}」含 shell 元字符「{bad}」。"
                        f"本项目禁止管道/重定向/命令分隔符。",
                    )
                    break
        norm[k] = list(argv)
        flat.extend(argv)
    return ({"param": pname, "cases": norm} if norm else None), flat


def _parse_steps(raw: Any, buf: list[str], aid: str, where: str) -> list[Step]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        _errs(buf, f"[{aid}] {where} 必须是列表")
        return []
    out: list[Step] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        at = f"[{aid}] {where}[{i}]"
        if not isinstance(item, dict):
            _errs(buf, f"{at} 必须是映射")
            continue
        name = str(item.get("name", ""))
        if not NAME_RE.match(name):
            _errs(buf, f"{at} name「{name}」不合法（应为 ^[a-z][a-z0-9_]*$）")
            continue
        if name in seen:
            _errs(buf, f"{at} 步骤名重复：{name}")
        seen.add(name)

        # ── T3：两种"非 run"步骤（规范 §9.5）─────────────────────────
        # 结构校验放在这里；**参数引用**校验统一在 _parse_action 里做（那里有完整的参数表）
        write_file = item.get("write_file")
        transfer = item.get("transfer")
        if write_file is not None or transfer is not None:
            if write_file is not None:
                if not isinstance(write_file, dict):
                    _errs(buf, f"{at} write_file 必须是映射（path / content / mode）")
                    continue
                wf_path = str(write_file.get("path") or "").strip()
                static_path = PARAM_REF_RE.sub("x", wf_path)
                if not wf_path:
                    _errs(buf, f"{at} write_file 缺少 path")
                elif not BACKUP_PATH_RE.match(static_path) or ".." in static_path:
                    _errs(buf, f"{at} write_file.path 必须是合法绝对路径：{wf_path}")
                if not str(write_file.get("content") or "").strip():
                    _errs(buf, f"{at} write_file 缺少 content")
                wf_mode = str(write_file.get("mode") or "0644")
                if not re.fullmatch(r"[0-7]{4}", wf_mode):
                    _errs(buf, f"{at} write_file.mode「{wf_mode}」不合法（应为 4 位八进制，如 0644）")
            else:
                kind = str(transfer).lower()
                if kind not in ("put", "get"):
                    _errs(buf, f"{at} transfer 只能是 put 或 get")
                # put 必须有 src 与 dst；get 必须有 src —— dst 可空（空 = 落到 var/downloads/）
                required_keys = ("src", "dst") if kind == "put" else ("src",)
                for need in required_keys:
                    if not str(item.get(need) or "").strip():
                        _errs(buf, f"{at} transfer 的 {kind} 必须给 {need}")
            run = []

        run_by: dict[str, Any] | None = None
        if not write_file and not transfer:
            # ── T6 新增（规范 §12.10）：`run` 与 `run_by` 互斥、必居其一 ──
            raw_run_by = item.get("run_by")
            if raw_run_by is not None:
                if item.get("run") is not None:
                    _errs(buf, f"{at} run 与 run_by 只能有一个（规范 §12.10）")
                if item.get("foreach") is not None:
                    _errs(buf, f"{at} run_by 的步骤不能用 foreach（规范 §12.10：case 里不许引用循环变量）")
                run_by, run = _parse_run_by(raw_run_by, buf, at)
            else:
                run = item.get("run")
                if not isinstance(run, list) or not run:
                    _errs(buf, f"{at} run 必须是非空数组（argv 形式）")
                    continue
        for element in run:
            if isinstance(element, dict):
                keys = set(element)
                if not {"when", "value"} <= keys:
                    _errs(buf, f"{at} run 的字典元素必须同时有 when 与 value")
                when = str(element.get("when", ""))
                if when and not NAME_RE.match(when):
                    _errs(buf, f"{at} run 的 when「{when}」不像参数名")
                continue
            text = str(element)
            if PARAM_REF_RE.search(text):
                continue          # 参数模板：值由参数白名单把关
            for bad in _FORBIDDEN_IN_ARGV:
                if bad in text:
                    _errs(
                        buf,
                        f"{at} run 元素「{text}」含 shell 元字符「{bad}」。"
                        f"本项目禁止管道/重定向/命令分隔符；"
                        f"请改用结构化输出（--output=json、-p KEY、/proc/*）。",
                    )
                    break

        parser = str(item.get("parser", "raw"))
        if parser not in PARSERS:
            _errs(buf, f"{at} parser「{parser}」未知，可选：{', '.join(PARSERS)}")

        # ── T8 新增（规范 §12.33）：幂等守卫声明 ──────────────────────
        # ★ 三条装载期硬校验（少一条都会让它变成"把不知道的当已达终态"的后门）：
        #   ① 只许写在 precheck 里 —— 写在 steps 上等于给"变更步骤"开后门；
        #   ② 没有 `run` 的步骤（write_file / transfer）不许声明 —— 它压根不是"问一句话"；
        #   ③ 声明了就必须写清"为什么"（人读）。
        means_done = bool(item.get("means_done", False))
        means_done_why = str(item.get("means_done_why") or "").strip()
        if item.get("means_done") is not None and not isinstance(item.get("means_done"), bool):
            _errs(buf, f"{at} means_done 必须是布尔（true / false）")
        if means_done or means_done_why:
            if where != "precheck":
                _errs(buf, f"{at} means_done 只许写在 precheck 步骤上"
                          f"（规范 §12.33：变更步骤不许声明「不成立 = 已达终态」）")
            if not means_done:
                _errs(buf, f"{at} 只写了 means_done_why 却没写 means_done: true（两者要成套）")
            if not run and not run_by:
                _errs(buf, f"{at} means_done 只能标在「问一句话」的步骤上（write_file / transfer 不行）")
            if not means_done_why:
                _errs(buf, f"{at} means_done: true 必须同时给 means_done_why"
                          f"（规范 §12.33 规矩 2：这是一句承诺，承诺必须带理由）")

        foreach = item.get("foreach")
        as_ = item.get("as")
        item_pattern = item.get("item_pattern")
        if foreach is not None:
            if not as_ or not NAME_RE.match(str(as_)):
                _errs(buf, f"{at} 使用 foreach 时必须给 as（循环变量名）")
            if not item_pattern:
                _errs(buf, f"{at} 使用 foreach 时必须给 item_pattern（循环项白名单正则）")
            else:
                try:
                    re.compile(str(item_pattern))
                except re.error as exc:
                    _errs(buf, f"{at} item_pattern 不是合法正则：{exc}")
            first = str(foreach).split(".")[0]
            if first not in seen - {name} and first not in [s.name for s in out]:
                _errs(buf, f"{at} foreach 引用了不存在的步骤：{first}")

        out.append(
            Step(
                name=name,
                title=str(item.get("title") or name),
                run=run,
                parser=parser,
                pick={str(k): str(v) for k, v in (item.get("pick") or {}).items()}
                if item.get("pick")
                else None,
                optional=bool(item.get("optional", False)),
                silent=bool(item.get("silent", False)),
                timeout=int(item["timeout"]) if item.get("timeout") else None,
                note=str(item.get("note") or "").strip(),
                foreach=str(foreach) if foreach else None,
                as_=str(as_) if as_ else None,
                item_pattern=str(item_pattern) if item_pattern else None,
                ok_exit_codes=[
                    int(x) for x in (item.get("ok_exit_codes") or [0])
                ],
                parser_arg=str(item.get("parser_arg")) if item.get("parser_arg") is not None else None,
                run_by=run_by,
                write_file=write_file if isinstance(write_file, dict) else None,
                transfer=str(transfer) if transfer else None,
                src=str(item.get("src")) if item.get("src") else None,
                dst=str(item.get("dst")) if item.get("dst") else None,
                means_done=means_done,
                means_done_why=means_done_why,
            )
        )
    return out


def _parse_action(data: Any, path: Path, buf: list[str]) -> Action | None:
    if not isinstance(data, dict):
        _errs(buf, f"[{path.name}] 顶层必须是映射")
        return None

    aid = str(data.get("id", ""))
    if not ACTION_ID_RE.match(aid):
        _errs(buf, f"[{path.name}] id「{aid}」不合法（应为 域.动作名，^[a-z][a-z0-9]*\\.[a-z][a-z0-9-]*$）")
    if path.stem != aid:
        _errs(buf, f"[{path.name}] 文件名与 id 不一致：文件名「{path.stem}」≠ id「{aid}」（防止复制粘贴漏改）")

    for key in ("title", "summary", "domain"):
        if not str(data.get(key, "")).strip():
            _errs(buf, f"[{aid or path.name}] 缺少必填项：{key}")

    risk = str(data.get("risk", ""))
    if risk not in RISKS:
        _errs(buf, f"[{aid or path.name}] risk「{risk}」不合法，可选：{', '.join(RISKS)}")
    priority = str(data.get("priority", ""))
    if priority not in PRIORITIES:
        _errs(buf, f"[{aid or path.name}] priority「{priority}」不合法，可选：{', '.join(PRIORITIES)}")

    # ★★ T16（规范 §12.115 规矩 1）：执行通道由**动作**声明。
    channel = str(data.get("channel") or "ssh").strip().lower()
    if channel not in CHANNELS:
        _errs(buf, f"[{aid or path.name}] channel「{channel}」不合法，可选：{', '.join(CHANNELS)}")

    confirm = data.get("confirm")
    if risk in ("yellow", "red") and not confirm:
        _errs(buf, f"[{aid or path.name}] risk={risk} 时必须提供 confirm 段（二次确认文案）")

    params = _parse_params(data.get("params"), buf, aid or path.name)
    precheck = _parse_steps(data.get("precheck"), buf, aid or path.name, "precheck")
    steps = _parse_steps(data.get("steps"), buf, aid or path.name, "steps")
    if not steps:
        _errs(buf, f"[{aid or path.name}] 至少要有一个 steps")

    # run 里引用的参数必须已定义
    defined = {p.name for p in params}
    loop_vars = {s.as_ for s in steps if s.as_}
    for s in steps + precheck:
        for element in s.run:
            text = str(element.get("value")) if isinstance(element, dict) else str(element)
            for ref in PARAM_REF_RE.findall(text):
                if ref not in defined and ref not in loop_vars and ref not in ENGINE_EXTRA_NAMES:
                    _errs(buf, f"[{aid}] 步骤 {s.name} 引用了未定义的参数：{ref}")
        # ── T6（规范 §12.10）：`run_by` 的三条硬校验 —— enum / required / **双向全覆盖** ──
        # ★ 双向全覆盖为什么是"硬"的：少一边就会出现"选得到却没有命令"或
        #   "写了却永远跑不到"—— 两种都是**假闸门**（让人以为检查过了）。
        if s.run_by:
            pname = str(s.run_by.get("param") or "")
            p = next((x for x in params if x.name == pname), None)
            if p is None:
                _errs(buf, f"[{aid}] 步骤 {s.name} 的 run_by.param「{pname}」不是本动作的参数")
            elif p.type != "enum" or not p.values:
                _errs(
                    buf,
                    f"[{aid}] 步骤 {s.name} 的 run_by.param「{pname}」必须是 type=enum 且给了 values 的参数"
                    f"（规范 §12.10：只有闭枚举才能选段，自由文本一选就等于任意命令）",
                )
            elif not p.required:
                _errs(
                    buf,
                    f"[{aid}] 步骤 {s.name} 的 run_by.param「{pname}」必须是 required 的枚举参数"
                    f"（否则它可能没有取值 → 选不出段）",
                )
            else:
                want = set(p.values)
                got = set(s.run_by.get("cases") or {})
                miss = sorted(want - got)
                extra = sorted(got - want)
                if miss:
                    _errs(
                        buf,
                        f"[{aid}] 步骤 {s.name} 的 run_by.cases 缺少取值：{'、'.join(miss)}"
                        f"（规范 §12.10 双向全覆盖：values 的每一项都要有对应命令）",
                    )
                if extra:
                    _errs(
                        buf,
                        f"[{aid}] 步骤 {s.name} 的 run_by.cases 出现枚举里没有的取值：{'、'.join(extra)}",
                    )

        # T4：parser_arg 里的引用也要校验（否则写错参数名会静默退回默认 20）
        if s.parser_arg:
            for ref in PARAM_REF_RE.findall(s.parser_arg):
                if ref not in defined and ref not in loop_vars and ref not in ENGINE_EXTRA_NAMES:
                    _errs(buf, f"[{aid}] 步骤 {s.name} 的 parser_arg 引用了未定义的参数：{ref}")

        # ★★ T16（规范 §12.115）：本机通道**没有** `write_file` / `transfer` 这两件事 ——
        #   它们是 ssh 侧的（写盘走远端原子 mv、传文件走 scp，备份路径白名单也是 POSIX 的）。
        #   ⇒ 加载期就拒：让"走错通道"在**启动时**暴露，而不是在真跑时变成一堆看不懂的报错。
        if channel == "local" and (s.write_file or s.transfer):
            _errs(
                buf,
                f"[{aid}] channel: local 的步骤 {s.name} 用了 write_file / transfer —— "
                f"这两个能力属于 ssh 通道（规范 §12.115）",
            )

    # verify
    verify: list[Verify] = []
    raw_verify = data.get("verify")
    if not isinstance(raw_verify, list) or not raw_verify:
        _errs(buf, f"[{aid or path.name}] 至少要有一条 verify（禁止「执行完就假定成功」）")
    else:
        step_names = {s.name for s in steps + precheck}
        for i, item in enumerate(raw_verify):
            at = f"[{aid}] verify[{i}]"
            if not isinstance(item, dict):
                _errs(buf, f"{at} 必须是映射")
                continue
            src = str(item.get("from", ""))
            if src not in step_names:
                _errs(buf, f"{at} from「{src}」不是本动作里已有的步骤名")
            sev = str(item.get("severity", "fail"))
            if sev not in ("fail", "warn"):
                _errs(buf, f"{at} severity「{sev}」不合法（fail/warn）")
            verify.append(
                Verify(
                    name=str(item.get("name") or f"断言 {i + 1}"),
                    from_=src,
                    field=str(item["field"]) if item.get("field") else None,
                    severity=sev,
                    on_missing=str(item.get("on_missing") or "自证未通过"),
                )
            )

    # 结论里的占位符引用必须能对上（抓拼写错误）
    # ★ v1.6 修正：来源要**包括 precheck 的步骤名** —— 引擎本来就把预检结果写进 ctx
    #   （verify 的 from 也一直允许引用它们），只有这里漏了，会把
    #   "确认服务存在：{unit_exists}" 这种完全合理的写法误杀。
    # ★★ T16（规范 §12.115）：`channel: local` 的动作还允许引用**引擎注入**的变量
    #   （`{vm_name}` / `{vm_vmx}` / `{vmrun}` …，由 `vm_guard` / `probe_extra` 放进 ctx）。
    #   ★ 只对 local 通道放行：ssh 动作里写 `{vm_name}` 会在渲染期**静默变成（无）**
    #     —— 那正是本项目一直在防的"看着像结论"（§12.104.2 同族）。
    extra_ok = set(ENGINE_EXTRA_NAMES) if channel == "local" else set()
    conclusion = str(data.get("conclusion") or "")
    for tpl, label in ((conclusion, "conclusion"),):
        for path_str in TEXT_REF_RE.findall(tpl):
            head = path_str.split(".")[0]
            if head not in {s.name for s in steps + precheck} | defined | {"host"} | extra_ok:
                _errs(buf, f"[{aid}] {label} 里引用了未知来源：{{{path_str}}}")

    backup = _parse_backup(data.get("backup"), buf, aid or path.name, {p.name for p in params})

    if buf:
        return None

    return Action(
        id=aid,
        title=str(data["title"]),
        summary=str(data["summary"]),
        domain=str(data["domain"]),
        risk=risk,
        priority=priority,
        tags=[str(t) for t in (data.get("tags") or [])],
        note=str(data.get("note") or "").strip(),
        confirm=confirm if isinstance(confirm, dict) else None,
        params=params,
        backup=backup,
        precheck=precheck,
        steps=steps,
        verify=verify,
        conclusion=conclusion,
        source=str(path),
        channel=channel,
    )


def load_actions(actions_dir: Path) -> dict[str, Action]:
    """加载并校验 catalog/actions/*.yaml。任何一条不合格都拒绝启动（快速失败）。"""
    if not actions_dir.is_dir():
        raise OpsError(
            code="CATALOG_INVALID",
            reason=f"动作目录不存在：{actions_dir}",
            advice="确认 config.yaml 的 paths.actions 指向正确。",
        )

    files = sorted(actions_dir.glob("*.yaml"))
    if not files:
        raise OpsError(
            code="CATALOG_INVALID",
            reason=f"动作目录是空的：{actions_dir}",
            advice="至少放一个动作 YAML。",
        )

    errors: list[str] = []
    actions: dict[str, Action] = {}
    for path in files:
        data = load_yaml(path, what="动作定义")
        local: list[str] = []
        action = _parse_action(data, path, local)
        if local:
            errors.extend(local)
            continue
        assert action is not None
        if action.id in actions:
            errors.append(
                f"[{path.name}] id 与 {Path(actions[action.id].source).name} 重复：{action.id}"
            )
            continue
        actions[action.id] = action

    if errors:
        raise OpsError(
            code="CATALOG_INVALID",
            reason=f"{len(errors)} 处动作定义未通过校验",
            advice="按下面每一条指出位置修正动作 YAML（规范见 repo/docs/动作规范.md）。",
            detail="\n".join(f"· {e}" for e in errors),
        )
    return actions


def load_map(path: Path) -> dict[str, Any]:
    """加载覆盖地图账本 catalog/map.yaml。"""
    data = load_yaml(path, what="覆盖地图 map.yaml")
    if not isinstance(data, dict) or "entries" not in data:
        raise OpsError(
            code="CATALOG_INVALID",
            reason="map.yaml 缺少 entries 段",
            advice="按 repo/catalog/map.yaml 的模板补齐。",
        )
    return data


def reconcile(map_data: dict[str, Any], actions: dict[str, Action], stage: str | None = None) -> dict[str, Any]:
    """地图对账：算出每一域的实现率与**缺口清单**（区域可见是设计目标之一）。

    ★ T4（规范 §10.3）新增**双口径**：
      · 条数口径（既有，语义不动）：`entries` 里 已实现 / 总数 → 40/44（90.9%）。
        保留它是因为它**与历史可比**（这个数字已写进总纲、Git 提交与各结题回执）。
      · 加权口径（新增）：`entries` **+ `platform:` 段** 的 `Σw_done / Σw_all` ——
        ★ 关键修正：**平台能力（批量 / 备份 / 恢复 / 纳管）入账**，它们才是这工作台真正的价值。

    权重来自 `map.yaml` 的 `weights:` 段（一处集中，便于横向对账，见 §10.3.2）。
    权重表里查不到的条目 → 就地按基准兜底（P0=4 / P1=3 / P2=2 / P3=1，platform=4）并标 `fallback`，
    同时记进 `weighted.implicit_weight_ids`，让自检能红（防"权重表与账本两张表漂移"）。
    """
    entries = map_data.get("entries") or []
    platform = map_data.get("platform") or []
    weights = map_data.get("weights") or {}

    _BASE = {"P0": 4, "P1": 3, "P2": 2, "P3": 1}
    implicit: list[str] = []

    def _weight(eid: str, priority: str, is_platform: bool) -> dict[str, Any]:
        row = weights.get(eid)
        if isinstance(row, dict) and isinstance(row.get("w"), int) and 1 <= row["w"] <= 5:
            return {
                "weight": int(row["w"]),
                "weight_src": str(row.get("src") or "fallback"),
                "weight_why": str(row.get("why") or ""),
            }
        implicit.append(eid)
        return {
            "weight": 4 if is_platform else _BASE.get(priority, 1),
            "weight_src": "fallback",
            "weight_why": "兜底：map.yaml 的 weights: 段里缺少该条目，已按基准就地兜底 —— 应补进权重表",
        }

    rows: list[dict[str, Any]] = []
    for e in entries:
        eid = str(e.get("id", ""))
        rows.append({
            "id": eid,
            "domain": str(e.get("domain", "")),
            "label": str(e.get("label", "")),
            "risk": str(e.get("risk", "")),
            "priority": str(e.get("priority", "")),
            "stage": str(e.get("stage", "")),
            "kind": "action",
            "done": eid in actions,
            **_weight(eid, str(e.get("priority", "")), False),
        })
    impl = [r for r in rows if r["done"]]
    missing = [r for r in rows if not r["done"]]

    def rate(rows_impl: list[dict[str, Any]], rows_all: list[dict[str, Any]]) -> float:
        return round(len(rows_impl) / len(rows_all) * 100, 1) if rows_all else 0.0

    # ── platform: 段（T4 新增：既进加权分母，也作为独立清单展示）
    plat_rows: list[dict[str, Any]] = []
    for p in platform:
        pid = str(p.get("id", ""))
        plat_rows.append({
            "id": pid,
            "domain": "P",
            "label": str(p.get("label", "")),
            "risk": str(p.get("risk", "")),
            "priority": "",
            "stage": str(p.get("since", "")),
            "kind": "platform",
            "done": bool(p.get("done")),
            "status": str(p.get("status", "")),
            **_weight(pid, "", True),
        })

    # ── 每域：条数口径 + 加权口径并列（加权只统计 entries，platform 单列 C 域外）
    by_domain: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = r["domain"]
        by_domain.setdefault(d, {"total": 0, "done": 0, "w_all": 0, "w_done": 0})
        by_domain[d]["total"] += 1
        by_domain[d]["w_all"] += r["weight"]
        if r["done"]:
            by_domain[d]["done"] += 1
            by_domain[d]["w_done"] += r["weight"]
    for d, v in by_domain.items():
        v["rate"] = round(v["done"] / v["total"] * 100, 1) if v["total"] else 0.0
        v["w_rate"] = round(v["w_done"] / v["w_all"] * 100, 1) if v["w_all"] else 0.0
        v["name"] = (map_data.get("domains") or {}).get(d, d)

    p0 = [e for e in entries if str(e.get("priority")) == "P0"]

    all_rows = rows + plat_rows
    w_all = sum(r["weight"] for r in all_rows)
    w_done = sum(r["weight"] for r in all_rows if r["done"])
    items_done = sum(1 for r in all_rows if r["done"])

    by_src: dict[str, dict[str, int]] = {}
    for r in all_rows:
        s = r["weight_src"]
        by_src.setdefault(s, {"count": 0, "w_all": 0, "w_done": 0})
        by_src[s]["count"] += 1
        by_src[s]["w_all"] += r["weight"]
        if r["done"]:
            by_src[s]["w_done"] += r["weight"]

    return {
        "stage": stage or map_data.get("stage_scope", ""),
        "domains": map_data.get("domains") or {},
        # ── 口径 A：条数（语义与历史一致，不动）
        "total": len(entries),
        "done": len(impl),
        "rate": rate(impl, entries),
        "p0_total": len(p0),
        "p0_done": len([e for e in p0 if str(e.get("id")) in actions]),
        "p0_rate": rate([e for e in p0 if str(e.get("id")) in actions], p0),
        "by_domain": by_domain,
        "implemented": impl,
        "missing": missing,
        "demos": map_data.get("demos") or [],
        # ── 口径 B：加权（T4 新增，规范 §10.3.4）
        "platform": plat_rows,
        "weighted": {
            "w_all": w_all,
            "w_done": w_done,
            "w_missing": w_all - w_done,
            "rate": round(w_done / w_all * 100, 1) if w_all else 0.0,
            "items_total": len(all_rows),
            "items_done": items_done,
            "platform_total": len(plat_rows),
            "platform_done": sum(1 for r in plat_rows if r["done"]),
            "by_src": by_src,
            "implicit_weight_ids": implicit,
            # ★ 加权口径的"缺口清单"：按权重降序 —— 让"高权重还没做"一眼可见
            "missing": sorted(
                [r for r in missing] + [r for r in plat_rows if not r["done"]],
                key=lambda r: -r["weight"],
            ),
        },
    }
