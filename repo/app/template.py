"""模板渲染（规范 §12.4）—— 纯替换、零逻辑，★ 不引 Jinja2。

三点必须守住（对应 `docs/动作规范.md` §12.4 的表）：

 ① **同一个实现**：变量替换直接复用 `catalog.render_argv_element()`，
    不造第二套语法（项目里已经有 `{{ 参数 }}` 与 `{步骤.字段}` 两套，不再加第三套）。
 ② **缺参数即报错中止**：模板里用到"没定义 / 有定义但值为空"的参数 → 抛 `TEMPLATE_PARAM_MISSING`。
    ★ 绝不静默渲染成空值 —— 那会把配置写坏，而界面还显示"成功"
    （T5 开题单 §8.2 坑 #2：这是"看起来成功"的典型形态）。
 ③ **幂等来自比对**：写盘前先算渲染内容的 sha256 与目标机现有文件比，**相同则不写**。
    这是"重复部署零变更"的**来源**，不是事后解释。比对与写盘在 `app/recipe.py` 里做，
    本模块只负责"把内容正确地渲染出来"。

禁止的能力（加载期即拒，规范 §12.4）：条件 / 循环 / 表达式 / 函数调用 / 过滤器 / 内联脚本。
判据：出现 Jinja 的块记号 `{%` 或注释记号 `{#` 一律拒绝 —— 本项目**没有** Jinja，
出现它们说明有人在用一套不存在的能力写模板。
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from app.catalog import PARAM_REF_RE, ParamValue, render_argv_element
from app.errors import OpsError

#: 模板里要写**字面的** `{{` 时用的唯一转义语法（T5 定死，规范 §12.4）
LITERAL_OPEN = "{{ '{{' }}"

#: 渲染期用来"先把转义保护起来"的哨兵。含 \x00，正常模板里不可能出现。
_SENTINEL = "\x00AOC-LITERAL-LBRACE\x00"

#: Jinja 痕迹（本项目不引 Jinja2，出现即拒）
_JINJA_MARKERS = ("{%", "{#")

#: 模板根目录名（相对 catalog/）
TEMPLATE_DIR_NAME = "templates"


def sha256_hex(text: str) -> str:
    """渲染内容的指纹。与目标机 `sha256sum` 的算法一致（十六进制小写）。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_no_jinja(text: str, where: str) -> None:
    for marker in _JINJA_MARKERS:
        if marker in text:
            raise OpsError(
                code="TEMPLATE_INVALID",
                reason=f"{where} 里出现了 Jinja 记号「{marker}」",
                advice=(
                    "本项目**不引 Jinja2**（vendor 里只有 PyYAML）。模板只支持变量替换："
                    "写 {{ 参数名 }}；需要条件/循环请把它挪到配方步骤或平台侧。"
                    "（要写真正的 {{ ，请用 {{ '{{' }} ）"
                ),
            )


def template_root(catalog_dir: Path) -> Path:
    return Path(catalog_dir) / TEMPLATE_DIR_NAME


def resolve_template(catalog_dir: Path, rel: str, *, where: str = "模板") -> Path:
    """把配方里的 `template:` 相对路径解析成磁盘路径。

    ★ 安全：只允许 `catalog/templates/**` 之内的**相对**路径；拒绝绝对路径、拒绝 `..`、
      拒绝解析后跳出模板根目录（防"配方把任意文件当模板读出来"）。
    """
    rel = str(rel or "").strip()
    if not rel:
        raise OpsError(code="TEMPLATE_INVALID", reason=f"{where} 缺少 template 路径",
                       advice="写相对路径，例如 nginx/nginx.conf。")
    p = Path(rel)
    if p.is_absolute() or rel.startswith("/") or rel.startswith("\\"):
        raise OpsError(code="TEMPLATE_INVALID", reason=f"{where} 必须是相对路径：{rel}",
                       advice=f"相对于 catalog/{TEMPLATE_DIR_NAME}/ 写，例如 nginx/nginx.conf。")
    if ".." in p.parts:
        raise OpsError(code="TEMPLATE_INVALID", reason=f"{where} 不得包含 ..：{rel}",
                       advice="模板只能取自模板目录内部。")
    root = template_root(catalog_dir).resolve()
    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise OpsError(code="TEMPLATE_INVALID", reason=f"{where} 跳出了模板目录：{rel}",
                       advice=f"模板必须放在 catalog/{TEMPLATE_DIR_NAME}/ 之内。") from None
    return target


def load_template(catalog_dir: Path, rel: str, *, where: str = "模板") -> tuple[str, Path]:
    """读取模板文件并做静态校验。返回 (文本, 磁盘路径)。"""
    path = resolve_template(catalog_dir, rel, where=where)
    if not path.is_file():
        raise OpsError(
            code="TEMPLATE_NOT_FOUND",
            reason=f"{where} 文件不存在：{rel}",
            advice=f"在 catalog/{TEMPLATE_DIR_NAME}/{rel} 放一个模板文件（进 Git，可读可改）。",
        )
    text = path.read_text(encoding="utf-8")
    check_no_jinja(text, f"{where}（{rel}）")
    return text, path


def render_template(
    text: str,
    params: dict[str, ParamValue],
    *,
    where: str = "模板",
    allowed_extra: dict[str, str] | None = None,
) -> str:
    """把模板里的 `{{ 参数名 }}` 全部替换掉。

    ★ 与 `render_argv_element()` **同一个实现**（规范 §12.4 要求"不造第二套"），
      本函数只负责在它前面加两道闸门：

      · 引用必须**已定义**（否则报"未定义的参数"，而不是渲染成空串）
      · ★ 引用到的参数**不能是空值** —— 空值渲染进配置 = 配置被写坏，
        但界面会显示成功。这正是"必填缺失必须报错中止"的落点。
    """
    s = text.replace(LITERAL_OPEN, _SENTINEL)

    undefined: list[str] = []
    empty: list[str] = []
    for ref in PARAM_REF_RE.findall(s):
        if ref in (allowed_extra or {}):
            continue
        pv = params.get(ref)
        if pv is None:
            undefined.append(ref)
        elif str(pv.value) == "":
            empty.append(ref)

    if undefined:
        raise OpsError(
            code="TEMPLATE_PARAM_MISSING",
            reason=f"{where} 引用了未定义的参数：{'、'.join(sorted(set(undefined)))}",
            advice="在配方的 params 里定义它，或改正模板里的占位符拼写。",
        )
    if empty:
        raise OpsError(
            code="TEMPLATE_PARAM_MISSING",
            reason=(
                f"{where} 用到的参数是**空的**：{'、'.join(sorted(set(empty)))}"
                " —— 已中止，绝不把空值写进配置文件"
            ),
            advice="把该参数填上（或在配方里给它一个默认值）；空值渲染进配置会写坏服务。",
        )

    out = render_argv_element(s, params, allowed_extra or {})
    return out.replace(_SENTINEL, "{{")
