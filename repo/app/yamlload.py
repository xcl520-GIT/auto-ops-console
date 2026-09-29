"""YAML 加载 —— 全项目**唯一**一处依赖第三方 YAML 解析器的地方。

取舍记录见 repo/docs/动作规范.md §7（阅读本文件前请先看那一节）：

  为什么需要第三方库：Python 标准库没有 YAML 解析器，只有 json。
  为什么选 A'：动作 YAML 是本项目最主要的人机接口，T2 要批量产出 20+ 个动作；
              改用 JSON 的写法成本会摊到每一个文件上，而 PyYAML 是一次性成本。
  为什么收敛到一个文件：将来若要改回 JSON 或自研子集解析器，只改 load_yaml() 即可。

解析器查找顺序（A' 方案）：
  ① 系统已安装的 PyYAML（pip / dnf install python3-pyyaml）
  ② 项目内嵌副本 repo/vendor/（pip install --target repo/vendor pyyaml）
  ③ 都没有 → 抛带「怎么装」指引的错误，而不是让人看一句 ImportError
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from app.errors import OpsError

_VENDOR = Path(__file__).resolve().parent.parent / "vendor"


def _try_import() -> tuple[Any, str]:
    try:  # ① 系统已安装
        import yaml  # type: ignore

        return yaml, "系统已安装的 PyYAML"
    except ModuleNotFoundError:
        pass

    if _VENDOR.is_dir():  # ② 项目内嵌
        if str(_VENDOR) not in sys.path:
            sys.path.insert(0, str(_VENDOR))
        try:
            import yaml  # type: ignore

            return yaml, f"项目内嵌副本（{_VENDOR}）"
        except ModuleNotFoundError:
            pass

    return None, ""


yaml, YAML_BACKEND = _try_import()

_INSTALL_HINT = (
    "动作与配置文件是 YAML 格式，需要一个 YAML 解析器。二选一：\n"
    "  · 项目内嵌（推荐，不污染全局）：python -m pip install --target repo\\vendor pyyaml\n"
    "  · 系统安装：python -m pip install pyyaml\n"
    "  · 部署到 RHEL/Rocky 管理机时改用发行版包：sudo dnf install -y python3-pyyaml"
)


def yaml_available() -> bool:
    return yaml is not None


def describe_backend() -> dict[str, Any]:
    """给 /api/health 与 selftest 用的自检信息。"""
    return {
        "available": yaml is not None,
        "backend": YAML_BACKEND,
        "vendor_dir": str(_VENDOR),
        "version": getattr(yaml, "__version__", None) if yaml is not None else None,
    }


def load_yaml(path: str | Path, *, what: str = "文件") -> Any:
    """读取一个 YAML 文件。失败时一律抛带建议的 OpsError。"""
    if yaml is None:
        raise OpsError(
            code="CONFIG_INVALID",
            reason=f"缺少 YAML 解析器，无法读取{what}：{path}",
            advice=_INSTALL_HINT,
        )

    p = Path(path)
    if not p.is_file():
        raise OpsError(
            code="CONFIG_INVALID",
            reason=f"{what}不存在：{p}",
            advice="确认路径拼写；或从模板重新生成该文件。",
        )

    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpsError(
            code="CONFIG_INVALID",
            reason=f"{what}读取失败：{p.name}",
            advice="确认文件未被其他程序占用、编码为 UTF-8。",
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc

    try:
        data = yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError 及其它
        raise OpsError(
            code="CONFIG_INVALID",
            reason=f"{what}语法错误：{p.name}",
            advice="按报错的行号检查缩进、引号与多行块（|）写法。注意正则要用单引号包裹。",
            detail=str(exc),
        ) from exc

    return data if data is not None else {}
