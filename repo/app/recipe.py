"""配方引擎（规范 §12）：把 Action 编排成「一件完整的运维事」。

★ 本模块是**编排层**，不是第二套执行引擎
------------------------------------------------
一次配方执行 = 一串 `Engine.run()`：

    · 配方引擎**不碰 ssh、不碰 argv、不碰 transport**
    · 每个配方步骤仍然是一次**普通动作任务**（独立 `task_id` → 独立留证 / 回放 / 备份 / 恢复）
    · 因此 §4 的三层安全契约对配方**天然成立** —— 配方里根本**没有**可以写命令的地方

三条设计宪法（违反即返工，规范 §12.0）
--------------------------------------
① 配方只声明「要什么」（`expect`），**判定与分支一律走平台侧**（`app/expect.py`）；
② ★「没变」**必须可断言** —— 统一采集 `changed`（`app/changed.py`），汇总成变更清单，
   **幂等的验收 = 第二次该清单为空**；未知来源一律 `unknown`，**不许默认 False**；
③ 每个正向步骤都要有**反向操作** —— 停止 / 卸载·保留数据 / 卸载·全删。

四种执行模式（`mode`）
----------------------
· `deploy`           正向部署（preflight → steps → 触发的步骤 → health）
· `stop`             只停服务（保留一切）
· `uninstall_keep`   卸载但**保留数据**（停服 + 撤自启 + 删配置，`keep_data` 明确不删）
· `uninstall_purge`  卸载**全删**（上面 + 删 `purge_paths` + 卸包）—— 🔴 手输确认词

★ 被 `notify` 触发的步骤（`trigger_only: true`）在**主序列跑完之后、健康检查之前**执行。
  这样「配置校验」一定发生在「重启」之前；而且第二次跑（无变更）根本不会触发它 —— 幂等靠这个成立。
"""
from __future__ import annotations

import posixpath
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.catalog import (
    NAME_RE,
    BackupItem,
    Param,
    ParamValue,
    _parse_params,
    render_argv_element,
    render_text,
    validate_params,
)
from app.changed import changed_for_action, describe as describe_changed, has_rule
from app.config import AppConfig, Host
from app.errors import OpsError
from app.expect import evaluate as eval_expect, render_spec, validate_expect
from app.engine import Engine, RESTORE_CONFIRM_TEXT
from app.store import Store, new_recipe_run_id, new_task_id, now_iso
from app.template import load_template, render_template, sha256_hex
from app.yamlload import load_yaml

RECIPE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
RISKS = ("green", "yellow", "red")
MODES = ("deploy", "stop", "uninstall_keep", "uninstall_purge")

#: 顶层键白名单（规范 §12.1）
TOP_KEYS = {
    "id", "name", "version", "summary", "risk",
    "params", "preflight", "steps", "health", "uninstall", "note",
    # ★★ T8·S6 新增（规范 §12.32.4）：**正向部署也要手输的确认词** ——
    #   本话题第一次出现"正向部署里含 red 动作"（`k8s-init` 要拆旧集群）。
    #   在此之前 deploy 模式只要一个"点一下"的勾选；而 red 的破坏性远不止点一下
    #   （总纲铁律 9：red 的确认词**只能由人输入**）。
    "deploy_confirm_text",
    # ★★ T16（规范 §12.6.5）新增：**非服务类配方的开口**。
    #   uninstall 硬规则是按"装一个服务"写的；"开一台虚拟机、干完事、关回去"这类编排型配方
    #   既不装包也不写配置 ⇒ 没有可停的服务 / 可撤的自启 / 可删的路径。
    #   ★ 开口只认「**声明 ＋ 写明理由**」：`no_uninstall` 必须配 `no_uninstall_why`（裸开关一律拒）。
    "no_uninstall", "no_uninstall_why",
}

#: ★ 明确拒绝的键（出现即报错，规范 §12.1）
FORBIDDEN_KEYS = {
    "run": "动作层才写命令；配方只能引用已登记动作",
    "command": "同上：配方不许写命令",
    "cmd": "同上：配方不许写命令",
    "shell": "同上：配方不许写命令",
    "argv": "同上：配方不许写命令",
    "script": "配方不许内联脚本",
    "inline": "配方不许内联脚本",
    "if": "配方不许写分支 —— 要什么写 expect，怎么判断走平台",
    "else": "配方不许写分支",
    "expr": "配方不许写表达式",
    "eval": "配方不许写表达式",
    "loop": "配方不许写循环",
    "for": "配方不许写循环",
    "while": "配方不许写循环",
    "switch": "配方不许写分支",
}

STEP_KEYS = {
    "name", "title", "action", "args", "template", "dest", "mode",
    "notify", "trigger_only", "optional", "when", "note",
    # ★ `wait` 必须在白名单里 —— 否则它会被当成"多余的键"，
    #   于是"这是预留给 T16 的能力"这句更有用的提示永远发不出来（自检当场抓到的）。
    #   ★★ T16（规范 §12.120）：**它现在真的实现了** —— 不再只是白名单里的一个名字。
    "wait",
}

#: ★★ T16（规范 §12.120）：`wait` 步骤自己的键白名单。
#:   语义 = **轮询一条 expect，直到它成立或超时**（判的是"条件"，不是"时间"）。
WAIT_KEYS = {"expect", "timeout_sec", "interval_sec", "fail_reason"}

UNINSTALL_KEYS = {
    "stop", "disable", "remove_config", "purge_paths", "keep_data",
    "remove_packages", "purge_confirm_text", "stop_confirm_text",
    # ★ v1.6 修订（规范 §12.6.3）：停止 / 「保留数据」卸载**之后**应当成立的事实。
    #   缺了它就必然拿部署段那句 `state: active` 去判"刚停完" —— 于是「停止」永远显示失败。
    "health",
}

#: ★ 模式的中文名 —— 闸门文案与结论**共用一处**，避免两处不一致
_MODE_TXT = {
    "deploy": "部署",
    "stop": "停止服务",
    "uninstall_keep": "卸载（保留数据）",
    "uninstall_purge": "卸载（全删）",
}

#: 卸载时「删路径」的统一出口（规范 §12.6 约束 2：只能经它删）
REMOVE_ACTION_ID = "file.remove"
PKG_REMOVE_ACTION_ID = "pkg.remove"

#: ★★ v1.8（规范 §12.16）：**卸载类动作** —— "目标本就不存在 ⇒ 已达终态、不中止"这条规矩
#:   只对它们生效。判据不是"动作 id 里带 remove"，而是这个事实：
#:   **它们的预检恰好就是"目标在不在 / 还在不在"**
#:     · `file.remove`  的预检 `before`          = `ls -ld <路径>`   （不在 → rc=2 → 预检不通过）
#:     · `pkg.remove`   的预检 `must_installed`  = `rpm -q <包>`     （没装 → rc=1 → 预检不通过）
#:     · ★ `svc.stop`   的预检 `unit_exists`     = `systemctl cat <unit>`（单元不在 → 非 0）
#:     · ★ `svc.disable` 的预检 `unit_exists`     = 同上
#:   ⇒ 在这四个动作上，"PRECHECK_FAILED" 的语义**就是**"目标已经不存在了"。
#:
#: ★★ **后两个是 v1.8·S2 真跑补进来的（详见规范 §12.16 规矩 4 的由来）**：
#:   在"包已被卸掉"的现状下点「卸载·全删」——
#:   `svc.stop` 的 `systemctl cat nginx` 必然失败（**单元文件随包一起没了**）⇒ 配方**第一步就中止**，
#:   后面的路径与包**一条都没删**（"全删"这个最危险的按钮又点了一次没效果，与 T6 那个缺陷同型）。
#:   ⇒ 一句话：**"卸载幂等"有两层 —— 路径层（东西不在了）与服务层（服务不在了）**。
#:
#: ★ 新增动作时必须先想一想"它的预检是不是也在问'目标在不在'" ——
#:   不是的话就**不能**列在这里（否则会把"权限不足 / 参数写错"这类真失败吞成"已达终态"）。
UNINSTALL_TERMINAL_ACTIONS = frozenset({
    REMOVE_ACTION_ID, PKG_REMOVE_ACTION_ID, "svc.stop", "svc.disable",
})

#: ★★ 这条规矩**只在非 deploy 模式**生效（规范 §12.16 规矩 4）。
#:   理由：deploy 段里的 `svc.stop` 预检失败是**真失败** ——
#:   我们正准备重启一个刚改过配置的服务，它却不见了，那是**必须停下来说清楚**的事。
#:   ★ 同一句 `PRECHECK_FAILED`，在"卸载"里是终态、在"部署"里是故障 ——
#:     差别不在命令，而在**这一次操作的目标**（卸载的目标就是"让它不在"）。
UNINSTALL_MODES = frozenset({"stop", "uninstall_keep", "uninstall_purge"})

#: ★★ T7·S4（规范 §12.20）：「回到这次部署前」的**组级确认词**（服务端校验，点一下不算）。
#:   ★ 为什么要**另起一句**而不是沿用单点恢复的「确认恢复」：
#:     组回退一次会覆盖**多个**路径，破坏性严格大于单点 ⇒ 闸门强度**只能更强、不能更弱**（§12.6.2）。
#:   ★ 组内每一项**仍然走单点恢复那条老路**（不另写一套恢复逻辑）⇒ 平台把内部那句
#:     `RESTORE_CONFIRM_TEXT` **转达**下去，与 §12.6.1「配方转达 red 动作确认词」同一个做法。
GROUP_RESTORE_CONFIRM_TEXT = "我已确认回到这次部署前"


# ════════════════════════════════════════════════════════════ 两条判定（纯函数）

# ★ 为什么把这两个判定**抽成模块级纯函数**：
#   它们是"卸载类操作到底算成功没有"这条规矩的**全部**所在，而这个项目的纪律是
#   **规矩必须能被离线自检钉死**（与 `engine.conclusion_with_failure_banner`、
#   `changed.changed_for_action` 同一个理由）—— 藏在 `RecipeRunner` 的方法里就只能靠真跑验，
#   而真跑恰恰是最不方便天天跑的那一种。


def uninstall_step_terminal(action_id: str, mode: str, task_status: str,
                            error_code: str | None) -> bool:
    """卸载段里的这一步是否**已达终态**（规范 §12.16 规矩 1 / 2 / 4）。

    成立条件**四条同时**满足（少一条都不算，这正是"判据必须仍能证伪"的落点）：

      1. 动作是**卸载类**（`UNINSTALL_TERMINAL_ACTIONS`：`file.remove` / `pkg.remove` /
         `svc.stop` / `svc.disable`）—— 它们的预检问的就是"目标在不在 / 还在不在"；
      2. ★ **这一次是卸载/停止，不是部署**（`UNINSTALL_MODES`）——
         同一句 `PRECHECK_FAILED`，在"卸载"里是终态、在"部署"里是故障；
      3. 任务状态是 `aborted`（被预检拦下，**目标机零改动**）；
      4. 失败码是 `PRECHECK_FAILED`。

    ⇒ 结论："目标本就不存在，这是**已达终态**，不是失败"。

    ★ **不满足第 4 条的一律 False**：权限不足 / 备份失败 / 依赖冲突 / SSH 不可达……
      全部照旧中止（检查清单 51：**写坏了要会红**）。
    """
    return (task_status == "aborted"
            and mode in UNINSTALL_MODES
            and action_id in UNINSTALL_TERMINAL_ACTIONS
            and error_code == "PRECHECK_FAILED")


def precheck_means_done(action: Any, task: Any) -> tuple[bool, str]:
    """★★ v1.11（规范 §12.33）：这一步的预检**「不成立 = 已达终态」**了吗。

    背景（T8·S6）：`kubeadm init` / `join` / `reset` 这类**一次性引导动作**，
    预检问的正是"**目标是不是还没做成**"。于是配方第二次跑时，预检必然不成立 ——
    若按"预检失败 ⇒ 中止"的老规矩处理，**「再点一次」就永远做不到**（验收 #2 落空）。

    ★★ 但**不能**把预检放宽来解决：预检就是"这台机器该不该被引导"的闸门。
    放宽它 = 让 `init` 落在已经初始化过的机器上（kubeadm 会拒绝并留下半个集群）。

    ⇒ 正确做法是**换一个判读**：**预检不成立 ⇒ 目标已经是我想要的样子了**。

    成立条件**四条同时**满足（少一条都不算 —— 这正是"判据必须仍能证伪"的落点）：

      1. 任务状态是 `aborted`（被预检拦下，**目标机零改动**）；
      2. 失败码是 `PRECHECK_FAILED`；
      3. ★★ **失败的那一步，恰好就是动作 `precheck` 里声明了 `means_done` 的那一步** ——
         这个"恰好"是关键：一个动作有多条预检，各自的语义**并不相同**。
         「这台机器上有没有旧集群」可以是终态判据；
         「`kubeadm` 这个工具在不在」**永远不是**（缺工具必须中止，绝不能被吞成"已达终态"）。
         ⇒ 所以守卫是**步骤级**的，不是动作级 —— 别把整条动作的失败一起放行。
      4. 那一步带了**理由**（装载期已强制要求，这里再兜一层）。

    ★ 与 `uninstall_step_terminal` 的分工：那条管"卸载类 + 非 deploy 模式"，
      这条管"**动作作者明确声明过的终态预检**"，两者**并存**、互不代替。

    返回 `(是否终态, 理由)`；不成立返回 `(False, "")`。
    """
    if getattr(task, "status", None) != "aborted":
        return False, ""
    err = getattr(task, "error", None)
    if err is None or getattr(err, "code", None) != "PRECHECK_FAILED":
        return False, ""
    failed = next((s for s in (getattr(task, "steps", None) or [])
                   if getattr(s, "status", None) not in ("ok", "skipped")), None)
    if failed is None:
        return False, ""
    st = action.precheck_step(str(getattr(failed, "name", "") or ""))
    if st is None or not getattr(st, "means_done", False):
        return False, ""
    why = str(getattr(st, "means_done_why", "") or "").strip()
    if not why:
        return False, ""
    return True, why


def step_blocks_recipe(row: dict[str, Any]) -> bool:
    """这一步失败**该不该中止配方**（规范 §12.6.5 / §12.16）。

    配方级的主判据，只有一条：**状态不是 ok / skipped，且这一步没被标为可容忍**。

    ★ `skipped` 在这里是**"过了"**：它既包含"条件不满足没跑"，也包含
      **"删除类目标本就不存在 ⇒ 已达终态"**（§12.16）—— 两者都不该拖垮整条配方。
    ★ 真的没删干净由**收敛检查**抓（`purge_convergence_expects`）：**跳过 ≠ 成功**。
    """
    return row.get("status") not in ("ok", "skipped") and not row.get("optional")


def purge_convergence_expects(recipe: Any, rendered: dict[str, Any]) -> list[dict[str, Any]]:
    """「全删」的收敛检查（规范 §12.16 规矩 3）：**包 **和** 路径**两类都要判。

    ★ 为什么必须两类都判：只判包 ⇒ "配置 / 数据目录还在"**没有任何判据能发现**，
      只要删除那几步没报错，报告就说"全删完成"（**假绿**）。反过来只判路径也一样漏。

    ★ 路径用的是**渲染后**的真值（`run.uninstall_rendered`），不拿 `{{ 参数 }}` 原文去比对 ——
      否则判的会是"字面量在那里吗"，永远判不过（清单 37 同族）。

    ★ 判据分工：**包**走 `pkg.installed`（rpm 数据库），**路径**走 `file.stat`（`ls -ld`）——
      两条都是**只读**来源（配方里依旧没有一处命令）。
    """
    expects: list[dict[str, Any]] = [
        {"expect": {"absent": {"action": "pkg.installed", "args": {"pkg": pkg}}},
         "fail_reason": f"包「{pkg}」仍然装着 —— 全删没有收敛",
         # ★ 机器可读的"这一条在判谁"（规范 §12.16 规矩 6）：
         #   结论要按它把"已删除 / 已达终态 / 没删掉"三段分开，
         #   ★ **不许靠下标配对** —— 顺序一错就会**静默念错**（这个项目最不能接受的那类缺陷）。
         "converge": {"kind": "package", "value": pkg}}
        for pkg in getattr(recipe.uninstall, "remove_packages", []) or []
    ]
    pairs: list[tuple[str, str]] = []
    for p in rendered.get("remove_config") or []:
        pairs.append((str(p), "配置"))
    for p in rendered.get("purge_paths") or []:
        pairs.append((str(p), "数据/目录"))
    for p, what in pairs:
        if not str(p).startswith("/"):
            # 没渲染出真值的（空串等）不参与判定 —— 免得把它判成"根目录还在"
            continue
        expects.append({
            "expect": {"absent": {"action": "file.stat", "args": {"path": str(p)}}},
            "fail_reason": f"{what}路径「{p}」仍然存在 —— 全删没有收敛",
            "converge": {"kind": "path", "value": str(p)},
        })
    return expects


def lint_recipe(recipe: Recipe, actions: dict[str, Any]) -> list[dict[str, Any]]:
    """**配方体检**（T7·S5 · 规范 §12.21）：一份配方"写全了没有 / 判得出来没有"。

    ★ 它**不连目标机**（全是静态检查）：目的是让"自己写配方"的人在**点部署之前**就知道
      哪几处还欠着 —— 而不是等跑出一条奇怪的失败才回头猜。

    每条结果三态：`ok` / `warn`（能跑，但有条边界要知道）/ `fail`（真有问题，别拿去跑）。
    """
    out: list[dict[str, Any]] = []

    def add(name: str, level: str, detail: str) -> None:
        out.append({"name": name, "level": level, "detail": detail})

    un = recipe.uninstall
    # ★★★ T16·S6（规范 §12.6.5 / §12.125）：**「非服务类配方」的开口，体检必须认账**。
    #   现场（真缺陷）：S5 开了这个口、**装载器**也认，但这一族判据**只看 `un.stop` / `un.disable`**
    #   ⇒ 一份合法的"不装服务"的配方（`vm-cycle`）照样被判 **fail**
    #   ⇒ `tools\recipe-check.py` 退出码 **1** ⇒ 自检 ㉖ 红（「配方体检的命令行入口跑得动」）。
    #   ★ 教训与 §12.122 同族：**信息在，但没送到读它的那一方** ⇒ 结论错了，且**一处都不报错**。
    #   ★ 开口**没有被放宽**：`no_uninstall` 仍必须配 `no_uninstall_why`，且与 `uninstall` 段**互斥**
    #     —— 两条都在**装载期**就拒（`_parse_recipe`），所以走到这里的必然是"声明 ＋ 写明理由"。
    no_un = bool(getattr(recipe, "no_uninstall", False)) and bool(
        str(getattr(recipe, "no_uninstall_why", "") or "").strip())
    un_why = ("★ 声明了 no_uninstall ＋ 写明了理由：本配方不装服务、不写文件 ⇒ "
              "没有可停的服务 / 可撤的自启 / 可删的路径（规范 §12.6.5）")
    # ① 反向操作：§12.6 要求"停 / 撤自启 / 删配置 / 删目录 / 卸包"都想过一遍
    if no_un or un.stop or un.disable:
        add("反向操作：停服 / 撤自启", "ok",
            un_why if no_un else f"stop {len(un.stop)} 条 · disable {len(un.disable)} 条")
    else:
        add("反向操作：停服 / 撤自启", "fail",
            "★ 一条都没有：卸不干净（服务还在跑）—— 配方必须有反向操作（规范 §12.6）")
    if no_un or un.remove_config or un.purge_paths:
        add("反向操作：删配置 / 删目录", "ok",
            un_why if no_un else f"remove_config {len(un.remove_config)} 条 · purge_paths {len(un.purge_paths)} 条")
    else:
        add("反向操作：删配置 / 删目录", "warn",
            "一条都没有：如果这份配方**确实不写任何文件**（纯装包 + 起服务）那就正常；"
            "否则「全删」会留下我们写出来的东西")
    if no_un or un.remove_packages:
        add("反向操作：卸包", "ok", un_why if no_un else "、".join(un.remove_packages))
    else:
        add("反向操作：卸包", "warn", "没写 remove_packages ⇒「全删」不会卸包（有时是有意的：装了公共依赖）")
    if un.keep_data:
        add("「保留数据」承诺", "ok", "、".join(un.keep_data))
    elif un.purge_paths:
        add("「保留数据」承诺", "warn", "有 purge_paths 但 keep_data 为空：**「保留数据」会把数据一起删掉吗？** 去核一遍")

    # ② 前置护栏 / 健康检查
    add("前置护栏（preflight）", "ok" if recipe.preflight else "warn",
        f"{len(recipe.preflight)} 条" if recipe.preflight else
        "没写 preflight：没有「装了它会出事」那道闸门（宁可不写，也不写假闸门 —— 规范 §12.6）")
    kinds = []
    for e in recipe.health:
        kinds.extend(str(k) for k in (e.get("expect") or {}))
    if not kinds:
        add("健康检查", "fail",
            "★ 一条都没有：配方**判不出「这件事做成了没有」** —— 用户的按钮会永远显示成功")
    else:
        strong = [k for k in kinds if k in ("responds", "http_status")]
        if strong:
            add("健康检查", "ok",
                f"{len(kinds)} 条，其中「真问一句」的有 {len(strong)} 条（{'、'.join(sorted(set(strong)))}）")
        else:
            add("健康检查", "warn",
                f"{len(kinds)} 条，但**全是旁证**（{'、'.join(sorted(set(kinds)))}）："
                "「单元在跑 / 端口在听」不等于「它真的能用」。★ 有现成探活动作就补一条 `responds`，"
                "HTTP 服务可以用 `http_status`（规范 §12.11）")

    # ③ 幂等可断言性（宪法 ②）：能变更的步骤，平台必须判得出"变了没有"
    unregistered: list[str] = []
    for st in recipe.steps:
        if st.kind != "action" or not st.action:
            continue
        a = actions.get(st.action)
        if a is None or a.risk == "green":
            continue
        if not has_rule(a):
            unregistered.append(st.action)
    if unregistered:
        add("幂等可断言（changed 规则）", "warn",
            "★ 这些能变更的动作平台**判不出「变了没有」**：" + "、".join(sorted(set(unregistered)))
            + " ⇒ 第二次跑不会给出「清单为空」这个幂等证据（先在 `app/changed.py` 登记规则）")
    else:
        add("幂等可断言（changed 规则）", "ok", "所有能变更的步骤平台都判得出「变了没有」")

    # ④ 检查点（能不能回退）
    cps = [st.name for st in recipe.steps if st.kind in ("template", "transfer", "write_file")]
    add("可回滚点（检查点）", "ok" if cps else "warn",
        ("会覆盖既有文件的步骤：" + "、".join(cps)
         + "（★ 只有「覆盖前文件已存在」时才会登记检查点；全新部署那一次通常是 0 个）") if cps else
        "没有任何会覆盖既有文件的步骤 ⇒ 这次执行**不会有**可回滚点（「回到部署前」也没有东西可回）")

    # ⑤ 参数
    forced = [p.name for p in recipe.params if p.required and p.default in (None, "")]
    add("参数", "ok" if not forced else "warn",
        ("这些参数**必填且没有默认值**，每次都要填：" + "、".join(forced)) if forced
        else f"{len(recipe.params)} 个参数都有默认值（可以直接点执行）")

    # ⑥ 批量闸门（规范 §12.18）
    add("批量闸门", "ok" if recipe.risk != "red" else "warn",
        "green 直接跑 / yellow 需二次确认" if recipe.risk != "red"
        else "★ 本配方是 **red**：禁止批量（不提供开关，规范 §12.18）")
    return out


def lint_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    """体检结论：`fail` 优先于 `warn` 优先于 `ok`（给界面一个一眼可读的总判）。"""
    levels = [i["level"] for i in items]
    overall = "fail" if "fail" in levels else ("warn" if "warn" in levels else "ok")
    return {
        "overall": overall,
        "ok": len([x for x in levels if x == "ok"]),
        "warn": len([x for x in levels if x == "warn"]),
        "fail": len([x for x in levels if x == "fail"]),
        "items": items,
    }


def batch_gate(recipe: Any, mode: str) -> dict[str, Any]:
    """**配方批量闸门**（规范 §12.18）—— 纯函数，便于离线钉死。

    | 风险 | 批量 |
    |---|---|
    | `green` | 直接跑 |
    | `yellow` | ★ 要**二次确认** |
    | `red` | ★★ **禁止批量**（**不提供配置开关** —— 沿用 T3 的硬规矩） |

    ★ 为什么 red 不给开关：批量会把**一次手误放大到 N 台**，而 red 恰好是不可 undo 的那一类。
    ★ 为什么闸门挂在**配方**的 risk 上而不是"这一次模式"上：配方 YAML 里**不许声明"我要批量"**
      （§9.3 的老规矩）—— 批量是**平台能力**，配方只描述"这件事怎么做"。
    """
    risk = str(getattr(recipe, "risk", ""))
    name = str(getattr(recipe, "name", ""))
    if risk == "red":
        return {
            "allowed": False, "needs_confirm": False, "risk": risk,
            "reason": f"配方「{name}」的风险等级是 red：**禁止批量**（平台不提供这个开关）",
            "advice": ("批量会把一次手误放大到 N 台，而 red 恰好是不可 undo 的那一类。"
                       "要么逐台执行（每台都要手输确认词），要么先把配方降到非 red。"),
        }
    if risk == "yellow":
        return {
            "allowed": True, "needs_confirm": True, "risk": risk,
            "reason": f"配方「{name}」是 yellow：**批量需要二次确认**",
            "advice": "",
        }
    return {"allowed": True, "needs_confirm": False, "risk": risk, "reason": "", "advice": ""}


def _batch_key(item: dict[str, Any]) -> str:
    """横向对照的**分组键**：执行状态 + **收敛检查结果**（规范 §12.18）。

    ★ 为什么不把"变更了几步"放进键：**两台机器的初始现状不同时，变更步数天生不同**
      （一台是全新的、一台早就装过）—— 那是"多机治理"的话题（T7 开题单 §4 明确不做）。
      把它算成差异，会让**每一份批量报告都在喊狼来了**；喊多了就没人看这张表了。
      变更情况单独放在 `changed_hosts` 里**作为信息给出**，不参与"一致 / 不一致"的判定。
    ★ 为什么必须看收敛检查：配方的"跑完没报错"**不等于**"事情成了"（§12.6.5 / §12.16）——
      T3 的动作批量是"一步 + 自证"，配方批量是"多步 + 收敛检查"，这一层不能照抄。
    """
    if item.get("status") != "ok":
        return f"{item.get('status') or '?'} / （没跑完，谈不上收敛）"
    total = int(item.get("checks_total") or 0)
    failed = int(item.get("checks_failed") or 0)
    if not total:
        return "ok / （这次没有收敛检查）"
    return f"ok / 收敛检查 {total - failed}/{total} 过"


def batch_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    """批量的**横向对照**（规范 §12.18）：只做"**汇总 + 找出不一样的**"，不做"取平均"。

    ★ 返回结构与 T3 的 `engine.batch_diff` **刻意同形**（`consistent` / `groups` /
      `differences` / `note`）—— 同一个概念不养两套形状（§9.9「Api 方法存在 ≠ 接口可用」
      的同族教训：形状不一致时，必然有一个消费者拿不到数据，而且不报错）。
    ★ 失败隔离的前提是**看得见**：任何一台不一样，都必须一眼看出来。
    """
    groups: dict[str, list[str]] = {}
    for i in items:
        groups.setdefault(_batch_key(i), []).append(str(i.get("host_name") or i.get("host_id")))

    differences: list[dict[str, Any]] = []
    for key, hosts in groups.items():
        if len(hosts) == len(items):
            continue                      # 全员都在这一组 ⇒ 没有差异
        reasons = []
        for i in items:
            nm = str(i.get("host_name") or i.get("host_id"))
            if nm in hosts and i.get("status") != "ok":
                why = (i.get("error") or {}).get("reason")
                if why:
                    reasons.append(f"{nm}：{why}")
        differences.append({"conclusion": key, "hosts": hosts, "count": len(hosts),
                            "reasons": reasons})

    ok = [i for i in items if i.get("status") == "ok"]
    return {
        "total": len(items),
        "ok": len(ok),
        "failed": len(items) - len(ok),
        "healthy": len([i for i in ok if not i.get("checks_failed")]),
        "changed_hosts": [i.get("host_id") for i in ok if i.get("changed_steps")],
        "consistent": len(groups) <= 1,
        "groups": [{"conclusion": k, "hosts": v, "count": len(v)} for k, v in groups.items()],
        "differences": differences,
        "note": ("差异按「**执行状态 + 收敛检查结果**」判定，**不按「命令返回 0」**，"
                 "也不比对整段结论（各台的路径 / 时间戳天然不同 —— T3 已实测修正过这条）。"
                 "★ 变更步数不参与判定：两台初始现状不同时它天生不同（多机治理不在本话题）。"),
    }


# ════════════════════════════════════════════════════════════ 数据模型


@dataclass
class RecipeStep:
    name: str
    title: str = ""
    action: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    template: str | None = None
    dest: str | None = None
    mode: str = "0644"
    notify: list[str] = field(default_factory=list)
    trigger_only: bool = False
    optional: bool = False
    when: str | None = None
    note: str = ""
    # ★★ T16（规范 §12.120）：`wait` 步骤的配置 —— **等一个条件成立**（不是睡时间）。
    #   {expect: {...}, timeout_sec: N, interval_sec: N, fail_reason: "..."}
    wait: dict[str, Any] | None = None

    @property
    def kind(self) -> str:
        if self.action:
            return "action"
        if self.template:
            return "template"
        return "wait"

    def to_public(self) -> dict[str, Any]:
        return {
            "name": self.name, "title": self.title or self.name, "kind": self.kind,
            "action": self.action, "args": self.args,
            "template": self.template, "dest": self.dest, "mode": self.mode,
            "notify": self.notify, "trigger_only": self.trigger_only,
            "optional": self.optional, "when": self.when, "note": self.note,
            "wait": self.wait,
        }


@dataclass
class Uninstall:
    stop: list[dict[str, Any]] = field(default_factory=list)
    disable: list[dict[str, Any]] = field(default_factory=list)
    remove_config: list[dict[str, Any]] = field(default_factory=list)
    purge_paths: list[str] = field(default_factory=list)
    keep_data: list[str] = field(default_factory=list)
    remove_packages: list[str] = field(default_factory=list)
    purge_confirm_text: str = ""
    #: ★ 停止 / 「保留数据」卸载要手输的确认词（当这些步骤里含 red 动作时必填）
    stop_confirm_text: str = ""
    #: ★ 停止 / 「保留数据」卸载**之后**应当成立的事实（规范 §12.6.3）。
    #:   为什么需要它：部署段那句 `state: active` 说的是"服务在跑"，
    #:   拿它去判"刚停完"**必然判红** —— 于是「停止」这个正向操作会永远显示失败。
    #:   全删（purge）不跑这里：那时连包都没了，没有可探的服务状态。
    health: list[dict[str, Any]] = field(default_factory=list)

    def to_public(self) -> dict[str, Any]:
        return {
            "stop": self.stop, "disable": self.disable, "remove_config": self.remove_config,
            "purge_paths": self.purge_paths, "keep_data": self.keep_data,
            "remove_packages": self.remove_packages,
            "purge_confirm_text": self.purge_confirm_text,
            "stop_confirm_text": self.stop_confirm_text,
            "health": self.health,
        }


@dataclass
class Recipe:
    id: str
    name: str
    version: str
    summary: str
    risk: str
    params: list[Param] = field(default_factory=list)
    preflight: list[dict[str, Any]] = field(default_factory=list)
    steps: list[RecipeStep] = field(default_factory=list)
    health: list[dict[str, Any]] = field(default_factory=list)
    uninstall: Uninstall = field(default_factory=Uninstall)
    note: str = ""
    source: str = ""
    # ★★ T8·S6（规范 §12.32.4）：正向部署的手输确认词。
    #   只在"配方里含 red 动作"时有意义 —— 声明了却没有 red 动作 ⇒ **装载期就拒**（假闸门）。
    deploy_confirm_text: str = ""
    # ★★★ T16·S6 补（规范 §12.6.5 / §12.125）：**非服务类配方的开口要能被"读"到**。
    #   ★ 现场（真缺陷）：S5 开了这个口、装载器也认，但 **`Recipe` 结构里没存它** ⇒
    #     `lint_recipe` 看不到 ⇒ 体检对 `vm-cycle` 照旧判 **fail** （「反向操作：停服/撤自启 一条都没有」）
    #     ⇒ `tools\recipe-check.py` 退出码 **1** ⇒ 自检 ㉖ 红。
    #   ★ 教训与 §12.122 同族：**信息在，没送到读它的那一方** ⇒ 结论错了，而且**一处都不报错**。
    #   ★ 开口本身没被放宽：`no_uninstall` 仍必须配 `no_uninstall_why`，且与 `uninstall` 段互斥（装载期拒）。
    no_uninstall: bool = False
    no_uninstall_why: str = ""

    # validate_params 会读 .title / .params，这里给它一个等价入口（复用同一套校验）
    @property
    def title(self) -> str:
        return self.name

    def step(self, name: str) -> RecipeStep | None:
        return next((s for s in self.steps if s.name == name), None)

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "version": self.version,
            "summary": self.summary, "risk": self.risk, "note": self.note,
            "params": [p.to_public() for p in self.params],
            "preflight": self.preflight, "health": self.health,
            "steps": [s.to_public() for s in self.steps],
            "uninstall": self.uninstall.to_public(),
            # ★★ T8·S6（规范 §12.32.4）：正向部署的确认词要**对外可见** ——
            #   界面上得先告诉人"这次要点什么词"，不然闸门就是个猜谜。
            "deploy_confirm_text": self.deploy_confirm_text,
            # ★★ T16·S6（规范 §12.6.5）：这个开口也要**对外可见** ——
            #   界面/报告要能念出"这份配方为什么没有卸载"，而不是让人对着一个空 uninstall 猜。
            "no_uninstall": self.no_uninstall,
            "no_uninstall_why": self.no_uninstall_why,
        }


# ════════════════════════════════════════════════════════════ 解析与校验


def _paths_disjoint(a: list[str], b: list[str]) -> tuple[bool, str]:
    """两组路径是否有交集（规范化之后）。

    ★ 规范 §12.6 约束 1：`purge_paths` 与 `keep_data` 不许有交集 ——
      那等于「自相矛盾的卸载承诺」（一边说要删，一边说保留）。
    """
    def norm(p: str) -> str:
        s = posixpath.normpath(str(p).strip())
        return s.rstrip("/") or "/"

    na = {norm(p) for p in a if str(p).strip()}
    nb = {norm(p) for p in b if str(p).strip()}
    both = sorted(na & nb)
    return (not both), "、".join(both)


#: 模板占位符（`{{ 参数 }}`）—— 装载期做路径白名单预检时，用它把参数换成"默认值 / 安全词"。
_TPL_REF_RE = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}")


def _whitelist_probe(path: str, defaults: dict[str, Any]) -> str:
    """把路径里的 `{{ 参数 }}` 换成"默认值 / 安全词"，好在**装载期**做白名单预检（规范 §12.14 #3）。

    ★ 为什么这样判是准的：`file.remove` 的白名单管的是**静态前缀**
      （`^/(etc|var/lib|var/log|opt|var/www)/<名>`），参数只影响 `<名>` 那一段 ——
      静态部分违规（`/srv/x`、`/usr/share/x`…）**一定**抓得到。
      默认值与真实取值不同时，这里只是"试算"；运行时还有动作层的参数白名单（安全契约第一层）兜底。
    """
    def _sub(m: re.Match[str]) -> str:
        v = defaults.get(m.group(1))
        if v is None or isinstance(v, (bool, int, float)):
            return "aoc-x"
        text = str(v)
        return text if text.startswith("/") else "aoc-x"

    return _TPL_REF_RE.sub(_sub, path)


def parse_recipe(data: Any, path: Path, actions: dict[str, Any]) -> tuple[Recipe | None, list[str]]:
    """解析并**静态校验**一份配方（不连目标机）。"""
    errs: list[str] = []
    if not isinstance(data, dict):
        return None, [f"[{path.name}] 顶层必须是映射"]

    rid = str(data.get("id", ""))
    if not RECIPE_ID_RE.match(rid):
        errs.append(f"[{path.name}] id「{rid}」不合法（应为 ^[a-z][a-z0-9-]*$）")
    if path.stem != rid:
        errs.append(f"[{path.name}] 文件名与 id 不一致：文件名「{path.stem}」≠ id「{rid}」")

    unknown = sorted(set(data) - TOP_KEYS)
    for k in unknown:
        if k in FORBIDDEN_KEYS:
            errs.append(f"[{rid or path.name}] ★ 配方不允许写命令或逻辑：`{k}` —— {FORBIDDEN_KEYS[k]}")
        else:
            errs.append(f"[{rid or path.name}] 不认识的顶层键「{k}」（白名单：{'、'.join(sorted(TOP_KEYS))}）")

    for key in ("name", "version", "summary"):
        if not str(data.get(key, "")).strip():
            errs.append(f"[{rid or path.name}] 缺少必填项：{key}")

    risk = str(data.get("risk", ""))
    if risk not in RISKS:
        errs.append(f"[{rid or path.name}] risk「{risk}」不合法，可选：{'、'.join(RISKS)}")

    # ★★ T8·S6 新增（规范 §12.32.4）：正向部署的手输确认词（见下面 `red_in_deploy` 的校验）。
    deploy_confirm_text = str(data.get("deploy_confirm_text") or "").strip()

    params = _parse_params(data.get("params"), errs, rid or path.name)
    defined = {p.name for p in params}

    # ── preflight / health：期望 ──────────────────────────────────
    def parse_expects(raw: Any, where: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if raw is None:
            return out
        if not isinstance(raw, list):
            errs.append(f"[{rid}] {where} 必须是列表")
            return out
        for i, item in enumerate(raw):
            at = f"{where}[{i}]"
            if not isinstance(item, dict) or "expect" not in item:
                errs.append(f"[{rid}] {at} 必须是 {{expect: {{…}}}} 形式")
                continue
            extra = set(item) - {"expect", "fail_reason"}
            if extra:
                errs.append(f"[{rid}] {at} 多余的键：{'、'.join(sorted(extra))}（只允许 expect / fail_reason）")
            errs.extend(validate_expect(item["expect"], actions, where=f"[{rid}] {at}"))
            # 期望里引用的参数必须已定义
            for ref in _refs(item["expect"]):
                if ref not in defined:
                    errs.append(f"[{rid}] {at} 引用了未定义的参数：{ref}")
            out.append({"expect": item["expect"], "fail_reason": str(item.get("fail_reason") or "")})
        return out

    preflight = parse_expects(data.get("preflight"), "preflight")
    health = parse_expects(data.get("health"), "health")
    if not health:
        errs.append(f"[{rid}] 必须有至少一条 health（健康检查就是「部署完了到底能不能用」）")

    # ── steps ────────────────────────────────────────────────────
    steps: list[RecipeStep] = []
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        errs.append(f"[{rid}] steps 必须是至少一个步骤的列表")
        raw_steps = []
    seen: set[str] = set()
    for i, item in enumerate(raw_steps):
        at = f"[{rid}] steps[{i}]"
        if not isinstance(item, dict):
            errs.append(f"{at} 必须是映射")
            continue
        name = str(item.get("name", ""))
        if not NAME_RE.match(name):
            errs.append(f"{at} name「{name}」不合法（应为 ^[a-z][a-z0-9_]*$，英文标识；中文写 title）")
            continue
        if name in seen:
            errs.append(f"{at} 步骤名重复：{name}")
        seen.add(name)
        extra = sorted(set(item) - STEP_KEYS)
        if extra:
            for k in extra:
                if k in FORBIDDEN_KEYS:
                    # ★ 步骤级也要说清"为什么不行"，不能只甩一句"多余的键"：
                    #   写配方的人看到「不许写命令/逻辑」才知道该改成 expect。
                    errs.append(f"{at} ★ 配方不允许写命令或逻辑：`{k}` —— {FORBIDDEN_KEYS[k]}")
                else:
                    errs.append(
                        f"{at} 多余的键：`{k}`（步骤键白名单：{'、'.join(sorted(STEP_KEYS))}）"
                    )
        kinds = [k for k in ("action", "template", "wait") if item.get(k)]
        if len(kinds) != 1:
            errs.append(f"{at} 必须**恰好**是 action / template / wait 三种形态之一（当前 {kinds or '一种都没有'}）")
            continue
        kind = kinds[0]
        wait_conf: dict[str, Any] | None = None
        if kind == "wait":
            # ★★ T16（规范 §12.120）：**兑现一个早就写下的承诺** ——
            #   本文件此前一直把 `wait` 放在 STEP_KEYS 里，而 loader 写着
            #   「`wait` 步骤类型尚未实现（预留给 T16 的「开机 → 等就绪」）」。
            #   ★ 它等的是**条件**（"能 ssh 进去吗"），不是**时间**：
            #     只写"睡 30 秒"是**假等待** —— 机器起来了它也多睡，没起来它到点就走。
            raw_w = item.get("wait")
            if not isinstance(raw_w, dict):
                errs.append(f"{at} wait 必须是一个映射（至少要给 expect）")
                continue
            w_extra = sorted(set(raw_w) - WAIT_KEYS)
            if w_extra:
                errs.append(f"{at} wait 里多余的键：{'、'.join(w_extra)}"
                            f"（只允许 {'、'.join(sorted(WAIT_KEYS))}）")
            if "expect" not in raw_w:
                errs.append(f"{at} wait 必须给一条 expect —— ★ 否则它只是「等时间」，不是「等条件」")
                continue
            errs.extend(validate_expect(raw_w["expect"], actions, where=f"{at}.wait"))
            for ref in _refs(raw_w["expect"]):
                if ref not in defined:
                    errs.append(f"{at} wait.expect 引用了未定义的参数：{ref}")
            wait_conf = {
                "expect": raw_w["expect"],
                "timeout_sec": int(raw_w.get("timeout_sec") or 120),
                "interval_sec": int(raw_w.get("interval_sec") or 5),
                "fail_reason": str(raw_w.get("fail_reason") or ""),
            }

        st = RecipeStep(
            name=name,
            title=str(item.get("title") or ""),
            action=str(item.get("action")) if item.get("action") else None,
            args=dict(item.get("args") or {}),
            template=str(item.get("template")) if item.get("template") else None,
            dest=str(item.get("dest")) if item.get("dest") else None,
            mode=str(item.get("mode") or "0644"),
            notify=[str(n) for n in (item.get("notify") or [])],
            trigger_only=bool(item.get("trigger_only", False)),
            optional=bool(item.get("optional", False)),
            when=str(item["when"]) if item.get("when") else None,
            note=str(item.get("note") or ""),
            wait=wait_conf,
        )

        if st.when and st.when not in defined:
            errs.append(f"{at} when「{st.when}」不是配方参数名（写**裸参数名**，不写 {{{{ }}}}）")

        if kind == "action":
            act = actions.get(st.action or "")
            if act is None:
                errs.append(f"{at} 引用的动作不存在：{st.action}")
            else:
                allowed = {p.name for p in act.params}
                for k, v in st.args.items():
                    if k not in allowed:
                        errs.append(
                            f"{at} 动作 {st.action} 没有参数「{k}」"
                            f"（可用：{'、'.join(sorted(allowed)) or '无'}）"
                        )
                    for ref in _refs(v):
                        if ref not in defined:
                            errs.append(f"{at} args.{k} 引用了未定义的参数：{ref}")
        elif kind == "template":
            if not st.dest:
                errs.append(f"{at} template 步骤必须给 dest（目标机绝对路径）")
            else:
                # ★ dest 允许以 {{ 参数 }} 开头（例如 "{{ root_dir }}/index.html"）——
                #   但那样**静态判不出**"渲染后是不是绝对路径"，所以要求**那个参数自己**
                #   用 pattern 保证它以 / 开头（例如 ^/var/www/...）。
                #   运行时（写盘前）还会再校验一次绝对路径与 `..`。
                head = re.match(r"^\{\{\s*([a-z][a-z0-9_]*)\s*\}\}", st.dest)
                if head:
                    pname = head.group(1)
                    pdef = next((p for p in params if p.name == pname), None)
                    if not ((pdef.pattern if pdef else None) or "").startswith("^/"):
                        errs.append(
                            f"{at} dest 以 {{{{ {pname} }}}} 开头，则该参数必须声明以 ^/ 开头的 pattern"
                            f"（否则无法保证渲染出来是绝对路径）"
                        )
                elif not st.dest.startswith("/"):
                    errs.append(f"{at} dest 必须是绝对路径：{st.dest}")
                if ".." in st.dest:
                    errs.append(f"{at} dest 不得包含 ..：{st.dest}")
            for ref in _refs(st.dest):
                if ref not in defined:
                    errs.append(f"{at} dest 引用了未定义的参数：{ref}")
            if not re.fullmatch(r"[0-7]{4}", st.mode):
                errs.append(f"{at} mode「{st.mode}」不合法（应为 4 位八进制，如 0644）")
            try:
                from app.template import resolve_template
                resolve_template(_catalog_dir_of(path), st.template or "")
            except OpsError as exc:
                errs.append(f"{at} {exc.reason}")
        else:
            # kind == "wait"（★★ T16 · 规范 §12.120）：等条件的步骤自己没有命令、没有模板，
            # ★ 但它必须有**边界**：超时与轮询间隔都要在合理区间里 ——
            #   否则一个 `timeout_sec: 99999` 的等待会把一次配方执行挂死在那儿。
            w = wait_conf or {}
            if not (10 <= int(w.get("timeout_sec") or 0) <= 3600):
                errs.append(f"{at} wait.timeout_sec 应在 10~3600 秒（当前 {w.get('timeout_sec')}）")
            if not (1 <= int(w.get("interval_sec") or 0) <= 300):
                errs.append(f"{at} wait.interval_sec 应在 1~300 秒（当前 {w.get('interval_sec')}）")
        steps.append(st)

    # notify / trigger_only 的对应关系（规范 §12.5）
    for st in steps:
        for target in st.notify:
            tgt = next((s for s in steps if s.name == target), None)
            if tgt is None:
                errs.append(f"[{rid}] 步骤 {st.name} 的 notify 指向不存在的步骤：{target}")
            elif not tgt.trigger_only:
                errs.append(
                    f"[{rid}] 步骤 {st.name} notify 的 {target} 没有声明 trigger_only: true"
                    f"（否则它每次都会无条件跑一遍 —— 比如白重启一次服务）"
                )

    # 配方风险不得低于其步骤引用动作的最高风险
    order = {"green": 0, "yellow": 1, "red": 2}
    max_risk = "green"
    for st in steps:
        act = actions.get(st.action or "")
        if act is not None and order.get(act.risk, 0) > order.get(max_risk, 0):
            max_risk = act.risk
    if risk in order and order[risk] < order[max_risk]:
        errs.append(f"[{rid}] risk={risk} 低于其步骤引用的动作最高风险 {max_risk}（配方风险取步骤内最严）")

    # ── uninstall（宪法 3：必填）──────────────────────────────────
    uninstall = Uninstall()
    raw_un = data.get("uninstall")
    # ★★ T16（规范 §12.6.5 · 新增）：**非服务类配方的开口**。
    #   本项目的 uninstall 硬规则（§12.6）是按"装一个服务"写的：停服务 / 撤开机自启 /
    #   删配置 / 全删路径。而"**开一台虚拟机、干完事、关回去**"这类**编排型配方**
    #   既不装包也不写配置 ⇒ **没有可停的服务、没有可撤的自启、没有可删的路径**。
    #   ★ 让它硬填一份 = 逼它**编一份假的 purge_paths** —— 那正是"报告/交付物不许说假话"的反面。
    #   ★ 所以开这个口，但**只认"声明 ＋ 写明理由"**：裸开关一律拒（闸门只增不减，规范 §12.116 同源）。
    no_uninstall = bool(data.get("no_uninstall"))
    if no_uninstall:
        if not str(data.get("no_uninstall_why") or "").strip():
            errs.append(
                f"[{rid}] 声明了 no_uninstall 就必须写 no_uninstall_why —— "
                f"★ 不许用一个裸开关把「服务类配方硬规则」关掉"
            )
        if isinstance(raw_un, dict):
            errs.append(f"[{rid}] no_uninstall 与 uninstall 段**互斥**：既然声明了没有卸载，就别写一份出来")
    if not isinstance(raw_un, dict) and not no_uninstall:
        errs.append(f"[{rid}] ★ 必须有 uninstall 段（只写正向步骤的配方不合格，规范 §12.6）")
    if isinstance(raw_un, dict):
        extra = sorted(set(raw_un) - UNINSTALL_KEYS)
        if extra:
            errs.append(f"[{rid}] uninstall 里多余的键：{'、'.join(extra)}")

        def action_list(key: str) -> list[dict[str, Any]]:
            raw = raw_un.get(key)
            out: list[dict[str, Any]] = []
            if raw is None:
                return out
            if not isinstance(raw, list):
                errs.append(f"[{rid}] uninstall.{key} 必须是列表")
                return out
            for j, it in enumerate(raw):
                if not isinstance(it, dict) or not it.get("action"):
                    errs.append(f"[{rid}] uninstall.{key}[{j}] 必须是 {{action: <已登记动作>, args: {{…}}}}")
                    continue
                aid = str(it["action"])
                act = actions.get(aid)
                if act is None:
                    errs.append(f"[{rid}] uninstall.{key}[{j}] 引用的动作不存在：{aid}")
                    continue
                allowed = {p.name for p in act.params}
                for k in (it.get("args") or {}):
                    if k not in allowed:
                        errs.append(f"[{rid}] uninstall.{key}[{j}] 动作 {aid} 没有参数「{k}」")
                out.append({"action": aid, "args": dict(it.get("args") or {})})
            return out

        uninstall.stop = action_list("stop")
        uninstall.disable = action_list("disable")
        uninstall.remove_config = action_list("remove_config")
        if not uninstall.stop:
            errs.append(f"[{rid}] uninstall.stop 至少要有一步（停服务）")
        if not uninstall.disable:
            errs.append(f"[{rid}] uninstall.disable 至少要有一步（撤开机自启）")
        for key in ("remove_config",):
            for it in getattr(uninstall, key):
                if it["action"] != REMOVE_ACTION_ID:
                    errs.append(
                        f"[{rid}] uninstall.{key} 只能用 {REMOVE_ACTION_ID} 删路径"
                        f"（限制性删除：red + 路径白名单 + 禁止批量），当前是 {it['action']}"
                    )
        for key in ("purge_paths", "keep_data"):
            raw = raw_un.get(key)
            if raw is None:
                if key == "purge_paths":
                    errs.append(f"[{rid}] uninstall.purge_paths 必填（「全删」要删哪些路径）")
                if key == "keep_data":
                    errs.append(f"[{rid}] uninstall.keep_data 必填（「保留数据」时明确承诺不删什么）")
                continue
            if not isinstance(raw, list):
                errs.append(f"[{rid}] uninstall.{key} 必须是列表")
                continue
            setattr(uninstall, key, [str(x) for x in raw])
        # ★ 真正"自相矛盾"的是：某路径**两种卸载都删**（remove_config），
        #   却又被承诺「保留数据时不删」（keep_data）。
        #   而 purge_paths 与 keep_data 重叠是**正常的** —— 那正是两种卸载的定义。
        remove_cfg_paths = [
            str((it.get("args") or {}).get("path") or "") for it in uninstall.remove_config
        ]
        ok, both = _paths_disjoint(remove_cfg_paths, uninstall.keep_data)
        if not ok:
            errs.append(
                f"[{rid}] ★ uninstall 里 {both} 同时出现在 remove_config（两种卸载都删）"
                f"与 keep_data（保留数据时不删）—— 这是自相矛盾的卸载承诺"
            )
        pkgs = raw_un.get("remove_packages")
        if pkgs is not None:
            if not isinstance(pkgs, list) or not pkgs:
                errs.append(f"[{rid}] uninstall.remove_packages 必须是非空列表")
            else:
                uninstall.remove_packages = [str(x) for x in pkgs]
        # ★ 停止 / 「保留数据」卸载之后的期望（规范 §12.6.3）：可选。
        #   解析走与 preflight / health **同一个** parse_expects —— 白名单、只许引用已登记动作、
        #   不许裸命令，这些约束一处定义、三处复用。
        uninstall.health = parse_expects(raw_un.get("health"), f"[{rid}] uninstall.health")
        uninstall.purge_confirm_text = str(raw_un.get("purge_confirm_text") or "").strip()
        if not uninstall.purge_confirm_text:
            errs.append(f"[{rid}] uninstall.purge_confirm_text 必填（全删是 🔴 级，要人**手输**确认词）")
        # ★ 停止 / 「保留数据」卸载里若含 red 动作，也必须手输确认词（规范 §12.6.1）：
        #   否则配方的闸门会比「直接执行那个动作」更松 —— 那是把闸门往低处挪。
        uninstall.stop_confirm_text = str(raw_un.get("stop_confirm_text") or "").strip()
        red_involved = any(
            actions[it["action"]].risk == "red"
            for it in (uninstall.stop + uninstall.disable + uninstall.remove_config)
            if it["action"] in actions
        ) or bool(uninstall.remove_packages)
        if red_involved and not uninstall.stop_confirm_text:
            errs.append(
                f"[{rid}] uninstall 的停止/删除步骤含 red 级动作，必须声明 stop_confirm_text"
                f"（停止与「保留数据」卸载都要**手输**确认词）"
            )
        if uninstall.remove_packages and PKG_REMOVE_ACTION_ID not in actions:
            errs.append(f"[{rid}] uninstall.remove_packages 需要动作 {PKG_REMOVE_ACTION_ID}，但它不存在")
        if (uninstall.purge_paths or uninstall.remove_config) and REMOVE_ACTION_ID not in actions:
            errs.append(f"[{rid}] uninstall 要删路径，但动作 {REMOVE_ACTION_ID} 不存在")

        # ★★ T8·S6 新增（规范 §12.32.4）：**正向部署的手输确认词**。
        #   背景：本话题第一次出现"**正向部署里含 red 动作**"（`k8s-init` 要拆旧集群）。
        #   在此之前，deploy 模式只要求一个"点一下"的勾选 —— 而 ≤red 的破坏性远不止"点一下"
        #   （总纲铁律 9：red 的确认词**只能由人输入**）。
        #   ⇒ 允许配方声明 `deploy_confirm_text`；★ 而**声明了它却没有任何 red 动作**是"假闸门"
        #     （凭空多要一句人话，只会教用户忽略闸门）⇒ **装载期就拒**。
        red_in_deploy = any(
            actions[s.action].risk == "red" for s in steps if s.action in actions
        )
        if deploy_confirm_text and not red_in_deploy:
            errs.append(
                f"[{rid}] ★ 声明了 deploy_confirm_text，但正向步骤里**没有任何 red 动作** ——"
                f"那是**假闸门**（凭空多要一句人话，只会教用户忽略闸门）。要么去掉它，要么把 red 动作写清楚。"
            )

        # ── ★★ v1.7 新增（规范 §12.13.2 / §12.14 #3）：白名单覆盖预检 ──
        #   `purge_paths` / `remove_config` 的每个路径都必须落在 `file.remove` 的**路径白名单**内。
        #   ★ 为什么必须在**装载期**就报：等到跑「全删」才发现删不掉时，
        #     报告已经把"会删掉 X、Y"念给人听过了 —— 那是**承诺兑现不了**，比"删不干净"更坏。
        #   （T6 开题单 §9.2 #6：`/srv/<名>` 不在白名单里，选它就会踩这个坑。）
        remove_action = actions.get(REMOVE_ACTION_ID)
        if remove_action is not None:
            path_param = remove_action.param("path")
            if path_param is not None and path_param.pattern:
                pat = re.compile(path_param.pattern)
                defaults = {p.name: p.default for p in params}
                targets = [
                    (f"uninstall.remove_config[{i}]", str((it.get("args") or {}).get("path") or ""))
                    for i, it in enumerate(uninstall.remove_config)
                ] + [
                    (f"uninstall.purge_paths[{i}]", p) for i, p in enumerate(uninstall.purge_paths)
                ]
                for where_, raw_path in targets:
                    probe = _whitelist_probe(raw_path, defaults)
                    if pat.fullmatch(probe):
                        continue
                    errs.append(
                        f"[{rid}] {where_} 的路径「{raw_path}」不在 {REMOVE_ACTION_ID} 的路径白名单内"
                        f"（按默认值试算为「{probe}」）。★ 「卸载·全删」**删不掉**它，"
                        f"但报告会承诺删掉 —— 自造目录请用 /opt/<名>（规范 §12.13.2）"
                    )

    if errs:
        return None, errs
    return (
        Recipe(
            id=rid, name=str(data["name"]), version=str(data["version"]),
            summary=str(data["summary"]), risk=risk, params=params,
            preflight=preflight, steps=steps, health=health, uninstall=uninstall,
            note=str(data.get("note") or "").strip(), source=str(path),
            deploy_confirm_text=deploy_confirm_text,
            # ★★ T16·S6（规范 §12.6.5 / §12.125）：**开口必须跟着配方对象一起走** ——
            #   否则装载器认它、体检不认它，合法配方过不了命令行体检（真缺陷）。
            no_uninstall=no_uninstall,
            no_uninstall_why=(str(data.get("no_uninstall_why") or "").strip() if no_uninstall else ""),
        ),
        [],
    )


def _catalog_dir_of(path: Path) -> Path:
    """配方文件在 catalog/recipes/ 下，模板根是 catalog/templates/。"""
    return path.parent.parent


def _refs(value: Any) -> list[str]:
    """从任意嵌套结构里找出 `{{ 参数 }}` 引用。"""
    from app.catalog import PARAM_REF_RE
    if isinstance(value, str):
        return PARAM_REF_RE.findall(value)
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_refs(v))
        return out
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(_refs(v))
        return out
    return []


@dataclass
class RecipeLoadReport:
    """一次装载的结果（规范 §12.17：「**不许静默少装载**」）。

    它回答三件事，缺一不可：**装了几份 / 哪几份没装进来 / 为什么**。
    启动横幅、`GET /api/recipes`、重载接口与界面都用同一个它 —— 而不是各写一句人话。
    """

    loaded: list[str] = field(default_factory=list)
    failed: list[dict[str, Any]] = field(default_factory=list)
    dir_missing: bool = False
    at: str = ""

    @property
    def ok(self) -> bool:
        return not self.failed

    def to_public(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "loaded": list(self.loaded),
            "failed": list(self.failed),
            "dir_missing": self.dir_missing,
            "at": self.at,
        }

    def summary(self) -> str:
        if self.dir_missing:
            return "没有配方目录（还不算错：T5 之前就没有配方）"
        if not self.failed:
            return f"装载成功 {len(self.loaded)} 份：{'、'.join(self.loaded) or '（无）'}"
        return (f"装载成功 {len(self.loaded)} 份；★ 有 {len(self.failed)} 份**没装进来**："
                + "、".join(str(f.get("file")) for f in self.failed))


def load_recipes(recipes_dir: Path, actions: dict[str, Any], *,
                 now: str = "") -> tuple[dict[str, Recipe], RecipeLoadReport]:
    """加载并校验 catalog/recipes/*.yaml（规范 §12.17）。

    ★★ v1.8 行为变更（v1.7 及以前：**任何一份不合格都拒绝启动**）：
      现在**不合格的那一份不装载、其余照常装载**，并如实记录"哪一份、哪些错"。

      为什么改：§12.17 要给"**用户自己写配方**"铺路。用户新写一份配方、手滑写坏了字段，
      如果控制台因此**整个起不来**，他连"看错误提示的界面"都没有 —— 那才是真正的死路
      （改一行 YAML 要去翻命令行日志，扩展点的门槛就高得离谱）。

      ★ 但这**不是**放松校验：**装载期校验一步没少**，不合格的照样进不了装载结果
        （宪法 1 与安全契约在配方这一层仍然由它执行）。
      ★ 自检里仍有一条"**我们自己的配方必须全部装载成功**"的断言在守着 ——
        所以"装载结果里有失败项"这件事，在交付物上仍然是会红的。

    返回 `(recipes, report)`：结果的**两个面**都要用 ——
    引擎要字典，人和界面要报告（装了几份 / 哪几份没装 / 为什么）。
    """
    report = RecipeLoadReport(at=now)
    if not recipes_dir.is_dir():
        # 还没有配方不算错（T5 之前的行为要保住）
        report.dir_missing = True
        return {}, report
    files = sorted(recipes_dir.glob("*.yaml"))
    out: dict[str, Recipe] = {}
    for path in files:
        # ★ 单份文件的**任何**问题都就地收进报告，绝不外抛 ——
        #   否则"一份坏 YAML 文件"就会变成"整个控制台起不来"（正是这次要拆掉的坎）。
        #   YAML 语法错与 schema 校验错**分开报**：两者给用户看的下一步动作完全不同。
        try:
            data = load_yaml(path, what="配方定义")
        except OpsError as exc:
            report.failed.append({
                "file": path.name, "errors": [f"YAML 读不了：{exc.reason}"],
                "detail": exc.detail or "", "kind": "yaml",
            })
            continue
        recipe, errs = parse_recipe(data, path, actions)
        if errs:
            report.failed.append({
                "file": path.name, "errors": list(errs), "detail": "", "kind": "schema",
                "id": str((data or {}).get("id") or ""),
            })
            continue
        assert recipe is not None
        if recipe.id in out:
            # id 撞了：★ 前一份保持装载（先到先得），后来的这份不装载 ——
            # 因为"同一个 id 两份定义"说不清哪份生效，而说不清的事就不许生效。
            report.failed.append({
                "file": path.name, "kind": "duplicate", "id": recipe.id,
                "errors": [f"id 与 {Path(out[recipe.id].source).name} 重复：{recipe.id}"],
                "detail": "",
            })
            continue
        out[recipe.id] = recipe
    report.loaded = sorted(out)
    return out, report


# ════════════════════════════════════════════════════════════ 执行结果模型


@dataclass
class RecipeRun:
    id: str
    recipe: Recipe
    host: Host
    mode: str
    status: str = "ok"                       # ok / failed / aborted
    params_display: dict[str, Any] = field(default_factory=dict)
    params_machine: dict[str, Any] = field(default_factory=dict)
    preflight: list[dict[str, Any]] = field(default_factory=list)
    health: list[dict[str, Any]] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    #: ★ 卸载段的路径**渲染后**的真值（规范 §12.6 / 清单 37）：
    #:   结论里的"已保留（未删除）：…"如果漏出 `{{ root_dir }}`，等于没说清保留了什么。
    uninstall_rendered: dict[str, Any] = field(default_factory=dict)
    confirm_relay: list[dict[str, Any]] = field(default_factory=list)
    skipped_steps: list[str] = field(default_factory=list)
    conclusion: str = ""
    error: OpsError | None = None
    started_at: str = ""
    ended_at: str = ""
    duration_ms: int = 0
    t0: float = 0.0

    # -- 变更清单三态（规范 §12.3）--
    @property
    def changed_steps(self) -> list[str]:
        return [s["name"] for s in self.steps if s.get("changed") is True]

    @property
    def unchanged_steps(self) -> list[str]:
        return [s["name"] for s in self.steps if s.get("changed") is False]

    @property
    def unknown_steps(self) -> list[str]:
        return [s["name"] for s in self.steps if s.get("changed") is None]

    def to_public(self) -> dict[str, Any]:
        return {
            "run_id": self.id,
            "recipe_id": self.recipe.id,
            "recipe_name": self.recipe.name,
            "recipe_version": self.recipe.version,
            "mode": self.mode,
            "status": self.status,
            "host_id": self.host.id,
            "host_name": self.host.name,
            "host_address": self.host.address,
            "params": self.params_display,
            "preflight": self.preflight,
            "health": self.health,
            "steps": self.steps,
            "changed_steps": self.changed_steps,
            "unchanged_steps": self.unchanged_steps,
            "unknown_steps": self.unknown_steps,
            "checkpoints": self.checkpoints,
            "confirm_relay": self.confirm_relay,
            "skipped_steps": self.skipped_steps,
            "conclusion": self.conclusion,
            "error": self.error.to_dict() if self.error else None,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
        }


# ════════════════════════════════════════════════════════════ 编排


class RecipeRunner:
    def __init__(self, cfg: AppConfig, actions: dict[str, Any], engine: Engine,
                 store: Store, recipes: dict[str, Recipe],
                 load_report: RecipeLoadReport | None = None) -> None:
        self.cfg = cfg
        self.actions = actions
        self.engine = engine
        self.store = store
        self.recipes = recipes
        self.load_report = load_report or RecipeLoadReport()

    # ---------------------------------------------------------- 装载 / 重载（规范 §12.17）

    def reload(self) -> RecipeLoadReport:
        """显式重载磁盘上的配方（规范 §12.17）—— 让"写一份新配方"**不用重启控制台**。

        三条不许，逐条落在这里：

        · ★ **不合规的不装载** —— 走的是与启动时**同一套** `load_recipes`
          （同一份装载期校验）；重载**不是**绕过校验的后门（宪法 1）。
        · ★ **不影响已装载的** —— 装载结果**整体替换**：不合格的那份进不来，
          其余各份照常。★ 这里刻意**不保留**"某份配方上次装载的旧版本"：
          磁盘上那一份已经不合法了，界面上却还挂着一个能跑的旧版本，
          用户会以为自己在部署刚改过的东西 —— 那是**比报错更坏的假绿**。
          这执行的是 T7 开题单那句"校验不过就不装载"。
        · ★ **不打断正在执行的** —— 一次执行在 `run()` 开头就把 `Recipe` 对象拿在手里
          （`recipe = self.recipe(recipe_id)`），这里换的只是字典里的引用；
          已经开跑的那一次继续用它**自己那一版**定义，跑到一半不会被换掉。
        """
        recipes, report = load_recipes(
            self.cfg.paths.catalog / "recipes", self.actions, now=now_iso(self.cfg),
        )
        self.recipes = recipes
        self.load_report = report
        return report

    # ---------------------------------------------------------- 查询

    def recipe(self, recipe_id: str) -> Recipe:
        r = self.recipes.get(recipe_id)
        if r is None:
            raise OpsError(
                code="NOT_FOUND",
                reason=f"没有这个配方：{recipe_id}",
                advice="刷新页面重新加载配方列表。",
                context={"available": sorted(self.recipes)},
            )
        return r

    def list_public(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for r in sorted(self.recipes.values(), key=lambda x: x.id):
            last = self.store.list_recipe_runs(limit=1, recipe_id=r.id)
            item = r.to_public()
            item["last_run"] = (
                {
                    "run_id": last[0]["id"], "status": last[0]["status"],
                    "mode": last[0]["mode"], "host_name": last[0]["host_name"],
                    "started_at": last[0]["started_at"],
                    "changed_steps": last[0].get("changed_json") or [],
                }
                if last else None
            )
            out.append(item)
        return out

    # ---------------------------------------------------------- 现状探测（只读）

    def probe(self, recipe_id: str, host_id: str,
              raw_params: dict[str, Any] | None = None) -> dict[str, Any]:
        """只读地看一眼"这个服务现在是什么状态"。

        做法：**只跑 `health` 那几条期望**（它们全是只读采集），不执行任何步骤。
        用途：服务目录里显示"已部署 / 没跑起来"，以及部署前先确认目标机现状。

        ★ 它与"点一次部署"走的是**同一条路**（同样的期望判定层、同样的采集动作），
          所以不会出现"探测说好了、部署却失败"这种两套标准的情况。
        """
        recipe = self.recipe(recipe_id)
        host = self.cfg.host(host_id)
        params = validate_params(recipe, raw_params)
        collect = self._collector(host)
        rows = self._eval_expects(recipe, recipe.health, params, collect, "health")
        states = {r["state"] for r in rows}
        if rows and states == {"pass"}:
            summary = "看起来已经在正常运行"
        elif "unknown" in states:
            summary = "★ 有项目无法判定（不等于没部署 —— 先看每条判定的原因）"
        else:
            summary = "看起来还没部署，或者没跑起来"
        return {
            "recipe_id": recipe.id,
            "host_id": host.id,
            "host_name": host.name,
            "params": {p.name: params[p.name].display for p in recipe.params},
            "checks": rows,
            "healthy": bool(rows) and states == {"pass"},
            "summary": summary,
        }

    # ---------------------------------------------------------- 计划

    def plan(self, recipe_id: str, host_id: str, raw_params: dict[str, Any] | None,
             mode: str = "deploy") -> dict[str, Any]:
        recipe = self.recipe(recipe_id)
        host = self.cfg.host(host_id)
        if mode not in MODES:
            raise OpsError(code="PARAM_INVALID", reason=f"不认识的方式：{mode}",
                           advice=f"允许：{'、'.join(MODES)}")
        params = validate_params(recipe, raw_params)

        planned: list[dict[str, Any]] = []
        if mode == "deploy":
            for st in recipe.steps:
                planned.append(self._plan_step(recipe, st, host, params))
        else:
            for item in self._mode_actions(recipe, mode):
                aid = item["action"]
                try:
                    prev = self.engine.preview(aid, host_id, item.get("args") or {})
                    commands = prev["commands"]
                except OpsError as exc:
                    commands = [{"name": "-", "title": "（预览失败）", "command": None,
                                 "note": exc.reason}]
                planned.append({
                    "name": aid, "title": self.actions[aid].title, "kind": "action",
                    "action": aid, "args": item.get("args") or {}, "commands": commands,
                    "trigger_only": False, "optional": False,
                })

        # ★ 要删什么 / 要保留什么，必须给出**渲染后的真值**（规范 §12.6.2）：
        #   磁盘上写的是 `{{ root_dir }}`，而"全删确认框"里给人看一句他自己都看不懂的模板，
        #   等于让人闭着眼按确认。
        def _r(x: str) -> str:
            try:
                return render_argv_element(x, params)
            except OpsError:
                return x

        un_public = recipe.uninstall.to_public()
        un_public["keep_data_rendered"] = [_r(x) for x in recipe.uninstall.keep_data]
        un_public["purge_paths_rendered"] = [_r(x) for x in recipe.uninstall.purge_paths]
        un_public["remove_config_rendered"] = [
            _r(str((it.get("args") or {}).get("path") or ""))
            for it in recipe.uninstall.remove_config
        ]

        return {
            "recipe": recipe.to_public(),
            "host": host.to_public(),
            "mode": mode,
            "params": {p.name: params[p.name].display for p in recipe.params},
            "params_machine": {p.name: params[p.name].value for p in recipe.params},
            "steps": [p for p in planned if not p.get("trigger_only")],
            "trigger_steps": [p for p in planned if p.get("trigger_only")],
            # ★ 预览里的期望也带上**渲染后的真值**（规范 §12.2）：否则人得自己替换 `{{ port }}`
            "preflight": [self._expect_public(x, i, "preflight", params)
                          for i, x in enumerate(recipe.preflight)],
            "health": [self._expect_public(x, i, "health", params)
                       for i, x in enumerate(recipe.health)],
            "uninstall": un_public,
            "needs_confirm": recipe.risk != "green" or bool(self._mode_needs_text(recipe, mode)),
            "purge_confirm_text": recipe.uninstall.purge_confirm_text,
            "stop_confirm_text": recipe.uninstall.stop_confirm_text,
            "confirm_text_required": self._mode_needs_text(recipe, mode),
        }

    def _plan_step(self, recipe: Recipe, st: RecipeStep, host: Host,
                   params: dict[str, ParamValue]) -> dict[str, Any]:
        base = st.to_public()
        base["commands"] = []
        if st.kind == "action":
            try:
                args = {k: render_argv_element(str(v), params) for k, v in st.args.items()}
                prev = self.engine.preview(st.action or "", host.id, args)
                base["args_rendered"] = args
                base["commands"] = prev["commands"]
            except OpsError as exc:
                base["commands"] = [{"name": "-", "title": "（预览失败）", "command": None,
                                     "note": exc.reason}]
        elif st.kind == "template":
            dest = render_argv_element(st.dest or "", params)
            want = sha256_hex(self._render_tpl(recipe, st, params))
            base["dest_rendered"] = dest
            base["render_sha256"] = want
            base["commands"] = [{
                "name": st.name, "title": f"渲染 {st.template} → {dest}",
                "command": f"（本地渲染 → 与目标机比对 sha256；相同则不写）sha256={want[:16]}…",
                "note": "幂等：内容相同就不写盘，文件时间戳不动",
            }]
        elif st.kind == "wait":
            # ★★ T16（规范 §12.120）：`wait` 步骤的**预览**要能一眼看出"等的是什么条件"。
            w = st.wait or {}
            base["wait"] = {
                "expect": str(w.get("expect") or ""),
                "timeout_sec": w.get("timeout_sec"),
                "interval_sec": w.get("interval_sec"),
            }
            base["commands"] = [{
                "name": st.name, "title": st.title or st.name,
                "command": (f"（轮询判定：最多等 {w.get('timeout_sec')}s，每 {w.get('interval_sec')}s 问一次）"
                            f" 条件 = {w.get('expect')}"),
                "note": "★ 等的是**条件**（能不能 ssh 进去 / 端口开没开），不是时间；"
                        "到点还没成立 ⇒ **判红**（如实说「没等到」）",
            }]
        return base

    def _expect_public(self, item: dict[str, Any], i: int, where: str,
                       params: dict[str, ParamValue] | None = None) -> dict[str, Any]:
        kind = next(iter(item["expect"]))
        out = {
            "where": f"{where}[{i}]", "kind": kind,
            "spec": item["expect"], "fail_reason": item.get("fail_reason") or "",
        }
        if params is not None:
            # ★ 预览给人看的是**真值**（渲染后），原始 spec 也一并留着便于对照排错
            try:
                out["spec_rendered"] = render_spec(item["expect"], params)
            except OpsError:
                out["spec_rendered"] = None
        return out

    def _render_tpl(self, recipe: Recipe, st: RecipeStep, params: dict[str, ParamValue]) -> str:
        text, _ = load_template(_catalog_dir_of(Path(recipe.source)), st.template or "",
                               where=f"配方 {recipe.id} 的模板 {st.template}")
        return render_template(text, params, where=f"模板 {st.template}")

    # ---------------------------------------------------------- 卸载/停止的步骤序列

    def _mode_actions(self, recipe: Recipe, mode: str) -> list[dict[str, Any]]:
        un = recipe.uninstall
        seq: list[dict[str, Any]] = []
        if mode == "stop":
            return list(un.stop)
        seq.extend(un.stop)
        seq.extend(un.disable)
        seq.extend(un.remove_config)
        if mode == "uninstall_purge":
            for p in un.purge_paths:
                seq.append({"action": REMOVE_ACTION_ID, "args": {"path": p}})
            for pkg in un.remove_packages:
                # ★★ v1.8（规范 §12.16 · T7 主线 2）：这里**不再**标 `optional`。
                #   T6 当时标它是为了绕开一个真缺陷：dnf 的 `clean_requirements_on_remove`
                #   （**默认开**）会在卸 A 时把"只是 A 的依赖"的 B 一起收走 ——
                #   紧接着那一步 `pkg.remove B` 的预检必然失败（`rpm -q B` 返回 1），
                #   于是**终态完全正确、报告却判 failed**。当时用"把这一步整个放宽"解决。
                #   ★ 但 `optional` 是**一把钝刀**：它把"目标已不存在"（该跳过）
                #     和"权限不足 / 依赖冲突 / 其他真失败"（该中止）**一起**放行了 ——
                #     §12.16 规矩 2 明确要求后者照旧中止（检查清单 51：**写坏了要会红**）。
                #   ⇒ 现在换成**精确**的做法：只有 `PRECHECK_FAILED`（目标本就不存在）
                #     才判"已达终态、跳过"（见 `_run_action_item` 里的 `terminal` 判定），
                #     其余失败**照旧中止**。钝刀换成手术刀，边界反而更严了。
                seq.append({"action": PKG_REMOVE_ACTION_ID, "args": {"package": pkg}})
        return seq

    def _mode_needs_text(self, recipe: Recipe, mode: str) -> str:
        """这个模式要不要**手输确认词**；要的话是哪一句（规范 §12.6.1）。

        规则：全删 → `purge_confirm_text`；停止 / 「保留数据」卸载里含 red 动作 →
        `stop_confirm_text`；★★ **正向部署里含 red 动作 → `deploy_confirm_text`**（T8·S6 新增）；
        其余正向部署 → 空串（点一次确认即可）。
        """
        un = recipe.uninstall
        if mode == "uninstall_purge":
            return un.purge_confirm_text
        if mode in ("stop", "uninstall_keep"):
            has_red = any(
                self.actions.get(it["action"]) is not None
                and self.actions[it["action"]].risk == "red"
                for it in self._mode_actions(recipe, mode)
            )
            return un.stop_confirm_text if has_red else ""
        # ★★ T8·S6（规范 §12.32.4）：deploy 段里也可能有 red 动作（本话题第一次出现）。
        #   ★ 为什么不能沿用"deploy 只要一个勾选"：那会让**配方的闸门比"直接执行那个动作"更松** ——
        #     把闸门往低处挪（与 §12.6.1 的 `stop_confirm_text` 同一条理由）。
        return getattr(recipe, "deploy_confirm_text", "") or ""

    # ---------------------------------------------------------- 执行

    def run(self, recipe_id: str, host_id: str, raw_params: dict[str, Any] | None, *,
            mode: str = "deploy", confirm: bool = False, confirm_text: str = "") -> RecipeRun:
        recipe = self.recipe(recipe_id)
        host = self.cfg.host(host_id)
        if mode not in MODES:
            raise OpsError(code="PARAM_INVALID", reason=f"不认识的方式：{mode}",
                           advice=f"允许：{'、'.join(MODES)}")
        params = validate_params(recipe, raw_params)

        # ── 闸门（规范 §12.6.1）──────────────────────────────────
        #   ★ 配方自己声明的确认词由**人**手输；平台只把它**转达**给内部的 red 动作。
        #     没有人的输入，一步都不许往下走。
        expect_txt = self._mode_needs_text(recipe, mode)
        if expect_txt:
            if confirm_text.strip() != expect_txt:
                raise OpsError(
                    code="CONFIRM_REQUIRED",
                    reason=f"「{_MODE_TXT.get(mode, mode)}」含破坏性步骤，"
                           f"需要**手输确认词**（点一下不算）",
                    advice=f"请手工输入：「{expect_txt}」",
                    context={"expect": expect_txt},
                )
        elif recipe.risk != "green" and not confirm:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason=f"配方「{recipe.name}」的风险等级是 {recipe.risk}，需要二次确认",
                advice="在界面上阅读影响面并勾选确认后再执行。",
                context={"risk": recipe.risk},
            )

        run = RecipeRun(
            id=new_recipe_run_id(self.cfg), recipe=recipe, host=host, mode=mode,
            started_at=now_iso(self.cfg),
        )
        run.t0 = time.monotonic()
        run.params_display = {p.name: params[p.name].display for p in recipe.params}
        run.params_machine = {p.name: params[p.name].value for p in recipe.params}

        # ★ 卸载段里的路径也渲染成真值（规范 §12.6 / 清单 37）：
        #   结论要念给用户听"保留了什么、删了什么"，念一句 `{{ root_dir }}` 等于没念。
        def _r(x: str) -> str:
            try:
                return render_argv_element(x, params)
            except OpsError:
                return x

        run.uninstall_rendered = {
            "keep_data": [_r(x) for x in recipe.uninstall.keep_data],
            "purge_paths": [_r(x) for x in recipe.uninstall.purge_paths],
            "remove_config": [
                _r(str((it.get("args") or {}).get("path") or ""))
                for it in recipe.uninstall.remove_config
            ],
        }

        collect = self._collector(host)

        # ── 前置期望（不成立 → aborted，目标机零改动）──────────────
        if mode == "deploy" and recipe.preflight:
            run.preflight = self._eval_expects(recipe, recipe.preflight, params, collect, "preflight")
            bad = [e for e in run.preflight if e["state"] != "pass"]
            if bad:
                first = bad[0]
                run.status = "aborted"
                run.error = OpsError(
                    code="PRECHECK_FAILED",
                    reason=f"前置条件不满足，已中止（目标机未被改动）：{first['expected']}",
                    advice=str(first.get("fail_reason") or first.get("advice") or
                                "按上面的判定结果处理后再跑一次。"),
                    detail=_outcome_detail(first),
                )
                return self._finish(run)

        # ── 主序列 + 触发队列 ────────────────────────────────────
        to_run: list[RecipeStep] = []
        if mode == "deploy":
            to_run = [s for s in recipe.steps if not s.trigger_only and self._when_ok(s, params)]
            run.skipped_steps = [
                s.name for s in recipe.steps if s.trigger_only or not self._when_ok(s, params)
            ]
            iterable: list[tuple[str, RecipeStep, dict[str, Any] | None]] = [
                ("deploy", s, None) for s in to_run
            ]
        else:
            run.skipped_steps = []
            iterable = [("uninstall", None, item) for item in self._mode_actions(recipe, mode)]

        aborted = False
        for _mode, st, action_item in iterable:
            if aborted:
                break
            if st is not None:
                row = self._run_recipe_step(recipe, st, host, params, run, collect)
            else:
                row = self._run_action_item(recipe, action_item or {}, host, params, run, mode)
            run.steps.append(row)
            if step_blocks_recipe(row):
                aborted = True
                run.status = "failed"
                run.error = OpsError(
                    code=row.get("error", {}).get("code") if isinstance(row.get("error"), dict) else "STEP_FAILED",
                    reason=f"步骤「{row.get('title') or row.get('name')}」失败，配方已中止（已完成步骤的留证与备份都保留）",
                    advice=("看该步骤对应任务的原始输出；需要回到变更前，"
                            "用下面列出的检查点一键恢复。") if run.checkpoints else
                           ("看该步骤对应任务的原始输出；★ 本次**没有登记到检查点**"
                            "（这一步之前没有覆盖既有文件），已完成步骤的留证都在各自任务 ID 下。"),
                    detail=(row.get("error") or {}).get("reason", "") if isinstance(row.get("error"), dict) else "",
                )
                # 失败前已触发的 notify 不再执行（宁可不重启）

        # ── 被 notify 触发的步骤（主序列跑完后、健康检查前）────────
        if not aborted and mode == "deploy":
            pending = self._pending_triggers(recipe, run)
            for name in pending:
                st = recipe.step(name)
                if st is None:
                    continue
                row = self._run_recipe_step(recipe, st, host, params, run, collect, triggered_by=True)
                run.steps.append(row)
                if step_blocks_recipe(row):
                    aborted = True
                    run.status = "failed"
                    run.error = OpsError(
                        code="STEP_FAILED",
                        reason=f"被触发的步骤「{row.get('title') or name}」失败",
                        advice=("看该步骤对应任务的原始输出；配置已写入，"
                            "可用下面列出的检查点恢复。") if run.checkpoints else
                           ("看该步骤对应任务的原始输出；这一步之前没有覆盖既有文件，"
                            "因此没有检查点。"),
                    )
                    break

        # ── 健康检查（★ 期望必须与"这次要做成什么"配对，规范 §12.6.3）────
        #   · 部署：判"服务可用"（recipe.health）
        #   · 停止 / 「保留数据」卸载：判 uninstall.health（"确实停了"）
        #     ★ 不能拿部署那句 `state: active` 去判"刚停完" —— 那必然判红，
        #       于是「停止」这个正向操作永远显示失败（T5 真跑时抓到的缺陷）
        #   · 全删：不判健康 —— 连包都没了，没有可探的服务状态；
        #     结局由各步自证（file.remove 的 ls 退出码 2、pkg.remove 的 isgone）
        if mode == "deploy":
            expects = recipe.health
        elif mode in ("stop", "uninstall_keep"):
            expects = recipe.uninstall.health
        elif mode == "uninstall_purge":
            # ★ v1.7（T6·S2 真跑抓到 · 规范 §12.6.5）：全删判的是**收敛（终态）**，不是"服务健康"。
            #   终态 = `remove_packages` 里每一个包**真的不存在**了。
            #   ★ 为什么必须有它：见 `_mode_actions` 里卸包步骤的处理 ——
            #     dnf 会顺带把依赖带走 ⇒ 中间某步"包已不在"是**正常**的；
            #     但如果**真有包没卸掉**，这里的 absent 判不过 → 配方 failed（不会假绿）。
            #   ★★ v1.8（规范 §12.16 规矩 3 · T7 主线 2）：收敛检查**扩到"包 + 路径"两类**。
            #     T6 只判了包 —— 于是"配置 / 数据目录还在"这件事**没有任何判据能发现**：
            #     只要 `file.remove` 那几步没报错，报告就说"全删完成"。
            #     现在逐条路径（删配置 + 删目录）都用 `file.stat` 的 `absent` 判一遍。
            #   ★ 一句话规矩：**删除类操作的成败永远是"目标在不在"，不是"命令返回了什么"。**
            expects = purge_convergence_expects(recipe, run.uninstall_rendered)
        else:
            expects = []
        if not aborted and expects:
            run.health = self._eval_expects(recipe, expects, params, collect, "health")
            bad = [e for e in run.health if e["state"] != "pass"]
            if bad:
                first = bad[0]
                run.status = "failed"
                run.error = OpsError(
                    code="VERIFY_FAILED",
                    reason=f"健康检查未通过：{first['expected']}",
                    advice=str(first.get("advice") or "看该条判定的采集任务原始输出。"),
                    detail=_outcome_detail(first),
                )

        return self._finish(run)

    # ---------------------------------------------------------- 配方批量（T7·S6 · 规范 §12.18）

    def batch_plan(self, recipe_id: str, host_ids: list[str], *, mode: str = "deploy") -> dict[str, Any]:
        """批量**预检**（只读，不碰目标机）：这一批会怎么做、闸门放不放行、每台会得到什么。"""
        recipe = self.recipe(recipe_id)
        gate = batch_gate(recipe, mode)
        hosts = []
        for hid in host_ids:
            try:
                h = self.cfg.host(hid)
                hosts.append({"host_id": h.id, "host_name": h.name, "target": h.target})
            except OpsError as exc:
                hosts.append({"host_id": hid, "host_name": hid, "target": "",
                              "error": exc.to_dict()})
        return {
            "recipe_id": recipe.id, "recipe_title": recipe.name, "recipe_version": recipe.version,
            "risk": recipe.risk, "mode": mode, "hosts": hosts, "gate": gate,
            "confirm_text": self._mode_needs_text(recipe, mode),
            "note": ("★ 每台是**一个独立的配方执行**（独立执行号 / 独立留证 / 可单独回放）；"
                     "★ 单台失败或不可达**不影响其它台**；★ 横向对照按「**执行状态 + 收敛检查结果**」判，"
                     "不按「命令返回 0」、不看变更步数（规范 §12.18 / §12.22）"),
        }

    def batch_run(self, recipe_id: str, host_ids: list[str],
                  raw_params: dict[str, Any] | None, *, mode: str = "deploy",
                  confirm: bool = False, confirm_text: str = "") -> dict[str, Any]:
        """把**同一份配方 + 同一份参数**铺到 N 台（每台一个独立执行）。

        三层闸门，一层都不许省（规范 §12.18）：
          ① `red` 配方 ⇒ **直接拒**（不提供开关）；
          ② `yellow` 配方 ⇒ 要 `confirm=True`（二次确认）；
          ③ 停止 / 全删这类模式 ⇒ **手输确认词**（服务端逐台校验，配方层的那句话在这里**转达**）。
        ★ 失败隔离：**任何一台**出问题（连不上 / 参数被拒 / 执行失败）都只记在它自己那一行，
          循环继续往下走 —— 一台坏把整批停掉，是最坏的组合。
        """
        recipe = self.recipe(recipe_id)
        gate = batch_gate(recipe, mode)
        if not gate["allowed"]:
            raise OpsError(code="BATCH_FORBIDDEN", reason=gate["reason"], advice=gate["advice"])
        if gate["needs_confirm"] and not confirm:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason=f"配方「{recipe.name}」（{recipe.risk}）批量执行需要二次确认",
                advice="在界面上阅读影响面并勾选确认后再执行。",
                context={"risk": recipe.risk},
            )
        want_text = self._mode_needs_text(recipe, mode)
        if want_text and confirm_text.strip() != want_text:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason=f"「{_MODE_TXT.get(mode, mode)}」含破坏性步骤，批量执行同样需要**手输确认词**",
                advice=f"请手工输入：「{want_text}」",
                context={"expect": want_text},
            )
        items: list[dict[str, Any]] = []
        for hid in host_ids:
            try:
                run = self.run(recipe_id, hid, raw_params, mode=mode,
                               confirm=confirm, confirm_text=confirm_text)
                pub = run.to_public()
                checks_failed = len([h for h in pub.get("health") or [] if h.get("state") != "pass"])
                items.append({
                    "host_id": pub["host_id"], "host_name": pub["host_name"],
                    "run_id": pub["run_id"], "status": pub["status"],
                    "changed_steps": pub["changed_steps"],
                    "unchanged_steps": pub["unchanged_steps"],
                    "unknown_steps": pub["unknown_steps"],
                    "checks_failed": checks_failed, "checks_total": len(pub.get("health") or []),
                    "checkpoints": len(pub.get("checkpoints") or []),
                    "duration_ms": pub.get("duration_ms") or 0,
                    "conclusion": pub.get("conclusion") or "",
                    "error": pub.get("error"),
                })
            except OpsError as exc:
                # ★ 失败隔离：这一台的问题**只记在它自己这一行**，循环继续。
                items.append({
                    "host_id": hid, "host_name": hid, "run_id": None,
                    "status": "failed", "changed_steps": [], "unchanged_steps": [],
                    "unknown_steps": [], "checks_failed": None, "checks_total": 0,
                    "checkpoints": 0, "duration_ms": 0, "conclusion": "",
                    "error": exc.to_dict(),
                })
        return {
            "recipe_id": recipe.id, "recipe_title": recipe.name, "mode": mode,
            "gate": gate, "confirm_text": want_text,
            "items": items, "summary": batch_summary(items),
            # ★ 边界**必须明说**（规范 §12.22）：这一批**不落地批次快照**。
            #   留证单元是"每台那一次配方执行"（`recipe_runs`，永久可回放、可回退到它自己部署前）
            #   —— 再存一层批次快照就是**两份真相**（§12.20「组回退不另写一套自证」同一个理由）。
            #   代价：这张横向对照表**只活在当前页面**；要回看某一台，用它自己的执行号打开。
            "boundary": ("★ 这一批**不落地批次快照**：横向对照表只活在当前页面 —— "
                         "但每一台的执行号都在「配方执行」里，可单独打开、单独回退到它自己那次部署前。"),
        }

    # ---------------------------------------------------------- 部署组回退（T7·S4 · 规范 §12.20）

    def rollback_plan(self, run_id: str) -> dict[str, Any]:
        """「回到这次部署前」的**逐项**计划（**只读**，不改任何东西）。

        ★ 一次执行 = **一组**检查点 ⇒ 计划与结果都是**逐项**的（规范 §12.20）。
        ★ 计划里必须同时给出三样东西，缺一不可：
          ① 逐项：哪一项 · 从哪个备份 · 期望 sha256 · 这一项能不能回去（不能就说清为什么）；
          ② ★★ 「**回不去的**」四类，**从这次执行真的做过什么反推**，空也要写"无"（§12.19）；
          ③ ★ **已知边界**：参数变更留下的上一版产物**不在**本计划的回退范围（清单 64）。
        """
        run = self.store.get_recipe_run(run_id)
        items: list[dict[str, Any]] = []
        for i, c in enumerate(run.get("checkpoints") or [], start=1):
            bid = c.get("backup_id")
            rec = None
            if bid is not None:
                try:
                    rec = self.store.get_backup(int(bid))
                except OpsError:
                    rec = None
            bak_ok = rec is not None and rec.get("status") == "ok"
            items.append({
                "seq": i,
                "backup_id": bid,
                "label": c.get("label") or (rec or {}).get("label") or c.get("orig_path"),
                "orig_path": c.get("orig_path") or (rec or {}).get("orig_path") or "",
                "kind": (rec or {}).get("kind") or c.get("kind"),
                "size": (rec or {}).get("size"),
                "expect_sha256": (rec or {}).get("sha256") or c.get("sha256") or "",
                "from_step": c.get("step"),
                "backup_status": (rec or {}).get("status") or "missing",
                "can_restore": bool(bak_ok),
                "why_not": "" if bak_ok else (
                    "★ 这一项**回不去**：备份记录不在或状态不是 ok（可能已被清理）"
                ),
                "self_proof": "恢复后由**单点恢复那条路**做 sha256 逐字节比对（目录型 = 逐文件指纹汇总）",
            })
        restorable = [int(i["backup_id"]) for i in items if i["can_restore"]]
        return {
            "run_id": run_id,
            "recipe_id": run.get("recipe_id"),
            "recipe_title": run.get("recipe_title"),
            "recipe_version": run.get("recipe_version"),
            "host_id": run.get("host_id"),
            "host_name": run.get("host_name"),
            "mode": run.get("mode"),
            "started_at": run.get("started_at"),
            "items": items,
            "restorable": restorable,
            "cannot_restore": self.unrecoverable_inventory(run),
            "boundary": ("★ **参数变更留下的上一版产物不在本计划的回退范围**（规范 §12.20 / 清单 64）："
                         "改了 root_dir / share 这类参数后重跑，上一版写过的目录或文件**没有**出现在"
                         "这次执行的检查点里 —— 本计划**不会**去清理它。"),
            "confirm_text": GROUP_RESTORE_CONFIRM_TEXT,
            "auto": False,
        }

    @staticmethod
    def unrecoverable_inventory(run: dict[str, Any]) -> list[dict[str, str]]:
        """「回不去的」四类（规范 §12.19 / §12.20）—— 从**这次执行真的做过什么**反推。

        ★★ **空也要写"无"**：这一栏的空白会被读成"都回得去"，那正是 §12.19 说的最危险的那种误解。
        """
        pkgs: list[str] = []
        svcs: list[str] = []
        for s in run.get("steps") or []:
            args = s.get("args") or {}
            aid = str(s.get("action") or "")
            if aid.startswith("pkg.") and args.get("package"):
                pkgs.append(str(args["package"]))
            if aid in ("svc.start", "svc.stop", "svc.restart", "svc.enable", "svc.disable") \
                    and args.get("unit"):
                svcs.append(f"{aid}({args['unit']})")
        return [
            {
                "kind": "包",
                "items": "、".join(sorted(set(pkgs))) or "无",
                "why": ("本入口**不动包**。★ 要回退包请用「回退软件包事务」按那次任务结论里的事务号回退"
                        "（它会把版本逐字对照摆出来）"),
            },
            {
                "kind": "服务状态（systemd）",
                "items": "、".join(sorted(set(svcs))) or "无",
                "why": ("start / stop / enable / disable **不在回退范围** —— 回退只还原**文件内容**，"
                        "不会替你把服务启停回去"),
            },
            {
                "kind": "运行时内存态 / 已写进数据文件的内容",
                "items": "无",
                "why": ("文件能回到备份那一刻的样子；但**进程里已经跑着的状态**、"
                        "**已经写进数据文件的内容**（例如数据库已落盘的行）**不在此列**"),
            },
            {
                "kind": "外部影响（别的机器 / 别的服务）",
                "items": "无",
                "why": "本入口只作用于这台机器；别的机器、别的服务上发生过的事**一件也撤不掉**",
            },
        ]

    def rollback_run(self, run_id: str, confirm_text: str,
                     backup_ids: list[int] | None = None) -> dict[str, Any]:
        """**逐项**把这次执行登记过的检查点恢复回去（🔴 red：手输确认词 + 逐项留证）。

        ★ 三条不许（规范 §12.20）：**不许自动**（只有人点了才算）· **不许一项失败拖垮其它项** ·
          **不许把"回不去"藏起来**（四类逐项摆出来）。
        ★ 自证复用**单点恢复那条路**（sha256 逐字节 / 目录逐文件指纹汇总）—— 组回退**不另写一套**。
        """
        if confirm_text.strip() != GROUP_RESTORE_CONFIRM_TEXT:
            raise OpsError(
                code="CONFIRM_REQUIRED",
                reason="「回到这次部署前」会**逐项覆盖**多个路径，属于 red 级操作",
                advice=f"请手工输入：「{GROUP_RESTORE_CONFIRM_TEXT}」（点一下不算）",
                context={"expect": GROUP_RESTORE_CONFIRM_TEXT},
            )
        plan = self.rollback_plan(run_id)
        want = {int(x) for x in (backup_ids if backup_ids is not None else plan["restorable"])}
        relay: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        # ★ 默认**逐项全过一遍**（含"回不去"的那些）—— 一次都不能静默跳过：
        #   只处理"能回去"的项，用户就永远看不到"有一项根本没回去"（§12.20 的逐项口径）。
        #   调用方显式给了 backup_ids 时，那才是一份"只做这几项"的清单。
        for it in plan["items"]:
            bid = it.get("backup_id")
            if bid is None:
                continue
            if backup_ids is not None and int(bid) not in want:
                continue
            row = {k: it[k] for k in ("seq", "backup_id", "label", "orig_path", "kind",
                                     "expect_sha256", "from_step")}
            if not it["can_restore"]:
                row.update({"ok": False, "task_id": None,
                            "error": {"code": "BACKUP_MISSING", "reason": it["why_not"], "advice": ""}})
                results.append(row)
                continue
            # ★ 转达单点恢复的确认词（§12.6.1 同一个做法）——留证，别让"人已经确认过"变成一句口头话。
            relay.append({
                "backup_id": int(bid), "orig_path": it["orig_path"],
                "confirm_text": RESTORE_CONFIRM_TEXT, "at": now_iso(self.cfg),
                "note": "组回退把**单点恢复**那条路的确认词转达下去（规范 §12.20 / §12.6.1）",
            })
            try:
                out = self.engine.restore_backup(int(bid), RESTORE_CONFIRM_TEXT)
                row.update({
                    "ok": bool(out.get("ok")),
                    "task_id": out.get("task_id"),
                    # ★ 自证的原文（"sha256 逐字节一致（…）" / 目录型的逐文件指纹汇总）原样带出来，
                    #   不压缩成一句"成功" —— 让人看得见它**凭什么**说成功了。
                    "self_proof_text": str(out.get("conclusion") or ""),
                    "error": None if out.get("ok") else {
                        "code": "RESTORE_FAILED", "reason": str(out.get("error") or ""),
                        "advice": "看这一项的恢复任务原始输出；其余各项不受影响（逐项独立）。",
                    },
                })
            except OpsError as exc:
                # ★ 逐项独立：一项抛错继续下一项（否则"一项坏 → 全都不会回去"是最坏的组合）。
                row.update({"ok": False, "task_id": None, "error": exc.to_dict()})
            results.append(row)
        ok_n = len([r for r in results if r.get("ok")])
        return {
            "run_id": run_id,
            "recipe_title": plan.get("recipe_title"),
            "host_name": plan.get("host_name"),
            "auto": False,
            "confirm_relay": relay,
            "items": results,
            "ok_count": ok_n,
            "failed_count": len(results) - ok_n,
            "cannot_restore": plan["cannot_restore"],
            "boundary": plan["boundary"],
            "conclusion": self._rollback_conclusion(plan, results),
        }

    @staticmethod
    def _rollback_conclusion(plan: dict[str, Any], results: list[dict[str, Any]]) -> str:
        ok_rows = [r for r in results if r.get("ok")]
        bad_rows = [r for r in results if not r.get("ok")]
        lines = [
            f"【{plan.get('host_name') or ''}】回到这次部署前（执行号 {plan.get('run_id')}）· "
            f"{'✅ 全部回去' if not bad_rows else f'⚠️ {len(ok_rows)}/{len(results)} 项回去'}",
            f"配方：{plan.get('recipe_title')} v{plan.get('recipe_version')} ｜ 模式：{plan.get('mode')}",
            "★ 本操作**逐项**执行，自证由**单点恢复那条路**给出（sha256 逐字节 / 目录逐文件指纹汇总）。",
            "",
            "── 逐项结果 ──",
        ]
        for r in results:
            mark = "✅" if r.get("ok") else "❌"
            lines.append(f"{mark} 第 {r.get('seq')} 项 {r.get('label')}")
            lines.append(f"    路径：{r.get('orig_path')}")
            sha = r.get("expect_sha256") or ""
            lines.append(f"    期望指纹：{sha[:24]}…" if sha else "    期望指纹：（无）")
            if r.get("task_id"):
                lines.append(f"    恢复留证任务：{r['task_id']}")
            if r.get("self_proof_text"):
                lines.append(f"    自证：{r['self_proof_text']}")
            if not r.get("ok"):
                err = r.get("error") or {}
                lines.append(f"    ★ 没回去：{err.get('reason') or ''}"
                             + (f" ｜ {err.get('advice')}" if err.get("advice") else ""))
        lines += ["", "── ★★ 这些**回不去**（逐项列清，空也要写「无」）──"]
        for u in plan.get("cannot_restore") or []:
            lines.append(f"· {u['kind']}：{u['items']}")
            lines.append(f"    {u['why']}")
        lines += ["", f"{plan.get('boundary')}",
                  "★ 本入口**不是**「撤销这次执行」：它只还原上面列出的那几项，其余一律不动（规范 §12.20）。"]
        return "\n".join(lines)

    # ---------------------------------------------------------- 内部：采集与判定

    def _collector(self, host: Host):
        """给期望判定层用的采集器：**只会调用已登记的动作**（规范 §12.2 约束 2）。"""
        def collect(action_id: str, args: dict[str, Any]) -> Any:
            return self.engine.run(action_id, host.id, args, confirm=True)
        return collect

    def _eval_expects(self, recipe: Recipe, items: list[dict[str, Any]],
                      params: dict[str, ParamValue], collect, where: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for i, item in enumerate(items):
            at = f"{where}[{i}]"
            try:
                oc = eval_expect(item["expect"], collect, params, where=at)
                row = oc.to_public()
            except OpsError as exc:
                row = {
                    "kind": "?", "where": at, "state": "unknown",
                    "expected": str(item["expect"]), "actual": "",
                    "collect_action": "", "collect_task": None,
                    "reason": exc.reason, "advice": exc.advice,
                }
            row["fail_reason"] = item.get("fail_reason") or ""
            # ★ 把"这一条在判谁"原样带到判定结果里（规范 §12.16 规矩 6）：
            #   结论按它分段，**不靠下标配对**（顺序一错会静默念错，见 `purge_convergence_expects`）。
            if item.get("converge"):
                row["converge"] = item["converge"]
            out.append(row)
        return out

    # ---------------------------------------------------------- 内部：跑一个步骤

    def _run_recipe_step(self, recipe: Recipe, st: RecipeStep, host: Host,
                         params: dict[str, ParamValue], run: RecipeRun, collect,
                         *, triggered_by: bool = False) -> dict[str, Any]:
        if st.kind == "action":
            args = {}
            try:
                args = {k: render_argv_element(str(v), params) for k, v in st.args.items()}
            except OpsError as exc:
                return {
                    "name": st.name, "title": st.title or st.name, "kind": "action",
                    "action": st.action, "status": "failed", "changed": None,
                    "optional": st.optional, "task_id": None, "triggered_by": triggered_by,
                    "error": exc.to_dict(),
                }
            return self._run_action_item(recipe, {"action": st.action, "args": args}, host,
                                         params, run, "deploy", st=st, triggered_by=triggered_by)

        if st.kind == "template":
            return self._run_template_step(recipe, st, host, params, run, triggered_by=triggered_by)

        if st.kind == "wait":
            return self._run_wait_step(recipe, st, params, collect, triggered_by=triggered_by)

        return {
            "name": st.name, "title": st.title or st.name, "kind": st.kind,
            "status": "skipped", "changed": None, "task_id": None,
            "optional": st.optional, "triggered_by": triggered_by,
            "error": None,
        }

    def _run_wait_step(self, recipe: Recipe, st: RecipeStep,
                       params: dict[str, ParamValue], collect,
                       *, triggered_by: bool = False) -> dict[str, Any]:
        """`wait` 步骤（规范 §12.120）：**轮询一条 expect，直到它成立或超时**。

        ★★ 它是本项目**早就写下、一直没兑现的承诺**：`wait` 一直躺在 `STEP_KEYS` 里，
          loader 写着「预留给 T16 的「开机 → 等就绪」」。
        ★★ 与"睡 N 秒"的根本区别：**它判的是条件，不是时间** ——
          · 机器起得快 ⇒ 立刻往下走（不必干等）；
          · 机器到点还没起来 ⇒ **判红**（如实说"没等到"），而不是"睡够了就走"。
        ★ 轮询用的判据请选**轻量、不产生任务**的那种（`port_open` / `http_status`）：
          用 `state` / `responds` 会在每一次轮询里真的起一个只读动作 —— 那是**制造噪音**。
        """
        import time as _t

        w = st.wait or {}
        timeout = max(1, int(w.get("timeout_sec") or 120))
        interval = max(1, int(w.get("interval_sec") or 5))
        item = {"expect": w.get("expect") or {}, "fail_reason": str(w.get("fail_reason") or "")}
        t0 = _t.monotonic()
        last: dict[str, Any] = {}
        while True:
            rows = self._eval_expects(recipe, [item], params, collect, where=f"wait:{st.name}")
            last = rows[0] if rows else {}
            waited = int(_t.monotonic() - t0)
            if last.get("state") == "pass":
                return {
                    "name": st.name, "title": st.title or st.name, "kind": "wait",
                    "status": "ok", "changed": False, "optional": st.optional,
                    "task_id": None, "triggered_by": triggered_by,
                    "waited_sec": waited, "evidence": last, "error": None,
                    "note": f"等了 {waited}s：条件成立",
                }
            if _t.monotonic() - t0 >= timeout:
                return {
                    "name": st.name, "title": st.title or st.name, "kind": "wait",
                    "status": "failed", "changed": False, "optional": st.optional,
                    "task_id": None, "triggered_by": triggered_by,
                    "waited_sec": waited, "evidence": last,
                    "error": {
                        "code": "WAIT_TIMEOUT",
                        "reason": (f"等了 {timeout}s，条件仍未成立：{item['expect']}"
                                   + (f" —— {item['fail_reason']}" if item["fail_reason"] else "")),
                        "advice": ("★ 这是**结论**，不是「再等等就好」：先看这一步的证据（最后一次判定"
                                   "问的是谁、答的是什么），再决定是加长超时、还是去查为什么没起来。"
                                   "★ 若它是被 `vm.start` 之前的那一步卡住，请回到那一步的结论看。"),
                    },
                }
            _t.sleep(interval)

    def _run_action_item(self, recipe: Recipe, item: dict[str, Any], host: Host,
                         params: dict[str, ParamValue], run: RecipeRun, mode: str,
                         *, st: RecipeStep | None = None,
                         triggered_by: bool = False) -> dict[str, Any]:
        aid = str(item["action"])
        action = self.actions[aid]
        raw_args = item.get("args") or {}
        try:
            args = {k: render_argv_element(str(v), params) for k, v in raw_args.items()}
        except OpsError as exc:
            return {
                "name": (st.name if st else aid), "title": (st.title if st else action.title),
                "kind": "action", "action": aid, "status": "failed", "changed": None,
                "optional": bool(st.optional) if st else bool(item.get("optional")), "task_id": None,
                "triggered_by": triggered_by, "error": exc.to_dict(),
            }
        name = st.name if st else aid
        title = (st.title or action.title) if st else action.title

        # ★ 内部 red 动作的「转达」（规范 §12.6.1）：人已经在配方层确认过，
        #   这里把**该动作自己的确认词**递下去，并留证。
        inner_text = ""
        if action.risk == "red":
            inner_text = str((action.confirm or {}).get("confirm_text") or "")
            if not inner_text:
                return {
                    "name": name, "title": title, "kind": "action", "action": aid,
                    "status": "failed", "changed": None, "task_id": None,
                    "optional": bool(st.optional) if st else bool(item.get("optional")), "triggered_by": triggered_by,
                    "error": {
                        "code": "RECIPE_INVALID",
                        "reason": f"配方引用了 red 动作 {aid}，但它没有 confirm_text，无法转达确认",
                        "advice": "在该动作 YAML 里补 confirm.confirm_text。",
                    },
                }
            run.confirm_relay.append({
                "action": aid, "step": name, "confirm_text": inner_text,
                "at": now_iso(self.cfg),
                "note": "由配方层已手输的确认词转达给该 red 动作（规范 §12.6.1）",
            })

        try:
            task = self.engine.run(aid, host.id, args, confirm=True, confirm_text=inner_text)
        except OpsError as exc:
            return {
                "name": name, "title": title, "kind": "action", "action": aid,
                "status": "failed", "changed": None, "task_id": None,
                "optional": bool(st.optional) if st else bool(item.get("optional")), "triggered_by": triggered_by,
                "error": exc.to_dict(),
            }

        # ★★ v1.8（规范 §12.16 · T7 主线 2）：卸载类步骤的「**终态达成**」语义。
        #   背景（T6 与 T7·S2 两次真跑各抓到一半）：
        #     · T6：路径已经被删过一次之后，再点「卸载·全删」→ `file.remove` 的预检必然失败
        #       → 配方当场中止 → **数据目录与软件包一个都没删**（"全删"点了没效果）；
        #     · T7·S2：「包已被卸掉」的现状下点「全删」→ **`svc.stop` 的预检失败**
        #       （单元文件随包一起没了）→ 配方**第一步就中止**，后面一条都没删。
        #   ⇒ 规矩：**目标本就不存在 ⇒ 已达终态，不是失败**（判 `skipped`，配方继续往下走）。
        #     ★ 这条覆盖**两层**：路径层（东西不在了）+ **服务层**（服务不在了）。
        #   ★ 但**只有 `PRECHECK_FAILED` 这一种原因**、且**只在非 deploy 模式**享受这个待遇：
        #     权限不足 / 备份失败 / 依赖冲突 / SSH 不可达……**照旧中止**（检查清单 51）；
        #     deploy 段里同一句失败**照旧中止**（要重启的服务不见了，必须停下来说清楚）。
        terminal = uninstall_step_terminal(
            aid, mode, task.status,
            task.error.code if task.error is not None else None,
        )
        # ★★ v1.11（规范 §12.33）：**幂等守卫** —— 动作作者在**某一条预检**上声明
        #   "它不成立 = 目标已经是我想要的样子了"。与上面那条（卸载类 + 非 deploy）并存。
        declared_done, declared_why = precheck_means_done(action, task)
        terminal = terminal or declared_done
        terminal_why = ""
        if terminal:
            # 把"是哪一步、退出码多少"记下来：这一条判 skipped 也要**能复核**，
            # 否则"已达终态"就成了一句谁也无法证伪的托词。
            pre = next((s for s in task.steps
                        if getattr(s, "status", None) not in ("ok", "skipped")), None)
            ev = (f"{getattr(pre, 'title', '') or getattr(pre, 'name', '')}"
                  f"（退出码 {getattr(pre, 'exit_code', '?')}）") if pre is not None else "预检未通过"
            if declared_done:
                terminal_why = (
                    f"**已达终态**：{declared_why}"
                    f"（复核依据：{ev}）—— 本步按「跳过」处理，配方继续往下走。"
                    "★ 它既不算「做成了事情」，也不算失败；"
                    "★ **这一步零改动是结构性可证的**（预检在任何变更步骤之前、失败即返回）。"
                )
            else:
                terminal_why = (
                    f"目标**本就不存在 / 服务本就没在**（{ev}）—— 已达终态：本步按「跳过」处理，配方继续往下走。"
                    "★ 它既不算「删掉了东西 / 停了服务」，也不算失败；"
                    "真正「清干净了没有」由全删的**收敛检查**回答。"
                )

        # 检查点：这一步产生的备份记录（可回滚到的点）
        for rec in self.store.list_backups(task_id=task.id):
            if rec.get("status") == "ok":
                run.checkpoints.append({
                    "step": name, "task_id": task.id, "backup_id": rec.get("id"),
                    "label": rec.get("label") or rec.get("orig_path"),
                    "orig_path": rec.get("orig_path"), "sha256": rec.get("sha256"),
                    "kind": rec.get("kind"),
                    "detail": f"改动前是 {rec.get('kind')}（{rec.get('size') or 0} 字节）",
                    "how": "在「历史」里找到这条任务 → 对备份点一次「恢复」，即回到改动前",
                })

        return {
            "name": name, "title": title, "kind": "action", "action": aid,
            "args": args, "status": "skipped" if terminal else task.status,
            # ★ 终态跳过的那一步，`changed` 记 **False**（规范 §12.16 规矩 5），不是 unknown：
            #   引擎的顺序是 预检 → 备份 → **执行**，预检失败即 return ⇒
            #   "**这一步零改动**"是**结构性可证的**，不是猜的。★ 仅这一步这么记，
            #   其余 aborted 步骤照旧 unknown（宪法 2 不动）。
            "changed": False if terminal else task.changed,
            "changed_rule": describe_changed(aid),
            # ★ 终态达成（规范 §12.16）：状态按 skipped 记，但**原始失败信息一并留着** ——
            #   "按已达终态跳过"这件事本身也要能被复核，不许把证据抹掉。
            "terminal": terminal,
            "terminal_why": terminal_why,
            # ★ v1.7 修订六·补（T6·S2 复验抓到）：这一条**主返回**也必须读 `item["optional"]`。
            #   前一版只改了上面三个**异常返回**，于是"动作跑完了、但任务本身是 aborted"
            #   这条**最常走**的路（`pkg.remove` 因包已被 dnf 连带收走而预检失败，就是它）
            #   仍然拿 `st is None → False` —— 修复等于没生效，配方照样中止。
            #   ★ 教训：同一个字段有 N 个出口，改就必须**每个出口都改**；
            #     只改"看起来像出错"的那几个出口，恰好漏掉"任务结束了但没成功"这个正主。
            "optional": bool(st.optional) if st else bool(item.get("optional")),
            "task_id": task.id, "duration_ms": task.duration_ms,
            "triggered_by": triggered_by,
            "conclusion": task.conclusion,
            "error": task.error.to_dict() if task.error else None,
        }

    def _run_template_step(self, recipe: Recipe, st: RecipeStep, host: Host,
                           params: dict[str, ParamValue], run: RecipeRun,
                           *, triggered_by: bool = False) -> dict[str, Any]:
        """渲染模板 → 与目标机比对 sha256 → **不同才写**（规范 §12.4）。"""
        name = st.name
        title = st.title or f"渲染 {st.template}"
        started = now_iso(self.cfg)
        try:
            dest = render_argv_element(st.dest or "", params)
            content = self._render_tpl(recipe, st, params)
        except OpsError as exc:
            return {
                "name": name, "title": title, "kind": "template", "status": "failed",
                "changed": None, "task_id": None, "optional": st.optional,
                "triggered_by": triggered_by, "error": exc.to_dict(),
            }
        want = sha256_hex(content)

        # ★ 改动前备份（T3 护栏 · 规范 §9.1 与 §12.7）：
        #   渲染会**覆盖目标机既有文件**，不备份就等于"改坏了没有可回滚的点" ——
        #   而"动作有备份、配方没有"就是同一件事两套标准。
        #   挂钩点选在 write_remote_file 的 `before_write`：只有"内容确实不同、真会写盘"
        #   才会走到，于是**幂等的那一次既不产生备份、也不产生检查点**。
        task_id = new_task_id(self.cfg)

        def _before_write(_before_sha: str) -> None:
            records, err = self.engine.backup_runner.run_items(
                task_id, host,
                [(0, BackupItem(path=dest,
                                label=f"{recipe.name} · {title}（覆盖前）",
                                required=False), dest)],
            )
            self.store.save_backups([
                dict(r.to_row(), host_id=host.id, host_name=host.name,
                     action_id="recipe.template") for r in records
            ])
            # ★ 回读**落库之后**的记录：检查点必须带 `backup_id`，
            #   否则界面上的「一键恢复」没有落脚点（验收 #5 要的就是那个按钮真能点）。
            saved = {str(x.get("orig_path")): x
                     for x in self.store.list_backups(task_id=task_id)}
            for r in records:
                if r.status == "ok":
                    row = saved.get(r.orig_path) or {}
                    run.checkpoints.append({
                        "step": name, "task_id": task_id, "backup_id": row.get("id"),
                        "label": r.label, "orig_path": r.orig_path, "sha256": r.sha256,
                        "kind": r.kind,
                        "detail": (f"覆盖前是 {r.kind}（{r.size} 字节"
                                   + (f"，{r.file_count} 个文件" if r.file_count else "")
                                   + (f"），原 sha256 {r.sha256[:16]}…" if r.sha256 else "）")),
                        "how": "在「历史」里找到这条任务 → 对备份点一次「恢复」，即回到覆盖前",
                    })
            if err is not None:
                raise err

        try:
            res = self.engine.write_remote_file(host, dest, content, st.mode,
                                                before_write=_before_write)
        except OpsError as exc:
            return {
                "name": name, "title": title, "kind": "template", "status": "failed",
                "changed": None, "task_id": task_id, "optional": st.optional,
                "triggered_by": triggered_by,
                "error": OpsError(
                    code=exc.code or "BACKUP_FAILED",
                    reason=f"改动前备份未完成，已放弃写盘：{exc.reason}",
                    advice=(exc.advice or "") + "（本步骤未改动目标机任何文件）",
                    detail=exc.detail,
                ).to_dict(),
            }
        status = "ok" if res["ok"] else "failed"

        # ★ 留证：模板步骤也要有一条可回放的任务记录（含**渲染后的最终内容**）
        stdout = (
            f"[目标] {dest}（mode {st.mode}）\n"
            f"[模板] {st.template}\n"
            f"[渲染] sha256={want}（{len(content.encode('utf-8'))} 字节）\n"
            + (res["stdout"] or "")
        )
        try:
            self.store.archive(task_id, "stdout", "rendered", content)
            self.store.archive(task_id, "stdout", "write", stdout)
            self.store.save_task(
                {
                    "id": task_id, "action_id": "recipe.template",
                    "action_title": f"{recipe.name} · {title}", "risk": "yellow",
                    "host_id": host.id, "host_name": host.name,
                    "host_address": host.address, "host_user": host.user,
                    "status": status,
                    "params": {"dest": dest, "template": st.template, "recipe": recipe.id,
                               "step": name},
                    "command_preview": f"render {st.template} -> {dest}（幂等：内容相同则不写）",
                    "conclusion": (
                        f"配置「{'已更新' if res['changed'] else '未变更'}」：{dest}\n"
                        f"渲染内容 sha256={want}"
                    ),
                    "error_code": (res["error"].code if res["error"] else None),
                    "error_reason": (res["error"].reason if res["error"] else None),
                    "error_advice": (res["error"].advice if res["error"] else None),
                    "verify_result": "ok" if res["ok"] else "failed",
                    "verify_detail": [{
                        "name": "写入后与渲染内容逐字节一致",
                        "ok": bool(res["ok"]),
                        "detail": f"期望 {want} / 实际 {res['after_sha'] or '（空）'}",
                        "severity": "fail",
                    }],
                    "changed": res["changed"],
                    "step_total": 1, "step_failed": 0 if res["ok"] else 1,
                    "exit_code": 0 if res["ok"] else 1,
                    "started_at": started, "ended_at": now_iso(self.cfg),
                    "duration_ms": 0, "batch_id": None,
                },
                [{
                    "seq": 1, "name": name, "title": title, "iter_key": None,
                    "argv": [], "argv_quoted": f"write_file {dest}",
                    "status": status, "optional": False,
                    "exit_code": 0 if res["ok"] else 1, "duration_ms": 0,
                    "stdout": stdout, "stderr": "",
                    "parsed": {"dest": dest, "sha256": want, "changed": res["changed"]},
                    "truncated": False, "changed": res["changed"],
                    "error_code": (res["error"].code if res["error"] else None),
                    "error_reason": (res["error"].reason if res["error"] else None),
                    "error_advice": (res["error"].advice if res["error"] else None),
                    "started_at": started, "ended_at": now_iso(self.cfg),
                }],
            )
        except OpsError:
            # 留证失败不该掩盖「写盘成功」这个事实，但要在结论里留痕
            pass

        return {
            "name": name, "title": title, "kind": "template", "status": status,
            "changed": res["changed"], "changed_rule": "模板渲染：内容 sha256 与目标机现有一致则不算变更",
            "dest": dest, "template": st.template, "sha256": want,
            "optional": st.optional, "task_id": task_id, "triggered_by": triggered_by,
            "error": res["error"].to_dict() if res["error"] else None,
        }

    # ---------------------------------------------------------- 内部：通知与开关

    def _when_ok(self, st: RecipeStep, params: dict[str, ParamValue]) -> bool:
        if not st.when:
            return True
        pv = params.get(st.when)
        return bool(pv is not None and str(pv.value) != "")

    def _pending_triggers(self, recipe: Recipe, run: RecipeRun) -> list[str]:
        """本步 `changed=true` → 触发它 notify 的步骤（按声明顺序、去重）。

        ★ `changed=unknown` **不触发**（宁可不重启，也不因为「判不出来」去重启一次服务）。
        """
        want: list[str] = []
        for row in run.steps:
            if row.get("changed") is not True:
                continue
            st = recipe.step(str(row.get("name") or ""))
            if st is None:
                continue
            for t in st.notify:
                if t not in want:
                    want.append(t)
        return want

    # ---------------------------------------------------------- 收尾

    def _finish(self, run: RecipeRun) -> RecipeRun:
        run.ended_at = now_iso(self.cfg)
        if run.t0:
            run.duration_ms = int((time.monotonic() - run.t0) * 1000)
        run.conclusion = self._conclusion(run)
        try:
            self.store.save_recipe_run({
                "id": run.id, "recipe_id": run.recipe.id, "recipe_title": run.recipe.name,
                "recipe_version": run.recipe.version, "host_id": run.host.id,
                "host_name": run.host.name, "host_address": run.host.address,
                "mode": run.mode, "status": run.status,
                "params": run.params_display, "preflight": run.preflight, "health": run.health,
                "steps": run.steps, "changed_steps": run.changed_steps,
                "unchanged_steps": run.unchanged_steps, "unknown_steps": run.unknown_steps,
                "checkpoints": run.checkpoints, "conclusion": run.conclusion,
                "error_code": run.error.code if run.error else None,
                "error_reason": run.error.reason if run.error else None,
                "error_advice": run.error.advice if run.error else None,
                "started_at": run.started_at, "ended_at": run.ended_at,
                "duration_ms": run.duration_ms,
            })
        except OpsError as exc:
            if run.error is None:
                run.error = exc
        return run

    def _conclusion(self, run: RecipeRun) -> str:
        mode_txt = _MODE_TXT.get(run.mode, run.mode)
        lines = [
            f"【{run.host.name}】配方「{run.recipe.name}」· {mode_txt} · "
            f"{'✅ 成功' if run.status == 'ok' else ('⛔ 已中止' if run.status == 'aborted' else '❌ 失败')}",
            f"本次变更：{len(run.changed_steps)} 项"
            + (f"（{'、'.join(run.changed_steps)}）" if run.changed_steps else "")
            + f" ｜ 未变更：{len(run.unchanged_steps)} 项"
            + f" ｜ ★ 无法判定：{len(run.unknown_steps)} 项"
            + (f"（{'、'.join(run.unknown_steps)}）" if run.unknown_steps else ""),
        ]
        if run.preflight:
            lines.append("前置检查：" + "；".join(
                f"{_kind_txt(e['kind'])}→{_state_txt(e['state'])}" for e in run.preflight))
        if run.health:
            label = "★ 收敛检查（终态）" if run.mode == "uninstall_purge" else "健康检查"
            lines.append(f"{label}：" + "；".join(
                f"{_kind_txt(e['kind'])}→{_state_txt(e['state'])}" for e in run.health))
        if run.checkpoints:
            lines.append(f"检查点：{len(run.checkpoints)} 个可回滚点（"
                         + "、".join(str(c.get("label")) for c in run.checkpoints[:6]) + "）")
        if run.mode == "uninstall_keep":
            kept = (run.uninstall_rendered or {}).get("keep_data") or run.recipe.uninstall.keep_data
            if kept:
                lines.append(f"★ 已保留（未删除）：{'、'.join(kept)}")
        if run.mode == "uninstall_purge":
            # ★ v1.7（T6·S2 真跑抓到 · 规范 §12.6.4）：**只念"真的删掉了"的，不念"计划要删的"**。
            #   实况：`remove_config` 那一步因"文件已不在"而 aborted → 配方 failed，
            #   而结论却把 remove_config + purge_paths + remove_packages 三份清单
            #   原样念成「已删除的路径 / 已卸载的软件包」—— **一条都没发生**（报告在骗人）。
            #   ★ 误报比漏报危险：它会让人以为数据已经没了。
            done_paths = [
                str((s.get("args") or {}).get("path") or "")
                for s in run.steps
                if s.get("action") == REMOVE_ACTION_ID and s.get("status") == "ok"
                and str((s.get("args") or {}).get("path") or "")
            ]
            done_pkgs = [
                str((s.get("args") or {}).get("package") or "")
                for s in run.steps
                if s.get("action") == PKG_REMOVE_ACTION_ID and s.get("status") == "ok"
                and str((s.get("args") or {}).get("package") or "")
            ]
            planned_paths = [
                x for x in (
                    ((run.uninstall_rendered or {}).get("remove_config") or [])
                    + ((run.uninstall_rendered or {}).get("purge_paths") or [])
                ) if x
            ]
            planned_pkgs = list(run.recipe.uninstall.remove_packages)
            # ★★ v1.8·S2（规范 §12.16 规矩 6）：**收敛检查已证实"不在"的，单独念一行**。
            #   两种情形都要落到这里：
            #     · 包被 dnf 当依赖一起收走 ⇒ 它的 pkg.remove 是 aborted（T6·§12.6.5）；
            #     · 包/路径**本来就不在** ⇒ 那一步是 skipped「已达终态」（S2·§12.16 规矩 1/4）。
            #   ★ 为什么要与"已删除/已卸载"**分开念**：
            #     混在一起是**误报**（把"本来就不在"说成"我删掉了"）；
            #     而把它们丢进下面那句「没删掉 / 没走到」是**反方向的误导** ——
            #     用户会以为清理失败、再白折腾一遍。两个方向都算骗人（清单 48 / 62 的尺子）。
            #   ★ 配对**按内容**（`converge.kind/value`），不按下标 ——
            #     下标配对在顺序变化时会**静默念错**，而"念错"正是这一节要防的事。
            health = run.health or []
            converged = [
                e.get("converge") for e in health
                if e.get("kind") == "absent" and e.get("state") == "pass" and e.get("converge")
            ]
            converged_paths = [
                str(c["value"]) for c in converged
                if c.get("kind") == "path" and str(c["value"]) not in done_paths
            ]
            converged_pkgs = [
                str(c["value"]) for c in converged
                if c.get("kind") == "package" and str(c["value"]) not in done_pkgs
            ]
            terminal_ones = list(converged_paths) + list(converged_pkgs)
            if done_paths:
                lines.append(f"★ 已删除的路径：{'、'.join(done_paths)}")
            if done_pkgs:
                lines.append(f"★ 已卸载的软件包：{'、'.join(done_pkgs)}")
            if terminal_ones:
                lines.append(
                    "★ 已达终态（本次**没动手**，收敛检查已证实它不在）："
                    + "、".join(terminal_ones)
                )
            left = [x for x in planned_paths if x not in done_paths and x not in terminal_ones] + [
                x for x in planned_pkgs if x not in done_pkgs and x not in terminal_ones
            ]
            if left:
                lines.append(
                    "★ **没删掉 / 没走到**的（本次未执行或未成功，**别当成已清理**）："
                    + "、".join(left)
                )
        if run.unknown_steps:
            lines.append("★ 上面「无法判定」的步骤，是平台**不知道它改了没有** —— "
                         "不要当成「没变更」（规范 §12.3）。")
        if run.error:
            lines.append(f"原因：{run.error.reason}")
            if run.error.advice:
                lines.append(f"建议：{run.error.advice}")
        if run.id:
            lines.append(f"本次执行号：{run.id}（每个步骤的留证在各自任务 ID 下）")
        return "\n".join(lines)


def _kind_txt(kind: str) -> str:
    return {
        "present": "应存在", "absent": "应不存在", "free_port": "端口空闲",
        "state": "服务状态", "http_status": "HTTP 探测",
    }.get(kind, kind)


def _state_txt(state: str) -> str:
    return {"pass": "通过", "fail": "不通过", "unknown": "★ 无法判定"}.get(state, state)


def _outcome_detail(row: dict[str, Any]) -> str:
    parts = [
        f"期望：{row.get('expected')}",
        f"实际：{row.get('actual') or '（未取到）'}",
    ]
    if row.get("collect_action"):
        parts.append(f"采集动作：{row['collect_action']}"
                     + (f"（任务 {row['collect_task']}）" if row.get("collect_task") else ""))
    if row.get("reason"):
        parts.append(f"原因：{row['reason']}")
    return "\n".join(parts)
