"""变更「请求」：AI 只摆卡片，人不点就不执行（T14·S3 · 规范 §12.96 / §12.98 / §12.99）。

★★ 本模块只回答一个问题：**AI 提出一次变更时，那张卡片上的字从哪儿来？**
   答：**全部来自平台** —— 动作 YAML ＋ `hosts.yaml` ＋ 本模块下面那两张表。
   模型只负责「提出」（选动作 / 给参数 / 说为什么），**不负责「填写」**（§12.98.2）。

★ 三张表，每张都**只许有一处定义**（§12.66.2）：

  | 表 | 回答卡片上的哪一问 | 出处 |
  |---|---|---|
  | `APPROVED_YELLOW` | 哪些 `yellow` 被**批准**可以让 AI 去「请求」 | T14 开题单 §4.3 · D4 拍板（原 **10** 个）＋ T16 的 **3** 个 `vm.*`（§12.120） |
  | `UNDO_TABLE` | **怎么撤** ＋ **撤不回来的是什么** | 规范 §12.98.3（＝开题单 §9.3） |
  | `REVIEW_TABLE` | 变更之后**看哪个只读动作**、**什么算成了** | 规范 §12.100.2 |

★★ `APPROVED_YELLOW` 与 `config.yaml` 的 `ai.yellow_allowlist` 是**「上限」与「当前放开」**的关系：
   配置**只能从这里取子集**。把没批准的动作（例如 `k8s.exec`）塞进配置 ⇒ 自检**当场红**
   —— 这正是验收 6 要的证伪判据：**表不许被悄悄改宽**。

★ 一条设计约束（会让后来的人少走弯路）：本模块**不 import 执行层 / 传输层**
  （`engine` / `transport` / `ssh`）—— 它只组装**文字**与**一条待办记录**。
  执行永远发生在 `app/api.py`：**人点了确认之后**，走既有的 `/api/tasks` 那一条路
  （留证 / 护栏 / 覆盖率账本三套体系自动生效，§12.96.2 规矩 1）。
"""
from __future__ import annotations

from typing import Any

from app.catalog import PARAM_REF_RE, Action
from app.config import AppConfig, Host
from app.errors import OpsError
from app.store import now_iso

# ------------------------------------------------------------------ 表一：被批准的 yellow（上限）

#: ★★ 这张表**就是**「放开 `yellow`」这句话的全部内容 —— 改动它必须是**人**的决定，
#:   而且要连规范一起改（§12.96.1 的三档权限表就在隔壁）。
#: ★ 「批准」的含义严格限定为：**AI 可以在卡片上提出这件事**，
#:   **不是**「AI 可以按下这个按钮」（§12.96.1 那句话）。
APPROVED_YELLOW: tuple[str, ...] = (
    "pkg.install",          # ★ 验收① 的主角（装 → 卸 → 回滚那一条链）
    "svc.start",
    "svc.restart",
    "svc.enable",
    "svc.reset-failed",
    "svc.daemon-reload",
    "sysctl.set",
    "fw.port-open",
    "cron.upsert",
    "file.push",
    # ── ★★ T16（规范 §12.120 · 清单 253 · 开题单 §10.1 拍板 2）──
    #    ★★ 红线 16「**开机不是默认行为**」的落地形态 = **人点确认那一下**（§12.120）：
    #      所以这里收的是「AI 可以**请求**」—— 卡片照样要在「待确认」页等人点。
    "vm.start",             # ★ 开机：AI 可以请求（人点头才执行）
    "vm.stop",              # ★ 优雅关机（soft）：可恢复（再开一次就回去了）
    "vm.snapshot-create",   # ★ 拍快照：护栏四件套第 4 件（§12.118），显式触发
    # ★★★ 以下两条**永远不在这里**（§12.120 · 红线 15）：
    #   `vm.stop-hard`（拔电源）· `vm.snapshot-revert`（覆盖当前状态，不可逆）
    #   —— 它们不只是"人点确认"，而是**必须由人在「动作」页手输确认词**；
    #     ★ 而且 `guard()` 按 **risk == red** 挡，与这张表**无关**（两道互不依赖的闸）。
)

# ------------------------------------------------------------------ 表二：撤法（卡片上"怎么撤"的唯一出处）

#: 每条三个字段：
#:   `how`        —— 怎么撤（人读的一句话）
#:   `by_action`  —— 用哪个动作撤（空串 = 没有对应动作，只能人工）
#:   `by_risk`    —— 那个撤法动作自己的风险等级（★ 卡片上要显式告诉人"撤也是 red"）
#:   `cannot`     —— ★★ **撤不回来的是什么**，逐项写清；**没有也要写「无」**（T7 口径）
#: ★ 依据：规范 §12.98.3 的映射表（与开题单 §9.3 同源）。
UNDO_TABLE: dict[str, dict[str, Any]] = {
    "pkg.install": {
        "how": "按**本次事务号**回滚：`pkg.rollback tx=<结论里给出的号>`",
        "by_action": "pkg.rollback",
        "by_risk": "red",
        "cannot": [
            "装包时被**连带升级**的依赖：回滚会把它们一起退回去 —— "
            "若那些包正被别的服务使用，回退会引起**服务重启**",
        ],
    },
    "pkg.update": {
        "how": "按**本次事务号**回滚：`pkg.rollback tx=<结论里给出的号>`",
        "by_action": "pkg.rollback",
        "by_risk": "red",
        "cannot": ["旧版本的 rpm 若已不在仓库里 ⇒ **回不去**"],
    },
    "svc.start": {
        "how": "用「停止服务」把它停掉（`svc.stop`，🔴 需要人手输确认词）",
        "by_action": "svc.stop",
        "by_risk": "red",
        "cannot": [
            "★ **运行时的内存态**（连接 / 缓存 / 临时数据）—— 停掉之后不会自己回来",
        ],
    },
    "svc.restart": {
        "how": "通常**无需撤回**：它只是停一下再起；若重启后没能起来 ⇒ 用「启动服务」再拉起",
        "by_action": "svc.start",
        "by_risk": "yellow",
        "cannot": ["重启窗口内**断掉的连接与请求**（已经丢掉的不会补回来）"],
    },
    "svc.enable": {
        "how": "反向再执行一次：用「取消服务开机自启」即可撤销",
        "by_action": "svc.disable",
        "by_risk": "yellow",
        "cannot": ["无"],
    },
    "svc.reset-failed": {
        "how": "**无需撤回** —— 它本来就不改变服务的运行状态，只是把 `failed` 记录清掉",
        "by_action": "",
        "by_risk": "",
        "cannot": [
            "★ 被清掉的 **`failed` 历史记录**回不来 —— 根因还在的话，下次它照样会失败",
        ],
    },
    "svc.daemon-reload": {
        "how": "**无需撤回** —— 只是让 systemd 重读盘上的单元文件，不重启任何服务",
        "by_action": "",
        "by_risk": "",
        "cannot": [
            "无（★ 例外：若**盘上的单元文件本身**有语法错，重载后该单元会进入 `failed` —— "
            "那是**盘上文件**的问题，不是重载造成的）",
        ],
    },
    "sysctl.set": {
        "how": "把 `value` 填回**原来的值**再跑一次（★ 原值**必须先读出来** —— 任务结论里会留现值）",
        "by_action": "sysctl.set",
        "by_risk": "yellow",
        "cannot": [
            "★ **运行时生效 ≠ 持久化生效**：只写了运行时的部分，**重启即复位**",
            "参数生效期间**已经发生**的内核行为（例如放宽了转发 / 队列之后已经进来的流量）",
        ],
    },
    "fw.port-open": {
        "how": "用「防火墙撤销端口」按同一个 zone / port / protocol 撤回来",
        "by_action": "fw.port-close",
        "by_risk": "yellow",
        "cannot": ["放行期间**已经建立的连接**会断（撤销本身不保证优雅）"],
    },
    "cron.upsert": {
        "how": "用「删除定时任务」按**同一个 `name`** 删掉",
        "by_action": "cron.remove",
        "by_risk": "yellow",
        "cannot": [
            "★ 如果**覆盖了同名的既有条目** ⇒ 旧内容回不来（除非备份过；"
            "平台在写入前会自动备份同名旧文件）",
        ],
    },
    "file.push": {
        "how": "用任务详情里的「恢复此文件」把被覆盖的原文件还原回去（T3 的双份备份）",
        "by_action": "",
        "by_risk": "",
        "cannot": ["目标文件**被覆盖期间**发生的**外部写入**"],
    },
    # ── ★★ T16（规范 §12.118 / §12.120）：域 M 的三条 ──
    #    ★ 口径与文件级备份**并列不替代**：VM 级快照回的是"**整台机器**当时的样子"。
    "vm.start": {
        "how": "用「优雅关机」把它关回去（`vm.stop`，yellow —— 界面上点一次确认即可）",
        "by_action": "vm.stop",
        "by_risk": "yellow",
        "cannot": [
            "★ 开机窗口内**失败的请求**恢复不了（里面的服务经历了一次冷启动）",
            "★ 宿主机上这段时间被它**占用**的 CPU / 内存 / 磁盘 IO —— 已经用掉的收不回来",
            "★ 它里面的**运行时内存态**：冷启动之后与上次关机前**不是同一个样子**",
        ],
    },
    "vm.stop": {
        "how": "用「启动虚拟机」再开起来（`vm.start`，yellow —— 界面上点一次确认即可）",
        "by_action": "vm.start",
        "by_risk": "yellow",
        "cannot": [
            "★ **没落盘的运行时状态**：优雅关机给了 guest 一次收尾机会，但收不收得住由它自己决定",
            "★ 关机期间的**服务不可用**：那段时间它对外的服务是停的（已经漏掉的请求不会补回来）",
        ],
    },
    "vm.snapshot-create": {
        "how": ("★ **本项目没有「删除快照」的动作**：要删请到 VMware 里删；"
                "想**回到**这条快照是 `vm.snapshot-revert`（🔴 red，必须人手输确认词）"),
        "by_action": "",
        "by_risk": "",
        "cannot": [
            "★ **磁盘被占用**这件事：删掉之前它一直占着（快照是增量盘，会越来越大）",
            "★ 快照链**从此多了一条**：链本身回不到「没有它」的样子",
            "★ ★ 这条快照**之后**对这台机器做的所有改动 —— 一旦用 `revert` 回去就**没了**",
        ],
    },
}

#: ★ `svc.disable` / `fw.port-close` / `cron.remove` / `pkg.rollback` / `svc.stop` / `svc.start` 都**不在**
#:   `APPROVED_YELLOW` 里 —— 这是**故意的**：撤法是给**人**看的按钮（人在界面上点），
#:   不是给 AI 的第二个入口。★ 把撤法动作也加进白名单，等于让 AI 能"绕一圈再改一次"。

# ------------------------------------------------------------------ 表三：复核（变更之后看哪个只读动作）

#: 复核的动作名 —— 挂在本次**变更**动作的 id 上：
#: 每条五个字段：
#:   `action_id` —— 复核用哪个**只读**动作（★ 本模块会在装载期核验它确实是 green）
#:   `params`    —— 复核动作的参数模板，`{{ 参数名 }}` 取自**本次请求的参数**（空 = 无参）
#:   `pass`      —— ★ **什么算成了**（这句话会原样出现在卡片上）
#:   `rule`      —— ★★ **机器怎么判**（人话与机器话必须成对出现，否则"判据"就只是修辞）：
#:                  `step`  复核任务里的**步骤名**
#:                  `field` 该步骤 `parsed` 里的字段路径（`.` 分隔；空串 = 取 parsed 本身）
#:                  `op`    `non_empty` / `eq` / `ne` / `contains` / `ge`
#:                  `value` 比较值
#:                  ★ `dynamic` 为真时，`field`/`value` 要**从本次请求的参数实时推**（见 `sysctl.set`）
#:   `must_fail` —— ★ 这个复核的"成了"**是不是以"某一步失败"为判据**（卸包那种"必须失败型"，
#:                  §12.100.3 —— 不许被判成假红）
#: ★ 依据：规范 §12.100.2 的对应关系表；`rule` 里的字段名全部取自各动作 YAML 的 `pick`
#:   （★ 不是我想出来的 —— 判据要落在**平台真读出来的那个字段**上）。
REVIEW_TABLE: dict[str, dict[str, Any]] = {
    "pkg.install": {
        "action_id": "pkg.installed",
        "params": {"pkg": "{{ package }}"},
        "pass": "`pkg.installed` 的「包详情」里读得到**包名**（rpm 查得到这个包）",
        "rule": {"step": "info", "field": "name", "op": "non_empty"},
        "must_fail": False,
    },
    # ★★ 卸包：**必须失败型**（§12.100.3）—— 它的"成了"**长在"查不到"上**。
    #   ★ 为什么还是登记它：`pkg.remove` 是 `red`（AI 连请求都不许发），
    #     但**人在界面上自己做完了，平台照样要能复核** —— 否则"必须失败型"这条规矩
    #     就只在纸上了。★ 判据写成 `empty`，不是 `non_empty`：把这两者弄反，
    #     就会把成功判成失败（T9 抓过的坑）。
    "pkg.remove": {
        "action_id": "pkg.installed",
        "params": {"pkg": "{{ package }}"},
        "pass": "`pkg.installed` 的「包详情」里**读不到包名**（rpm 查不到 ⇒ 包装卸掉了）",
        "rule": {"step": "info", "field": "name", "op": "empty"},
        "must_fail": True,
    },
    "svc.start": {
        "action_id": "svc.status",
        "params": {"unit": "{{ unit }}"},
        "pass": "`svc.status` 读出来的 `ActiveState` 是 `active`",
        "rule": {"step": "show", "field": "ActiveState", "op": "eq", "value": "active"},
        "must_fail": False,
    },
    "svc.restart": {
        "action_id": "svc.status",
        "params": {"unit": "{{ unit }}"},
        "pass": "`svc.status` 的 `ActiveState` 是 `active`（★ 重启后「活着」，且启动时间是新的）",
        "rule": {"step": "show", "field": "ActiveState", "op": "eq", "value": "active"},
        "must_fail": False,
    },
    "svc.enable": {
        "action_id": "svc.status",
        "params": {"unit": "{{ unit }}"},
        "pass": "`svc.status` 里的 `UnitFileState` 含 `enabled`（★ 这一项**不改变当前运行状态**）",
        "rule": {"step": "show", "field": "UnitFileState", "op": "contains", "value": "enabled"},
        "must_fail": False,
    },
    "svc.reset-failed": {
        "action_id": "svc.status",
        "params": {"unit": "{{ unit }}"},
        "pass": "`svc.status` 里该 unit 的 `ActiveState` **不再是 `failed`**",
        "rule": {"step": "show", "field": "ActiveState", "op": "ne", "value": "failed"},
        "must_fail": False,
    },
    "svc.daemon-reload": {
        "action_id": "svc.status",
        "params": {"unit": "{{ unit }}"},
        "pass": "`svc.status` 能**读回该 unit 的定义**（`LoadState` 有内容）",
        "rule": {"step": "show", "field": "LoadState", "op": "non_empty"},
        "must_fail": False,
    },
    "sysctl.set": {
        "action_id": "host.kernelparams",
        "params": {},
        "pass": "`host.kernelparams` 读到的该 key **值等于请求值**；"
                "★ 这个 key 若**没被那份只读动作采样覆盖** ⇒ 判**「未证实」**，不许当成通过",
        # ★★ 动态规则：`field` 要按**本次请求的 key** 去 `host.kernelparams` 的 `pick` 表里找
        #   （那张表只映射了固定的几个 key —— 没覆盖到就是"平台读不到"，不是"没成功"）。
        "rule": {"step": "core", "field": "", "op": "eq", "value": "", "dynamic": "pick_of_key"},
        "must_fail": False,
    },
    "fw.port-open": {
        "action_id": "net.firewall",
        "params": {},
        "pass": "`net.firewall` 的**运行时规则**里出现 `<port>/<protocol>`",
        "rule": {"step": "runtime", "field": "ports", "op": "contains", "value": "{{ port }}/{{ protocol }}"},
        "must_fail": False,
    },
    "cron.upsert": {
        # ★★ 复核动作的选择**必须过得了那个动作自己的参数白名单**：
        #   第一版写的是 `file.cat`（它的白名单只有 sysctl.d / modules-load.d / yum.repos.d /
        #   yum.conf.d / containerd / cni/net.d）⇒ `/etc/cron.d/...` **当场被参数校验拒掉**，
        #   复核任务根本起不来。★ 真跑抓到的（不是想出来的）。
        #   `file.stat` 的白名单是 `/etc/<名>/…` ⇒ `/etc/cron.d/aoc-x` 合规。
        "action_id": "file.stat",
        "params": {"path": "/etc/cron.d/aoc-{{ name }}"},
        "pass": "`file.stat` 读到**它在**（`1`）",
        "rule": {"step": "count", "field": "", "op": "eq", "value": 1},
        "must_fail": False,
    },
    # ★★ 撤法动作也登记复核（`cron.remove` 是 `yellow`，人可以在界面上自己撤）：
    #   它的"成了"同样长在"**文件不在了**"上 ⇒ 又一个「必须失败型」（§12.100.3）。
    "cron.remove": {
        "action_id": "file.stat",
        "params": {"path": "/etc/cron.d/aoc-{{ name }}"},
        "pass": "`file.stat` 里「它在不在」= **0**（文件已经不在了）",
        "rule": {"step": "count", "field": "", "op": "eq", "value": 0},
        "must_fail": True,
    },
    "file.push": {
        "action_id": "file.stat",
        "params": {"path": "{{ remote_path }}"},
        "pass": "`file.stat` 读到**它在**（`1`）",
        "rule": {"step": "count", "field": "", "op": "eq", "value": 1},
        "must_fail": False,
    },
    # ── ★★ T16（规范 §12.117 / §12.120）：域 M 的三条 ──
    #    ★★ 复核动作同样是**只读**（`vm.status` / `vm.snapshot-list`，都 green）——
    #      而它们的判据仍然是"**再问一次被管的那一方**"（§12.117），不是"命令返回 0"。
    #    ★ 字段名全部取自 `app\vmware.py` 的探针载荷（★ 不是我想出来的）。
    "vm.start": {
        "action_id": "vm.status",
        "params": {"vm": "{{ vm }}"},
        "pass": "`vm.status` 读到的电源状态是 `running`（★ 这是**再问一次 VMware**，不是「开机命令返回 0」）",
        "rule": {"step": "state", "field": "state", "op": "eq", "value": "running"},
        "must_fail": False,
    },
    "vm.stop": {
        "action_id": "vm.status",
        "params": {"vm": "{{ vm }}"},
        "pass": "`vm.status` 读到的电源状态是 `stopped`（同样是再问 VMware）",
        "rule": {"step": "state", "field": "state", "op": "eq", "value": "stopped"},
        "must_fail": False,
    },
    "vm.snapshot-create": {
        "action_id": "vm.snapshot-list",
        "params": {"vm": "{{ vm }}"},
        "pass": "`vm.snapshot-list` 的链上**逐字**出现这个名字（★ 名字含中文与空格，差一个字符就算没成）",
        "rule": {"step": "snaps", "field": "snapshots", "op": "contains", "value": "{{ snapshot }}"},
        "must_fail": False,
    },
}

#: ★ 卡片五要素的键名（★ **顺序就是人在界面上读到的顺序**）。
CARD_FIELDS: tuple[str, ...] = ("what", "impact", "undo", "cannot_undo", "criteria")

#: 「撤不回来的是什么」在**确实没有**时的写法（★ 空也要写「无」，不许留空 —— T7 口径）。
NOTHING_CANNOT_UNDO = "无"


# ------------------------------------------------------------------ 工具


def _render(template: str, params: dict[str, Any]) -> str:
    """把 `{{ 名字 }}` 换成**本次请求的参数值**；没有对应参数的占位符**原样留着**。

    ★ 原样留着是**故意的**：卡片上出现 `{{ package }}` 比悄悄换成空串诚实得多
      （空串会让人以为"这个参数不用填"）。
    ★★ 用**动作 YAML 那一套写法与正则**（`catalog.PARAM_REF_RE`，双花括号）——
      因为卡片上要渲染的东西有两类：**来自 YAML 的备份路径**（`/etc/sysctl.d/99-aoc-{{ key }}.conf`）
      和本模块 `REVIEW_TABLE` 里的参数模板。★ 第一版自作聪明用了单花括号 ⇒
      **YAML 那条路径一个占位符都没被填上**（卡片上原样印着 `{{ key }}`），
      而当时**所有断言都是绿的** —— 断言不问渲染，它就没人看住（见断言 ⒃d）。
      ★ 一条约定比两条好：**全库只认双花括号**。
    """
    def _sub(m: Any) -> str:
        name = str(m.group(1))
        if name in params and params[name] not in (None, ""):
            return str(params[name])
        return m.group(0)

    return PARAM_REF_RE.sub(_sub, template or "")


def _blank(value: Any) -> bool:
    """空 = 「没写」：`None` / 空白串 / 空列表 / 只含空白项的列表。"""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple)):
        return not value or all(_blank(x) for x in value)
    if isinstance(value, dict):
        return not value
    return False


def validate_card(card: dict[str, Any]) -> None:
    """★★ 五要素齐备性检查 —— **缺一项就不许生成卡片**（验收 5 的判据）。

    ★ 它必须是**一个能被单独调用的函数**：断言的做法是"把好卡片里任意一个字段清空，
      再看它是不是被拒"，所以校验不能埋在 `build_card` 的深处。
    ★ 报错要说清**缺的是哪一项**（只报"不合法"等于没说）。
    """
    for key in CARD_FIELDS:
        if key not in card:
            raise OpsError(
                code="AI_CARD_INCOMPLETE",
                reason=f"变更卡片缺少要素「{key}」",
                advice="卡片五要素必须齐全：要做什么 / 影响面 / 怎么撤 / 撤不回来的是什么 / 判据。",
                context={"missing": key, "action_id": card.get("action_id")},
            )
    for key in CARD_FIELDS:
        if _blank(card[key]):
            raise OpsError(
                code="AI_CARD_INCOMPLETE",
                reason=f"变更卡片里的「{key}」是空的",
                advice=(
                    "五要素**每一条都要有内容**；"
                    f"确实没有的内容也要写「{NOTHING_CANNOT_UNDO}」（尤其是「撤不回来的是什么」）。"
                ),
                context={"missing": key, "action_id": card.get("action_id")},
            )
    # 判据必须指到一个**真实存在的只读动作**（否则那句"成了怎么看"是空话）
    crit = card["criteria"] or {}
    if _blank(crit.get("action_id")) or _blank(crit.get("pass")):
        raise OpsError(
            code="AI_CARD_INCOMPLETE",
            reason="变更卡片里的「判据」没有指明「看哪个只读动作 + 什么算成了」",
            advice="判据必须写成「跑哪个只读动作 + 看到什么算成了」。",
            context={"missing": "criteria", "action_id": card.get("action_id")},
        )


def build_card(
    cfg: AppConfig,
    action: Action,
    host: Host,
    params: dict[str, Any],
    reason: str,
    *,
    domain_names: dict[str, str] | None = None,
    undo_table: dict[str, dict[str, Any]] | None = None,
    review_table: dict[str, dict[str, Any]] | None = None,
    request_id: str = "",
    created_at: str = "",
) -> dict[str, Any]:
    """组装一张变更卡片（★ 每一段都标了**出处**，模型一个字都插不进来）。

    ★ `undo_table` / `review_table` 可注入：**只为了让断言能把表弄坏**（验收 5 的证伪），
      生产路径上不传（默认用模块级那张表）。
    """
    undo_table = UNDO_TABLE if undo_table is None else undo_table
    review_table = REVIEW_TABLE if review_table is None else review_table
    domain_names = domain_names or {}

    # ── ① 要做什么 ────────────────────────────────────────────────
    rows: list[dict[str, Any]] = []
    for p in action.params:
        raw = params.get(p.name)
        default_used = raw in (None, "") and p.default not in (None, "")
        value = p.default if default_used else ("" if raw is None else raw)
        rows.append({
            "name": p.name,
            "label": p.label or p.name,
            "value": value,
            "source": "动作默认值（★ 没有显式给）" if default_used else "请求参数（原样，未美化）",
        })
    what = {
        "action_id": action.id,
        "title": action.title,
        "summary": action.summary,
        "params": rows,
    }

    # ── ② 影响面（★ 全部取自动作 YAML ＋ `hosts.yaml`，没有一处是编的）──
    paths = [_render(b.path, params) for b in action.backup]
    services = [str(params[p.name]) for p in action.params
                if p.name in ("unit", "service") and params.get(p.name)]
    impact = {
        "host": f"{host.name}（{host.address}）· 登录用户 {host.user} · 角色 {host.role}",
        "domain": f"{action.domain} {domain_names.get(action.domain, '')}".strip(),
        "paths": paths,
        "services": services,
        "text": (
            f"只影响这一台：{host.name}（{host.address}，角色 {host.role}）"
            + (f"；**会改动的文件**：{'、'.join(paths)}" if paths
               else "；★ 动作 YAML 里**没有声明要改的文件**（无备份项）")
            + (f"；**涉及的服务**：{'、'.join(services)}" if services else "")
        ),
    }

    # ── ③ 怎么撤 ＋ ④ 撤不回来的是什么 ─────────────────────────────
    undo_row = undo_table.get(action.id)
    if undo_row is None:
        # ★ 映射不到 ⇒ **必须写「无已知撤回路径」**，不许留空、不许含糊（规范 §12.98.3）
        undo = {
            "how": "**无已知撤回路径**（这个动作没有登记撤法）",
            "by_action": "",
            "by_risk": "",
            "human_confirm_required": False,
        }
        cannot = ["★ **没有登记撤法** —— 也就是说：做完之后**只能靠人手工收拾**"]
    else:
        undo = {
            "how": str(undo_row.get("how") or ""),
            "by_action": str(undo_row.get("by_action") or ""),
            "by_risk": str(undo_row.get("by_risk") or ""),
            # ★ 铁律 9 / 红线 7：`red` 的确认词只能由人输入 ⇒ 撤法是 red 时，卡片上必须写明这一点
            "human_confirm_required": str(undo_row.get("by_risk") or "") == "red",
        }
        cannot = [str(x) for x in (undo_row.get("cannot") or [])] or [NOTHING_CANNOT_UNDO]

    # ── ⑤ 判据 ────────────────────────────────────────────────────
    review = review_table.get(action.id)
    if review is None:
        criteria = {
            "action_id": "",
            "params": {},
            "pass": "**未登记复核动作** —— 这次变更之后平台不知道该问谁（要补 `REVIEW_TABLE`）",
            "must_fail": False,
        }
    else:
        criteria = {
            "action_id": str(review.get("action_id") or ""),
            "params": {k: _render(str(v), params) for k, v in (review.get("params") or {}).items()},
            "pass": str(review.get("pass") or ""),
            "must_fail": bool(review.get("must_fail")),
        }

    card = {
        "kind": "变更请求（待人工确认）",
        "request_id": request_id,
        "created_at": created_at or now_iso(cfg),
        "status": "pending",
        "action_id": action.id,
        "title": action.title,
        "risk": action.risk,
        "host": {
            "id": host.id, "name": host.name, "address": host.address,
            "user": host.user, "role": host.role, "target": host.target,
        },
        "reason": reason,
        # ★ 五要素（键名与顺序见 CARD_FIELDS）
        "what": what,
        "impact": impact,
        "undo": undo,
        "cannot_undo": cannot,
        "criteria": criteria,
        # ★★ 这句话是**平台的承诺**，不是模型的措辞（§12.96.2 规矩 3）：
        "note": (
            "★ 这只是**一张待确认的卡片**：AI 不执行，**人在界面上点了确认才会跑**，"
            "而且走的是既有的执行那条路（留证 / 护栏 / 覆盖率账本自动生效）。"
        ),
    }
    validate_card(card)
    return card


# ------------------------------------------------------------------ 渲染成人话


def card_text(card: dict[str, Any]) -> str:
    """把一张卡片渲染成**人读的那段话**（★ 这段也是**平台**写的，不是模型写的，§12.98.2）。

    ★ 顺序就是 `CARD_FIELDS` 的顺序：要做什么 / 影响面 / 怎么撤 / 撤不回来的是什么 / 判据。
      ★ 聊天里说的话、卡片上写的字、报告里引的内容**必须是同一份**（§12.66.2）。
    """
    what = card["what"]
    impact = card["impact"]
    undo = card["undo"]
    crit = card["criteria"]
    params = "、".join(
        f"{r['name']}={r['value']}（{r['source']}）" for r in what["params"]
    ) or "（这个动作没有参数）"
    undo_line = f"③ 怎么撤：{undo['how']}"
    if undo.get("human_confirm_required"):
        undo_line += "　★ 撤法本身是 **red**：要人**手输确认词**才能撤。"
    crit_line = f"⑤ 判据：跑 `{crit['action_id']}`"
    if crit.get("params"):
        crit_line += "（参数 " + "、".join(f"{k}={v}" for k, v in crit["params"].items()) + "）"
    crit_line += f" —— {crit['pass']}"
    if crit.get("must_fail"):
        crit_line += "　★ 这是**必须失败型**判据（§12.100.3），不许把它判成假红。"
    return "\n".join([
        f"**待确认的变更请求**（号：`{card.get('request_id') or '（还没落库）'}`）",
        f"① 要做什么：在 **{impact['host']}** 上执行 **{what['title']}**（`{what['action_id']}`）",
        f"　　参数：{params}",
        f"② 影响面：{impact['text']}",
        undo_line,
        "④ 撤不回来的是什么：" + "；".join(card["cannot_undo"]),
        crit_line,
        "",
        card["note"],
        f"★ 我给出这件事的理由：{card.get('reason') or '（没写）'}",
    ])


# ------------------------------------------------------------------ 复核：计划与判定


def _dig(parsed: Any, field: str) -> Any:
    """按 `a.b.c` 取值；取不到就是 `None`（★ 不抛异常 —— "读不到"是一条**结论**）。"""
    cur = parsed
    if not field:
        return cur
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _compare(op: str, observed: Any, value: Any) -> bool:
    if op == "non_empty":
        return observed not in (None, "", [], {})
    if op == "empty":
        # ★ **必须失败型**（§12.100.3）："成了"长在"读不到"上 —— 卸包之后 `rpm -q` 本来就该查不到。
        return observed in (None, "", [], {})
    if op == "eq":
        return str(observed) == str(value)
    if op == "ne":
        return str(observed) != str(value)
    if op == "contains":
        return str(value) in str(observed if observed is not None else "")
    if op == "ge":
        try:
            return float(observed) >= float(value)
        except (TypeError, ValueError):
            return False
    raise OpsError(
        code="AI_REVIEW_RULE_BAD",
        reason=f"复核规则里的比较符不认识：{op}",
        advice="只支持 non_empty / eq / ne / contains / ge —— ★ 想加新的，先想清楚它能不能被证伪。",
    )


def review_plan(
    action_id: str,
    params: dict[str, Any],
    actions: dict[str, Action],
    *,
    review_table: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """给出这次变更**该复核什么**（★ 只算，不跑 —— 跑由 `app/api.py` 走既有的任务路）。

    ★ 返回里同时带着**人话**（`pass`）与**机器话**（`rule`）：
      人话是给人看的承诺，机器话是平台真去读的那个字段。★ 两者缺一，判据就落不了地。
    """
    table = REVIEW_TABLE if review_table is None else review_table
    entry = table.get(action_id)
    if entry is None:
        raise OpsError(
            code="AI_NO_REVIEW",
            reason=f"「{action_id}」没有登记复核动作 ⇒ 平台不知道该问谁",
            advice="在 `app/ai/requests.py::REVIEW_TABLE` 里补一条（★ 只读动作才合规）。",
        )
    rule = dict(entry.get("rule") or {})
    review_action_id = str(entry["action_id"])
    note = ""
    if rule.get("dynamic") == "pick_of_key":
        # ★★ 动态规则：`field` 要按**本次请求的 key** 去复核动作的 `pick` 表里找。
        #   找不到 ⇒ 不是"没成功"，而是**平台读不到** —— 那必须如实判「未证实」（不许当通过）。
        key = str(params.get("key") or "")
        rev = actions.get(review_action_id)
        pick: dict[str, str] = {}
        for st in (list(rev.steps) + list(rev.precheck)) if rev else []:
            if st.name == rule.get("step") and st.pick:
                pick = dict(st.pick)
        field = pick.get(key)
        if field:
            rule["field"] = field
            rule["value"] = params.get("value")
        else:
            rule["readable"] = False
            note = (
                f"★ `{review_action_id}` 的采样**没有覆盖** `{key}`"
                f"（它只映射了 {len(pick)} 个固定 key）⇒ 这次复核**从只读证据里读不到它**，"
                "按规矩判「未证实」（★ 不许把它当成通过）"
            )
    return {
        "action_id": review_action_id,
        "params": {k: _render(str(v), params) for k, v in (entry.get("params") or {}).items()},
        "pass": str(entry.get("pass") or ""),
        "rule": rule,
        "must_fail": bool(entry.get("must_fail")),
        "note": note,
    }


def judge_review(
    action_id: str,
    params: dict[str, Any],
    plan: dict[str, Any],
    review_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """★★ 复核的**判定**（§12.100）：只读动作跑完之后，"这次变更到底成了没有"。

    ★★ 三条纪律都落在这一小段里：
      ① **问被管的那一方**（T9 §12.37）：判据只读**复核任务自己读出来的字段**，不看变更任务的退出码；
      ② **"读不到" ≠ "没成功"**：字段缺失 / 采样没覆盖 ⇒ 判**未证实**，并说清是"没读到"；
      ③ **必须失败型**（`must_fail`）**不许被判成假红**：那种复核的"成了"本来就长在"某一步失败"上。
    """
    rule = dict(plan.get("rule") or {})
    step_name = str(rule.get("step") or "")
    field = str(rule.get("field") or "")
    op = str(rule.get("op") or "")
    step = next((s for s in (review_steps or []) if str(s.get("name")) == step_name), None)
    if rule.get("readable") is False:
        return {
            "proved": False,
            "verdict": "not_proved",
            "basis": plan.get("note") or "复核规则本身没有覆盖到要判的那个字段",
            "observed": None,
            "checked": f"{step_name}.{field or '(整步)'}",
        }
    if step is None:
        return {
            "proved": False,
            "verdict": "not_proved",
            "basis": f"复核任务里**没有** `{step_name}` 这一步 ⇒ 这次没读到，**不是「没成功」**",
            "observed": None,
            "checked": f"{step_name}.{field or '(整步)'}",
        }
    parsed = step.get("parsed")
    observed = _dig(parsed, field)
    checked = f"{step_name}.{field}" if field else f"{step_name}（整步）"
    if parsed is None:
        return {
            "proved": False,
            "verdict": "not_proved",
            "basis": f"复核任务里 `{step_name}` 这一步**没有解析结果**（可能没跑到 / 被跳过）⇒ 未证实",
            "observed": None,
            "checked": checked,
        }
    hit = _compare(op, observed, rule.get("value"))
    basis = (
        f"读 `{checked}` = {observed!r}，判据是 `{op} {rule.get('value')!r}` ⇒ "
        + ("成立" if hit else "**不成立**")
    )
    return {
        "proved": bool(hit),
        "verdict": "proved" if hit else "not_proved",
        "basis": basis,
        "observed": observed,
        "checked": checked,
    }


def approve_guard(
    row: dict[str, Any],
    actions: dict[str, Action],
    allowlist: tuple[str, ...],
) -> Action:
    """★★ 人点「确认执行」时的**第二道自检**（纵深防御，规范 §12.99.1）。

    ★ 为什么还要查一遍：`request_action` 的入口已经拦过 red 了，但**入口不是唯一入口** ——
      库里的一行也可能是别的东西写进去的（导入、手改、将来的别的路径）。
      "**执行口也要自己站得住**"比"相信上游拦过了"稳（同 §12.74.2 的写法）。
    """
    rid = str(row.get("id") or "?")
    if str(row.get("status")) != "pending":
        raise OpsError(
            code="AI_REQUEST_DECIDED",
            reason=f"这条请求已经处理过了（`{rid}` 现在状态是 `{row.get('status')}`）",
            advice="刷新「待确认」列表；同一张卡片只许点一次。",
        )
    action = actions.get(str(row.get("action_id") or ""))
    if action is None:
        raise OpsError(
            code="AI_NO_SUCH_ACTION",
            reason=f"这条请求指向的动作不存在了：{row.get('action_id')}",
            advice="多半是动作被改名/删掉了 —— 驳回它，重新提一条。",
        )
    if action.risk != "yellow":
        raise OpsError(
            code="AI_APPROVE_NOT_YELLOW",
            reason=f"`{action.id}` 的风险等级是 **{action.risk}**，这条路子只允许 `yellow`",
            advice=(
                "★ `red` 永远不许从这里执行：请到「动作」页签里**自己选它、自己手输确认词**；"
                "`green` 是只读动作，本来就不需要人确认。"
            ),
            context={"risk": action.risk, "request_id": rid},
        )
    if action.id not in allowlist:
        raise OpsError(
            code="AI_NOT_REQUESTABLE",
            reason=f"`{action.id}` 不在当前白名单里（白名单可能被收窄了）",
            advice="要么把白名单放回去（要人改 `config.yaml`），要么驳回这条请求。",
            context={"request_id": rid, "allowlist": list(allowlist)},
        )
    return action


# ------------------------------------------------------------------ 服务

class ActionRequests:
    """把「请求」落成**一条待办记录 + 一张卡片**（★ 不执行 —— 这是本类的全部职责）。"""

    def __init__(self, cfg: AppConfig, actions: dict[str, Action], face: Any, sessions: Any) -> None:
        self.cfg = cfg
        self.actions = actions
        self.face = face
        self.sessions = sessions
        self.allowlist: tuple[str, ...] = tuple(getattr(face, "yellow_allowlist", ()) or ())

    # -- 装载期核验（★ 写错了要**当场报**，不许静默少放开 / 多放开）──────
    def audit_allowlist(self) -> list[str]:
        """返回配置白名单里的**问题项**（空列表 = 健康）。

        ★ 三类问题各有各的错法，都要单独说清：
          ① 不在 `APPROVED_YELLOW` 里 ⇒ **表被改宽了**（验收 6 要抓的就是这个）；
          ② 动作根本不存在 ⇒ 配置写了个不存在的 id；
          ③ 动作不是 `yellow` ⇒ 白名单的含义被搞混了（`green` 本来就能跑、`red` 永远不许）。
        """
        problems: list[str] = []
        for aid in self.allowlist:
            action = self.actions.get(aid)
            if aid not in APPROVED_YELLOW:
                problems.append(f"{aid}：**没有被批准**（不在 APPROVED_YELLOW 里）")
            if action is None:
                problems.append(f"{aid}：动作不存在（检查 catalog/actions/*.yaml）")
            elif action.risk != "yellow":
                problems.append(f"{aid}：风险等级是 {action.risk}，白名单只收 yellow")
        return problems

    # -- 第一层闸门（规范 §12.99.1：`red` 连请求都不许发）──────────────
    def guard(self, action_id: str) -> Action:
        action = self.actions.get(action_id)
        if action is None:
            raise OpsError(
                code="AI_NO_SUCH_ACTION",
                reason=f"没有这个动作：{action_id}",
                advice="先在「动作」页签里确认它的 id；或用域索引重新挑一个。",
            )
        if action.risk == "red":
            raise OpsError(
                code="AI_RED_NEEDS_HUMAN",
                reason=f"「{action.title}」（{action.id}）是 **red**，而且是不可逆的那一类",
                advice=(
                    "★ 这件事**必须由人在界面上自己做**：打开「动作」页签 → 选它 → "
                    "**手输确认词**之后才会执行。AI **不能代**，连「替我请求一下」也不行 —— "
                    "这条挡在请求入口上，不是挡在执行上。"
                ),
                context={"risk": "red", "action_id": action.id},
            )
        if action.risk == "yellow" and action.id not in self.allowlist:
            raise OpsError(
                code="AI_NOT_REQUESTABLE",
                reason=f"「{action.title}」（{action.id}）没有被批准给 AI 请求",
                advice=(
                    "★ 两条路：① 在「动作」页签里**自己点**（yellow 点一次确认即可）；"
                    "② 若确实希望 AI 能提出这件事，**由人在 config.yaml 的 `ai.yellow_allowlist` 里**"
                    "加进去（★ 那只收 APPROVED_YELLOW 里的动作，改宽了自检会红）。"
                ),
                context={"risk": "yellow", "action_id": action.id,
                         "allowlist": list(self.allowlist)},
            )
        return action

    # -- 提交（★ 只写记录，不执行）──────────────────────────────────
    def submit(
        self,
        action_id: str,
        host_id: str,
        params: dict[str, Any] | None,
        reason: str,
        *,
        session_id: str = "",
    ) -> dict[str, Any]:
        action = self.guard(str(action_id))
        try:
            host = self.cfg.host(str(host_id))
        except OpsError as exc:
            raise OpsError(
                code="AI_NO_SUCH_HOST",
                reason=f"主机清单里没有「{host_id}」这台机器",
                advice="用主机清单里的 id；界面上的「主机」页签能看到全部。",
            ) from exc
        clean = {str(k): v for k, v in (params or {}).items()}
        missing = [p.name for p in action.params if p.required and clean.get(p.name) in (None, "")]
        if missing:
            raise OpsError(
                code="AI_NEED_PARAMS",
                reason=f"「{action.title}」缺必填参数：{'、'.join(missing)}",
                advice="补全参数再请求；★ 不许拿默认值糊过去（缺什么就问人）。",
                context={"missing": missing, "action_id": action.id},
            )
        domain_names = getattr(self.face, "domain_names", {}) or {}
        card = build_card(
            self.cfg, action, host, clean, str(reason or ""),
            domain_names=domain_names,
        )
        # ★★ 先落记录、再把 `request_id` 写回卡片 —— 卡片与记录是**同一件事的两面**。
        request_id = self.sessions.add_action_request(
            session_id=session_id,
            action_id=action.id,
            host_id=host.id,
            risk=action.risk,
            params=clean,
            reason=str(reason or ""),
            card=card,
        )
        card["request_id"] = request_id
        self.sessions.attach_card(request_id, card)
        return {
            "request_id": request_id,
            "status": "pending",
            "card": card,
            "note": (
                "★ 已经**只是记下来**了：没有执行、没有碰目标机。"
                "请人在界面上看过卡片再点确认（§12.96.2 规矩 1）。"
            ),
        }

    # -- 读 ────────────────────────────────────────────────────────
    def listing(self, limit: int = 50) -> dict[str, Any]:
        rows = self.sessions.list_action_requests(limit)
        return {
            "requests": rows,
            "pending": sum(1 for r in rows if r.get("status") == "pending"),
            "note": "★ 待确认队列：AI 只是「提出」，执行由人点出来。",
        }

    def detail(self, request_id: str) -> dict[str, Any]:
        row = self.sessions.get_action_request(request_id)
        if row is None:
            raise OpsError(
                code="AI_NO_SUCH_REQUEST",
                reason=f"没有这条变更请求：{request_id}",
                advice="刷新「待确认」列表；请求号形如 REQ20260927-213000-ab12cd。",
            )
        return row
