"""`changed` 推导层（规范 §12.3）：平台统一回答"这一步到底改了没有"。

为什么必须有它
--------------
既有 42 个动作的 `verify` 只回答「**成功了吗**」，**没有统一的「变了没有」**。
而"重复部署 = 第二次零变更"（幂等证明）需要一个**可断言**的信号 —— 本项目用：

    ★ 幂等的验收 = 第二次跑同一配方，`changed_steps` 为空。

设计（与规范 §12.3 的规则表**一一对应**）
----------------------------------------
· 规则**按动作 id 登记**，配方侧一个字都不用写（判定走平台 = 宪法 1）；
· 数据来源全是**动作本来就有的**前后对照步骤（`before` / `after`、sha256、状态字段），
  因此**不需要改造**那 42 个动作；
· ★ **未登记的动作一律 `None`（unknown），不许默认 `False`**（宪法 2）——
  "看起来没变"和"确实没变"是两件不同的事，把它们混在一起，幂等证明就变成一句口号。

返回值三态
----------
`True`  = 变了
`False` = 没变（**幂等的正面证据**）
`None`  = **无法判定**（未登记规则 / 取不到对照数据）→ 报告里必须显式标 `unknown`
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:  # 只为类型标注，避免与 engine 循环导入
    from app.catalog import Action
    from app.engine import StepOut, TaskResult


# ------------------------------------------------------------------ 内部工具


def _step(result: Any, name: str) -> Any:
    """取该任务里**最后一次**出现的同名步骤。

    为什么取最后一次：`foreach` 会把一个步骤展开成多条同名记录，
    对"变更判定"来说最后一条才是最终状态。
    """
    found = None
    for s in getattr(result, "steps", None) or []:
        if getattr(s, "name", None) == name:
            found = s
    return found


def _val(result: Any, name: str) -> Any:
    s = _step(result, name)
    return None if s is None else getattr(s, "parsed", None)


def _ran_ok(result: Any, name: str) -> bool:
    """该步骤是否**确实跑过**（ok / skipped 都算跑过）。

    ★ 必须区分"步骤没跑/失败"与"步骤跑了但没有输出"：
      例如 `firewall-cmd --list-ports` 在这个区域一个端口都没放行时，
      输出为空、退出码 0 —— 那是"没有端口"，不是"拿不到数据"。
      只看 parsed 是否为空会把这两件事混掉。
    """
    s = _step(result, name)
    return s is not None and getattr(s, "status", None) in ("ok", "skipped")


def _field(result: Any, name: str, field: str) -> Any:
    v = _val(result, name)
    return v.get(field) if isinstance(v, dict) else None


def _norm(v: Any) -> str:
    """把取值归一成可比较的字符串。

    ★ 只做 strip，**不做**任何"聪明"加工（大小写折叠、去空白行等）：
      我们要比的是"目标机报出的这两个值是否相同"，
      任何额外加工都可能把真变化抹平 —— 那就等于伪造幂等。
    """
    if v is None:
        return ""
    if isinstance(v, list):
        return "\n".join(_norm(x) for x in v)
    return str(v).strip()


def _diff(a: Any, b: Any) -> bool | None:
    """两个对照值"是否不同"。任一侧取不到 → `None`（无法判定），不猜。"""
    # ★★ §12.48（T9·S4 真跑抓到的真缺陷 ⑧）：这里原来写的是 `a is None and b is None` ——
    #   **与上面那句"任一侧取不到 → None"自相矛盾**。一侧为 None 时 `_norm` 把它折成 ""，
    #   于是"有值 vs 空"必然不同 ⇒ **报"变了"**。实况：换镜像时容器名不存在 ⇒ 动作红、
    #   `image_after` 那一步被跳过 ⇒ `changed=True`（**集群一个字节都没变** = 假变更）。
    # ★ 为什么必须是 `or`：**"取到空"与"取不到"是两件事**（§12.45.3 同一条纪律）——
    #   `parse_text("raw","") == ""` / `lines → []` / `line_count → 0` 是"跑了但输出为空"（**真结论**）；
    #   步骤 `skipped` / `failed` / 没有 `parsed` ⇒ `None`（**算不出来**）。
    # ★★ 本函数是**共用助手**：改它等于同时改十几条规则 —— 动它之前先数调用方。
    if a is None or b is None:
        return None
    return _norm(a) != _norm(b)


def _step_changed(result: Any, name: str) -> bool | None:
    """读某个步骤自己算出来的 `changed`（由引擎在写盘类步骤里填）。"""
    s = _step(result, name)
    if s is None:
        return None
    return getattr(s, "changed", None)


# ------------------------------------------------------------------ 逐动作规则


def _r_pkg_install(action: Any, result: Any) -> bool | None:
    # 装包：before（rpm -q，未装时无输出）vs after（rpm -q，已装时给 NEVRA）
    return _diff(_val(result, "before"), _val(result, "after"))


def _r_pkg_update(action: Any, result: Any) -> bool | None:
    # 升级：版本号真的变了才算变更（重跑一次版本相同 → False）
    return _diff(_val(result, "ver_before"), _val(result, "ver_after"))


def _r_pkg_remove(action: Any, result: Any) -> bool | None:
    # 卸包：该动作的 precheck（must_installed）保证"装过"，
    # 所以只要它跑到了 isgone 且动作整体成功，就是"确实删掉了"。
    if _step(result, "isgone") is None:
        return None
    return True


def _r_svc_active(action: Any, result: Any) -> bool | None:
    # 启停：比较 ActiveState（start: inactive→active；stop: active→inactive）
    return _diff(_field(result, "before", "ActiveState"), _field(result, "after", "ActiveState"))


def _r_svc_unitfile(action: Any, result: Any) -> bool | None:
    # 开机自启开关：before / after 都是 `systemctl is-enabled` 的原文（enabled / disabled / …）
    return _diff(_val(result, "before"), _val(result, "after"))


def _r_svc_restart(action: Any, result: Any) -> bool | None:
    # ★ 重启：靠 **ActiveEnterTimestamp 变化**判定，不是恒为 true。
    #   （规范 §9.4 的"真的重启了"用的就是同一个事实。）
    return _diff(_field(result, "before", "ActiveEnterTimestamp"),
                 _field(result, "after", "ActiveEnterTimestamp"))


def _r_fw_open(action: Any, result: Any) -> bool | None:
    # 放行端口：变更前该区域已放行这个端口 → 本次是空操作（firewall-cmd 会报 ALREADY_ENABLED）
    s = _step(result, "before")
    if s is None or getattr(s, "status", None) not in ("ok", "skipped"):
        return None
    want = f"{_params(action, result).get('port', '')}/{_params(action, result).get('protocol', '')}"
    return want not in _norm(getattr(s, "parsed", None))


def _r_fw_close(action: Any, result: Any) -> bool | None:
    # 撤销放行：`already` 是变更前的 --query-port，输出 yes / no（firewall-cmd 的原文）
    s = _step(result, "already")
    if s is None or getattr(s, "status", None) != "ok":
        return None
    v = _norm(getattr(s, "parsed", None))
    if v == "yes":
        return True
    if v == "no":
        return False
    return None


def _params(action: Any, result: Any) -> dict[str, Any]:
    return getattr(result, "params_machine", None) or {}


def _r_cron_upsert(action: Any, result: Any) -> bool | None:
    # 定时任务写入：走 write_file 步骤的"先比对 sha256、相同则不写"（规范 §12.4）
    return _step_changed(result, "write")


def _r_cron_remove(action: Any, result: Any) -> bool | None:
    # 删定时任务：`show_before`（cat）成功 = 文件本来就在 → 删掉就是变更
    if not _ran_ok(result, "show_before"):
        return None
    return True


def _r_file_push(action: Any, result: Any) -> bool | None:
    # 上传：目标机**原有** sha256 vs 上传后 sha256（sha256_before 由引擎在 scp 之前采集）
    push = _step(result, "push")
    if push is None or getattr(push, "status", None) != "ok":
        return None
    parsed = getattr(push, "parsed", None)
    if not isinstance(parsed, dict):
        return None
    after = parsed.get("sha256")
    before = parsed.get("sha256_before")
    if before in (None, ""):
        # 目标机原本没有这个文件 → 一定是"变了"（不是"无法判定"）
        return True
    if not after:
        return None
    return str(before) != str(after)


# ── T16（规范 §12.117）：虚拟化层 ────────────────────────────────────
# ★★ 判据来自**探针在动手之前读到的状态**（`probe_before` 那一步），
#   不是"命令有没有报错" —— 对已经在跑的 VM 执行 vm.start，vmrun 可能报错，
#   但那**不是失败**，而是**幂等**（已达终态）。


def _r_vm_power(action: Any, result: Any) -> bool | None:
    """开机 / 关机 / 拔电源：**动手前**它是相反状态 → 本次确实改变了它。"""
    s = _step(result, "probe_before")
    if s is None or getattr(s, "status", None) not in ("ok", "skipped"):
        return None                      # 没读到动手前的状态 ⇒ 无法判定（绝不猜）
    val = getattr(s, "parsed", None)
    if not isinstance(val, dict) or "was_running" not in val:
        return None
    was = str(val.get("was_running")).strip().lower()
    if was not in ("yes", "no"):
        return None
    want_up = getattr(action, "id", "") in ("vm.start",)
    return (was == "no") if want_up else (was == "yes")


def _r_vm_clone(action: Any, result: Any) -> bool | None:
    """克隆（T17）：★ 规则只有一句 —— **这次到底有没有造出一个新的 `.vmx`**。

    判据来自**动手前后各看一次文件系统**（`target_before` / `wait_created`），
    **不是**"`vmrun clone` 有没有报错"：

      · 动手前 `vmx_exists=false` ＋ 动手后 `true` ⇒ **True**（真的造出来了）；
      · 动手前 `true` ⇒ **None**：那说明预检那道"不覆盖"的闸没拦住（异常路径），
        "我改了它没有"**证不了** ⇒ 按宪法 2 一律 `None`，不许猜。

    ★ 为什么不能只看"命令返回 0"：`vmrun clone` 对某些情形会返回非零却**什么都没做成**；
      反过来，它对"新机已经在那个位置"也可能返回非零 —— 那时的"变没变"要问**文件系统**。
    """
    before = _step(result, "target_before")
    after = _step(result, "wait_created")
    if before is None or after is None:
        return None
    if getattr(after, "status", None) != "ok":
        return None                       # 判据那一步没成立 ⇒ 无法判定（任务本身也已经是失败）
    b = getattr(before, "parsed", None)
    a = getattr(after, "parsed", None)
    if not isinstance(b, dict) or not isinstance(a, dict):
        return None
    b_ex, a_ex = b.get("vmx_exists"), a.get("vmx_exists")
    if not isinstance(b_ex, bool) or not isinstance(a_ex, bool):
        return None
    if b_ex:
        return None                       # 动手前就在 ⇒ 证不了（"不覆盖"本该拦住它）
    return True if a_ex else None


def _r_host_register(action: Any, result: Any) -> bool | None:
    """登记（T17）：★ 判据来自工具输出的两个布尔 —— `written` / `already`。

      · `written=true`  ⇒ **True**（真的往 hosts.yaml 里写了东西）；
      · `already=true`  ⇒ **False**（id 已在、地址与 vmx 都对得上 ⇒ **已达终态、零变更**）；
      · 两个都不是      ⇒ **None**（**证不了**，按宪法 2 一律不猜）。

    ★ 为什么"已达终态"能算 `False`（而不是 `unknown`）：幂等在这里有**正面证据** ——
      工具**逐字比过** hosts.yaml 里那一条的 address 与 vmx（规范 §12.131）。
    """
    s = _step(result, "register")
    if s is None or getattr(s, "status", None) != "ok":
        return None
    val = getattr(s, "parsed", None)
    if not isinstance(val, dict):
        return None
    if val.get("written") is True:
        return True
    if val.get("already") is True:
        return False
    return None


def _r_host_identity(action: Any, result: Any) -> bool | None:
    """身份重置四项（T17 · 规范 §12.128）：machine-id / SSH host key / 主机名 / 静态 IP。

    ★★ 判据就是**那一步脚本自己对出来的退出码**（`reset` 步骤，`ok_exit_codes: [0]`）：

      · `0` ⇒ **True**：脚本**在同一段上下文里**读了旧值、重置、再读新值，比对通过
        （machine-id 长度 32 且与旧值不同 / host key 指纹变了 / 主机名回读一致 / 网卡上出现新地址）；
      · `3` ⇒ **False**：脚本明确报了"**没变 / 形状不对**" ——
        ★ 这是**真结论**（这次确实一个字节都没改），不是"算不出来"；
        而且此时**动作本身是失败的**（判据步非 optional ⇒ 任务红）—— 两件事各归各家；
      · `2` / 空 / 步骤没跑到 ⇒ **None**（读不到、工具不在 ⇒ 无从判定，绝不猜）。

    ★ 为什么不看"平台自己有没有写过那个文件"：写文件的是脚本，判据也是脚本 ——
      平台只认它交回来的那个结论（"问**被重置的那一方**"，与 T9 §12.37 同源）。
    """
    s = _step(result, "reset")
    if s is None:
        return None
    rc = getattr(s, "exit_code", None)
    if rc == 0:
        return True
    if rc == 3:
        return False
    return None


def _r_vm_snapshot_revert(action: Any, result: Any) -> bool | None:
    """回滚快照：★ **刻意总是 `unknown`**（规范 §12.3 宪法 2）。

    为什么不返回 `True`：回滚会把"当前状态"换成"快照那一刻的状态" ——
    但如果这台机器**本来就处在那个状态**，本次就是**空操作**。
    ★★ 而"它本来在不在那个状态"**没有可核的证据**：VMware 不提供"当前状态 vs 某条快照"的比较，
      动作自己的判据（VMware 收下了请求 ＋ 这条快照仍在链上）也**证明不了"它变了"**。
    ⇒ 按"未判定 ≠ 没变"的纪律，这里只能如实说 **unknown**，
      不许拿"命令返回 0"冒充"它变了"（§12.42 同族：报告不许说假话）。
    """
    return None


def _r_vm_snapshot_create(action: Any, result: Any) -> bool | None:
    """建快照：**动手前**链上没有这个名字 → 本次确实新增了一条快照。"""
    s = _step(result, "before")
    if s is None or getattr(s, "status", None) not in ("ok", "skipped"):
        return None
    val = getattr(s, "parsed", None)
    if not isinstance(val, dict):
        return None
    names = val.get("snapshots")
    if not isinstance(names, list):
        return None
    want = str(_params(action, result).get("snapshot") or "").strip()
    if not want:
        return None
    return want not in [str(x).strip() for x in names]


def _r_file_remove(action: Any, result: Any) -> bool | None:
    # 受限删除：`before`（删除前是否存在）成功 = 本来就有 → 删掉就是变更
    if not _ran_ok(result, "before"):
        return None
    return True


def _r_pkg_rollback(action: Any, result: Any) -> bool | None:
    # 按事务号回退（T7 · 规范 §12.15.3）：**回退前后版本逐字对照**才是"变了没有"。
    # ★ 没填 `package` 时两边的步骤都被跳过（parsed 都是 None）⇒ `_diff` 返回 **None（无法判定）**，
    #   而不是 False —— 宪法 2：「拿不到对照数据」和「确实没变」是两件事，
    #   后者是幂等的正面证据，前者什么都不是。
    return _diff(_val(result, "ver_before"), _val(result, "ver_after"))


def _r_sysctl_set(action: Any, result: Any) -> bool | None:
    """写内核参数（T8 · 规范 §12.24）：**复读值变了吗**才是「改了没有」。

    ★ 为什么不用「sysctl -w 返回 0」：那正是 §12.24.1 说的假成功来源。
      证据只能是 before / after 两次读数。
    """
    return _diff(_val(result, "before"), _val(result, "after"))


def _r_sysctl_load_module(action: Any, result: Any) -> bool | None:
    """加载内核模块（T8 · 规范 §12.24.3）：条数 0 → 非 0 才算变了。

    ★ 两次读数来自 `grep -c`（数 /proc/modules 里含该名字的行）——
      它对「一个都没匹配」给 **1**（退出码即结论），
      所以 `count_after` 那一步只接受 0，模块没真在就当场判红。
    """
    return _diff(_val(result, "count_before"), _val(result, "count_after"))


def _r_container_pull(action: Any, result: Any) -> bool | None:
    """按 CRI 路拉镜像（T8 · 规范 §12.31.5）：★ **只认"新增了一个 ref"这一个方向**。

    ★ 为什么不做"前后清单整体不同"：镜像清单会因为**别的**原因变
      （别的步骤也在拉镜像、别的镜像也被清掉），整体比较会把"不是这一步干的"
      算到这一步头上。
    ★ 幂等天然成立：第二次跑时该 ref 已在 `before` 里 ⇒ 不新增 ⇒ `False`。
    ★ 任一侧取不到 ⇒ `None`（宪法 2：**"拿不到对照数据"和"确实没变"是两件事**）。
    """
    if not (_ran_ok(result, "before") and _ran_ok(result, "after")):
        return None
    after = _val(result, "after")
    if not isinstance(after, list):
        return None
    before = _val(result, "before")
    # ★ `before` 为空输出时 `lines` 给 None —— 那是"**一个镜像都没有**"这个结论，
    #   按空集合处理是对的（不是"取不到"；"取不到"由上面的 `_ran_ok` 承担）。
    before_set = {_norm(x) for x in before} if isinstance(before, list) else set()
    return bool({_norm(x) for x in after} - before_set)


def _r_svc_reset_failed(action: Any, result: Any) -> bool | None:
    """清失败状态（T8 · 规范 §12.26）：**失败清单变了没有**。

    ★ 本来就没有失败单元 ⇒ 前后都空 ⇒ `False`（幂等，没改动目标机）——
      那才是「复位」这个词的正确含义。
    ★ 任一侧没问出来 ⇒ `None`（不许猜）。
    """
    # ★ 判据走**计数**（`line_count`）而不是原文：
    #   一个失败单元都没有时，`raw` 给的是 None（空结果 ≠ 空数据）——
    #   拿它做对照只能得 unknown；而 `line_count` 给的是 **0**（结论），
    #   于是"前后都是 0"能正确地判成 **没变（幂等）**。
    if not (_ran_ok(result, "fail_count_before") and _ran_ok(result, "fail_count_after")):
        return None
    return _diff(_val(result, "fail_count_before"), _val(result, "fail_count_after"))



def _r_k8s_apply(action: Any, result: Any) -> bool | None:
    """应用 Kubernetes 清单（T8 · S7 · 规范 §12.34）：★ 判据是 `kubectl diff` 的**退出码**。

    · `kubectl diff -f <清单>` 的退出码本身就是它的一句话结论：
      **0 = 盘上那份清单与集群里的对象一模一样**、**1 = 有差异**；
    · ⇒ `0 → False`（这次什么都没改，幂等）、`1 → True`（真的改了）；
    · 其它退出码 ⇒ `None`（**不是 False**；宪法 2：拿不到对照数据 ≠ 确实没变）。
    · ★ 另加一道前置：**`apply` 那一步必须真的跑成**（rc=0）才允许下结论 ——
      否则"连不上集群"这类错会被 `diff` 的退出码伪装成一个判断。

    ★★ 为什么**不用**「`kubectl apply` 的输出里有没有 `created` / `configured`」：
      服务端会给对象补默认字段，`configured` 可能在"其实没变"时**也**出现 ⇒
      "第二次跑 changed 为空"这条验收就**永远做不到**（假变化）。
      `kubectl diff` 判的是**差异本身**（把同一份清单一前一后各算一遍再比），
      不是"命令干了什么活"。
    """
    if not _ran_ok(result, "apply"):
        return None
    s = _step(result, "diff")
    if s is None:
        return None
    code = getattr(s, "exit_code", None)
    if code == 0:
        return False
    if code == 1:
        return True
    return None


def _r_k8s_reset(action: Any, result: Any) -> bool | None:
    """退出集群（T8 · S6 · 规范 §12.32.4）：**静态 Pod 清单条数**从"有"变"没有"才算变了。

    ★ 不拿"`kubeadm reset` 返回 0"当判据 —— 它会跳过够不着的东西并照样返回 0。
    ★ 任一侧没数出来 ⇒ `None`（宪法 2）。
    """
    return _diff(_val(result, "manifests_before"), _val(result, "manifests_after"))


def _r_k8s_init(action: Any, result: Any) -> bool | None:
    """引导控制面（T8 · S6 · 规范 §12.32.4）：**静态 Pod 清单条数**从 0 变"有"才算变了。"""
    return _diff(_val(result, "manifests_before"), _val(result, "manifests_after"))


def _r_k8s_join(action: Any, result: Any) -> bool | None:
    """工作节点入列（T8 · S6 · 规范 §12.32.4）：**`kubelet.conf` 条数**从 0 变 1 才算变了。"""
    return _diff(_val(result, "kubelet_conf_before"), _val(result, "kubelet_conf_after"))


def _r_k8s_kubeconfig(action: Any, result: Any) -> bool | None:
    """装入 kubeconfig（T8 · S6 · 规范 §12.32.4）：★ 判据是 `cmp -s` 的**退出码**。

    · `0` = 装之前两个文件就**逐字节相同** ⇒ 本次**没写盘** ⇒ `False`（幂等）；
    · `1` = 内容不同、`2` = 目标不存在 ⇒ 这次是**真变更** ⇒ `True`；
    · 其它 ⇒ `None`。
    ★★ 复制类操作的唯一硬判据就是"两个文件是不是一样" ——
      不是"文件在不在"、也不是"`install` 返回 0"（§12.32.2）。
    """
    s = _step(result, "dest_before")
    if s is None:
        return None
    code = getattr(s, "exit_code", None)
    if code == 0:
        return False
    if code in (1, 2):
        return True
    return None


def _r_k8s_scale(action: Any, result: Any) -> bool | None:
    """扩缩容（T9 · §12.38）：★ 判据是 **`spec.replicas` 前后是否不同**。

    · 调到**当前值** ⇒ 前后相同 ⇒ `False`（**幂等**：没改动集群）；
    · 任一侧没读到 ⇒ `None`（宪法 ②：拿不到对照数据 ≠ 确实没变）。
    ★★ 不用"`kubectl scale` 的输出里有没有 `scaled`"：那答的是"我们发了什么"，
      而我们要答的是"**集群里的期望副本数变没变**"。
    """
    return _diff(_val(result, "desired_before"), _val(result, "desired_after"))


def _r_k8s_rollout_restart(action: Any, result: Any) -> bool | None:
    """滚动重启（T9 · §12.38）：★ 判据是 **`metadata.generation` 前进过**。

    ★ 重启两次 = 两次真实变更（每次都换一批新容器）⇒ 这里**不该**追求幂等，
      追求的是"**能证明它真的触发了一次新滚动**"。
    """
    return _diff(_val(result, "gen_before"), _val(result, "gen_after"))


def _r_k8s_image(action: Any, result: Any) -> bool | None:
    """换镜像 / 回滚（T9 · §12.38）：★ 判据是 **`spec.template...containers[*].image` 变没变**。

    · 换成一个**相同**的镜像 ⇒ `False`（幂等）；
    · 回滚到"上一版恰好是同一个镜像" ⇒ `False`（**如实**：模板确实没变）。
    """
    return _diff(_val(result, "image_before"), _val(result, "image_after"))


def _r_k8s_node_sched(action: Any, result: Any) -> bool | None:
    """排空 / 恢复调度（T9 · §12.38）：★ 判据是 **`spec.unschedulable` 的前后对照**。

    ★ 这里有一步**必须做的归一**：`uncordon` 会把 `unschedulable` **整个字段移除** ⇒
      `raw` 解析器给 `None`。而 `None` 与 `""` 在这件事上**是同一个意思**（可调度）。
      ⇒ 把两侧都归一成字符串再比：**"已可调度 vs 已可调度" 应当判 `False`（没变）**，
      而不是 `None`（拿不到对照数据）—— ★ 后者会让"再点一次"看起来"无法判定"。
    ★ 但**两侧都没跑到**（步骤不存在）仍判 `None`：那是"真的没有对照数据"。
    """
    b, a = _step(result, "sched_before"), _step(result, "sched_after")
    if b is None or a is None:
        return None
    if getattr(b, "status", None) not in ("ok", "skipped"):
        return None
    if getattr(a, "status", None) not in ("ok", "skipped"):
        return None
    return _norm(getattr(b, "parsed", None)) != _norm(getattr(a, "parsed", None))


def _r_k8s_delete_workload(action: Any, result: Any) -> bool | None:
    """删除工作负载对象（T9 · §12.38）：★ **删除类的判据是终态**。

    · 预检保证"删之前它存在"；`before` 那一步拿到了它的原文 ⇒ **删掉就是变更**；
    · ★ `after` 那一步的退出码是 **1**（NotFound = 真的没了）—— 那是**预期**，
      不影响本函数的结论（它回答的是"变了没有"，不是"删成功没有"）。
    """
    if not _ran_ok(result, "before"):
        return None
    return True


def _r_k8s_delete_namespace(action: Any, result: Any) -> bool | None:
    """删除命名空间（T9 · §12.38）：同上 —— 预检保证它存在，删了就是变更。"""
    if not _ran_ok(result, "act"):
        return None
    return True


def _r_mon_unpack(action: Any, result: Any) -> bool | None:
    """解包装机（T10 · 规范 §12.53）：★ 判据是**组件软链指向变了没有**。

    ★ 为什么不用"看看 /opt 下有没有多出东西"：那会把"解包成功但版本没变"也算成变更，
      而"同一个版本再解一次"恰恰是幂等要证明的情形。
    ★★ **为什么不能只用 `_diff`**（T10·S2 真跑抓到的第一版写法）：首次装机时
      `readlink` 对"还没有这个软链"**退出码 1、stdout 空** ⇒ 那一步的 `parsed` 是 `None`，
      而 `_diff` 对 `None` 一律给 `None`（"无法判定"）。于是**第一次装完**报的是
      "无法判定"而不是"变了" —— ★ 幂等的正面证据反而丢了（正是 §12.45.3 那条纪律的另一面：
      "退出码 1 + 空输出"在这里是**真结论**（确实没有这个软链），不是"取不到"）。
    ⇒ 用**退出码**把这个三态说清楚：1 = 本来就没有（⇒ 装上就是变更）；0 = 有（⇒ 比指向）；
      其它 = 无法判定。
    """
    s_before = _step(result, "link_before")
    s_after = _step(result, "link_after")
    if s_before is None or s_after is None:
        return None
    if getattr(s_before, "status", None) != "ok" or getattr(s_after, "status", None) != "ok":
        return None
    rc_before = getattr(s_before, "exit_code", None)
    if rc_before == 1:
        return True
    if rc_before != 0:
        return None
    return _diff(_val(result, "link_before"), _val(result, "link_after"))


def _r_mon_target_add(action: Any, result: Any) -> bool | None:
    """注册抓取目标（T10 · 规范 §12.54）：★ 判据是**那个 json 的 sha256 变了没有**。

    ★ 幂等的正面证据：写同一份内容时引擎的**幂等写**根本不写盘 ⇒ 两次指纹相同 ⇒ `False`。

    ★★★ T10·S7 真跑抓到的真缺陷 ⑥（**与 §12.48 逐字同族**）：
      原来这里只写了 `return _diff(_val(result, "before"), _val(result, "after"))` ——
      而"**这个文件还不存在**"那一步（`before`，`ok_exit_codes: [0, 1]`，rc=1）
      **虽然 `status=ok`，但它的 `parsed` 是 `None`**（空输出 ⇒ raw 给 None）⇒ `_diff` 返回
      **`None`（unknown）** ⇒ 首次注册被报成"**无法判定**"，而它其实是**确定的变更**。
      ★ 根因与 §12.45.3 是同一句话：**"取到空"与"取不到"是两件事** ——
        但这里更细一层：**"跑过了、并且用退出码说了『它不在』"既不是"取到空"也不是"取不到"**，
        它是一个**由退出码承担的结论**（§9.6 同族）。
      ⇒ 修法：**先读退出码**（`rc=1` = 文件不存在 ⇒ 一定变了），再退回指纹对照。
      ★ 与 `_r_mon_unpack` / `_r_mon_target_remove` 用的是**同一条**思路：
        **判据先看退出码，再看内容。**
    """
    s_before = _step(result, "before")
    if s_before is None or getattr(s_before, "status", None) not in ("ok", "skipped"):
        return None                                  # 那一步没跑成 ⇒ 拿不到对照数据
    if getattr(s_before, "exit_code", None) == 1:
        return True                                  # ★★ "还没有这个文件" ⇒ 首次注册 = 变了
    return _diff(_val(result, "before"), _val(result, "after"))


def _r_mon_target_remove(action: Any, result: Any) -> bool | None:
    """注销抓取目标（T10 · 规范 §12.54）：预检拿到了内容 = 本来就有 ⇒ 删掉就是变更。

    ★ 与 `file.remove` 同一条思路：**不能**拿"删完之后读不回来"当变更证据 ——
      删完读不回来是**预期结果**（那一步的 `ok_exit_codes` 就是 [2]），不是变化量。
      真正的对照是**预检那一步**：它成功了 ⇒ 删之前确实有东西。
    """
    if not _ran_ok(result, "exists"):
        return None
    return True


def _r_mon_selftest_metric(action: Any, result: Any) -> bool | None:
    """人造自检指标（T10 · 规范 §12.59）：★ 读**写盘步骤自己算好的** `changed`。

    ★ 写盘类步骤（`write_file`）的 `changed` 由引擎按 sha256 直接判定 ——
      本规则只是把它**转达**出来（与 `_r_svc_*` 那类"再判一次"不同，这里没有可判定量）。
      ★ 注意三态：写盘步骤**失败或没跑** ⇒ `_step_changed` 返回 `None`（不算"没变"）。
    """
    return _step_changed(result, "write")


#: ★ 规则表：动作 id → 推导函数。**新增"能变更的动作"时必须在这里加一行**
#:   （不加不会报错，只会让它静默变成 unknown —— selftest 会遍历断言，漏了就红）
RULES: dict[str, Callable[[Any, Any], bool | None]] = {
    "pkg.install": _r_pkg_install,
    "pkg.update": _r_pkg_update,
    "pkg.remove": _r_pkg_remove,
    "pkg.rollback": _r_pkg_rollback,
    "svc.start": _r_svc_active,
    "svc.stop": _r_svc_active,
    "svc.restart": _r_svc_restart,
    "svc.enable": _r_svc_unitfile,
    "svc.disable": _r_svc_unitfile,
    "fw.port-open": _r_fw_open,
    "fw.port-close": _r_fw_close,
    "cron.upsert": _r_cron_upsert,
    "cron.remove": _r_cron_remove,
    "file.push": _r_file_push,
    "file.remove": _r_file_remove,
    "sysctl.set": _r_sysctl_set,
    "sysctl.load-module": _r_sysctl_load_module,
    "svc.reset-failed": _r_svc_reset_failed,
    "container.pull": _r_container_pull,
    "k8s.apply": _r_k8s_apply,
    "k8s.kubeadm-reset": _r_k8s_reset,
    "k8s.kubeadm-init": _r_k8s_init,
    "k8s.kubeadm-join": _r_k8s_join,
    "k8s.kubeconfig": _r_k8s_kubeconfig,
    # ★ T9·S4（K8s 管理台 · 变更面）
    "k8s.scale": _r_k8s_scale,
    "k8s.rollout-restart": _r_k8s_rollout_restart,
    "k8s.set-image": _r_k8s_image,
    "k8s.rollout-undo": _r_k8s_image,
    "k8s.node-drain": _r_k8s_node_sched,
    "k8s.node-resume": _r_k8s_node_sched,
    "k8s.delete-workload": _r_k8s_delete_workload,
    "k8s.delete-namespace": _r_k8s_delete_namespace,
    # ★ T10·S4（监控告警接入 · 装机 / 采集面 / 造条件）
    "mon.unpack": _r_mon_unpack,
    "mon.target-add": _r_mon_target_add,
    "mon.target-remove": _r_mon_target_remove,
    "mon.selftest-metric": _r_mon_selftest_metric,
    # ★ T16·S2（虚拟化层基座 · 电源与快照）
    # ★★ 判据全部来自**动手前那条探针读到的状态**（规范 §12.117）——
    #    对已经在跑的 VM 执行 vm.start，vmrun 可能报错，但那是**幂等**（已达终态），
    #    不是失败；反过来"命令没报错"也证明不了"它真的起来了"。
    "vm.start": _r_vm_power,
    "vm.stop": _r_vm_power,
    "vm.stop-hard": _r_vm_power,
    "vm.snapshot-create": _r_vm_snapshot_create,
    # ★ T17·S2（克隆与身份重置）：**造出一台新机器** ⇒ 规则读"动手前后文件系统上的样子"。
    "vm.clone": _r_vm_clone,
    # ★ T17·S4（自动纳管）：写 hosts.yaml ⇒ 规则读工具自己的 written / already
    "host.register": _r_host_register,
    # ★ T17·S3（身份重置四项）：规则读**脚本自己对出来的退出码**（0=变了 / 3=没变 / 2=读不到）。
    #   ★ 四项共用一条：它们问的是同一件事 —— "与动手前比，这一项的身份真换了吗"。
    "host.machine-id-reset": _r_host_identity,
    "host.ssh-hostkey-reset": _r_host_identity,
    "host.hostname-set": _r_host_identity,
    "host.static-ip-set": _r_host_identity,
    # ★ 回滚**登记了规则，但它刻意返回 unknown** —— 见函数 docstring：
    #   "看起来会变更"的动作**必须**在表里有一条规则（否则会被自检红出来），
    #   而这条规则的内容就是"我们**证不了**它变了"。
    "vm.snapshot-revert": _r_vm_snapshot_revert,
}

#: 豁免清单：**risk 不是 green，但本来就不会变**的动作。
#: 每一条都必须写清理由 —— 否则它会变成"把不知道的当没变"的后门。
NO_CHANGE_EXEMPT: dict[str, str] = {
    "demo.confirm-gate": (
        "演示动作：risk 之所以是 yellow，只是因为它用来演示「确认闸门」这件事；"
        "步骤本身全是只读命令（timedatectl / chronyc），不会改动目标机。"
    ),
    "k8s.exec": (
        "★ T9·S4。它是 yellow 只为『进别人的容器』这件事加一道闸门："
        "白名单里的探针（`cat` / `ps` / `env` / `df` / `ip` / `ss` 这类）**全是只读**，"
        "不写目标机、不改容器。★ 详见规范 §12.41。"
    ),
    "k8s.kubectl": (
        "★ T9·S5。它是 **只读逃生口**：`verb` 是白名单枚举，九条 case 全为只读子命令"
        "（`get` / `describe` / `logs` / `events` / `top` / `explain` / `api-resources` / "
        "`cluster-info` / `version`），命令里没有一处来自输入。★ 详见规范 §12.40。"
        "★ 它 yellow 的原因是『少见的读法要有闸门』，不是因为会改东西。"
    ),
    "svc.daemon-reload": (
        "★ T8·S2 新增。理由是**它本身不改目标机的任何东西**：`systemctl daemon-reload` 只是让 "
        "systemd 重新读一遍盘上的单元定义（不写盘、不重启服务、不改单元文件）。"
        "★ 因此「改了什么」必须记在**真正写盘的那一步**上（`write_file` 写 drop-in 才是变更）；"
        "把 daemon-reload 记成 unknown 只会让配方报告的变更清单多一条噪音。"
        "★ 注意：这不等于「它没作用」 —— 它的作用在「让定义生效」，判据见规范 §12.25.2。"
    ),
    "mon.reload": (
        "★ T10 新增。理由是**它不改盘上的任何东西**：`POST /-/reload` 只是让 Prometheus "
        "重新读一遍**已经在盘上**的配置与规则文件（不写盘、不重启进程）。"
        "★ 因此「改了什么」必须记在**真正写盘的那一步**上（`mon.selftest-metric` / "
        "`mon.target-add` / 配方里的 `template:` 步骤）；把 reload 记成 unknown 只会让报告的变更清单多一条噪音。"
        "★ 注意：这不等于「它没作用」—— 它的作用在「让声明变成生效面」，判据见规范 §12.55。"
    ),
}


def has_rule(action: Any) -> bool:
    """这个动作**平台判不判得出「变了没有」**（宪法 ② 的看门狗入口）。

    ★ 为什么单独开一个函数而不是让调用方去试 `changed_for_action(a, None)`：
      后者在 `result is None` 时**对已登记的动作也返回 `None`**（没有结果当然算不出来）——
      拿它当"有没有登记规则"用，会把 `pkg.install` / `svc.start` 这些**明明登记过**的动作
      全判成"未登记"，报出一堆**假警报**（T7·S5 的配方体检第一版就这么错过一次）。
      ★ 教训：**"算不出来"与"没登记"是两件事** —— 与本项目那条"空结果 ≠ 空数据"同一个道理。
    """
    aid = str(getattr(action, "id", "") or "")
    if not aid:
        return False
    if str(getattr(action, "risk", "")) == "green":
        return True                     # 只读动作恒 false（规范 §12.3），不需要逐条登记
    return aid in RULES or aid in NO_CHANGE_EXEMPT


# ------------------------------------------------------------------ 对外入口


def changed_for_action(action: Any, result: Any) -> bool | None:
    """算出这次动作"到底改了没有"。

    优先级：**规则表 → 豁免清单 → 只读（green）恒 False → 其余 unknown**。
    ★ 最后那条是宪法 2 的落点：**未登记 ≠ 没变**，一律 `None`。
    """
    fn = RULES.get(getattr(action, "id", ""))
    if fn is not None:
        try:
            return fn(action, result)
        except Exception:  # noqa: BLE001
            # 推导过程出意外 → unknown。★ 绝不当成"没变"：
            # 那会让幂等证明凭空通过（假绿比报错危险得多）。
            return None
    if getattr(action, "id", "") in NO_CHANGE_EXEMPT:
        return False
    if getattr(action, "risk", "") == "green":
        return False
    return None


def audit_rules(actions: dict[str, Any]) -> list[str]:
    """自检用：列出"看起来会变更、却没有 changed 规则"的动作。

    判定口径：`risk != green` **且** 不在豁免清单里 **却** 不在规则表里 → 可疑。
    （这是开题单 §12 断言 ⑤ 的实现。）
    """
    missing: list[str] = []
    for aid, action in sorted(actions.items()):
        if getattr(action, "risk", "") == "green":
            continue
        if aid in NO_CHANGE_EXEMPT or aid in RULES:
            continue
        missing.append(aid)
    return missing


def describe(aid: str) -> str:
    """给报告用的一句话说明（`changed=unknown` 时人要能问"为什么"）。"""
    if aid in RULES:
        return f"已登记推导规则（{RULES[aid].__name__.removeprefix('_r_')}）"
    if aid in NO_CHANGE_EXEMPT:
        return f"豁免（{NO_CHANGE_EXEMPT[aid]}）"
    return "未登记推导规则 → 只能标 unknown"
