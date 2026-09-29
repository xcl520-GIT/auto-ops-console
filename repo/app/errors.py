"""统一错误模型。

铁律（开题单验收标准 #5）：界面**永远不直接展示裸 stderr**。
每个对外错误都必须带「原因（出了什么事，人话）」+「建议（该怎么办）」。
技术细节放进 detail，界面上默认折叠。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- 错误码 → 默认建议
ADVICE: dict[str, str] = {
    "CONFIG_INVALID": "检查 repo/config.yaml 的字段拼写与取值，改正后重启服务。",
    "BIND_REJECTED": (
        "监听地址必须在白名单内（127.0.0.1 或内网网段）。0.0.0.0 一律拒绝 —— "
        "这是项目安全红线，改回 config.yaml 的 server.host 即可。"
    ),
    "HOST_NOT_FOUND": "检查 hosts.yaml 里的主机 id 是否拼对；或在界面上刷新主机列表。",
    "HOST_UNREACHABLE": (
        "① 确认目标机已开机（VMware 里能看到登录画面）；"
        "② 在宿主机执行 ping <目标机IP>，看是否通；"
        "③ 确认两台机都在 VMnet8 的 192.0.2.0/24 网段；"
        "④ 确认目标机上 sshd 正在运行（systemctl status sshd）。"
    ),
    "SSH_AUTH_FAILED": (
        "① 确认 hosts.yaml 里的 user 与实际账号一致；"
        "② 确认公钥已写入目标机的 ~/.ssh/authorized_keys，且该文件权限 600、.ssh 目录权限 700；"
        "③ 确认目标机 /etc/ssh/sshd_config 未禁用 PubkeyAuthentication。"
    ),
    "SSH_HOSTKEY_UNKNOWN": (
        "首次连接需要确认目标机指纹。在界面「主机」区点击「信任此主机」后重试；"
        "或在 config.yaml 里把 ssh.strict_host_key 改为 accept-new。"
    ),
    "SSH_TIMEOUT": "目标机响应过慢或网络不通。可在 config.yaml 里调大 ssh.connect_timeout。",
    "ACTION_NOT_FOUND": "刷新页面重新加载动作列表；确认 catalog/actions/ 下存在对应文件。",
    "CATALOG_INVALID": "动作 YAML 未通过 schema 校验。按错误中指出的字段修正后刷新页面。",
    "PARAM_INVALID": "按字段下方的说明填写。参数只允许白名单内的字符。",
    "PARAM_MISSING": "这是必填参数，填上再执行。",
    "CONFIRM_REQUIRED": "该动作风险等级高于 green，必须二次确认后才能执行。",
    "PRECHECK_FAILED": "前置条件不满足，动作**未开始执行**（目标机未被改动）。按上面的原因处理。",
    "STEP_FAILED": (
        "这一步在目标机上返回了非零退出码，动作已中止。"
        "看该步骤的「原始输出」定位；若它是可选步骤，可忽略。"
    ),
    "STEP_TIMEOUT": "这一步超过了超时时间。若命令本身耗时长，在该动作 YAML 里调大该步骤的 timeout。",
    "TOOL_MISSING": (
        "目标机上没有这个命令。① 用「包搜索」动作查哪个包提供它；"
        "② dnf install -y <包名> 装上后重试；③ 或改用已有的等价命令。"
        "（RHEL 10 最小安装默认没有 dig / nslookup / traceroute / mtr，属正常现象。）"
    ),
    "VERIFY_FAILED": (
        "命令跑完了，但**自证没通过 —— 结果不可信**。"
        "请查看原始输出；这种情况应作为缺陷记录，不能当作成功。"
    ),
    "OUTPUT_TOO_LARGE": "输出过大已截断。收窄查询范围（缩短时间范围、加关键字、减少行数）后重试。",
    "STORE_ERROR": "本地数据库读写失败。确认 repo/var/ 目录可写、磁盘未满。",
    "INTERNAL": "这是控制台自身的缺陷，不是目标机的问题。请记录本次「任务 ID」与错误详情。",
    # ── T4 新增：包管理与文件系统类失败的翻译（见 classify_remote_failure）
    "PKG_REPO_UNREACHABLE": (
        "① 先看这台机器配了哪些源、指向哪里：`dnf repolist -v`；"
        "② 常见两类原因：源指向**本地 ISO 挂载点**（file:///mnt/…）而 ISO 已卸载/未挂载，"
        "或源是远端地址但机器出不去网；"
        "③ 修好源（挂回 ISO / 换可达的镜像 / 配好代理）后重试。"
    ),
    "PKG_NOT_SUBSCRIBED": (
        "RHEL 未在 entitlement 服务注册，官方源不可用。"
        "① 若这是实验机，指向本地 ISO 或内部镜像即可；"
        "② 生产机请用 subscription-manager / rhc 注册；"
        "③ 注册前这套包管理动作都不会成功 —— 这属于环境问题，不是动作的问题。"
    ),
    "PKG_NOT_FOUND": (
        "源里找不到这个名字的包。① 用「包搜索」动作确认包名拼写；"
        "② 确认提供它的源是**启用**状态（dnf repolist）；"
        "③ 有些命令在子包里（例如 dig 在 bind-utils 里）。"
    ),
    "PKG_CONFLICT": (
        "依赖冲突。① 看原始输出里互相冲突的两个包；"
        "② 可考虑先卸载冲突方，或用 dnf --allowerasing；"
        "③ 不要连续重试 —— 冲突不会自己消失。"
    ),
    "PKG_NOTHING_TO_DO": (
        "dnf 认为无事可做：目标状态其实已经达成了（已装 / 已卸）。"
        "这通常**不是错误**，而是幂等语义 —— 看结论里的「安装前/卸载前」状态确认。"
    ),
    "PKG_DB_BROKEN": (
        "rpm 数据库读不开 —— 这会让「装了什么」的判断全部不可信。"
        "① 确认 /var/lib/rpm 存在且可读；② 不要贸然重建数据库，先备份 /var/lib/rpm。"
    ),
    "DISK_FULL": (
        "目标机磁盘写满。先用「目录体积排行」「大文件查找」清理出空间再重试；"
        "装包/写文件类动作在磁盘满时一定会失败。"
    ),
    "FS_READONLY": (
        "文件系统是只读挂载。① 用「磁盘与分区总览」看该挂载点的选项；"
        "② 只读通常是内核把出错的 fs 自动 remount 了 —— 先看内核日志有没有 I/O 错误。"
    ),
    # ── T14 新增：最小鉴权（规范 §12.97；红线 11 的执行面）──────────────
    #   ★ 这些错误的**建议**都要"说清该去哪儿办"，不能只说不行（§12.99.3 同源）。
    "AUTH_NOT_INITIALIZED": (
        "本机还没设过口令，控制台现在是**全拒**状态（红线 11：没口令就不许用，不是「没口令就放行」）。"
        "在界面上完成「设置口令」即可 —— 首次设置：POST /api/auth/setup。"
    ),
    "AUTH_REQUIRED": (
        "这个请求没带有效令牌。① 在控制台界面上登录；"
        "② 命令行工具请先登录拿令牌，再把 `Authorization: Bearer <token>` 带上；"
        "③ 令牌只在内存里，服务重启后会全体失效 —— 重新登录即可。"
    ),
    "AUTH_BAD_CREDENTIALS": "确认口令后重试。★ 连续失败会触发限速锁定（策略见 GET /api/auth/status）。",
    "AUTH_RATE_LIMITED": "等锁定期过去再试。★ 这道闸是为「本机其它程序/插件乱撞」准备的，不是防公网。",
    "AUTH_ALREADY_INITIALIZED": (
        "本机已经设过口令 —— 初始化接口**刻意**不允许重复调用（否则它就是免鉴权的重置口令 = 后门）。"
        "先登录，再走改口令流程。"
    ),
    "AUTH_WEAK_PASSWORD": "换一个长一点的口令。★ 这是本机唯一的门，别用空口令或纯数字短口令。",
    "AUTH_STORE_BROKEN": (
        "口令文件坏了。★ **不要删掉它当作「没设过口令」** —— 那等于把门打开。"
        "从备份恢复，或确认这是本机自己的文件后再手工处理。"
    ),
}


# ---------------------------------------------------------------- 远端失败的翻译（T4）

def classify_remote_failure(tool: str, exit_code: int | None, stdout: str, stderr: str) -> OpsError | None:
    """把**命令自己**的失败翻译成「原因 + 建议」；认不出来返回 None（调用方退回 STEP_FAILED）。

    ★ 为什么要有它（T4 真跑逼出来的一个真缺陷）：
      `pkg.install tree` 在 docker-01 上失败时，界面只给了一句
      「命令返回非零退出码 1」—— 而真实原因是
      「dnf 的源指向一个**已经不存在的本地 ISO 挂载点**（file:///mnt/BaseOS）」。
      这种废话式报错直接违背本项目的铁律（验收标准 #5：失败必须给原因 + 建议），
      所以这里按**真跑时实际见过的输出片段**逐条认领，认不出就老实退回通用错误。

    判定顺序很重要：先认"后果更明确"的（磁盘满 / 只读），再认包管理特有的。
    """
    blob = f"{stdout or ''}\n{stderr or ''}"
    low = blob.lower()
    detail = (stderr or stdout or "").strip()[:2000]

    def hit(*frags: str) -> bool:
        return any(f and f in low for f in frags)

    if hit("no space left on device"):
        return OpsError(code="DISK_FULL", reason="目标机磁盘已满（No space left on device）", detail=detail)
    if hit("read-only file system"):
        return OpsError(code="FS_READONLY", reason="目标机上该路径是只读文件系统", detail=detail)
    if hit("cannot open packages database", "rpmdb", "cannot open packages index"):
        return OpsError(code="PKG_DB_BROKEN", reason="rpm 数据库读不开", detail=detail)
    if hit("failed to download metadata", "cannot download repomd.xml", "all mirrors were tried",
           "could not read a file:// file", "curl error", "failed to download metadata for repo"):
        return OpsError(
            code="PKG_REPO_UNREACHABLE",
            reason=f"软件源不可达：下载仓库元数据失败（命令 {tool} 返回 {exit_code}）",
            detail=detail,
        )
    if hit("not registered with an entitlement server"):
        return OpsError(code="PKG_NOT_SUBSCRIBED", reason="这台 RHEL 未注册，官方源不可用", detail=detail)
    # ★ 注意不要用裸 "no package" —— `rpm -q --whatrequires` 的正常输出里有
    #   "no package requires X"（那是**结论**，不是错误）。
    if hit("unable to find a match", "no match for argument", "nothing provides"):
        return OpsError(code="PKG_NOT_FOUND", reason="源里找不到匹配的软件包", detail=detail)
    if hit("conflicting requests", "conflicts between attempted installs", "file conflicts"):
        return OpsError(code="PKG_CONFLICT", reason="软件包依赖冲突，dnf 拒绝执行", detail=detail)
    if hit("nothing to do"):
        return OpsError(code="PKG_NOTHING_TO_DO", reason="dnf 无事可做（目标状态已经达成）", detail=detail)
    return None


@dataclass
class OpsError(Exception):
    """带「原因 + 建议」的错误对象。所有 API 错误响应都由它生成。"""

    code: str
    reason: str
    advice: str = ""
    detail: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, f"[{self.code}] {self.reason}")
        if not self.advice:
            self.advice = ADVICE.get(self.code, "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "reason": self.reason,
            "advice": self.advice,
            "detail": self.detail,
            "context": self.context,
        }


def fail(code: str, reason: str, **kw: Any) -> OpsError:
    """快捷构造。"""
    return OpsError(code=code, reason=reason, **kw)
