"""改动前自动备份 + 恢复（规范 §9.1 / §9.2）。

护栏地基：变更类动作**执行前**，把它声明要改的路径备份到两处：

  ① 目标机 `<backup.remote_root>/<任务ID>/`  —— **现场恢复**用（目标机断网也能恢复）
  ② 管理机 `<backup.local_root>/<任务ID>/`    —— **长期留证**用（目标机可能被重装/销毁）

★ 备份失败 → 变更步骤一律不执行。
  变更动作的底线只有"能撤回"这一条；备份没成功就动手，等于把"可撤回"变成一句口号。

与动作层的关系：本模块是**平台能力**，不占用动作的步骤编号，也不进 step_total。
所有远端命令仍然经 SshTransport 发出（沿用三层安全契约，逐元素 shlex.quote）。

唯一的"内部聚合"是**目录文件计数**：`sh -c 'find <path> -type f | wc -l'`。
它不是动作 YAML 的 `run`，因此不违反规范 §4 对 run 的管道禁令 —— 在此显式记账，
免得后人以为动作层开了后门。
"""
from __future__ import annotations

import posixpath
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.catalog import (
    BACKUP_FORBIDDEN,
    BACKUP_PATH_RE,
    Action,
    BackupItem,
    ParamValue,
    render_argv_element,
)
from app.config import AppConfig, Host
from app.errors import OpsError
from app.transport import SshTransport

# stat 的输出格式：用 | 分隔，避免路径里的空格与我猜的列混淆
_STAT_FMT = "%s|%a|%U|%G|%F"


@dataclass
class BackupRecord:
    task_id: str
    seq: int
    label: str
    orig_path: str
    remote_path: str = ""
    local_path: str = ""
    kind: str = "file"          # file / dir / missing / failed
    size: int = 0
    file_count: int = 0
    sha256: str = ""
    mode: str = ""
    owner: str = ""
    status: str = "ok"          # ok / missing / failed
    error: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "seq": self.seq, "label": self.label,
            "orig_path": self.orig_path, "remote_path": self.remote_path,
            "local_path": self.local_path, "kind": self.kind, "size": self.size,
            "file_count": self.file_count, "sha256": self.sha256, "mode": self.mode,
            "owner": self.owner, "status": self.status, "error": self.error,
        }

    def to_public(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "label": self.label, "orig_path": self.orig_path,
            "kind": self.kind, "size": self.size, "file_count": self.file_count,
            "sha256": self.sha256, "status": self.status,
            "error": self.error or "", "local_path": self.local_path,
        }


class BackupRunner:
    """备份 / 恢复的执行者。只依赖 cfg + transport，便于离线单测。"""

    def __init__(self, cfg: AppConfig, transport: SshTransport) -> None:
        self.cfg = cfg
        self.transport = transport
        b = (cfg.raw.get("backup") or {}) if isinstance(cfg.raw, dict) else {}
        self.remote_root = str(b.get("remote_root") or "/var/backups/aoc")
        self.local_root = str(b.get("local_root") or "var/backups")
        self.max_file_mb = int(b.get("max_file_mb") or 50)
        self.keep_tasks = int(b.get("keep_tasks") or 20)
        self.min_free_mb = int(b.get("min_free_mb") or 512)

    # ------------------------------------------------------------------ 规划

    def plan(self, action: Action, params: dict[str, ParamValue]) -> list[tuple[int, BackupItem, str]]:
        """把动作声明的 backup[] 渲染成**真实路径**，并做运行时校验（第二道）。"""
        out: list[tuple[int, BackupItem, str]] = []
        for i, item in enumerate(action.backup):
            try:
                path = render_argv_element(item.path, params)
            except OpsError as exc:
                raise OpsError(
                    code="BACKUP_INVALID",
                    reason=f"备份路径渲染失败：{item.path}",
                    advice="检查动作 YAML 的 backup.path 是否引用了已定义的参数。",
                    detail=exc.reason,
                ) from exc
            self.validate_path(path)
            out.append((i, item, path))
        return out

    @staticmethod
    def validate_path(path: str) -> None:
        """运行时校验：渲染后的路径必须过白名单（与加载期的静态校验同源）。"""
        if not BACKUP_PATH_RE.match(path):
            raise OpsError(
                code="BACKUP_INVALID",
                reason=f"备份路径不合法：{path}",
                advice="只允许绝对路径，字符限于 A-Za-z0-9 . _ @ / + -。",
            )
        if ".." in path:
            raise OpsError(
                code="BACKUP_INVALID",
                reason=f"备份路径不得包含 '..'：{path}",
                advice="用明确的绝对路径，不要用相对跳转。",
            )
        if path.rstrip("/") in BACKUP_FORBIDDEN:
            raise OpsError(
                code="BACKUP_INVALID",
                reason=f"不允许备份「{path}」（会递归复制整个系统）",
                advice="指出具体子路径，例如 /etc/ 下的某个文件或目录。",
            )

    # ------------------------------------------------------------------ 执行

    def run(
        self, task_id: str, action: Action, params: dict[str, ParamValue], host: Host
    ) -> tuple[list[BackupRecord], OpsError | None]:
        """执行**动作声明**的全部备份。返回 (记录列表, 致命错误)。

        致命错误非 None 时，调用方**必须**放弃执行变更步骤。
        """
        return self.run_items(task_id, host, self.plan(action, params))

    def run_items(
        self, task_id: str, host: Host, items: list[tuple[int, BackupItem, str]]
    ) -> tuple[list[BackupRecord], OpsError | None]:
        """按 (seq, BackupItem, 真实路径) 执行备份 —— **备份的唯一实现**。

        ★ T5 v1.6 修订抽出（规范 §12.7）：配方的 `template:` 步骤会**覆盖目标机既有文件**，
          它必须与"动作声明 backup"共用**同一道护栏**（同一套空间检查、同一条留证链、
          同一句"备份失败即中止"），否则就是"同一件事、两套标准"。
          于是把核心循环收敛到这里；`run()` 只剩"从动作声明里取路径"这一层包装。
        """
        plan = items
        if not plan:
            return [], None

        # ① 可用空间前置检查（防把目标机写满）
        free_mb = self._free_mb(host)
        if free_mb is not None and free_mb < self.min_free_mb:
            return [], OpsError(
                code="BACKUP_NO_SPACE",
                reason=(
                    f"目标机 {host.address} 可用空间仅 {free_mb}MB，"
                    f"低于下限 {self.min_free_mb}MB，已拒绝执行本变更动作"
                ),
                advice="先清理空间再执行；或调低 config.yaml 的 backup.min_free_mb（不建议）。",
            )

        # ② 建备份目录
        remote_dir = f"{self.remote_root}/{task_id}"
        res = self.transport.run(host, ["mkdir", "-p", remote_dir], timeout=15)
        if res.exit_code != 0:
            return [], OpsError(
                code="BACKUP_FAILED",
                reason=f"无法在目标机创建备份目录 {remote_dir}",
                advice="确认目标机磁盘可写、空间足够。**本动作未执行任何变更。**",
                detail=(res.stderr or "").strip()[:500],
            )

        # ③ 逐项备份
        records: list[BackupRecord] = []
        for seq, item, path in plan:
            rec = BackupRecord(task_id=task_id, seq=seq, label=item.label or path, orig_path=path)
            failure = self._backup_one(host, path, remote_dir, seq, item, rec)
            records.append(rec)
            if failure is not None:
                return records, failure
        return records, None

    def _free_mb(self, host: Host) -> int | None:
        """取目标机根分区可用空间（MB）。取不到就返回 None（不阻断，交由后续步骤暴露问题）。"""
        res = self.transport.run(host, ["df", "-P", "-m", "/"], timeout=15)
        if res.exit_code != 0:
            return None
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        if len(lines) < 2:
            return None
        parts = lines[-1].split()
        if len(parts) < 4 or not parts[3].isdigit():
            return None
        return int(parts[3])

    def _backup_one(
        self,
        host: Host,
        path: str,
        remote_dir: str,
        seq: int,
        item: BackupItem,
        rec: BackupRecord,
    ) -> OpsError | None:
        """备份单个路径。返回非 None 表示**必须中止动作**。"""
        # 1) 元数据（顺便判断存在性）
        st = self.transport.run(host, ["stat", "-c", _STAT_FMT, path], timeout=15)
        if st.exit_code != 0:
            msg = (st.stderr or st.stdout or "").strip()
            if st.exit_code == 1 or "No such file" in msg:
                rec.kind = "missing"
                rec.status = "missing"
                rec.error = "路径不存在（未备份）"
                if item.required:
                    return OpsError(
                        code="BACKUP_MISSING",
                        reason=f"动作声明必须备份的路径不存在：{path}",
                        advice=(
                            "确认路径是否正确（参数是不是填错了）；"
                            "若该路径本来就可能不存在，在动作 YAML 里把该项 required 去掉。"
                        ),
                    )
                return None
            rec.status = "failed"
            rec.error = msg[:300]
            return OpsError(
                code="BACKUP_FAILED",
                reason=f"无法读取 {path} 的元数据（stat 返回 {st.exit_code}）",
                advice="确认目标机可访问该路径且权限足够。**本动作未执行任何变更。**",
                detail=msg[:500],
            )

        parts = st.stdout.strip().split("|")
        if len(parts) >= 5:
            rec.size = int(parts[0]) if parts[0].isdigit() else 0
            rec.mode = parts[1]
            rec.owner = parts[2]
            rec.kind = "dir" if "directory" in parts[4] else "file"

        # 2) 单文件大小闸门
        if rec.kind == "file" and rec.size > self.max_file_mb * 1024 * 1024 and not item.allow_large:
            rec.status = "failed"
            rec.error = f"{rec.size} 字节，超过单文件上限 {self.max_file_mb}MB"
            return OpsError(
                code="BACKUP_TOO_LARGE",
                reason=f"{path} 有 {rec.size // 1024 // 1024}MB，超过单文件备份上限 {self.max_file_mb}MB",
                advice=(
                    "确认确实需要备份它，然后在动作 YAML 里给该项加 `allow_large: true`；"
                    "或调大 config.yaml 的 backup.max_file_mb。"
                ),
            )

        # 3) 指纹 / 文件数
        if rec.kind == "file":
            h = self.transport.run(host, ["sha256sum", path], timeout=60)
            if h.exit_code == 0 and h.stdout.strip():
                rec.sha256 = h.stdout.strip().split()[0]
        else:
            # 目录：文件数 + 总字节（du -sb 给出字节数）
            cnt = self.transport.run(
                host, ["sh", "-c", f"find {shlex.quote(path)} -type f | wc -l"], timeout=120
            )
            if cnt.exit_code == 0 and cnt.stdout.strip().isdigit():
                rec.file_count = int(cnt.stdout.strip())
            du = self.transport.run(host, ["du", "-sb", path], timeout=120)
            if du.exit_code == 0 and du.stdout.strip():
                first = du.stdout.strip().split()[0]
                if first.isdigit():
                    rec.size = int(first)

        # 4) 复制到目标机备份目录（cp -a 保留权限与时间戳）
        base = posixpath.basename(path.rstrip("/")) or "root"
        target = f"{remote_dir}/{seq:02d}-{base}"
        cp = self.transport.run(host, ["cp", "-a", path, target], timeout=300)
        if cp.exit_code != 0:
            rec.status = "failed"
            rec.error = (cp.stderr or "").strip()[:300]
            return OpsError(
                code="BACKUP_FAILED",
                reason=f"备份 {path} 失败（cp -a 返回 {cp.exit_code}）",
                advice="确认目标机空间足够、目标目录可写。**本动作未执行任何变更。**",
                detail=(cp.stderr or "").strip()[:500],
            )
        rec.remote_path = target

        # 5) 回拉管理机（长期留证）。★ 失败只告警，不中止 —— 目标机那份仍然在。
        local_dir = self.cfg.paths.root / self.local_root / rec.task_id
        try:
            local_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            rec.error = f"管理机备份目录创建失败（未影响目标机）：{exc}"
            rec.status = "ok"
            return None
        ok, msg = self.transport.scp_get(host, target, local_dir, recursive=(rec.kind == "dir"))
        if ok:
            # ★ 记**真实落盘的那个名字**：scp 拉回来的是带序号前缀的 target 文件名（00-<base>），
            #   不是裸 base。以前这里写的是 base，于是 local_path 指向一个**不存在的文件** ——
            #   当前没人读这个字段所以看不出来，但"从管理机副本恢复 / 下载备份"一上就会踩空。
            #   教训：记录路径的字段，必须来自"实际写盘时用的那个变量"，而不是重新拼一遍。
            local_name = f"{seq:02d}-{base}"
            rec.local_path = str(local_dir / local_name)
        else:
            rec.error = f"回拉管理机失败（目标机备份仍在，可现场恢复）：{msg}"

        rec.status = "ok"
        return None

    # ------------------------------------------------------------------ 恢复

    def restore(self, host: Host, rec: dict[str, Any], restore_task_id: str) -> dict[str, Any]:
        """把一条备份恢复回原路径，并**逐字节自证**（规范 §9.2）。

        返回 {ok, steps: [...], conclusion, error}。恢复过程本身也是留证执行。
        """
        orig = str(rec.get("orig_path") or "")
        remote = str(rec.get("remote_path") or "")
        want = str(rec.get("sha256") or "")
        kind = str(rec.get("kind") or "file")
        steps: list[dict[str, Any]] = []

        def _step(title: str, res: Any) -> None:
            steps.append({
                "title": title,
                "command": getattr(res, "quoted", ""),
                "exit_code": getattr(res, "exit_code", None),
                "stdout": (getattr(res, "stdout", "") or "")[:2000],
                "stderr": (getattr(res, "stderr", "") or "")[:2000],
            })

        if not orig or not remote:
            return {"ok": False, "steps": steps, "conclusion": "", "error": "该备份记录缺少原路径或备份路径，无法恢复"}

        # 1) 备份还在吗
        st = self.transport.run(host, ["stat", "-c", _STAT_FMT, remote], timeout=15)
        _step("确认目标机上的备份仍在", st)
        if st.exit_code != 0:
            return {
                "ok": False, "steps": steps, "conclusion": "",
                "error": f"目标机上的备份已不存在：{remote}（可能是备份被清理）",
            }

        # 2) 恢复前校验指纹（文件才比 sha256；目录只校验存在）
        if kind == "file" and want:
            h1 = self.transport.run(host, ["sha256sum", remote], timeout=60)
            _step("校验备份文件指纹", h1)
            got = h1.stdout.strip().split()[0] if (h1.exit_code == 0 and h1.stdout.strip()) else ""
            if got != want:
                return {
                    "ok": False, "steps": steps, "conclusion": "",
                    "error": f"备份文件指纹与记录不一致（记录 {want[:16]}…，实际 {got[:16] or '空'}）",
                }

        # 3) 恢复
        #   ★★ 目录型备份必须复制**内容**、而不是复制**目录本身**（T5 修 · 规范 §9.2）：
        #     `cp -a <备份目录> <原路径>` 在"原路径已存在"时，会把源目录**塞进**目标里，
        #     于是恢复出 /etc/nginx/00-nginx/… 这种**多套一层**的结果 ——
        #     报告写着"已恢复"，实际一个文件都没还原回来。
        #     文件型备份没有这个问题（目标是个文件名），所以 T3 一直没暴露；
        #     T5 是第一次真去删一个**目录**再恢复，坑才现形。
        if kind == "dir":
            mk = self.transport.run(host, ["mkdir", "-p", orig], timeout=15)
            _step(f"确保原路径存在 {orig}", mk)
            if mk.exit_code != 0:
                return {
                    "ok": False, "steps": steps, "conclusion": "",
                    "error": f"无法创建原路径 {orig}：{(mk.stderr or '').strip()[:300]}",
                }
            cp = self.transport.run(host, ["cp", "-a", f"{remote}/.", f"{orig}/"], timeout=300)
            _step(f"恢复 {orig}（按目录的内容覆盖）", cp)
        else:
            cp = self.transport.run(host, ["cp", "-a", remote, orig], timeout=300)
            _step(f"恢复 {orig}", cp)
        if cp.exit_code != 0:
            return {
                "ok": False, "steps": steps, "conclusion": "",
                "error": f"恢复失败（cp -a 返回 {cp.exit_code}）：{(cp.stderr or '').strip()[:300]}",
            }

        # 4) 恢复后自证：逐字节比对
        conclusion = f"已从备份恢复 {orig}"
        if kind == "file" and want:
            h2 = self.transport.run(host, ["sha256sum", orig], timeout=60)
            _step("恢复后重新计算指纹", h2)
            got2 = h2.stdout.strip().split()[0] if (h2.exit_code == 0 and h2.stdout.strip()) else ""
            if got2 != want:
                return {
                    "ok": False, "steps": steps, "conclusion": "",
                    "error": f"恢复后指纹仍不一致（期望 {want[:16]}…，实际 {got2[:16] or '空'}）",
                }
            conclusion += f"，sha256 逐字节一致（{want[:16]}…）"
        elif kind == "dir":
            # ★ 目录型也要自证（T5 修 · 规范 §9.2）：
            #   原来只写"已按 cp -a 覆盖，未做逐文件指纹比对" —— 那等于**没有自证**
            #   （"成功"只是"命令返回 0"），而恰恰就是这条路上出过"多套一层"的假成功。
            #   这里比的是**逐文件指纹的汇总**：两侧都先 `cd` 进目录、用相对路径，
            #   于是路径前缀不影响摘要，同一份内容算出来的值才可比。
            #   ⚠️ 记账：本模块第二处内部管道聚合（第一处是目录文件计数，见模块头注释）。
            inner = ("cd %s && find . -type f -print0 | sort -z "
                     "| xargs -0 -r sha256sum | sha256sum")
            d1 = self.transport.run(host, ["sh", "-c", inner % shlex.quote(remote)], timeout=180)
            _step("备份目录的逐文件指纹汇总", d1)
            d2 = self.transport.run(host, ["sh", "-c", inner % shlex.quote(orig)], timeout=180)
            _step("恢复后逐文件指纹汇总", d2)
            g1 = (d1.stdout or "").strip().split()[0] if d1.stdout else ""
            g2 = (d2.stdout or "").strip().split()[0] if d2.stdout else ""
            if not g1 or g1 != g2:
                return {
                    "ok": False, "steps": steps, "conclusion": "",
                    "error": (f"恢复后逐文件指纹汇总不一致（备份 {g1[:16] or '空'}… / "
                              f"实际 {g2[:16] or '空'}…）—— 目录没有真正还原"),
                }
            conclusion += f"，逐文件指纹汇总一致（{g1[:16]}…）"
        else:
            conclusion += "（非文件/目录型备份，未做自证）"

        return {"ok": True, "steps": steps, "conclusion": conclusion, "error": None}
