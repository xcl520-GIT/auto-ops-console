"""数据层：SQLite + 原始输出归档。

验收标准 #2 要求：每次执行都落库「命令原文、起止时间、退出码、stdout/stderr」，且可回放。

留证分两处：
  · SQLite（var/ops.db）—— 结构化元数据，方便查询与界面回放
  · var/artifacts/<task_id>/ —— 原始输出原文（含 sha256），作为不可篡改的对照证据

时间统一用 config.yaml 的 timezone（Asia/Shanghai），带偏移量落库，避免"这是谁的时区"的歧义。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import AppConfig, get_tz
from app.errors import OpsError

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS tasks (
    id               TEXT PRIMARY KEY,
    action_id        TEXT NOT NULL,
    action_title     TEXT,
    risk             TEXT,
    host_id          TEXT,
    host_name        TEXT,
    host_address     TEXT,
    host_user        TEXT,
    status           TEXT,             -- ok / failed / aborted
    params_json      TEXT,
    command_preview  TEXT,             -- 计划执行的命令（执行前就确定）
    conclusion       TEXT,
    error_code       TEXT,
    error_reason     TEXT,
    error_advice     TEXT,
    verify_result    TEXT,             -- ok / warn / failed / none
    verify_detail    TEXT,
    changed          TEXT,             -- T5：true / false / unknown（规范 §12.3）
    exit_code        INTEGER,
    step_total       INTEGER,
    step_failed      INTEGER,
    started_at       TEXT,
    ended_at         TEXT,
    duration_ms      INTEGER,
    batch_id         TEXT,
    created_at       TEXT
);

CREATE TABLE IF NOT EXISTS task_steps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id      TEXT NOT NULL,
    seq          INTEGER,
    name         TEXT,
    title        TEXT,
    iter_key     TEXT,                 -- foreach 的当前项（非循环步骤为 NULL）
    argv_json    TEXT,                 -- 远端 argv（数组形式）
    argv_quoted  TEXT,                 -- 实际交给 ssh 的命令原文（留证）
    status       TEXT,                 -- ok / failed / timeout / rejected / skipped
    optional     INTEGER,
    exit_code    INTEGER,
    duration_ms  INTEGER,
    stdout       TEXT,
    stderr       TEXT,
    parsed_json  TEXT,
    truncated    INTEGER,
    error_code   TEXT,
    error_reason TEXT,
    error_advice TEXT,
    started_at   TEXT,
    ended_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_steps_task ON task_steps(task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id    TEXT NOT NULL,
    kind       TEXT,                   -- stdout / stderr / conclusion / plan
    label      TEXT,
    path       TEXT,
    sha256     TEXT,
    size       INTEGER,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_artifacts_task ON artifacts(task_id);

-- ── T3：改动前自动备份的记录（规范 §9.1）─────────────────────────────
-- 每一条 = 某个变更动作在动手前备份的**一个路径**；界面据此提供「恢复」。
CREATE TABLE IF NOT EXISTS backups (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id          TEXT NOT NULL,
    host_id          TEXT,
    host_name        TEXT,
    action_id        TEXT,
    seq              INTEGER,              -- 动作 YAML 里 backup[] 的序号
    label            TEXT,
    orig_path        TEXT,                 -- 被备份的原路径
    remote_path      TEXT,                 -- 目标机上的备份路径
    local_path       TEXT,                 -- 管理机回拉路径（回拉失败时为空）
    kind             TEXT,                 -- file / dir / missing / failed
    size             INTEGER,
    file_count       INTEGER,
    sha256           TEXT,
    mode             TEXT,
    owner            TEXT,
    status           TEXT,                 -- ok / missing / failed
    error            TEXT,
    created_at       TEXT,
    restored_at      TEXT,
    restore_task_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_backups_task ON backups(task_id);
CREATE INDEX IF NOT EXISTS idx_backups_orig ON backups(orig_path);

-- ── T5：配方执行（规范 §12）────────────────────────────────────────
-- 一次配方执行 = **一条 recipe_runs + 若干条 tasks**
--   · 每个配方步骤仍是一次普通动作任务（有独立 task_id，可单独点开回放 / 恢复）
--   · 这里只存"编排层"的事实：前置/健康判定、变更清单、检查点
CREATE TABLE IF NOT EXISTS recipe_runs (
    id               TEXT PRIMARY KEY,
    recipe_id        TEXT NOT NULL,
    recipe_title     TEXT,
    recipe_version   TEXT,
    host_id          TEXT,
    host_name        TEXT,
    host_address     TEXT,
    mode             TEXT,             -- deploy / stop / uninstall_keep / uninstall_purge
    status           TEXT,             -- ok / failed / aborted
    params_json      TEXT,
    preflight_json   TEXT,             -- 前置期望的判定结果（逐条 pass/fail/unknown）
    health_json      TEXT,             -- 健康检查的判定结果（逐条）
    steps_json       TEXT,             -- [{name,title,action,task_id,status,changed}]
    changed_json     TEXT,             -- ★ 本次变更清单（changed=true 的步骤名）
    unchanged_json   TEXT,             -- changed=false 的步骤名
    unknown_json     TEXT,             -- ★ changed=unknown 的步骤名（必须显式列出，不许混进 unchanged）
    checkpoints_json TEXT,             -- 可回滚到的检查点（备份记录 id + 说明）
    conclusion       TEXT,
    error_code       TEXT,
    error_reason     TEXT,
    error_advice     TEXT,
    started_at       TEXT,
    ended_at         TEXT,
    duration_ms      INTEGER,
    created_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_recipe_runs_created ON recipe_runs(created_at DESC);

-- ── T3：批量执行批次（规范 §9.3）────────────────────────────────────
-- 一次批量 = 一个批次；每台机器仍然是 tasks 表里的一条独立任务（batch_id 关联）。
CREATE TABLE IF NOT EXISTS batches (
    id            TEXT PRIMARY KEY,
    action_id     TEXT NOT NULL,
    action_title  TEXT,
    risk          TEXT,
    host_ids_json TEXT,
    params_json   TEXT,
    status        TEXT,                    -- ok / partial / failed
    total         INTEGER,
    ok_count      INTEGER,
    failed_count  INTEGER,
    started_at    TEXT,
    ended_at      TEXT,
    duration_ms   INTEGER,
    created_at    TEXT
);
"""


def now_iso(cfg: AppConfig) -> str:
    return datetime.now(get_tz(cfg.timezone)).isoformat(timespec="seconds")


def new_task_id(cfg: AppConfig) -> str:
    stamp = datetime.now(get_tz(cfg.timezone)).strftime("%Y%m%d-%H%M%S")
    return f"T{stamp}-{uuid.uuid4().hex[:6]}"


def new_batch_id(cfg: AppConfig) -> str:
    """批次号（T3 · 批量执行）：前缀 B 以便与任务号 T 一眼区分。"""
    stamp = datetime.now(get_tz(cfg.timezone)).strftime("%Y%m%d-%H%M%S")
    return f"B{stamp}-{uuid.uuid4().hex[:6]}"


def new_recipe_run_id(cfg: AppConfig) -> str:
    """配方执行号（T5）：前缀 R，与任务号 T / 批次号 B 一眼区分。"""
    stamp = datetime.now(get_tz(cfg.timezone)).strftime("%Y%m%d-%H%M%S")
    return f"R{stamp}-{uuid.uuid4().hex[:6]}"


def _changed_text(value: Any) -> str | None:
    """把 changed 三态落库成文本。

    ★ `None`（无法判定）**必须**落成 `'unknown'`，绝不能写成 NULL 或 'false' ——
      将来任何按 `changed='false'` 数"没变更步骤"的统计，都不该把"判不出来"算进去。
    """
    if value is None:
        return "unknown"
    return "true" if value else "false"


class Store:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self.db_path = cfg.paths.database

    # ------------------------------------------------------------------ 基础设施

    def _conn(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=10)
        except sqlite3.Error as exc:
            raise OpsError(
                code="STORE_ERROR",
                reason="无法打开本地数据库",
                advice="确认 repo/var/ 目录存在且可写、磁盘未满。",
                detail=str(exc),
            ) from exc
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        self.cfg.paths.ensure()
        try:
            with self._conn() as conn:
                conn.executescript(SCHEMA)
                # ── T3 迁移：旧库补 tasks.batch_id（新库建表时已含该列）──
                cols = {r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()}
                if "batch_id" not in cols:
                    conn.execute("ALTER TABLE tasks ADD COLUMN batch_id TEXT")
                # ── T5 迁移：旧库补 tasks.changed（新库建表时已含该列）──
                if "changed" not in cols:
                    conn.execute("ALTER TABLE tasks ADD COLUMN changed TEXT")
        except sqlite3.Error as exc:
            raise OpsError(
                code="STORE_ERROR",
                reason="数据库初始化失败",
                advice="确认 repo/var/ 可写；如数据库损坏，可删除 var/ops.db 重新初始化（历史记录会丢失）。",
                detail=str(exc),
            ) from exc

    # ------------------------------------------------------------------ 留证

    def archive(self, task_id: str, kind: str, label: str, content: str) -> dict[str, Any] | None:
        """把原始输出写到 var/artifacts/<task_id>/，并返回含 sha256 的记录。"""
        if not content:
            return None
        folder = self.cfg.paths.artifacts / task_id
        folder.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)[:80]
        path = folder / f"{kind}-{safe}.txt"
        data = content.encode("utf-8", errors="replace")
        try:
            path.write_bytes(data)
        except OSError as exc:
            raise OpsError(
                code="STORE_ERROR",
                reason=f"原始输出归档失败：{path.name}",
                advice="确认 repo/var/artifacts/ 可写、磁盘未满。",
                detail=str(exc),
            ) from exc
        return {
            "kind": kind,
            "label": label,
            "path": str(path.relative_to(self.cfg.paths.root)),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    # ------------------------------------------------------------------ 写入

    def save_task(self, task: dict[str, Any], steps: list[dict[str, Any]]) -> None:
        now = now_iso(self.cfg)
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO tasks
                (id, action_id, action_title, risk, host_id, host_name, host_address, host_user,
                 status, params_json, command_preview, conclusion, error_code, error_reason,
                 error_advice, verify_result, verify_detail, changed, exit_code,
                 step_total, step_failed,
                 started_at, ended_at, duration_ms, batch_id, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    task["id"], task["action_id"], task.get("action_title"), task.get("risk"),
                    task.get("host_id"), task.get("host_name"), task.get("host_address"),
                    task.get("host_user"), task.get("status"),
                    json.dumps(task.get("params") or {}, ensure_ascii=False),
                    task.get("command_preview"), task.get("conclusion"),
                    task.get("error_code"), task.get("error_reason"), task.get("error_advice"),
                    task.get("verify_result"),
                    json.dumps(task.get("verify_detail") or [], ensure_ascii=False),
                    _changed_text(task.get("changed")),
                    task.get("exit_code"), task.get("step_total"), task.get("step_failed"),
                    task.get("started_at"), task.get("ended_at"), task.get("duration_ms"),
                    task.get("batch_id"),
                    now,
                ),
            )
            conn.execute("DELETE FROM task_steps WHERE task_id = ?", (task["id"],))
            for s in steps:
                conn.execute(
                    """INSERT INTO task_steps
                    (task_id, seq, name, title, iter_key, argv_json, argv_quoted, status, optional,
                     exit_code, duration_ms, stdout, stderr, parsed_json, truncated,
                     error_code, error_reason, error_advice, started_at, ended_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        task["id"], s.get("seq"), s.get("name"), s.get("title"), s.get("iter_key"),
                        json.dumps(s.get("argv") or [], ensure_ascii=False),
                        s.get("argv_quoted"), s.get("status"), 1 if s.get("optional") else 0,
                        s.get("exit_code"), s.get("duration_ms"), s.get("stdout"), s.get("stderr"),
                        json.dumps(s.get("parsed"), ensure_ascii=False) if s.get("parsed") is not None else None,
                        1 if s.get("truncated") else 0,
                        s.get("error_code"), s.get("error_reason"), s.get("error_advice"),
                        s.get("started_at"), s.get("ended_at"),
                    ),
                )

    def save_artifacts(self, task_id: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        now = now_iso(self.cfg)
        with self._conn() as conn:
            for r in rows:
                conn.execute(
                    """INSERT INTO artifacts (task_id, kind, label, path, sha256, size, created_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (task_id, r["kind"], r["label"], r["path"], r["sha256"], r["size"], now),
                )

    # ------------------------------------------------------------------ 备份与批次（T3）

    def save_backups(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        now = now_iso(self.cfg)
        with self._conn() as conn:
            for r in rows:
                conn.execute(
                    """INSERT INTO backups
                    (task_id, host_id, host_name, action_id, seq, label, orig_path,
                     remote_path, local_path, kind, size, file_count, sha256, mode, owner,
                     status, error, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        r["task_id"], r.get("host_id"), r.get("host_name"), r.get("action_id"),
                        r.get("seq"), r.get("label"), r.get("orig_path"), r.get("remote_path"),
                        r.get("local_path"), r.get("kind"), r.get("size"), r.get("file_count"),
                        r.get("sha256"), r.get("mode"), r.get("owner"), r.get("status"),
                        r.get("error"), now,
                    ),
                )

    def list_backups(self, *, task_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as conn:
            if task_id:
                rows = conn.execute(
                    "SELECT * FROM backups WHERE task_id = ? ORDER BY seq", (task_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM backups ORDER BY created_at DESC, seq LIMIT ?", (int(limit),)
                ).fetchall()
        return [dict(r) for r in rows]

    def get_backup(self, backup_id: int) -> dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM backups WHERE id = ?", (int(backup_id),)).fetchone()
        if row is None:
            raise OpsError(
                code="NOT_FOUND",
                reason=f"找不到备份记录：{backup_id}",
                advice="刷新页面；该记录可能已被清理。",
            )
        return dict(row)

    def mark_restored(self, backup_id: int, restore_task_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE backups SET restored_at = ?, restore_task_id = ? WHERE id = ?",
                (now_iso(self.cfg), restore_task_id, int(backup_id)),
            )

    def save_batch(self, batch: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO batches
                (id, action_id, action_title, risk, host_ids_json, params_json, status,
                 total, ok_count, failed_count, started_at, ended_at, duration_ms, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    batch["id"], batch["action_id"], batch.get("action_title"), batch.get("risk"),
                    json.dumps(batch.get("host_ids") or [], ensure_ascii=False),
                    json.dumps(batch.get("params") or {}, ensure_ascii=False),
                    batch.get("status"), batch.get("total"), batch.get("ok_count"),
                    batch.get("failed_count"), batch.get("started_at"), batch.get("ended_at"),
                    batch.get("duration_ms"), now_iso(self.cfg),
                ),
            )

    def list_batches(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM batches ORDER BY created_at DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        with self._conn() as conn:
            b = conn.execute("SELECT * FROM batches WHERE id = ?", (batch_id,)).fetchone()
            if b is None:
                raise OpsError(
                    code="NOT_FOUND",
                    reason=f"找不到批次：{batch_id}",
                    advice="刷新页面重试。",
                )
            tasks = conn.execute(
                "SELECT * FROM tasks WHERE batch_id = ? ORDER BY host_name", (batch_id,)
            ).fetchall()
        out = dict(b)
        for key in ("host_ids_json", "params_json"):
            if out.get(key):
                try:
                    out[key] = json.loads(out[key])
                except json.JSONDecodeError:
                    pass
        return {"batch": out, "tasks": [dict(t) for t in tasks]}

    # ------------------------------------------------------------------ 配方执行（T5 · 规范 §12）

    #: recipe_runs 里需要按 JSON 解码的列
    _RUN_JSON_FIELDS = (
        "params_json", "preflight_json", "health_json", "steps_json",
        "changed_json", "unchanged_json", "unknown_json", "checkpoints_json",
    )

    #: ★★ T7·S4 补的一个**旧缺陷**（T5 起就在，真跑"回到这次部署前"时当场撞出来）：
    #:   `recipe_runs` 表里存的是 `steps_json` / `checkpoints_json` / `changed_json`…，
    #:   而 `RecipeRun.to_public()`（以及**界面**）用的是 `steps` / `checkpoints` / `changed_steps`…
    #:   ⇒ 于是"**刚跑完**的那一次"显示正常（它直接用 `to_public()` 的返回值），
    #:     而"**刷新后从历史打开**"的那一次，这些字段全是 `undefined` —— 界面上
    #:     变更清单、步骤留证、检查点**整段是空的**（`undefined.length` 还会把渲染打断）。
    #:   ★ 教训与 §9.9「Api 方法存在 ≠ 接口可用」同族：**库里的字段名 ≠ 接口的字段名**，
    #:     两套名字之间没有一层映射，就一定会有一个消费者拿不到数据 —— 而且**不报错**。
    #:   修法：解码时**同时**给出公开名（`_json` 那套原样保留，免得动到既有消费者）。
    _JSON_ALIASES = {
        "params_json": "params",
        "preflight_json": "preflight",
        "health_json": "health",
        "steps_json": "steps",
        "changed_json": "changed_steps",
        "unchanged_json": "unchanged_steps",
        "unknown_json": "unknown_steps",
        "checkpoints_json": "checkpoints",
    }

    def save_recipe_run(self, run: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO recipe_runs
                (id, recipe_id, recipe_title, recipe_version, host_id, host_name, host_address,
                 mode, status, params_json, preflight_json, health_json, steps_json,
                 changed_json, unchanged_json, unknown_json, checkpoints_json,
                 conclusion, error_code, error_reason, error_advice,
                 started_at, ended_at, duration_ms, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run["id"], run["recipe_id"], run.get("recipe_title"), run.get("recipe_version"),
                    run.get("host_id"), run.get("host_name"), run.get("host_address"),
                    run.get("mode"), run.get("status"),
                    json.dumps(run.get("params") or {}, ensure_ascii=False),
                    json.dumps(run.get("preflight") or [], ensure_ascii=False),
                    json.dumps(run.get("health") or [], ensure_ascii=False),
                    json.dumps(run.get("steps") or [], ensure_ascii=False),
                    json.dumps(run.get("changed_steps") or [], ensure_ascii=False),
                    json.dumps(run.get("unchanged_steps") or [], ensure_ascii=False),
                    json.dumps(run.get("unknown_steps") or [], ensure_ascii=False),
                    json.dumps(run.get("checkpoints") or [], ensure_ascii=False),
                    run.get("conclusion"),
                    run.get("error_code"), run.get("error_reason"), run.get("error_advice"),
                    run.get("started_at"), run.get("ended_at"), run.get("duration_ms"),
                    now_iso(self.cfg),
                ),
            )

    def list_recipe_runs(self, *, limit: int = 20, recipe_id: str | None = None) -> list[dict[str, Any]]:
        with self._conn() as conn:
            if recipe_id:
                rows = conn.execute(
                    """SELECT * FROM recipe_runs WHERE recipe_id = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (recipe_id, int(limit)),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM recipe_runs ORDER BY created_at DESC LIMIT ?", (int(limit),)
                ).fetchall()
        return [self._decode_run(dict(r)) for r in rows]

    def get_recipe_run(self, run_id: str) -> dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM recipe_runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise OpsError(
                code="NOT_FOUND",
                reason=f"找不到这次配方执行：{run_id}",
                advice="刷新页面重试；这次执行的步骤任务仍然可以在「历史」里按任务 ID 找到。",
            )
        run = self._decode_run(dict(row))
        # 把每一步对应的动作任务也带上（界面据此点开回放 / 恢复备份）
        ids = [s.get("task_id") for s in run.get("steps_json") or [] if s.get("task_id")]
        run["tasks"] = []
        if ids:
            marks = ",".join("?" for _ in ids)
            with self._conn() as conn:
                rows = conn.execute(
                    f"""SELECT id, action_id, action_title, status, changed, conclusion,
                              duration_ms, started_at FROM tasks WHERE id IN ({marks})""",
                    tuple(ids),
                ).fetchall()
            by_id = {r["id"]: dict(r) for r in rows}
            run["tasks"] = [by_id[i] for i in ids if i in by_id]
        return run

    @classmethod
    def _decode_run(cls, row: dict[str, Any]) -> dict[str, Any]:
        for key in cls._RUN_JSON_FIELDS:
            if row.get(key):
                try:
                    row[key] = json.loads(row[key])
                except json.JSONDecodeError:
                    pass
        # ★ 同时给出**公开名**（`steps` / `checkpoints` / `changed_steps`…）：
        #   界面与编排层读的都是公开名，只有"刚跑完那一次"碰巧有值 —— 见 `_JSON_ALIASES` 的说明。
        for src, public in cls._JSON_ALIASES.items():
            if src in row:
                row.setdefault(public, row[src] if row.get(src) not in (None, "") else [])
        return row

    # ------------------------------------------------------------------ 读取

    def list_tasks(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, action_id, action_title, risk, host_name, host_address, status,
                          exit_code, step_total, step_failed, verify_result,
                          started_at, ended_at, duration_ms, created_at
                   FROM tasks ORDER BY created_at DESC LIMIT ?""",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_task(self, task_id: str, *, include_raw: bool = True) -> dict[str, Any]:
        with self._conn() as conn:
            t = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if t is None:
                raise OpsError(
                    code="INTERNAL",
                    reason=f"找不到任务记录：{task_id}",
                    advice="该任务可能已被清理；在历史列表里重新选择一次。",
                )
            steps = conn.execute(
                "SELECT * FROM task_steps WHERE task_id = ? ORDER BY seq", (task_id,)
            ).fetchall()
            arts = conn.execute(
                "SELECT kind, label, path, sha256, size FROM artifacts WHERE task_id = ?", (task_id,)
            ).fetchall()

        task = dict(t)
        for key in ("params_json", "verify_detail"):
            if task.get(key):
                try:
                    task[key] = json.loads(task[key])
                except json.JSONDecodeError:
                    pass

        out_steps: list[dict[str, Any]] = []
        for s in steps:
            row = dict(s)
            if row.get("argv_json"):
                try:
                    row["argv"] = json.loads(row["argv_json"])
                except json.JSONDecodeError:
                    row["argv"] = []
            if row.get("parsed_json"):
                try:
                    row["parsed"] = json.loads(row["parsed_json"])
                except json.JSONDecodeError:
                    row["parsed"] = None
            else:
                # 显式给出 None，避免调用方靠 "parsed in row" 判断而踩 KeyError
                row["parsed"] = None
            if not include_raw:
                row.pop("stdout", None)
                row.pop("stderr", None)
            out_steps.append(row)

        return {"task": task, "steps": out_steps, "artifacts": [dict(a) for a in arts]}

    def stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            ok = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='ok'").fetchone()[0]
            failed = conn.execute("SELECT COUNT(*) FROM tasks WHERE status<>'ok'").fetchone()[0]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "db": str(self.db_path.relative_to(self.cfg.paths.root)),
            "tasks_total": total,
            "tasks_ok": ok,
            "tasks_failed": failed,
            "db_size": size,
        }
