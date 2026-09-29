"""会话即证据（规范 §12.80）：`ai_session` / `ai_turn` / `ai_tool_call` / `ai_outflow` 四张表。

```
ai_session          一次对话（谁 / 何时 / 哪个模型 / 哪个档位）
  └─ ai_turn        一轮（用户说了什么 / AI 决定调什么、为什么 / ★ conflict 标记）
       └─ ai_tool_call     一次工具调用 → ★ 挂既有 task_id（→ 原始输出 / 自证 / 备份，全部已有）
       └─ ai_outflow       外流账本（薄版）：一次发出去几条结论 / 多少 token
```

★ 四条边界：
  1. **工具调用必须挂 `task_id`** —— 这是"AI 的每句话都能回放"的唯一实现方式。
  2. **不存目标机原始输出**（A 档）。
  3. **不存 key**（§12.79）。
  4. ★ **分歧单独记** —— 因为**分歧是发现幻觉的唯一机制**（§12.73.2）。

★ 为什么单独建表而不是改 `app/store.py`：本话题的边界是"AI 侧只读，不改承重墙"（§12.71）。
  新增表是**加法**，`ops.db` 里既有的任务/步骤/备份三套表一行不动。
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_session (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  model       TEXT NOT NULL,
  provider    TEXT NOT NULL,
  tier        TEXT NOT NULL,
  title       TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ai_turn (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  role        TEXT NOT NULL,
  text        TEXT NOT NULL,
  conflict    INTEGER DEFAULT 0,
  note        TEXT DEFAULT '',
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_tool_call (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  action_id   TEXT NOT NULL,
  host_id     TEXT NOT NULL,
  task_id     TEXT DEFAULT '',
  status      TEXT DEFAULT '',
  verify      TEXT DEFAULT '',
  ok          INTEGER DEFAULT 0,
  explain     TEXT DEFAULT '',
  evidence    TEXT DEFAULT '',
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_outflow (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  tier        TEXT NOT NULL,
  actions     TEXT DEFAULT '',
  conclusion_chars INTEGER DEFAULT 0,
  prompt_tokens    INTEGER DEFAULT 0,
  completion_tokens INTEGER DEFAULT 0,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_turn_session ON ai_turn(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_ai_call_session ON ai_tool_call(session_id, seq);
-- ★ T13 新增（§12.92）：选域命中率的**本地**账本 —— ★ 它**永不外发**（断言 ⑽ 看住）
CREATE TABLE IF NOT EXISTS ai_domain_pick (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  asked       TEXT DEFAULT '',
  picked      TEXT DEFAULT '',
  fallback    INTEGER DEFAULT 0,
  reason      TEXT DEFAULT '',
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_pick_session ON ai_domain_pick(session_id, seq);
-- ★ T14·S3 新增（规范 §12.96.2）：AI 的**变更请求** —— ★★ 它**不是任务表**。
--   「请求」＝ 一条待办记录（`status=pending`）；任务**只由「人在界面点确认」之后**产生，
--   而且走的是既有的 `/api/tasks` 那条路（留证 / 护栏 / 覆盖率账本自动生效）。
--   ★ 卡片的正文整张存进 `card`（人是读它做决定的，所以它必须**可复现**，不是让人回来重算）。
CREATE TABLE IF NOT EXISTS ai_action_request (
  id          TEXT PRIMARY KEY,
  session_id  TEXT DEFAULT '',
  created_at  TEXT NOT NULL,
  action_id   TEXT NOT NULL,
  host_id     TEXT NOT NULL,
  risk        TEXT NOT NULL,
  params      TEXT DEFAULT '{}',
  reason      TEXT DEFAULT '',
  status      TEXT DEFAULT 'pending',
  card        TEXT DEFAULT '{}',
  decided_at  TEXT DEFAULT '',
  decided_by  TEXT DEFAULT '',
  task_id     TEXT DEFAULT '',
  note        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_req_status ON ai_action_request(status, created_at);
"""


class AiSessions:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            # ★ T13：给既有表**加一列**（老库没有这一列）—— 加不上就说明已经有了，忽略即可。
            #   为什么需要它：规范 §12.89 第 3 条要求"会话记录里能看出本次结论含目标机内容"。
            for stmt in (
                "ALTER TABLE ai_outflow ADD COLUMN content_note TEXT DEFAULT ''",
            ):
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ 写
    def start_session(self, model: str, provider: str, tier: str, title: str = "") -> str:
        sid = "A" + datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO ai_session (id, created_at, model, provider, tier, title) VALUES (?,?,?,?,?,?)",
                (sid, datetime.now().isoformat(timespec="seconds"), model, provider, tier, title[:120]),
            )
        return sid

    def _next_seq(self, conn: sqlite3.Connection, session_id: str) -> int:
        row = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS m FROM ai_turn WHERE session_id = ?", (session_id,)
        ).fetchone()
        return int(row["m"]) + 1

    def add_turn(
        self, session_id: str, role: str, text: str, conflict: bool = False, note: str = ""
    ) -> int:
        with self._conn() as conn:
            seq = self._next_seq(conn, session_id)
            cur = conn.execute(
                "INSERT INTO ai_turn (session_id, seq, role, text, conflict, note, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    session_id,
                    seq,
                    role,
                    text,
                    1 if conflict else 0,
                    note,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
            return int(cur.lastrowid or 0)

    def add_tool_call(
        self,
        session_id: str,
        action_id: str,
        host_id: str,
        task_id: str = "",
        status: str = "",
        verify: str = "",
        ok: bool = False,
        explain: str = "",
        evidence: str = "",
    ) -> None:
        with self._conn() as conn:
            seq = self._next_seq(conn, session_id)
            conn.execute(
                "INSERT INTO ai_tool_call (session_id, seq, action_id, host_id, task_id, status,"
                " verify, ok, explain, evidence, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id,
                    seq,
                    action_id,
                    host_id,
                    task_id,
                    status,
                    verify,
                    1 if ok else 0,
                    explain,
                    evidence,   # ★ 出处的本地留档（**不外发**，见 §12.77.1 规矩 1）
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

    def add_outflow(
        self,
        session_id: str,
        tier: str,
        actions: str,
        conclusion_chars: int,
        prompt_tokens: int,
        completion_tokens: int,
        content_note: str = "",
    ) -> None:
        with self._conn() as conn:
            seq = self._next_seq(conn, session_id)
            conn.execute(
                "INSERT INTO ai_outflow (session_id, seq, tier, actions, conclusion_chars,"
                " prompt_tokens, completion_tokens, content_note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    session_id,
                    seq,
                    tier,
                    actions,
                    conclusion_chars,
                    prompt_tokens,
                    completion_tokens,
                    content_note,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

    def add_domain_pick(
        self, session_id: str, asked: str, picked: str, fallback: bool, reason: str = ""
    ) -> None:
        """★ 选域命中率**本地**记账（§12.92）—— ★ 它**永不外发**（断言 ⑽ 看住）。"""
        with self._conn() as conn:
            seq = self._next_seq(conn, session_id)
            conn.execute(
                "INSERT INTO ai_domain_pick (session_id, seq, asked, picked, fallback, reason,"
                " created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    session_id,
                    seq,
                    asked[:200],
                    picked[:120],
                    1 if fallback else 0,
                    reason[:200],
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

    # ------------------------------------------------------------------ 读
    def hitrate(self, limit: int = 200) -> dict[str, Any]:
        """选域命中率（**只给本地看**）：样本数 / 退回全量次数 / 命中率 ＋ 最近若干条。

        ★ 这是"平台自己的账"：它帮我们回答"选域到底准不准"（T12 遗留 #6），
          而**不参与任何外发**（§12.92 规矩 2）。
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(fallback),0) AS f FROM ("
                " SELECT fallback FROM ai_domain_pick ORDER BY id DESC LIMIT ?)", (limit,)
            ).fetchone()
            rows = conn.execute(
                "SELECT id, session_id, asked, picked, fallback, reason, created_at"
                " FROM ai_domain_pick ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        n = int(row["n"] or 0)
        f = int(row["f"] or 0)
        return {
            "samples": n,
            "fallback": f,
            "hit_rate": (round(100.0 * (n - f) / n, 1) if n else None),
            "recent": [dict(r) for r in rows],
        }

    def usage(self, session_id: str) -> dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(prompt_tokens),0) AS p, COALESCE(SUM(completion_tokens),0) AS c,"
                " COUNT(*) AS n FROM ai_outflow WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            calls = conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(ok),0) AS ok FROM ai_tool_call WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            conflicts = conn.execute(
                "SELECT COUNT(*) AS n FROM ai_turn WHERE session_id = ? AND conflict = 1",
                (session_id,),
            ).fetchone()
        return {
            "outflow_calls": int(row["n"]),
            "prompt_tokens": int(row["p"]),
            "completion_tokens": int(row["c"]),
            "total_tokens": int(row["p"]) + int(row["c"]),
            "tool_calls": int(calls["n"]),
            "tool_ok": int(calls["ok"]),
            "conflicts": int(conflicts["n"]),
        }

    def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ai_session ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> dict[str, Any]:
        with self._conn() as conn:
            session = conn.execute(
                "SELECT * FROM ai_session WHERE id = ?", (session_id,)
            ).fetchone()
            turns = conn.execute(
                "SELECT * FROM ai_turn WHERE session_id = ? ORDER BY seq", (session_id,)
            ).fetchall()
            calls = conn.execute(
                "SELECT * FROM ai_tool_call WHERE session_id = ? ORDER BY seq", (session_id,)
            ).fetchall()
        return {
            "session": dict(session) if session else None,
            "turns": [dict(r) for r in turns],
            "tool_calls": [dict(r) for r in calls],
            "usage": self.usage(session_id),
        }

    # ------------------------------------------------------------------ 变更请求（T14·S3）
    # ★★ 这一节里**没有**"执行"两个字：它只写一条待办、只读回它。
    #    「请求 → 人点确认 → 执行」里的最后一步发生在 `app/api.py`（走既有 /api/tasks）。
    def add_action_request(
        self,
        session_id: str,
        action_id: str,
        host_id: str,
        risk: str,
        params: dict[str, Any],
        reason: str,
        card: dict[str, Any],
    ) -> str:
        rid = "REQ" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO ai_action_request (id, session_id, created_at, action_id, host_id,"
                " risk, params, reason, status, card) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    rid,
                    session_id or "",
                    datetime.now().isoformat(timespec="seconds"),
                    action_id,
                    host_id,
                    risk,
                    json.dumps(params, ensure_ascii=False, default=str),
                    reason[:400],
                    "pending",
                    json.dumps(card, ensure_ascii=False, default=str),
                ),
            )
        return rid

    def attach_card(self, request_id: str, card: dict[str, Any]) -> None:
        """把**带 `request_id` 的**那版卡片写回去（先落记录、后补号，见 `ActionRequests.submit`）。"""
        with self._conn() as conn:
            conn.execute(
                "UPDATE ai_action_request SET card = ? WHERE id = ?",
                (json.dumps(card, ensure_ascii=False, default=str), request_id),
            )

    #: ★ 允许更新的列（**白名单**）—— 防止"随手拼一列"把表写花。
    _REQ_UPDATABLE = ("status", "decided_at", "decided_by", "task_id", "note", "card")

    def update_action_request(self, request_id: str, **fields: Any) -> None:
        """按列名更新一条请求（★ 列名走白名单；`card` 是整张卡片的 JSON）。"""
        bad = [k for k in fields if k not in self._REQ_UPDATABLE]
        if bad:
            raise ValueError(f"ai_action_request 里不许更新这些列：{bad}")
        if not fields:
            return
        sets, vals = [], []
        for key, val in fields.items():
            if key == "card":
                val = json.dumps(val, ensure_ascii=False, default=str)
            sets.append(f"{key} = ?")
            vals.append(val)
        vals.append(request_id)
        with self._conn() as conn:
            conn.execute(f"UPDATE ai_action_request SET {', '.join(sets)} WHERE id = ?", vals)

    def list_action_requests(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, created_at, action_id, host_id, risk, status, reason,"
                " decided_at, task_id FROM ai_action_request ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_action_request(self, request_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ai_action_request WHERE id = ?", (request_id,)
            ).fetchone()
        if row is None:
            return None
        out = dict(row)
        for key in ("params", "card"):
            try:
                out[key] = json.loads(out.get(key) or "{}")
            except json.JSONDecodeError:
                out[key] = {}
        return out

    def session_action_requests(self, session_id: str, limit: int = 200) -> list[dict[str, Any]]:
        """某个会话的**变更请求**（整行，含 `card`）—— 报告要用它写"人决定了吗 / 复核怎么样"。

        ★ 与 `list_action_requests()` 的区别：那个是**待确认队列**（跨会话、只取展示要用的列）；
          这个是**按会话取全行**（`session_id` 与 `card` 都在里面）。
        """
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ai_action_request WHERE session_id = ? ORDER BY created_at",
                (session_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows[: int(limit)]:
            row = dict(r)
            for key in ("params", "card"):
                try:
                    row[key] = json.loads(row.get(key) or "{}")
                except json.JSONDecodeError:
                    row[key] = {}
            out.append(row)
        return out
    # ★★ 这一节只做**一件事**：把"结构化记录"摊平成一张**可检索的表**（规范 §12.106.1）。
    #   ★★ 它**故意不返回** `ai_turn` 里 `role='assistant'` 的文本 ——
    #      那是 AI 的**自由回答**，是**不可核的散文**；拿它当知识库 = 把幻觉检索回来当天条
    #      （§12.106.2）。★ 这条不是"文档里劝一句"，是实现层直接**不查它**（断言 Ⓔ 扫实现）。
    def knowledge_corpus(self, limit_sessions: int = 200) -> dict[str, Any]:
        """摊平最近 N 个会话的结构化记录（会话 / **人**的问句 / 工具调用 / 变更请求）。

        ★ 只**读**，不写；★ 不含 AI 的回答正文（§12.106.2）。
        ★ 返回里带 `scanned` 计数 —— 命中不到时要**如实交代查了多少行**（§12.106.3）。
        """
        with self._conn() as conn:
            sess = conn.execute(
                "SELECT id, created_at, title, model, provider, tier FROM ai_session"
                " ORDER BY created_at DESC LIMIT ?",
                (int(limit_sessions),),
            ).fetchall()
            ids = [str(r["id"]) for r in sess]
            turns: list[Any] = []
            calls: list[Any] = []
            reqs: list[Any] = []
            for chunk in _chunks(ids, 400):
                marks = ",".join("?" for _ in chunk)
                # ★ role='user' **写死在 SQL 里** —— 见本节开头那段注释
                turns += conn.execute(
                    f"SELECT session_id, seq, text, created_at FROM ai_turn"
                    f" WHERE role = 'user' AND session_id IN ({marks})",
                    chunk,
                ).fetchall()
                calls += conn.execute(
                    f"SELECT session_id, seq, action_id, host_id, task_id, status, explain,"
                    f" created_at FROM ai_tool_call WHERE session_id IN ({marks})",
                    chunk,
                ).fetchall()
                reqs += conn.execute(
                    f"SELECT id, session_id, created_at, action_id, host_id, status, reason, task_id"
                    f" FROM ai_action_request WHERE session_id IN ({marks})",
                    chunk,
                ).fetchall()

        rows: list[dict[str, Any]] = []
        for r in sess:
            rows.append({
                "kind": "session", "session_id": r["id"], "seq": 0, "at": r["created_at"],
                "host_id": "", "action_id": "", "task_id": "", "status": "",
                "text": str(r["title"] or ""),
            })
        for r in turns:
            rows.append({
                "kind": "ask", "session_id": r["session_id"], "seq": int(r["seq"]),
                "at": r["created_at"], "host_id": "", "action_id": "", "task_id": "",
                "status": "", "text": str(r["text"] or ""),
            })
        for r in calls:
            rows.append({
                "kind": "call", "session_id": r["session_id"], "seq": int(r["seq"]),
                "at": r["created_at"], "host_id": str(r["host_id"] or ""),
                "action_id": str(r["action_id"] or ""), "task_id": str(r["task_id"] or ""),
                "status": str(r["status"] or ""), "text": str(r["explain"] or ""),
            })
        for r in reqs:
            rows.append({
                "kind": "request", "session_id": r["session_id"], "seq": 0,
                "at": r["created_at"], "host_id": str(r["host_id"] or ""),
                "action_id": str(r["action_id"] or ""), "task_id": str(r["task_id"] or ""),
                "status": str(r["status"] or ""), "text": str(r["reason"] or ""),
                # ★ 请求的"行号"用它自己的 id（界面上认得出）
                "ref": str(r["id"] or ""),
            })
        return {
            "rows": rows,
            "scanned": {
                "sessions": len(sess),
                "session_rows": len(sess),
                "ask_rows": len(turns),
                "call_rows": len(calls),
                "request_rows": len(reqs),
            },
            # ★★ 语料边界的**自述**：拿它去回答"你都查了哪些表"
            "sources": [
                "ai_session.title（会话标题 ≈ 首轮问题）",
                "ai_turn（★ 只取 role='user'，人的原话）",
                "ai_tool_call（动作 / 主机 / 状态 / 失败解释 / 任务号）",
                "ai_action_request（变更请求的动作 / 理由 / 状态）",
                "tasks（动作 / 主机 / 状态 / 结论 —— 由调用方并入）",
            ],
            "excluded": (
                "★ 明确排除：`ai_turn` 里 `role='assistant'` 的文本"
                "（AI 的自由回答 = 不可核的散文，§12.106.2）"
            ),
        }


def _chunks(items: list[str], size: int) -> list[list[str]]:
    """把 id 列表切成小块（SQLite 的占位符数量有上限，别一次塞几百个）。"""
    return [items[i:i + size] for i in range(0, len(items), size)] or []
