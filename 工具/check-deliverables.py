# -*- coding: utf-8 -*-
"""交付包校验（可复跑）

用法：
    python 工具\\check-deliverables.py                 # 全部检查
    python 工具\\check-deliverables.py --with-ledger   # 额外拉一次 /api/coverage 做数字对账

它检查七件事（★ 每一件都有"写坏了会红"的判据）：

  ① **交付物齐全**：根 README / 工程方法 / 技术实现 / CHANGELOG / LICENSE / docs\\screenshots / 工具
  ② **引用可点开**：交付物文档里点名的路径**真实存在**（`证据\\` 前缀按真实证据目录解析）
  ③ **截图与文字快照成对**：截图 ≥8 张，且**文字快照存在**（★ 图不可核、文本可逐字对）
  ④ **措辞黑名单**：公开面向文件里 0 命中（工作流词 + 自夸形容词）
  ⑤ **未跑通自查表**：交付记录里那张表存在，且**没有"无证据"的行**
  ⑥ **改动范围可审**（★ 语义自 T12 起改）：对照最新开工基线，列出 `repo\\app\\` + `repo\\web\\` 的改动；
     ★ **只有"文件被删掉"才判红**（T12 故意改了平台代码 ⇒ 旧判据"逐字节不变"会**永远红**，而永远红 = 没有检查）
  ⑦ **敏感物扫描**：工作区里没有凭据 / 私钥 / 运行期数据库被纳入版本控制

★ 豁免与豁免理由都写在代码里（`EXEMPT_PATTERNS`）—— 依据：本项目的纪律「豁免也要写明理由」。
"""
from __future__ import annotations

import glob as glob_module
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ROOT = Path(__file__).resolve().parent.parent            # 项目根 = 仓库根
REPO = ROOT / "repo"
EVID = REPO / "var" / "artifacts" / "_manual-对照证据"
SHOTS = ROOT / "docs" / "screenshots"

PUBLIC_DOCS = ["README.md", "工程方法.md", "技术实现.md", "CHANGELOG.md",
               "docs/screenshots/README.md", "repo/README.md"]
CHECK_DOCS = PUBLIC_DOCS + ["开发记录/演示手册.md"]

BLACKLIST = ["交接", "新话题", "工作流", "高质量", "优雅", "极致", "完美", "业界领先"]

# ★ 豁免：不是"路径引用"而是"命令 / 命名规律说明"的写法（理由必须写出来）
EXEMPT_PATTERNS = [
    r"^\d+-",                       # 截图编号
    r"^<",                          # 形如 <你的路径> / <名称> 的占位
    r"^[A-Za-z]:\\",                # 绝对路径（换机器即失效，不参与存在性判定）
    r"^(pkg|ls|du|df|cat|grep|wc|stat|find|kubeadm|kubectl|systemctl|dnf|rpm|ssh|scp)\b",
    r"\s",                          # ★ 含空格的写法 = **命令行**（如 `python tools\selftest.py`），不是路径
    r"^/",                          # ★ 以 `/` 开头 = **远端路径或接口路径**（`/api/**`、`/opt/aoc-*`、`/proc/*`），本机不判定
    r"[<>]",                        # ★ 含尖括号 = **占位符**（如 `catalog\actions\<域>.<动作名>.yaml`）
    r"\.(json|txt|png|log)$",       # 运行期产物（在 .gitignore 里，换机器需重跑）
    r"^_",                          # 私有/临时文件
    # ★ Windows **环境变量式的 glob**（`%LOCALAPPDATA%\Programs\Python\Python3*` /
    #   `%ProgramFiles%\Python3*`）：它说的是"解释器**可能**装在哪"，**不是本仓库的路径** ——
    #   本机（或换一台机器）没有那个目录，就必然"glob 无匹配"。
    #   ★ T18 收尾实测到的误判：CHANGELOG 里描述「六层解释器探测」的那句话被这条规则
    #     判成"引用了不存在的路径"⇒ 交付物校验 9/10。豁免的是**写法**，不是那条事实。
    r"%[A-Za-z_]+%",
    # ★★ `var\` 底下的东西（留证归档 / 运行期数据 / 本地留档）：**本来就不在 Git 里** ——
    #   "引用可点开"这条规矩对它们**不适用**（克隆下来必然没有，换台机器也必然没有）。
    #   ★ 触发这次豁免的现场：CHANGELOG 里引用了**本地留档目录**（脱敏前原文＋sha256 清单，
    #     有意不入 Git），路径里的省略号被当成了"点名的路径" ⇒ 交付物校验 11/12。
    #   ★ 豁免的是**这一条规矩的适用范围**，不是某一句文案。
    r"var[\\/]",
]

RESULTS: list[tuple[str, bool, str]] = []


def rec(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print("  %s %s%s" % ("OK " if ok else "!! ", name, ("    " + detail) if detail else ""))


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def check_bundle() -> None:
    print("\n① 交付物齐全")
    need = ["README.md", "工程方法.md", "技术实现.md", "CHANGELOG.md", "LICENSE",
            "docs/screenshots", "工具", "repo"]
    lack = [n for n in need if not (ROOT / n).exists()]
    rec("交付包七件套 + 工具 + repo", not lack,
        ("缺：" + "、".join(lack)) if lack else "齐全：%s" % "、".join(need))
    ev = [n for n in ["README.md", "界面-结论原文-20260927.md"] if not (SHOTS / n).exists()] if SHOTS.is_dir() else ["docs/screenshots/"]
    rec("docs/screenshots 里有中文说明与结论原文", not ev,
        ("缺：" + "、".join(ev)) if ev else "与截图成对")


def _resolve(ref: str) -> Path | None:
    r = ref.strip().strip("`")
    if not r:
        return None
    if any(re.search(p, r) for p in EXEMPT_PATTERNS):
        return None
    r = r.replace("`", "")
    if r.startswith("证据\\") or r.startswith("证据/"):
        r = str(EVID) + "\\" + re.sub(r"^证据[\\/]", "", r)
    r = r.replace("/", "\\")
    # T? 只出现在"命名规律"的写法里 ⇒ 变成通配
    r = r.replace("T?", "T*").replace("T*-", "T*")
    # ★ 两种基准都试：项目根（交付文档的写法）与 repo\\（控制台文档的写法）
    for base in (ROOT, REPO):
        p = base / r
        if p.exists() or "*" in r:
            if "*" in str(p) and not glob_module.glob(str(p)):
                continue
            return p
    return ROOT / r


def check_refs() -> None:
    print("\n② 引用可点开（交付物文档里点名的路径真实存在）")
    bad, total, exempt = [], 0, 0
    pat = re.compile(r"`([^`\n]{3,120})`")
    for rel in CHECK_DOCS:
        p = ROOT / rel
        if not p.is_file():
            continue
        for m in pat.finditer(read(p)):
            ref = m.group(1)
            if "\\" not in ref and "/" not in ref:
                continue
            if not re.search(r"\.(md|py|yaml|yml|json|png|txt)$|\*|\\$", ref):
                continue
            resolved = _resolve(ref)
            if resolved is None:
                exempt += 1
                continue
            total += 1
            s = str(resolved)
            if "*" in s:
                # ★ 用 glob 模块（它认绝对路径与反斜杠）；pathlib 的 glob 只吃相对模式
                if not glob_module.glob(s):
                    bad.append("%s → %s（glob 无匹配）" % (rel, ref))
            elif not resolved.exists():
                bad.append("%s → %s" % (rel, ref))
    rec("交付物里点名的路径都存在（%d 条引用 · %d 条豁免）" % (total, exempt),
        not bad, "；".join(bad[:6]) if bad else "全部可点开")


def check_shots() -> None:
    print("\n③ 截图与文字快照成对")
    pngs = sorted(SHOTS.glob("*.png")) if SHOTS.is_dir() else []
    # ★★ 2026-09-29（开源脱敏批 · 规范 §12.158）：**截图不入 Git**。
    #   为什么：截图是**图片** —— 里面的地址与主机名是**像素**，不是字节；文本脱敏器
    #   （以及本文件那些扫描）**看不见它们**，而又没有可信的机械脱敏法。
    #   ⇒ 公开仓库只带**文字快照**（可逐字比对、可机械脱敏）；截图由读者**自己生成**：
    #     `工具\capture-screenshots.py`。★ 本地那 12 张**留在磁盘上**，只是不提交。
    #   ★ 这条判据因此从"≥8 张"改成"**要么有截图；要么没有截图但生成器在**"——
    #     不是放松：**本地**照样有那 8+ 张（它们只是**不入 Git**）。
    gen = ROOT / "工具" / "capture-screenshots.py"
    rec("截图 ≥ 8 张（实际 %d）**或**没有截图但**生成器在**（公开版不带截图）"
        % len(pngs), len(pngs) >= 8 or gen.is_file(),
        "、".join(p.name for p in pngs[:10]) if pngs else "无截图；生成器在：%s" % gen.name)
    snaps = sorted(SHOTS.glob("界面-结论原文-*.md")) if SHOTS.is_dir() else []
    rec("文字快照 ≥ 1 份（★ 机器可核的那一半）", bool(snaps),
        "、".join(s.name for s in snaps) or "缺：跑 python 工具\\capture-screenshots.py")


def check_words() -> None:
    print("\n④ 措辞黑名单（★ 只扫公开面向文件）")
    hits, n = [], 0
    for rel in PUBLIC_DOCS:
        p = ROOT / rel
        if not p.is_file():
            continue
        n += 1
        tx = read(p)
        hits += ["%s 命中「%s」" % (rel, w) for w in BLACKLIST if w in tx]
    rec("%d 个公开面向文件 × %d 个词 · 0 命中" % (n, len(BLACKLIST)), not hits,
        "；".join(hits) if hits else "干净")


def check_unverified_table() -> None:
    print("\n⑤ 未跑通自查表（交付记录里那张表）")
    cands = sorted((ROOT / "开发记录" / "交接").glob("T11-*结题回执.md"))
    if not cands:
        rec("T11 结题回执存在", False, "还没写")
        return
    tx = read(cands[0])
    has_table = ("未跑通" in tx) or ("无证据" in tx)
    rec("交付记录里有「未跑通自查表」", has_table, cands[0].name)
    # ★ 判据：凡是**标了"无证据"的行**，最后一列（处置）必须有内容 ——
    #   只有"❌ 无证据"却**不写怎么处置**的，才算不合格。
    #   （★ 第一版判据写成"不含'已删'就算未处置"，把"已写明处置"的两行误判成不合格 ——
    #     与 T10 ⑬「看门狗自己也会咬错人」同一张脸：**匹配规则太糙**。改规则，不放宽标准。）
    EMPTY = {"", "❌ **无证据**", "❌ 无证据", "**无证据**", "无证据", "❌", "—", "-"}
    bad_rows = []
    for ln in tx.splitlines():
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) < 3 or not any("无证据" in c for c in cells):
            continue
        if cells[-1] in EMPTY:
            bad_rows.append(ln[:90])
    rec("标了「无证据」的每一行都写了**处置**（不是只标不办）", not bad_rows,
        "；".join(bad_rows[:3]) if bad_rows else "全部有处置")


def check_code_freeze() -> None:
    """★ T12 起改语义：从「**零改动**」改成「**改动范围可审**」。

    为什么必须改：**「零改动」是 T11 那一版的承诺，不是永久约束** ——
    T12（AI 助手基座）**故意改了** `app\\` 与 `web\\`。若继续拿 T11 的基线判"逐字节不变"，
    这个检查会**永远红**；而"永远红"等于**没有检查**（它不再传递任何信息，还会训练人忽略它）。
    ⇒ 现在的判据：对照**最新的** `T*-S0-code-hash-baseline.txt`，**列出改动（信息）**，
      **只在两种情况下判红**：① 找不到基线；② ★ **有文件被删掉**（改动是有意的，**删除才可疑**）。
    """
    print("\n⑥ 改动范围可审（对照最新的开工基线；★ 语义自 T12 起由「零改动」改为「改动可审」）")
    cands = sorted(EVID.glob("T*-S0-code-hash-baseline.txt"))
    if not cands:
        rec("找到哈希基线", False, str(EVID))
        return
    base = cands[-1]
    # ★★ T15·S10 修：这个判据**从 T13 起就"永远红"**了 —— 因为**基线文件换了格式**，
    #    而这里没跟着改：T11 的基线是「<64 位哈希>  repo\app\…」（两列）；
    #    T13/T14 的基线变成「<12 位短哈希>  <大小>  <路径>」（**三列**，且**不带 `repo\` 前缀**）。
    #    ⇒ 旧解析把「大小 + 路径」整段当成路径 ⇒ 与现状**一个键都对不上** ⇒
    #      改动永远 0、新增 38、**删除 28 ⇒ 永远红**。
    #    ★ 一个**永远红**的判据 = 一个**会被忽略**的判据（比没有判据更糟：它占着"有人看着"的位置）。
    #    ⇒ 改成：**两种格式都认**（正则：首列哈希 ＋ 末段路径）＋ **归一掉 `repo\` 前缀**
    #      ＋ 比较时用**前缀匹配**（基线存短哈希，现状是全长 sha256）。
    want = {}
    for ln in read(base).lstrip("\ufeff").splitlines():     # ★ 基线文件带 BOM（Out-File 写的），先剥掉
        ln = ln.rstrip()
        if not ln or ln.startswith(("=", "#", "HEAD")) or "：" in ln:
            continue                                        # ★ T13 起的基线里混进了表头 / 说明行
        m = re.match(r"^([0-9A-Fa-f]{8,})\s+(?:\d+\s+)?(\S.*)$", ln)
        if not m:
            continue
        h, rel = m.group(1).casefold(), m.group(2).strip().replace("/", "\\").lstrip("\\")
        if rel.casefold().startswith("repo\\"):             # ★ 各版前缀不一致，归一
            rel = rel[5:]
        want[rel.casefold()] = h
    now = {}
    # ★★ 另一半同样的病：**扫描范围比基线窄** ⇒ 基线里那些"不在 app/ + web/ 下的条目"
    #    会被一律判成**"删除"**（`catalog\ai-tools.json` · `config.yaml` · `docs\动作规范.md` ·
    #    `hosts.yaml` · `tools\ai-ask.py` … 它们**一直在**）⇒ 于是**还是永远红**。
    #    ⇒ 扫描范围改成 **`app` / `web` ∪ 基线里出现过的顶层目录 / 顶层文件**。
    scope = {"app", "web"} | {k.split("\\", 1)[0] for k in want if k}
    for d in sorted(scope):
        p = REPO / d
        if p.is_file():                                     # ★ 顶层文件（config.yaml / hosts.yaml）
            now[d.replace("/", "\\").casefold()] = \
                hashlib.sha256(p.read_bytes()).hexdigest().casefold()
            continue
        if not p.is_dir():
            continue
        for f in sorted(p.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                now[str(f.relative_to(REPO)).replace("/", "\\").casefold()] = \
                    hashlib.sha256(f.read_bytes()).hexdigest().casefold()
    changed = [k for k in sorted(set(want) & set(now)) if not now[k].startswith(want[k])]
    added = [k for k in sorted(set(now) - set(want))]
    removed = [k for k in sorted(set(want) - set(now))]
    detail = ("改动：" + ("、".join(changed[:5]) or "无")
              + " ｜ 新增：" + ("、".join(added[:5]) or "无")
              + " ｜ 删除：" + ("、".join(removed[:5]) or "无"))
    rec("对照 %s → 改动 %d · 新增 %d · 删除 %d（★ 只有「删除」判红）"
        % (base.name, len(changed), len(added), len(removed)),
        not removed, detail)


def check_sensitive() -> None:
    print("\n⑦ 敏感物扫描")
    tracked = subprocess.run(["git", "ls-files"], cwd=str(ROOT), capture_output=True, text=True,
                             encoding="utf-8", errors="replace").stdout.splitlines()
    bad = [f for f in tracked
           if re.search(r"(CREDENTIALS.*\.md|\.key$|\.pem$|(^|/)id_[a-z0-9]+$|known_hosts|"
                        r"authorized_keys|(^|/)\.env$|(^|/)ops\.db$|(^|/)var/backups/)", f)]
    rec("版本控制里没有凭据 / 私钥 / 运行期数据库（%d 个受跟踪文件）" % len(tracked), not bad,
        "；".join(bad[:6]) if bad else "干净")

    # ══════════════════════════════════════════════ ★★ 2026-09-29：**拓扑残留扫描**
    # ★ 为什么要有这一条：仓库要**公开**（脱敏后开源）。"脱敏"如果只靠人记得做一次，
    #   下次改个默认值、贴一段真跑输出，就**悄悄漏回去**了 —— 所以把它变成**判据**。
    # 分界线（与 `repo\docs\动作规范.md` §12.158 同一套）：
    #   · **要占位**：主机名 / 主机地址 / 宿主与网关地址 / 夹具地址 / 网卡 MAC / 本机目录 / VM 名。
    #   · **豁免（写明理由）**：**网段口径** —— 上游默认值与协议口径，不含主机身份；
    #     改掉反而会把帮助文本里「为什么刻意这么设」的依据写假。
    allow_reasons = {
        "10.244.0.0/16": "k8s Pod 网段 / Calico IPPool 默认值",
        "10.96.0.0/12": "kubeadm Service 默认值（帮助文本里作对照）",
        "10.10.0.0/12": "本集群 Service 口径（帮助文本解释了为什么这么设）",
        "192.168.0.0/16": "Calico 官方默认值（帮助文本里作对照）",
        "127.0.0.1": "本机回环（绑定地址红线，判据要引用它）",
        "0.0.0.0": "通配绑定（被白名单明确拒绝，判据要引用它）",
    }
    topo_rules = [
        ("私网地址(RFC1918)",
         re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
                    r"\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b")),
        ("主机名/VM 名",
         re.compile(r"(?:k8s-master01|k8s-node0[12]|docker1\b|monitor-02|7\.24-60|学习原型机)")),
        # ★ 允许 1~2 个反斜杠：源码里同一条路径会写成**转义形式**（`E:\\xuniji\\…`）——
        #   只写单反斜杠那一版**漏过 7 处**（实测，正是这条判据自己抓出来的）。
        ("本机目录",
         re.compile(r"[A-Za-z]:[\\/]{1,2}(?:vmware-1|xuniji|pythoncode)")),
        ("网卡 MAC", re.compile(r"00:0c:29:be:e7:d9")),
        ("话术式通配地址",
         re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
                    r"\.\d{1,3}(?:\.\d{1,3})?\.(?:x|X)\b")),
    ]
    # ★★ 自豁免（写明理由）：**这个文件本身**就是这些字面量的**定义处** ——
    #   要求"它自己不许出现这些字面量"等于要求这条判据不存在。
    #   豁免的是**定义**，不是被测物；别处一律不豁免。
    SELF = "工具/check-deliverables.py"
    leaks = {}
    for f in tracked:
        if f == SELF:
            continue
        p = ROOT / f
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, rx in topo_rules:
            for m in rx.findall(txt):
                if m in allow_reasons:
                    continue
                leaks.setdefault(name, []).append("%s:%s" % (f, m))
    rec("受跟踪文件里**没有本机标识**（私网地址/主机名/VM 名/本机目录/MAC）"
        "—— 这是「脱敏后公开」的判据（§12.158 / 清单 292）",
        not leaks,
        ("；".join("%s %s" % (k, "、".join(sorted(set(v))[:3])) for k, v in leaks.items()))
        if leaks else
        "干净（豁免 %d 条网段口径：%s）" % (len(allow_reasons), "、".join(allow_reasons)))

    # ★★ 同一条规矩的**第二半**：**截图不入 Git** —— 图片里的地址/主机名是**像素**，
    #    上面的字节扫描看不见它 ⇒ 只能靠"它压根不在库里"来保证（规范 §12.158）。
    shots = [f for f in tracked
             if f.startswith("docs/screenshots/") and f.lower().endswith(".png")]
    rec("截图**不入 Git**（★ 图片无法机械脱敏；公开版只带文字快照）",
        not shots, "；".join(shots[:4]) if shots else "干净（截图留在本地，读者自己生成）")


def check_ledger() -> None:
    print("\n⑧ 账本对账（需要控制台在跑，且已过鉴权门）")
    sys.path.insert(0, str(ROOT / "repo" / "tools"))
    try:
        from console_client import AuthFailed, ConsoleClient  # noqa: PLC0415
        d = ConsoleClient().get_data("/api/coverage")["coverage"]
    except AuthFailed as exc:  # ★ T14：控制台有鉴权了 —— 过不了门要说清"该设哪个环境变量"
        rec("拿到 /api/coverage（★ T14 起要过鉴权门）", False,
            "%s ｜ 设 AOC_CONSOLE_PASSWORD 后重试" % str(exc).splitlines()[0][:160])
        return
    except Exception as exc:  # noqa: BLE001
        rec("拿到 /api/coverage", False, "%s（先起控制台）" % exc)
        return
    w = d["weighted"]
    facts = {
        "条数": "%d/%d" % (d["done"], d["total"]),
        "加权": "%d/%d" % (w["w_done"], w["w_all"]),
        "platform": "%d/%d" % (w["platform_done"], w["platform_total"]),
        "条目": "%d/%d" % (w["items_done"], w["items_total"]),
    }
    readme = read(ROOT / "README.md")
    miss = [k for k, v in facts.items() if v not in readme]
    rec("根 README 的覆盖率数字与账本一致", not miss,
        "；".join("缺 %s=%s" % (k, facts[k]) for k in miss) if miss else " ｜ ".join(
            "%s %s" % (k, v) for k, v in facts.items()))


def main() -> int:
    print("=" * 72)
    print("  auto-ops-console · 交付包校验")
    print("  项目根：%s" % ROOT)
    print("=" * 72)
    check_bundle()
    check_refs()
    check_shots()
    check_words()
    check_unverified_table()
    check_code_freeze()
    check_sensitive()
    if "--with-ledger" in sys.argv:
        check_ledger()

    ok = sum(1 for _, o, _ in RESULTS if o)
    bad = [(n, d) for n, o, d in RESULTS if not o]
    print("\n" + "=" * 72)
    print("  结果：通过 %d / 共 %d　失败 %d" % (ok, len(RESULTS), len(bad)))
    for n, d in bad:
        print("    !! %s    %s" % (n, d))
    print("=" * 72)
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
