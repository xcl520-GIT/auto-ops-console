"""T17/T18：把一台机器**登记 / 注销**进 `hosts.yaml`（规范 §12.131）—— 与 `tools\\vmprobe.py` 同一个形态。

★ 为什么登记要单独做一个工具：`hosts.yaml` 是**平台自己的配置文件**，
  而"自动纳管"的最后一步就是把它写上。规范要求写入必须三件齐：
    ① **写前备份** ② **逐字节可回退** ③ **对外可见**（界面上看得见改了什么）。
  ⇒ 这个脚本把三件事一起做掉，并把"改之前/改之后"的 sha256 打进输出（留证）。

★ 三条硬纪律：
  · **不覆盖**：id 已存在就**绝不**改写（§12.130 第 4 条同源：覆盖比失败严重得多）；
  · **不改别人的东西**：只在 hosts 列表末尾插一段，**不通篇重排**、不丢注释；
  · ★ 不用 YAML 库"读出来再 dump 回去"——那会把文件里的注释与排版全部抹掉。
    用的是**文本插入**（在「已退役」那一段之前插），并在插入前后各算一次 sha256。

退出码：
    0 = 成功（新增登记 / 只改了地址 / ★ **已达终态**——后者由 JSON 里的 `already: true` 如实区分）
    2 = 读不到 / 写不了 / 发现"id 已存在但内容不一致"（★ 这要人来定，不许静默覆盖）

★★ 为什么"已达终态"**不用退出码 3** 表达（T17·S5 真跑修正）：
  平台的**本地通道**在 `app/engine.py::_to_step_out` 里先判
  `host.transport == "local" and res.exit_code not in (None, 0)` ⇒ **非零一律算失败**，
  `ok_exit_codes` 在这条通道上不生效。⇒ 本地通道的状态只能"回 0 ＋ JSON 里说清"。
  ★ 判据本身没变弱：它仍然是**逐字比对 hosts.yaml**，只是"没变"这个结论由 JSON 承载。
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HOSTS = ROOT / "hosts.yaml"
BACKUP_DIR = ROOT / "var" / "backups"
RETIRED_MARKERS = ("# ── 已退役", "# ── 已退休", "# ── 已注销")
ID_RE = re.compile(r"^\s*-\s*id:\s*(\S+)\s*$")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _blocks(text: str) -> dict[str, str]:
    """把 hosts 列表切成 {id: 该条目的原文}（用于"内容一致吗"的对照）。"""
    lines = text.splitlines(keepends=True)
    out: dict[str, str] = {}
    cur_id, buf = "", []
    for ln in lines:
        m = ID_RE.match(ln)
        if m:
            if cur_id:
                out[cur_id] = "".join(buf)
            cur_id, buf = m.group(1), [ln]
            continue
        if cur_id:
            if ln.startswith("  -") or ln.startswith("#") or ln.startswith("-"):
                out[cur_id] = "".join(buf)
                cur_id, buf = "", []
            else:
                buf.append(ln)
    if cur_id:
        out[cur_id] = "".join(buf)
    return out


def build_block(a: argparse.Namespace) -> str:
    tags = a.tags or "Rocky, 造机, T17"
    name = a.name or f"{a.id}（克隆靶机）"
    role = a.role or "cloned-target"
    note = (
        f"{datetime.now().strftime('%Y-%m-%d')} 由平台克隆自母机「{a.from_mother}」"
        f"（配方 vm-provision）；身份四项已逐项重置（machine-id / SSH host key / 主机名 / 静态 IP），"
        f"第 5 项（VMware UUID·MAC）见 `vm.vmx-read` 的对照证据。"
        f"★ 静态地址来源：平台只读扫描未用地址后选定（规范 §12.132）。"
    )
    return (
        f"  - id: {a.id}\n"
        f"    name: {name}\n"
        f"    address: {a.address}\n"
        f"    port: 22\n"
        f"    user: {a.user}\n"
        f"    auth: key\n"
        f"    identity_file: ~/.ssh/id_ed25519\n"
        f"    role: {role}\n"
        f"    tags: [{tags}]\n"
        f"    # ★★ T17（规范 §12.116 / §12.131）：虚拟化登记 —— 「哪些 VM 归本项目管」的**唯一来源**。\n"
        f"    #    ★ 不许靠「id == 目录名」的巧合（实测 docker-01 的 vmx 叫 vm-docker-01.vmx）。\n"
        f"    vm:\n"
        f"      provider: vmware-workstation\n"
        f"      vmx: {a.vmx}\n"
        f"    note: >\n"
        f"      {note}\n"
    )


def do_register(a: argparse.Namespace) -> tuple[int, dict]:
    if not HOSTS.is_file():
        return 2, {"error": "HOSTS_MISSING", "reason": f"找不到 {HOSTS}"}
    raw = HOSTS.read_bytes()
    before_sha = sha(raw)
    text = raw.decode("utf-8")
    blocks = _blocks(text)

    if a.id in blocks:
        blk = blocks[a.id]
        same = (f"address: {a.address}" in blk) and (a.vmx in blk)
        if same:
            # ★★ T17·S5 真跑修正：**"已达终态"回 0，不回 3**。
            #   原因：平台的**本地通道**在 `engine.py::_to_step_out` 里先判
            #   `host.transport == "local" and res.exit_code not in (None, 0)` ⇒ **非零即失败**，
            #   `ok_exit_codes` 在这条通道上**不生效**（那是 ssh 通道那一支的准绳）。
            #   ⇒ 本地通道要用"是否变更"表达状态，只能**回 0 ＋ 在 JSON 里如实说清**
            #     （`written` / `already`）—— 而 `changed` 规则读的就是这两个字段。
            #   ★ 这条与"退出码就是结论"不冲突：判据仍然是**逐字比对 hosts.yaml**，
            #     只是"没变"这个结论由 JSON 承载，而不是由退出码承载。
            return 0, {
                "checked": "hosts.yaml 文本对照（id + address + vmx）",
                "id": a.id, "already": True, "written": False,
                "hosts_sha256": before_sha,
                "verdict": "already（已达终态：id 已在，且 address 与 vmx 都对得上）",
            }
        # ★ T17·S5：**只有显式 `--update-mode address` 才允许**改地址那一行（其余不动）
        if a.update_mode == "address" and (a.vmx in blk):
            old_line = re.search(r"^\s*address:\s*\S+\s*$", blk, re.M)
            if not old_line:
                return 2, {"error": "REGISTER_CONFLICT",
                           "reason": f"hosts.yaml 里 id={a.id} 那一条找不到 `address:` 行",
                           "advice": "人工看一眼那一条的写法（本工具的改地址只认 `address: <值>` 这一行）。",
                           "id": a.id, "hosts_sha256": before_sha}
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = BACKUP_DIR / f"hosts.yaml.{stamp}.bak"
            backup.write_bytes(raw)
            new_block = blk[:old_line.start()] + f"    address: {a.address}\n" + blk[old_line.end():]
            new_text = text.replace(blk, new_block, 1)
            HOSTS.write_bytes(new_text.encode("utf-8"))
            return 0, {
                "checked": "只改 id 那一块的 `address:` 一行（其余逐字节不动）＋ 前后各算 sha256",
                "id": a.id, "written": True, "already": False, "updated": "address",
                "address_old": old_line.group(0).strip().split(":", 1)[1].strip(),
                "address_new": a.address,
                "hosts_sha256_before": before_sha,
                "hosts_sha256_after": sha(HOSTS.read_bytes()),
                "backup": str(backup),
                "backup_sha256": sha(backup.read_bytes()),
                "vmx": a.vmx,
                "verdict": "written（只改了地址那一行）",
                "revert": f"python tools\\host_register.py --revert \"{backup}\"",
            }
        return 2, {
            "error": "REGISTER_CONFLICT",
            "reason": f"hosts.yaml 里已经有 id={a.id}，而它的 address / vmx 与本次不一致",
            "advice": ("★ 拒绝**静默覆盖**（覆盖比失败严重得多）：请人工确认该改谁 —— "
                       "改 `hosts.yaml` 的那一条，或换一个 id 再跑；"
                       "★ 若**确实**是「地址按计划变了」，用 `--update-mode address`（只改地址那一行）。"),
            "id": a.id, "hosts_sha256": before_sha,
        }

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = BACKUP_DIR / f"hosts.yaml.{stamp}.bak"
    backup.write_bytes(raw)

    block = build_block(a)
    lines = text.splitlines(keepends=True)
    at = None
    for i, ln in enumerate(lines):
        if any(ln.startswith(m) for m in RETIRED_MARKERS):
            at = i
            break
    if at is None:
        at = len(lines)
    new_text = "".join(lines[:at]) + block + "".join(lines[at:])
    new_raw = new_text.encode("utf-8")
    HOSTS.write_bytes(new_raw)

    return 0, {
        "checked": "hosts.yaml 文本插入（在「已退役」段之前）＋ 前后各算一次 sha256",
        "id": a.id, "written": True, "already": False,
        "hosts_sha256_before": before_sha,
        "hosts_sha256_after": sha(HOSTS.read_bytes()),
        "backup": str(backup),
        "backup_sha256": sha(backup.read_bytes()),
        "vmx": a.vmx, "address": a.address,
        "verdict": "written（新增登记）",
        "revert": f"python tools\\host_register.py --revert \"{backup}\"",
    }


def _find_span(text: str, host_id: str) -> tuple[int, int]:
    """找出 hosts 列表里 id=<host_id> 那一条的**字符区间** `[start, end)`。

    ★ 边界规则与 `_blocks()` **同一套**（下一条以 `  - ` / `#` / `-` 开头即结束），
      只差一处：**结尾的空行不算在这一条里**。
      ★ 为什么：空行是**两个条目之间的分隔** —— 删一条不该把分隔也吃掉
        （否则删完会多出一根空行，或者把下一条挤到上一条的注释后面）。
    ★ 找不到 ⇒ 回 `(-1, -1)`：由调用方如实报错。**不模糊匹配、不猜。**
    """
    start = end = None
    pos = 0
    for ln in text.splitlines(keepends=True):
        if start is None:
            m = ID_RE.match(ln)
            if m and m.group(1) == host_id:
                start = pos
        elif ln.startswith("  -") or ln.startswith("#") or ln.startswith("-"):
            end = pos
            break
        pos += len(ln)
    if start is None:
        return -1, -1
    return start, (end if end is not None else len(text))


def do_unregister(host_id: str) -> tuple[int, dict]:
    """把一台机器**注销**出 `hosts.yaml`（与 `--register` 对称；同样"三件齐"）。

    ★★ 为什么注销也要做成一个工具、而不是"手改一行 YAML"：
      `hosts.yaml` 是**平台自己的配置文件**，而"注销"是**改变平台边界**的动作
      —— 注销之后 `vm.*` 会拒操作这台 VM、界面不再把它当目标机（规范 §12.116 红线 12）。
      与 `--register` 同一条纪律：**写前备份 · 逐字节可回退 · 把改了什么吐出来**。

    ★ 三条硬纪律：
      · **找不到就一定报错**（退出码 2）：不模糊匹配（`aoc-tpl` ≠ `aoc-tpl-01`）；
      · **只摘这一段**：别的一行不动、注释不重排（同 `--register`：不用 YAML 库 dump 回去）；
      · ★★ **如实告知"机器还在不在"**：**注销 ≠ 删机器** —— 若 vmx 仍在宿主机上，
        它会变成一台"**不在册的虚拟机**"（界面里**只读可见、不可操作**）。
        这个事实写进 JSON 的 `vmx_still_on_disk`，让"以为删干净了"这件事**不可能悄悄发生**。
    """
    if not HOSTS.is_file():
        return 2, {"error": "HOSTS_MISSING", "reason": f"找不到 {HOSTS}"}
    raw = HOSTS.read_bytes()
    text = raw.decode("utf-8")
    start, end = _find_span(text, host_id)
    if start < 0:
        return 2, {
            "error": "UNREGISTER_NOT_FOUND",
            "reason": f"hosts.yaml 里没有 id={host_id} 这一条",
            "advice": ("★ 本工具**不模糊匹配**（`aoc-tpl` 不等于 `aoc-tpl-01`）："
                       "请拿 hosts.yaml 里那个**逐字**的 id 再来一次。"),
            "id": host_id, "hosts_sha256": sha(raw),
        }
    removed = text[start:end]
    m = re.search(r"^\s*vmx:\s*(\S.*?)\s*$", removed, re.M)
    vmx = m.group(1) if m else ""
    new_text = text[:start] + text[end:]
    if new_text == text:                      # 兜底：真删掉了才写盘（防"以为删了"）
        return 2, {"error": "UNREGISTER_NOOP", "reason": "定位到的区间是空的，没动文件",
                   "id": host_id, "hosts_sha256": sha(raw)}

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = BACKUP_DIR / f"hosts.yaml.{stamp}.bak"
    backup.write_bytes(raw)
    HOSTS.write_bytes(new_text.encode("utf-8"))
    return 0, {
        "checked": ("从 hosts.yaml 里**只摘掉** id 那一段（区间 = `  - id:` 到下一个条目/注释之前）"
                    "＋ 前后各算一次 sha256 ＋ 把摘掉的原文原样吐出来（留痕）"),
        "id": host_id, "written": True, "removed": True,
        "removed_block": removed,
        "removed_vmx": vmx,
        "vmx_still_on_disk": bool(vmx) and Path(vmx).is_file(),
        "hosts_sha256_before": sha(raw),
        "hosts_sha256_after": sha(HOSTS.read_bytes()),
        "backup": str(backup),
        "backup_sha256": sha(backup.read_bytes()),
        "verdict": ("unregistered（已不在册；★ 若 `vmx_still_on_disk` 为真，"
                    "这台机器**仍在宿主机上**，只是平台不再管它 —— **注销 ≠ 删机器**）"),
        "revert": f"python tools\\host_register.py --revert \"{backup}\"",
    }


def do_revert(path: str) -> tuple[int, dict]:
    p = Path(path)
    if not p.is_file():
        return 2, {"error": "BACKUP_MISSING", "reason": f"备份文件不在：{path}"}
    raw = p.read_bytes()
    HOSTS.write_bytes(raw)
    return 0, {
        # ★★ 老实说清这一条**证明了什么、没证明什么**（T17·S7 的证伪当场抓到的坑）：
        #    "把备份整文件写回"这件事，用"备份的 sha256 vs 写回后文件的 sha256"比是**同义反复**
        #    （我们就是把那份字节写回去的）⇒ 那种比对**永远绿**，是一条空转的判据。
        #    真正有意义的判据在**外面**：回退之后 `hosts.yaml` 是否等于**写之前那一版**
        #    —— 那要用写那一步留下的 `hosts_sha256_before` 去比（自检的 Ⓨ 就是这么做的）。
        "checked": "把备份整文件写回 hosts.yaml（★ 本工具只保证「写回的是这一份备份」）",
        "backup": str(p),
        "backup_sha256": sha(raw),
        "hosts_sha256": sha(HOSTS.read_bytes()),
        "verdict": ("reverted（已写回；★ 要判「是否回到写前那一版」，请拿写那一步留下的 "
                    "`hosts_sha256_before` 与这里的 `hosts_sha256` 比 —— 本工具不替你做这个判断，"
                    "因为自己跟自己的备份比是同义反复）"),
    }


try:  # ★★ T17（规范 §12.134）：工具自己的 stdout 也要 pin 编码（同 run_one.py 的理由）
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="把一台机器登记进 hosts.yaml（写前备份 + 可回退）")
    ap.add_argument("--id", help="主机 id（也是后续 hosts.yaml 里的 id）")
    ap.add_argument("--address", help="静态地址")
    ap.add_argument("--user", default="root")
    ap.add_argument("--vmx", help="该机在宿主机的 vmx 全路径（虚拟化登记）")
    ap.add_argument("--from-mother", default="（未注明）", help="从哪台母机克隆来的（写进 note）")
    ap.add_argument("--name", default="")
    ap.add_argument("--role", default="")
    ap.add_argument("--tags", default="")
    ap.add_argument("--revert", default="", help="把一个备份文件整文件写回 hosts.yaml")
    ap.add_argument("--unregister", default="",
                    help="把 id 这一条**注销**出 hosts.yaml（★ 与 --register 对称：写前备份 + 可回退；"
                         "★ 注销 ≠ 删机器 —— 若 vmx 仍在宿主机上，它会变成'不在册的虚拟机'）")
    ap.add_argument("--update-mode", default="refuse", choices=["refuse", "address"],
                    help="id 已存在但地址不同时：refuse=拒绝（默认）· address=只改地址那一行")
    ap.add_argument("--root", default=str(ROOT))
    a = ap.parse_args(argv)

    global HOSTS, BACKUP_DIR
    HOSTS = Path(a.root) / "hosts.yaml"
    BACKUP_DIR = Path(a.root) / "var" / "backups"

    if a.revert:
        code, payload = do_revert(a.revert)
    elif a.unregister:
        code, payload = do_unregister(a.unregister)
    else:
        if not (a.id and a.address and a.vmx):
            print("ERROR=缺参数：--id / --address / --vmx 都是必需的")
            return 2
        code, payload = do_register(a)

    import json
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
