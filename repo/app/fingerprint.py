"""源码指纹（T15 · 规范 §12.108）—— 让「**在跑的是哪个构建**」一眼可辨。

★ 缘起（T14 遗留 #4 / 坑 #7）：从接口上**看不出**在跑的是哪个构建。
  T13 撞过"跑的是旧进程"（新接口 404），T14 又撞过"版本横幅从 T13 收口后就没动过" ——
  两次都是同一件事换了形态：**没有一枚指纹**。

三条口径（§12.108）：

  · ★ **算法只许有一处定义** —— 就在这里；别处只许 `import` 它，不许再算一份。
  · ★ 指纹里**只有文件名与哈希** —— 不含文件内容、不含凭据、不含主机信息（红线 8 同源）。
  · ★★ **判据必须能证伪**：改任意一个 `app/*.py` 或 `web/*` 的**一个字符** ⇒ 指纹必须变
    （断言 Ⓖ）。★ 另留**重算入口**（`tools/fingerprint.py`）——
    不许"启动时算一次就算完"（那正好是"看不出跑的是哪一版"的成因）。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

#: 参与指纹的**相对路径 glob**（相对 repo 根）
#: ★ `web/**/*` 而不是 `web/**` —— 后者会把 `web` **目录自己**也匹配进来
#:   （`**` 可以匹配"零个目录"）。虽然 `source_files()` 会跳过非文件，
#:   但"范围里混进目录"这件事本身就该在写法上避免（自检 Ⓖa 的第一版就是被它绊的）。
SOURCE_GLOBS: tuple[str, ...] = ("app/**/*.py", "web/**/*")

#: 展示位（短指纹）—— 12 位十六进制，够分辨、又不至于长到念不出来
DISPLAY_LEN = 12

ALGO = "sha256(按路径排序的「相对路径\\t内容sha256」串)"


def source_files(root: Path) -> list[tuple[str, str]]:
    """收集参与指纹的文件 → [(相对路径, 内容 sha256)]，**按相对路径排序**。

    ★ 排序是**算法的一部分**：不排序的话，同样的代码在不同文件系统上会算出不同指纹，
      那这条指纹就只剩"能变"这一个用处了（而"同一份代码要给同一个值"才是它的价值）。
    """
    out: list[tuple[str, str]] = []
    for pattern in SOURCE_GLOBS:
        for p in sorted(root.glob(pattern)):
            if not p.is_file() or p.name.endswith(".pyc"):
                continue
            rel = p.relative_to(root).as_posix()
            out.append((rel, hashlib.sha256(p.read_bytes()).hexdigest()))
    out.sort(key=lambda x: x[0])
    return out


def source_fingerprint(root: Path) -> dict[str, Any]:
    """算一次源码指纹（§12.108.1）。

    ★ 返回里 `scanned_at` **不参与哈希**（它是"什么时候算的"，不是"算的是什么"）——
      否则同一个构建每次算出来都不一样，指纹就没法当指纹用。
    """
    files = source_files(root)
    h = hashlib.sha256()
    for rel, digest in files:
        h.update(f"{rel}\t{digest}\n".encode("utf-8"))
    full = h.hexdigest()
    return {
        "hash": full,
        "short": full[:DISPLAY_LEN],
        "files": len(files),
        "algo": ALGO,
        "scope": list(SOURCE_GLOBS),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        # ★★ 自我说明：这东西**能外露**（它是我们自己的构建标识，不是秘密），
        #   但"能外露"≠"该塞进外发 payload" —— 见 §12.108.3。
        "note": (
            "★ 指纹只含**文件名与哈希**：不含文件内容、不含凭据、不含主机信息（红线 8 同源）；"
            "★ 它**不进**任何给模型看的 payload。"
        ),
    }


def short(root: Path) -> dict[str, Any]:
    """只要"一眼可辨"的那几位（给 `/api/auth/ping` 用 —— 那条是免鉴权的）。"""
    fp = source_fingerprint(root)
    return {"source_short": fp["short"], "files": fp["files"]}
