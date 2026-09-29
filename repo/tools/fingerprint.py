"""重算源码指纹（T15 · 规范 §12.108.4）。

用法（在 repo 根目录下）：

```plain
python tools\\fingerprint.py            # 打印当前源码的指纹（短 + 全长 + 文件数）
python tools\\fingerprint.py --files    # 连每个文件的 sha256 一起打（排查"到底哪个文件变了"）
python tools\\fingerprint.py --json     # 给脚本用
```

★ 为什么要有这个入口：**不许"启动时算一次就算完"**。
  `/api/auth/ping` 上那枚指纹回答的是"**这个进程**跑的是哪一份源码"；
  而这里回答的是"**磁盘上现在**是哪一份"。**两个值不一样 = 你改完代码没重启** ——
  这正是 T13/T14 两次踩到的那个坑（"看不出跑的是新是旧"）的正面判据。

★ 本脚本**只读**：不写任何文件、不碰目标机。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

from app.fingerprint import source_files, source_fingerprint  # noqa: E402


def main() -> int:
    fp = source_fingerprint(ROOT)
    want_json = "--json" in sys.argv
    want_files = "--files" in sys.argv

    if want_json:
        payload = dict(fp)
        if want_files:
            payload["file_hashes"] = dict(source_files(ROOT))
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print("=" * 68)
    print("  auto-ops-console · 源码指纹（规范 §12.108）")
    print("=" * 68)
    print(f"  根目录   : {ROOT}")
    print(f"  短指纹   : {fp['short']}")
    print(f"  全长     : {fp['hash']}")
    print(f"  文件数   : {fp['files']}")
    print(f"  算法     : {fp['algo']}")
    print(f"  范围     : {'、'.join(fp['scope'])}")
    print(f"  算的时刻 : {fp['scanned_at']}")
    print()
    print("  ★ 拿它跟 `/api/auth/ping` 里的 `build.source_short` 对一眼：")
    print("     一样  = 进程跑的就是磁盘上这一份")
    print("     不一样 = **你改完代码没重启**（T13/T14 两次踩到的那个坑）")
    if want_files:
        print()
        print("  逐文件 sha256：")
        for rel, digest in source_files(ROOT):
            print(f"    {digest[:16]}…  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
