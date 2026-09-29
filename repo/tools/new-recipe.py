#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""配方脚手架（T7·S5 · 规范 §12.21）：把"写一份新配方"从"抄一份不知道该改哪里"变成"填空"。

用法（在 repo 根目录下）：

    python tools\\new-recipe.py myapp --unit myapp --package myapp --port 9100 ^
        --config /etc/myapp/myapp.conf --data /var/lib/myapp --dir /opt/aoc-myapp

生成的是一份**能直接装载**的骨架（★ 这条是硬规矩：脚手架产出物必须先过装载期校验，
否则它教出来的第一件事就是"写坏了"）。给你标 `★ TODO` 的地方就是**必须按你的服务改掉**的地方。

★ 为什么要有它（而不是"照着 valkey.yaml 抄一份"）：
  抄一份 = 把别人的服务名、端口、路径**全带上**，改漏一处就是一次事故；
  骨架只留**结构**，服务相关的东西全是参数化的 TODO，并且每一处 TODO 都写明"不改会怎样"。

★ 生成之后怎么让它生效：控制台「服务目录」→「重新装载配方」（**不用重启控制台**，规范 §12.17）；
  或在命令行 `python -m app.server --check` 先看它过不过装载期校验。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
PATH_RE = re.compile(r"^/(etc|var/lib|var/log|opt|var/www)/[A-Za-z0-9_@+][A-Za-z0-9._@+-]*"
                     r"(/[A-Za-z0-9_@+][A-Za-z0-9._@+-]*)*$")

RECIPE_TPL = """\
# ============================================================
# 配方：{name}（★ 用 tools/new-recipe.py 生成的骨架 · 规范 §12.21）
# ------------------------------------------------------------
# 一次点击 = 从"机器上什么都没有"到"{name} 可用且有健康检查"：
#   装包 → 渲染配置 → 启动 + 自启 → （配置变了才）重启 → 健康检查
# 反向操作：停止 / 卸载（保留数据）/ 卸载（全删）
#
# ★ 设计宪法（规范 §12.0）—— 这三条**一个字都不许改**：
#   ① 本文件只声明"要什么"，**判定与分支一律走平台侧**（没有一处命令、没有一处表达式）
#   ② 「没变」可断言：平台采集 changed → **第二次跑该清单为空**就是幂等证明
#   ③ 每个正向步骤都有反向操作（见 uninstall）
#
# ★★ 生成后请按顺序做这三件事：
#   1) 把下面所有 `★ TODO` 按你的服务改掉（一共 {todo_n} 处）；
#   2) `python -m app.server --check` —— 先过装载期校验，再去碰目标机；
#   3) 控制台「服务目录」→「重新装载配方」→「配方体检」→ 再点「部署 / 收敛」。
# ============================================================

id: {rid}
name: {name}
version: "1"
summary: 一键部署 {name}（★ TODO：一句话说清它做什么，用户先看这一行）
risk: yellow

note: |
  ★ **这份骨架只保证"结构对"，不保证"对你的服务对"** —— 下面每一处都必须按实际确认：

  ★ TODO ①【配置文件写在哪】—— 规范 §12.13.5：**找服务自己留的钩子**，不要凭想象写路径。
      真机上确认，例如：
        · 单元有没有 drop-in 目录？           `systemctl cat {unit} | grep -i drop`
        · 单元有没有"环境文件/变量"钩子？      `systemctl cat {unit} | grep -iE 'EnvironmentFile|\\$OPTIONS'`
        · 有没有独立的配置目录被单元引用？      `systemctl cat {unit} | grep -F .conf`
      ★ 现在骨架写的是 `{config}` —— 它**只对"我们自造的文件"成立**。
        如果那个文件其实是**包自带**的（`rpm -qf {config}` 能查到归属），**立刻改掉**：
        卸载时 `remove_config` 复原不了包里的默认值，卸一次就成残缺的包（T5 踩过）。

  ★ TODO ②【生效方式】—— 改了配置之后靠什么生效？骨架用的是"`notify` 唤起 `svc.restart`"。
      如果这个服务**不需要重启**（或靠别的方式生效，例如 NFS 的 `exportfs -r` 藏在单元自己的
      `ExecStartPre` 里），那就在下面 `restart` 步骤上写清楚，并把 `notify` 去掉。

  ★ TODO ③【健康检查要"真问一句"】—— 规范 §12.11。现在是 `state: active`（**旁证**）+ 端口。
      真正的"它活着吗"需要一条 `responds`（命令类判据），例如：
        responds: {{ action: db.valkey-ping, args: {{ port: "{{{{ port }}}}" }} }}      # 缓存类
        responds: {{ action: db.mariadb-ping, args: {{}} }}                            # 数据库类
        responds: {{ action: nfs.export-check, args: {{}} }}                           # NFS 类
      ★ 若你的服务**没有**现成的探活动作，**先升规范再加一个只读探活动作**（别在这儿就地发明）。
        现状：健康检查只有旁证 ⇒ 「配方体检」会给你一个 **warn**，那不是错，是提醒。

  ★ TODO ④【数据目录】—— `{data}` 是**数据**：它必须进 `keep_data`（"保留数据"是真的保留），
      只在「全删」时才由 `purge_paths` 删掉。★ 别把包自带的目录写进 `purge_paths`（那会让包残缺）。

params:
  - name: port
    label: 监听端口
    type: int
    required: true
    min: 1024
    max: 65535
    default: {port}
    help: '默认 {port}。改端口后重跑一次配方即可：会写新配置并触发重启。'
  - name: bind
    label: 监听地址
    type: enum
    required: true
    choices: [仅本机, 所有网卡]
    values: ["127.0.0.1", "0.0.0.0"]
    default: 仅本机
    help: '★ 默认只监听本机。「所有网卡」等于把它暴露到网络上，请想清楚再选。'

preflight:
  # ★ TODO ⑤：这里写"**装了它就会出事**"的前置条件（例如已经装了别的同类服务会抢端口/目录）。
  #   没有的话**删掉这一段**（宁可不写，也不写一个假闸门 —— 规范 §12.6）。
  - expect:
      absent: {{ action: pkg.installed, args: {{ pkg: httpd }} }}
    fail_reason: '这台机器上已经装了 httpd（Apache）：它常常会抢端口与站点目录。先确认那是不是你要的，再决定要不要继续。'

steps:
  - name: install
    title: 安装 {package}
    action: pkg.install
    args: {{ package: {package} }}
    note: '★ TODO ⑥：确认包名（Rocky/RHEL 10 上名字可能和你想的不一样，例如 mysql→mariadb、redis→valkey）。'

  - name: render_conf
    title: 渲染配置（{config}）
    template: {rid}/main.conf
    dest: {config}
    mode: "0644"
    notify: [restart]
    note: >
      ★ 内容 sha256 与目标机现有一致时**不写盘**（规范 §12.4）⇒ 幂等的那一次
      既不产生变更、也不触发重启。

  - name: start
    title: 启动服务
    action: svc.start
    args: {{ unit: {unit} }}

  - name: enable
    title: 设为开机自启
    action: svc.enable
    args: {{ unit: {unit} }}

  - name: restart
    title: 重启 {name}（仅当配置真的变了）
    action: svc.restart
    args: {{ unit: {unit} }}
    trigger_only: true
    note: '由 render_conf 的 notify 唤起；第二次跑（内容没变）**根本不会执行** —— 幂等靠这个成立。'

health:
  - expect:
      state: {{ unit: {unit}, equals: active }}
  - expect:
      port_open: "{{{{ port }}}}"

uninstall:
  stop:
    - action: svc.stop
      args: {{ unit: {unit} }}
  disable:
    - action: svc.disable
      args: {{ unit: {unit} }}
  # ★ 只删**配方自己写出来的**那一个文件（规范 §12.13：包自带的文件一个都不许动）
  remove_config:
    - action: file.remove
      args: {{ path: {config} }}
  # ★ 数据目录 / 自造目录：只在「全删」时删
  purge_paths:
    - {data}
  # ★ 「保留数据」是一条**承诺**，报告里必须念出来，而且要被真验（规范 §12.13.1）
  keep_data:
    - {data}
  remove_packages:
    - {package}
  stop_confirm_text: 我已确认要停止服务
  purge_confirm_text: 我已确认全删
  # ★ 停止 / 「保留数据」卸载**之后**应当成立的事实（规范 §12.6.3）：
  #   ★★ 用"**端口没人听**"这种外部可观测的判据，**不用** `state: {{equals: inactive}}` ——
  #     后者依赖"单元还驻留在 systemd 内存里"，`svc.disable` 之后它会从内存卸载（T5 真跑踩过）。
  health:
    - expect:
        free_port: "{{{{ port }}}}"
"""

TEMPLATE_TPL = """\
# {name} 的配置文件（由配方「{rid}」渲染到这里：{config}）
#
# ★ 这是**模板**，不是最终文件：`{{{{ 参数名 }}}}` 会被配方参数替换后写入目标机（规范 §12.4）。
# ★ 模板里**没有"注释"这种东西** —— 说明文字里的裸 `{{{{ }}}}` 也会被当成占位符（T6 踩过）。
#   要写大括号，就像这一行一样转义：`{{{{{{` 或直接别写。

port = {{{{ port }}}}

# ★ TODO ⑦：把这里换成**你这个服务真正认的配置语法**（上面这个 `key = value` 只是占位）。
"""


def _die(msg: str) -> int:
    print(f"❌ {msg}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="生成一份能直接装载的配方骨架（T7·S5 · 规范 §12.21）")
    ap.add_argument("recipe_id", help="配方 id（小写字母开头，只含小写字母/数字/连字符）")
    ap.add_argument("--unit", help="systemd 单元名（默认等于 id）")
    ap.add_argument("--package", help="软件包名（默认等于 id）")
    ap.add_argument("--port", type=int, default=9100, help="默认端口（默认 9100）")
    ap.add_argument("--config", help="配置文件路径（默认 /etc/<id>/<id>.conf）")
    ap.add_argument("--data", help="数据/自造目录（默认 /opt/aoc-<id>）")
    ap.add_argument("--name", help="给人看的名字（默认取 id）")
    ap.add_argument("--root", help="写到哪个 repo 根（默认＝本脚本所在的 repo；自检与「先试一份」会用）")
    ap.add_argument("--force", action="store_true", help="已存在也覆盖（默认不覆盖）")
    args = ap.parse_args(argv)

    rid = args.recipe_id
    if not ID_RE.match(rid):
        return _die(f"配方 id「{rid}」不合法：必须是 `^[a-z][a-z0-9-]*$`（小写字母开头，只含小写字母/数字/连字符）")
    unit = args.unit or rid
    package = args.package or rid
    name = args.name or unit
    config = args.config or f"/etc/{rid}/{rid}.conf"
    data = args.data or f"/opt/aoc-{rid}"
    for label, p in (("--config", config), ("--data", data)):
        if not PATH_RE.match(p):
            return _die(
                f"{label} 给的路径「{p}」不在白名单内。\n"
                "   只允许 /etc/<名>、/var/lib/<名>、/var/log/<名>、/opt/<名>、/var/www/<名> 形式，\n"
                "   且每一段都不能以点开头（于是 `..` 一律被拒）—— 这是 `file.remove` 的同一套白名单，\n"
                "   ★ 配方删得掉的路径必须在这个范围内，否则「全删」会因为越权而中止（规范 §12.6）。"
            )
    if not (1024 <= args.port <= 65535):
        return _die(f"端口 {args.port} 不在 1024~65535 之间")

    root = Path(args.root).resolve() if args.root else ROOT
    recipes_dir = root / "catalog" / "recipes"
    tpl_dir = root / "catalog" / "templates" / rid
    recipe_path = recipes_dir / f"{rid}.yaml"
    tpl_path = tpl_dir / "main.conf"
    if recipe_path.exists() and not args.force:
        return _die(f"已经存在：{recipe_path}（要覆盖就加 --force）")
    if not recipes_dir.is_dir():
        if args.root:
            # ★ 显式给了 --root：这是在"另一个地方先试一份"，缺目录就建（自检就是这么用的）
            recipes_dir.mkdir(parents=True, exist_ok=True)
        else:
            return _die(f"找不到配方目录：{recipes_dir}（要在 repo 根目录下运行本脚本）")

    body = RECIPE_TPL.format(
        rid=rid, name=name, unit=unit, package=package, port=args.port,
        config=config, data=data, todo_n=7,
    )
    tpl_dir.mkdir(parents=True, exist_ok=True)
    # ★ 显式 newline="\n"：Windows 上默认会把 \n 写成 \r\n（规范 §9.12 同族坑）
    recipe_path.write_text(body, encoding="utf-8", newline="\n")
    tpl_path.write_text(
        TEMPLATE_TPL.format(rid=rid, name=name, config=config),
        encoding="utf-8", newline="\n",
    )

    def _rel(p: Path) -> str:
        """★ 用 --root 写到别处时，`relative_to(ROOT)` 会抛 ValueError —— 显示用的东西不该让命令崩。"""
        try:
            return str(p.relative_to(root))
        except ValueError:
            return str(p)

    print(f"✅ 已生成：{_rel(recipe_path)}")
    print(f"✅ 已生成：{_rel(tpl_path)}")
    print("")
    print("下一步（顺序别换）：")
    print(f"  1) 把两份文件里的 `★ TODO` 按你的服务改掉（{7} 处）")
    print("  2) python -m app.server --check          # 先过装载期校验，再去碰目标机")
    print("  3) 控制台「服务目录」→「重新装载配方」→「配方体检」→「部署 / 收敛」")
    print("")
    print("★ 这份骨架**故意**只给到'结构对'：服务相关的每一处都标了 TODO 与'不改会怎样'。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
