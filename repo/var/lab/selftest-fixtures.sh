#!/usr/bin/env bash
# ============================================================
# 完整自检的**实验室夹具**（T6 补）：up = 铺 / down = 清。
# ------------------------------------------------------------
# 为什么需要它：
#   `tools/selftest.py` 里那条"**svc.list 能检出失败服务**"的断言，需要一个
#   **故意失败**的单元在场 —— 而那是**夹具**，不是被测代码。
#   ★ 平台**铺不进去**：全库没有任何动作做 `systemctl daemon-reload`，
#     所以新写上去的单元文件 systemd 看不见（`svc.start` 会报 not found）。
#     ⇒ 铺夹具只能**场外**做 —— 就是这个脚本。
#
# 用法（在**目标机**上跑；目标机 = config.yaml 的 `selftest.host_id`）：
#   bash selftest-fixtures.sh up      # 铺夹具（并让它真的进入 failed）
#   python tools/selftest.py          # 跑完整自检
#   bash selftest-fixtures.sh down    # 清夹具（★ 别留在机器上）
#
#   也可以从管理机管道执行（脚本自包含，不依赖同目录的其它文件）：
#   ssh root@<目标机> 'bash -s up'   < var/lab/selftest-fixtures.sh
#   ssh root@<目标机> 'bash -s down' < var/lab/selftest-fixtures.sh
#
# ★ 靶子纪律：本脚本只碰 `aoc-` 前缀的自造对象，不碰任何真实服务。
# ============================================================
set -u

case "${1:-}" in
  up)
    echo "=== 铺自检夹具 on $(hostname) ==="

    # ① 一个"故意失败"的单元：svc.list 的失败检出能力拿它当对照物。
    #    ★ 必须**真的 start**：svc.list 的「失败明细」只列处于 failed 的单元，
    #      一个"已加载但从未启动"的单元根本不会出现在报告里（那就白铺了）。
    cat > /etc/systemd/system/aoc-fail.service <<'UNIT'
[Unit]
Description=AOC selftest fixture (intentionally fails; failure-detection comparison)

[Service]
Type=oneshot
ExecStart=/bin/false

[Install]
WantedBy=multi-user.target
UNIT

    # ② 一个"可以正常启停"的单元：留给 start/stop/enable/disable 这类演练当靶子。
    cat > /etc/systemd/system/aoc-lab.service <<'UNIT'
[Unit]
Description=AOC selftest fixture (safe to start/stop/restart)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
Restart=no
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
UNIT

    # ③ 一个可写的配置目录：留给 file push / 备份 / 恢复演练当靶子。
    mkdir -p /opt/aoc-lab/config
    if [ ! -f /opt/aoc-lab/config/aoc.conf ]; then
      cat > /opt/aoc-lab/config/aoc.conf <<'CONF'
# AOC selftest fixture config (used for file push / backup / restore drills)
version=1
mode=lab
note=created by selftest-fixtures.sh
CONF
      echo "(created /opt/aoc-lab/config/aoc.conf)"
    else
      echo "(aoc.conf already exists, left untouched)"
    fi

    systemctl daemon-reload
    systemctl start aoc-fail.service || true   # 它就是来失败的

    echo "--- 自证（aoc-fail 必须是 failed，否则下面的断言还是红）---"
    ls -l /etc/systemd/system/aoc-*.service
    printf 'aoc-fail: %s\n' "$(systemctl is-failed aoc-fail.service || true)"
    printf 'aoc-lab : %s\n' "$(systemctl is-active aoc-lab.service || true)"
    echo "=== done（现在可以去跑 tools/selftest.py 了）==="
    ;;

  down)
    echo "=== 清自检夹具 on $(hostname) ==="
    systemctl stop aoc-fail.service 2>/dev/null || true
    systemctl reset-failed aoc-fail.service 2>/dev/null || true
    systemctl stop aoc-lab.service 2>/dev/null || true
    systemctl disable aoc-lab.service 2>/dev/null || true
    rm -f /etc/systemd/system/aoc-fail.service /etc/systemd/system/aoc-lab.service
    systemctl daemon-reload
    rm -rf /opt/aoc-lab
    echo "--- 自证（下面应当全部查不到）---"
    ls -l /etc/systemd/system/aoc-*.service 2>&1 || true
    printf 'aoc-fail: %s\n' "$(systemctl is-failed aoc-fail.service 2>&1 || true)"
    ls -d /opt/aoc-lab 2>&1 || true
    echo "=== done（夹具已清干净）==="
    ;;

  *)
    echo "用法：bash selftest-fixtures.sh up | down" >&2
    exit 2
    ;;
esac
