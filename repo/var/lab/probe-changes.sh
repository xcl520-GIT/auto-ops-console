#!/usr/bin/env bash
# T3 probe: exit codes & output formats of the CHANGE commands.
# Touches ONLY aoc- lab fixtures (/etc/systemd/system/aoc-*.service, /opt/aoc-lab/, /etc/cron.d/aoc-*).
# Never touches kubelet / containerd / docker / harbor / sshd.
set -u

echo "##### T3 PROBE on $(hostname) #####"

probe() {
  desc="$1"; shift
  out="$("$@" 2>&1)"; rc=$?
  printf '%-50s rc=%-4s | %s\n' "$desc" "$rc" "$(printf '%s' "$out" | head -2 | tr '\n' '~')"
}

echo "--- A. systemctl 查询（只读） ---"
probe "is-active aoc-lab.service"            systemctl is-active aoc-lab.service
probe "is-active aoc-nope.service"           systemctl is-active aoc-nope.service
probe "is-enabled aoc-lab.service"           systemctl is-enabled aoc-lab.service
probe "is-enabled aoc-nope.service"          systemctl is-enabled aoc-nope.service
probe "is-failed aoc-fail.service"           systemctl is-failed aoc-fail.service
probe "show ActiveEnterTimestamp (lab)"      systemctl show -p ActiveEnterTimestamp aoc-lab.service
probe "show ActiveEnterTimestamp (nope)"     systemctl show -p ActiveEnterTimestamp aoc-nope.service
probe "show ActiveState (nope)"              systemctl show -p ActiveState aoc-nope.service
probe "cat aoc-lab.service"                  systemctl cat aoc-lab.service
probe "cat aoc-nope.service"                 systemctl cat aoc-nope.service

echo "--- B. systemctl 变更（只在 aoc- 靶子上） ---"
probe "start aoc-lab.service"                systemctl start aoc-lab.service
probe "is-active after start"                systemctl is-active aoc-lab.service
probe "show timestamp after start"           systemctl show -p ActiveEnterTimestamp aoc-lab.service
probe "start again (idempotent?)"            systemctl start aoc-lab.service
probe "start aoc-nope.service"               systemctl start aoc-nope.service
probe "restart aoc-lab.service"              systemctl restart aoc-lab.service
probe "enable aoc-lab.service"               systemctl enable aoc-lab.service
probe "enable again (idempotent?)"           systemctl enable aoc-lab.service
probe "disable aoc-lab.service"              systemctl disable aoc-lab.service
probe "disable again (idempotent?)"          systemctl disable aoc-lab.service
probe "start aoc-fail.service"               systemctl start aoc-fail.service
probe "is-failed after start"                systemctl is-failed aoc-fail.service
probe "stop aoc-lab.service"                 systemctl stop aoc-lab.service
probe "stop again (already stopped)"         systemctl stop aoc-lab.service
probe "daemon-reload"                        systemctl daemon-reload

echo "--- C. firewalld（本机当前 inactive —— 决定防火墙动作能否验证） ---"
probe "firewall-cmd --state"                 firewall-cmd --state
probe "--list-all (no daemon)"               firewall-cmd --list-all
probe "--permanent --list-ports (no daemon)" firewall-cmd --permanent --list-ports

echo "--- D. dnf（不真装，只看行为与耗时） ---"
probe "dnf --version"                        dnf --version
probe "dnf --assumeno install (不存在包)"     dnf --assumeno install aoc-no-such-package-xyz
probe "dnf list --installed (前2行)"          dnf list --installed
probe "dnf history (前2行)"                   dnf history
probe "rpm -q aoc-lab-none"                  rpm -q aoc-lab-none

echo "--- E. cron ---"
probe "systemctl is-active crond"            systemctl is-active crond
probe "crontab -l (root)"                    crontab -l
probe "ls /etc/cron.d"                       ls -l /etc/cron.d
probe "写自建 cron 文件"                      bash -c 'echo "* * * * * root /bin/true" > /etc/cron.d/aoc-probe && echo wrote'
probe "读回自建 cron 文件"                    cat /etc/cron.d/aoc-probe
probe "删自建 cron 文件"                      rm -f /etc/cron.d/aoc-probe

echo "--- F. 备份原语（stat / sha256 / cp / 空间） ---"
probe "stat 存在的文件"                       stat -c '%s|%a|%U|%G|%F' /opt/aoc-lab/config/aoc.conf
probe "stat 不存在的文件"                     stat -c '%s|%a|%U|%G|%F' /opt/aoc-lab/config/nope.conf
probe "sha256sum 文件"                       sha256sum /opt/aoc-lab/config/aoc.conf
probe "cp -a 到 /tmp"                        cp -a /opt/aoc-lab/config/aoc.conf /tmp/aoc-probe-copy.conf
probe "df -P /var (可用空间)"                 df -P /var
probe "mkdir -p /var/backups/aoc"            mkdir -p /var/backups/aoc/probe
probe "cp -a 进备份目录"                      cp -a /opt/aoc-lab/config/aoc.conf /var/backups/aoc/probe/
probe "ls 备份目录"                           ls -l /var/backups/aoc/probe/
probe "目录型备份 (cp -a 目录)"               cp -a /opt/aoc-lab /var/backups/aoc/probe/dir-copy
probe "ls 目录型备份"                          ls -l /var/backups/aoc/probe/dir-copy/
probe "清理探针备份"                           rm -rf /var/backups/aoc/probe /tmp/aoc-probe-copy.conf

echo "##### PROBE END on $(hostname) #####"
