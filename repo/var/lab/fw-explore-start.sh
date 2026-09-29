#!/usr/bin/env bash
# T3 防火墙演练 · 第一阶段：起 firewalld 并采集影响面
# 说明：本脚本**只做两件改变状态的事**——start firewalld，以及最后的报告。
#      不动 enable（原状是 disabled，演练完要停回去）。
set -u

echo "######## before ########"
printf 'firewalld=%s\n' "$(systemctl is-active firewalld)"
printf 'containers_running=%s\n' "$(docker ps -q | wc -l)"
printf 'iptables_rules=%s\n' "$(iptables -S 2>/dev/null | wc -l)"

echo "######## starting firewalld ########"
systemctl start firewalld
sleep 3

echo "######## after ########"
printf 'firewalld=%s\n' "$(systemctl is-active firewalld)"
firewall-cmd --state
printf 'containers_running=%s\n' "$(docker ps -q | wc -l)"
echo "--- 容器清单（前 12）---"
docker ps --format '{{.Names}}' | head -12
printf 'iptables_rules=%s\n' "$(iptables -S 2>/dev/null | wc -l)"
echo "--- 活跃 zone ---"
firewall-cmd --get-active-zones
echo "--- public zone 现状 ---"
firewall-cmd --zone=public --list-all
echo "--- Harbor 端口探测（本机内网口）---"
curl -s -o /dev/null -w 'http_80=%{http_code}\n' --max-time 5 http://192.0.2.60/ || echo "http_80=失败"
echo "######## end ########"
