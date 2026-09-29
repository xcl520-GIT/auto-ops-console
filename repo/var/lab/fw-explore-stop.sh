#!/usr/bin/env bash
# T3 防火墙演练 · 第二阶段：停回 firewalld 并复核"零残留"
set -u

echo "######## 停之前 ########"
printf 'firewalld=%s\n' "$(systemctl is-active firewalld)"
printf 'ports=%s\n' "$(firewall-cmd --zone=public --list-ports)"

echo "######## 停 firewalld（原状：inactive + disabled）########"
systemctl stop firewalld
sleep 2

echo "######## 停之后 ########"
printf 'firewalld=%s\n' "$(systemctl is-active firewalld)"
printf 'enabled=%s\n' "$(systemctl is-enabled firewalld 2>/dev/null || true)"
printf 'containers_running=%s\n' "$(docker ps -q | wc -l)"
printf 'iptables_rules=%s\n' "$(iptables -S 2>/dev/null | wc -l)"

echo "######## 残留检查：演练端口 12345 是否还留在永久配置里 ########"
if grep -q 12345 /etc/firewalld/zones/public.xml 2>/dev/null; then
  echo "!! 残留：public.xml 里还有 12345，需要清理"
else
  echo "ok：public.xml 里没有 12345（撤销是彻底生效的）"
fi

echo "######## 复核：容器与业务端口 ########"
printf 'http_80=%s\n' "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://192.0.2.60/ || echo 失败)"
echo "--- 容器清单 ---"
docker ps --format '{{.Names}}' | sort
echo "######## end ########"
