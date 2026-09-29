#!/usr/bin/env bash
# auto-ops-console T3 lab fixtures (idempotent). Safe to re-run.
# Purpose: give the console SAFE objects to change, so that no real service
# (kubelet / containerd / docker / harbor / sshd) is ever touched by T3 drills.
# All objects use the "aoc-" prefix so they can be found and removed easily.
set -u

echo "=== T3 lab fixtures on $(hostname) ==="

# 1) A unit that is safe to start / stop / restart / enable / disable
cat > /etc/systemd/system/aoc-lab.service <<'UNIT'
[Unit]
Description=AOC lab fixture service (safe to start/stop/restart)
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

# 2) A unit that intentionally fails (comparison object for failure detection)
cat > /etc/systemd/system/aoc-fail.service <<'UNIT'
[Unit]
Description=AOC lab fixture service (intentionally fails; failure-detection comparison)

[Service]
Type=oneshot
ExecStart=/bin/false

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

# 3) A config file + directory for file push / backup / restore drills
mkdir -p /opt/aoc-lab/config
if [ ! -f /opt/aoc-lab/config/aoc.conf ]; then
  cat > /opt/aoc-lab/config/aoc.conf <<'CONF'
# AOC lab config fixture (used for file push / backup / restore drill)
version=1
mode=lab
note=created by T3 setup
CONF
  echo "(created /opt/aoc-lab/config/aoc.conf)"
else
  echo "(aoc.conf already exists, left untouched)"
fi

echo "--- units ---"
ls -l /etc/systemd/system/aoc-*.service
echo "--- config ---"
ls -l /opt/aoc-lab/config/
echo "--- current state ---"
printf 'aoc-lab: %s\n' "$(systemctl is-active aoc-lab.service || true)"
printf 'aoc-fail: %s\n' "$(systemctl is-active aoc-fail.service || true)"
echo "=== done ==="
