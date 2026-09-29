#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AOC 监控告警**收端**（T10）—— 只做一件事：把 Alertmanager 投递过来的告警原样记下来。

★ 为什么必须有它（规范 v1.13 §12.57）：
  「配了 webhook 地址」不等于「告警送到了」。**收端留证**才是"送出去了"的**唯一判据** ——
  带接收时间戳、来源、组键、每条告警的状态/标签/注解，追加写 JSONL。
★ 它 **只绑 127.0.0.1**（默认）：Alertmanager 与它在同一台机器上，
  ⇒ **监听面一处都没有扩大**；控制台通过**只读动作** `mon.alerts-received` 把它读回去。
★ 写入是 **append-only**：一行 = 一次投递。不覆盖、不轮转由本脚本负责（那是运维的事）。
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SINK = os.environ.get("AOC_WEBHOOK_SINK") or "/opt/aoc-monitoring/data/webhook/alerts-received.jsonl"
BIND = os.environ.get("AOC_WEBHOOK_BIND") or "127.0.0.1"
PORT = int(os.environ.get("AOC_WEBHOOK_PORT") or "9095")
MAX_BODY = 1 << 20          # 1MB —— Alertmanager 的正常投递只有几 KB


class Handler(BaseHTTPRequestHandler):
    server_version = "aoc-mon-webhook/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):          # noqa: A003
        sys.stderr.write("[%s] %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), fmt % args))

    def _send(self, code, obj):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):                            # noqa: N802
        if self.path.startswith("/healthz"):
            return self._send(200, {"ok": True, "sink": SINK, "bind": "%s:%d" % (BIND, PORT)})
        return self._send(404, {"ok": False, "reason": "only POST /webhook"})

    def do_POST(self):                           # noqa: N802
        if not self.path.startswith("/webhook"):
            return self._send(404, {"ok": False, "reason": "unknown path"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"ok": False, "reason": "bad body size"})
        raw = self.rfile.read(n)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:                        # noqa: BLE001
            return self._send(400, {"ok": False, "reason": "body is not JSON"})

        alerts = payload.get("alerts") or []
        rec = {
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "received_epoch": time.time(),
            "source": self.client_address[0],
            "status": payload.get("status"),
            "receiver": payload.get("receiver"),
            "groupKey": payload.get("groupKey"),
            "commonLabels": payload.get("commonLabels"),
            "alerts": [
                {
                    "status": a.get("status"),
                    "alertname": (a.get("labels") or {}).get("alertname"),
                    "severity": (a.get("labels") or {}).get("severity"),
                    "instance": (a.get("labels") or {}).get("instance"),
                    "startsAt": a.get("startsAt"),
                    "endsAt": a.get("endsAt"),
                    "labels": a.get("labels"),
                    "annotations": a.get("annotations"),
                }
                for a in alerts
            ],
        }
        d = os.path.dirname(SINK)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(SINK, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.log_message("recorded %d alert(s) status=%s", len(alerts), payload.get("status"))
        return self._send(200, {"ok": True, "recorded": len(alerts)})


if __name__ == "__main__":
    d = os.path.dirname(SINK)
    if d:
        os.makedirs(d, exist_ok=True)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    sys.stderr.write("aoc-mon-webhook listening on %s:%d -> %s\n" % (BIND, PORT, SINK))
    srv.serve_forever()
