"""T2 解析器单元验证（用探针拿到的**真实输出**，不是编的样本）。跑完即删。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.parsers import parse_text  # noqa: E402

DF_FULL = """Filesystem            1024-blocks    Used Available Capacity Mounted on
/dev/mapper/rhel-root    46596096 2999952  43596144       7% /
devtmpfs                     4096       0      4096       0% /dev
tmpfs                      741272   12276    728996       2% /run
/dev/nvme0n1p2             983040  247928    735112      26% /boot"""

DF_INODE = """Filesystem              Inodes IUsed    IFree IUse% Mounted on
/dev/mapper/rhel-root 23330816 43837 23286979    1% /
tmpfs                    92658    21    92637    1% /run/user/0"""

DU = "406\t/var/lib\n0\t/var/adm\n79\t/var/cache\n0\t/var/db\n504\t/var"

FIND = "79691776\t/var/lib/mysql/ibdata1\n100663296\t/var/lib/mysql/ib_logfile0\n33554432\t/var/lib/mysql/zabbix/items.ibd"

SS = (
    'udp UNCONN 0      0        0.0.0.0:111 0.0.0.0:* users:(("rpcbind",pid=905,fd=6),("systemd",pid=1,fd=173))\n'
    'tcp LISTEN 0      128      0.0.0.0:22  0.0.0.0:* users:(("sshd",pid=1800,fd=7))\n'
    'tcp LISTEN 0      100    127.0.0.1:25  0.0.0.0:* users:(("master",pid=1219,fd=13))'
)

IP_JSON = ('[{"ifindex":2,"ifname":"ens160","operstate":"UP","mtu":1500,"address":"00:50:56:3a:11:22",'
           '"addr_info":[{"family":"inet","local":"203.0.113.100","prefixlen":24},'
           '{"family":"inet6","local":"fe80::250:56ff:fe3a:1122","prefixlen":64}]},'
           '{"ifindex":1,"ifname":"lo","operstate":"UNKNOWN","mtu":65536,"address":"00:00:00:00:00:00",'
           '"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]}]')

ok = True


def check(name, cond, got=""):
    global ok
    if not cond:
        ok = False
    print(f"  {'✅' if cond else '❌'} {name}" + (f"    {got}" if got else ""))


print("── df_rows（普通用量）")
r = parse_text("df_rows", DF_FULL)
check("识别到 4 个挂载点", len(r) == 4, f"实际 {len(r)}")
check("根分区容量换算正确（46596096 块 = 45504MB）", r[0]["size_mb"] == 45504, str(r[0]))
check("根分区百分比可读", r[0]["pcent"] == "7%", r[0]["pcent"])
check("挂载点含 / 与 /boot", [x["mount"] for x in r] == ["/", "/dev", "/run", "/boot"], str([x["mount"] for x in r]))

print("── df_rows（inode 模式）")
ri = parse_text("df_rows", DF_INODE)
check("按表头自动切到 inode 字段", "ipcent" in ri[0] and ri[0]["ipcent"] == "1%", str(ri[0]))

print("── du_rows（必须降序 + 过滤 0MB + 取 TOP）")
rd = parse_text("du_rows", DU)
check("按体积降序", [x["size_mb"] for x in rd] == [504, 406, 79], str([x["size_mb"] for x in rd]))
check("0MB 行被过滤掉（du -m 是整数 MB，空目录一律算 0，留在排行里没信息量）",
      all(x["size_mb"] > 0 for x in rd), str([x["size_mb"] for x in rd]))
check("路径解析正确", rd[0]["path"] == "/var", rd[0]["path"])

print("── find_rows（字节 → MB）")
rf = parse_text("find_rows", FIND)
check("按体积降序", [x["size_mb"] for x in rf] == [96.0, 76.0, 32.0], str([x["size_mb"] for x in rf]))
check("路径解析正确", rf[0]["path"] == "/var/lib/mysql/ib_logfile0", rf[0]["path"])

print("── ss_rows（端口 → 进程 → PID）")
rs = parse_text("ss_rows", SS)
check("解析出 3 条套接字", len(rs) == 3, f"实际 {len(rs)}")
byport = {x["port"]: x for x in rs}
check("22 端口 → sshd / pid 1800",
      byport["22"]["proc"] == "sshd" and byport["22"]["pid"] == "1800", str(byport["22"]))
check("多进程时取第一个属主（111 → rpcbind）", byport["111"]["proc"] == "rpcbind", str(byport["111"]))
check("udp 行也能解析", byport["111"]["proto"] == "udp", byport["111"]["proto"])

print("── ip_addr（展平整平）")
ra = parse_text("ip_addr", IP_JSON)
check("解析出 2 张网卡", len(ra) == 2, f"实际 {len(ra)}")
check("ens160 的 ipv4 展平正确", ra[0]["ipv4"] == "203.0.113.100/24", ra[0]["ipv4"])
check("ens160 的 ipv6 展平正确", "fe80::" in ra[0]["ipv6"], ra[0]["ipv6"])
check("lo 无 ipv6 时给（无）", ra[1]["ipv6"] == "（无）", ra[1]["ipv6"])

print("── 空输入语义：应当是「没有匹配项」，不是故障")
check("ss_rows 空输入 → 空列表", parse_text("ss_rows", "") == [])
check("find_rows 空输入 → 空列表", parse_text("find_rows", "") == [])
check("du_rows 空输入 → 空列表", parse_text("du_rows", "") == [])

print("── 有行但解析不出来 → 必须报错（格式变了要让人知道）")
from app.errors import OpsError  # noqa: E402
for kind, junk in (("ss_rows", "this is not a socket line"), ("du_rows", "??? garbage")):
    try:
        parse_text(kind, junk)
        check(f"{kind} 垃圾输入应报错", False, "竟然没报错")
    except OpsError as exc:
        check(f"{kind} 垃圾输入报错（{exc.code}）", exc.code == "STEP_FAILED", exc.reason)

print()
print("结论：" + ("全部通过 ✅" if ok else "有失败项 ❌"))
sys.exit(0 if ok else 1)
