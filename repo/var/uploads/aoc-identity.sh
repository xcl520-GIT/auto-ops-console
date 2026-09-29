#!/bin/sh
# ============================================================================
# aoc-identity.sh —— 身份重置的**guest 侧**执行体（T17 · 规范 §12.128）
# ----------------------------------------------------------------------------
# ★★ 为什么它是个脚本，而不是一堆"简单的 argv 步骤"：
#   动作 YAML 的 `run` 元素里**禁止 shell 元字符**（`|` `>` `<` `&&` `;` `$(` 反引号 `||`）——
#   这是平台的既有硬规矩（`app/catalog.py::_FORBIDDEN_IN_ARGV`，"不许偷偷写管道"）。
#   而"身份重置"天生需要：删除 + 重新生成 + **动手前后对比** + 把结论变成退出码。
#   ⇒ 把这些收进这一份**进 Git、可复核、可单跑**的脚本里；动作层只留 `sh 脚本 子命令` 这样的朴素 argv。
#
# ★★ 退出码语义（与 `systemctl is-active` / `tools\vmprobe.py` 同一套）：
#     0 = **成立**（读到了 / 真的变了）
#     3 = **不成立**（读不到期望的东西 / ★ **还是那个旧值** —— 这就是"串味"）
#     2 = **读不到/环境不具备**（命令不在、权限不够 —— 如实说"读不到"，不许当成"没变"）
#
# ★★ 覆盖的**四项 guest 身份**（第 5 项 VMware UUID / MAC 在 `.vmx` 里，属宿主机侧，
#    由 `vm.vmx-read` 只读读出，红线 13：**只读，不改**）：
#     ① machine-id   ② ssh-hostkey（比**指纹**，不比文件字节）   ③ hostname   ④ static-ip
#
# ★★ 诚实边界（规范 §12.133）：本脚本**只改**这几件事的实现所必需的文件；
#    它**不改** `.vmx`、不碰 k8s / 监控 / 任何 aoc- 之外的业务。
#
# 用法：
#   aoc-identity.sh show                                  # 只读：四项全打印 + 各自指纹
#   aoc-identity.sh show <kind>
#   aoc-identity.sh reset machine-id          [dry]
#   aoc-identity.sh reset ssh-hostkey         [dry]
#   aoc-identity.sh reset hostname <名字>     [dry]
#   aoc-identity.sh reset static-ip <地址/掩码> <网关> [dry]
#   （dry = 演练：**只跑判据、不动手** ⇒ 判据会红（3）—— 这正是"判据真在盯着"的反例）
# ============================================================================

LC_ALL=C
export LC_ALL
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

MACHINE_ID=/etc/machine-id
HOSTNAME_KEY=hostname
IP_KEY=static-ip

say() { printf '%s\n' "$*"; }

# --------------------------------------------------------------- 取值（只读）

machine_id_value() {
    [ -r "$MACHINE_ID" ] || return 1
    tr -d ' \t\r\n' < "$MACHINE_ID"
}

ssh_hostkey_files() {
    # ★★ T17·S8 真跑修订（真缺陷，规范 §12.139）：**先回答"有没有钥匙文件"，再谈指纹。**
    #   现场：克隆机上一共 6 个文件（priv=3 · pub=3），**公钥一直都在**；
    #   而老写法报的是 `no-host-keys` —— 明明读到了 3 个指纹，却对外说"没有钥匙"。
    #   ★★ 真因（一个老掉牙的 shell 陷阱）：老写法是
    #        for _p in /etc/ssh/ssh_host_*_key.pub; do ... _any=1 ... done | sort
    #        函数末尾再 `[ "$_any" = "1" ] || return 1`
    #      ⇒ **`for ... done | sort` 把整个循环放进了子 shell**，循环体里设的 `_any=1`
    #        落在子 shell 里，函数外面**永远读到 0** ⇒ 无条件 `return 1`。
    #   ★ 它属于本项目最在意的那一类：**信息在，但没送到读它的那一方**（§12.122 同族），
    #     而且这次是**判据自己说了假话**（"读不到"被写成了"不存在"）。
    #   ⇒ 修法：把"有没有文件"这一步**移出管道**（命令替换先拿到串，再在外面判）——
    #     凡是要拿出去下结论的变量，一律在管道**外面**赋值。
    #   ★ 顺手多做一件（防御，不是本缺陷的原因）：`.pub` 缺失时用**私钥**也算得出同一个指纹。
    ls -1 /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub 2>/dev/null | sort -u
}

ssh_hostkey_fps() {
    # ★ 判据是**公钥指纹**（不是文件字节）：换过钥匙的人一眼能对上，比对文件更稳。
    # ★ 两级取值：① 先认 `.pub`；② 没有 `.pub` 就用**私钥**算（`ssh-keygen -lf <私钥>` 也认，
    #   两头算出来是**同一个指纹**）⇒ `sort -u` 天然去重，不会重复计数。
    # ★★ 注意这里**没有**"循环里设标志位、循环外下结论"的写法：`_files` 是在管道**外面**
    #   用命令替换拿到的（§12.139 的口径）。
    _files=$(ssh_hostkey_files)
    [ -n "$_files" ] || return 1                      # 1 = 一个 ssh_host_* 都没有（真没有）
    printf '%s\n' "$_files" | while read -r _p; do
        _fp=$(ssh-keygen -lf "$_p" 2>/dev/null | awk '{print $2}')
        [ -n "$_fp" ] && printf '%s\n' "$_fp"
    done | sort -u
}

hostname_value() {
    hostname 2>/dev/null || return 1
}

ip_value() {
    # 只取**非回环**的 IPv4（判据要问"网卡"，不是问"我以为我写过了"）
    _v=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2" "$4}' | sort)
    [ -n "$_v" ] || return 1
    printf '%s\n' "$_v"
}

sha_of() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }

show_one() {
    _kind=$1
    case "$_kind" in
        machine-id)
            _v=$(machine_id_value) || { say "kind=machine-id verdict=unreadable"; return 2; }
            say "kind=machine-id value=$_v len=${#_v} sha256=$(sha_of "$_v")"
            ;;
        ssh-hostkey)
            _files=$(ssh_hostkey_files)
            _nfiles=$(printf '%s\n' "$_files" | grep -c .)
            _npub=$(printf '%s\n' "$_files" | grep -c '\.pub$')
            _npriv=$(printf '%s\n' "$_files" | grep -c -v '\.pub$')
            _v=$(ssh_hostkey_fps) || { say "kind=ssh-hostkey verdict=no-host-keys files=0"; return 2; }
            _n=$(printf '%s\n' "$_v" | grep -c .)
            if [ "$_n" = "0" ]; then
                # ★ 有钥匙文件、却一个指纹都算不出来 ⇒ **读不到**（不是"没有钥匙"，§12.139）
                say "kind=ssh-hostkey verdict=keys-present-but-unreadable" \
                    "files=$_nfiles priv=$_npriv pub=$_npub"
                say "  ★ 交代：/etc/ssh 下有 ssh_host_* 文件但 ssh-keygen 算不出指纹（权限？形态？）"
                return 2
            fi
            say "kind=ssh-hostkey count=$_n files=$_nfiles priv=$_npriv pub=$_npub"
            printf '%s\n' "$_v" | while read -r _fp; do say "  fingerprint=$_fp"; done
            say "kind=ssh-hostkey sha256=$(sha_of "$_v")"
            ;;
        hostname)
            _v=$(hostname_value) || { say "kind=hostname verdict=unreadable"; return 2; }
            say "kind=hostname value=$_v sha256=$(sha_of "$_v")"
            ;;
        static-ip)
            _v=$(ip_value) || { say "kind=static-ip verdict=unreadable"; return 2; }
            printf '%s\n' "$_v" | while read -r _l; do say "  iface_address=$_l"; done
            say "kind=static-ip sha256=$(sha_of "$_v")"
            ;;
        vm-uuid)
            say "kind=vm-uuid verdict=not-in-guest"
            say "  ★ 第 5 项身份（UUID / MAC）在 .vmx 里，属**宿主机侧**：用动作 vm.vmx-read 只读读出。"
            return 2
            ;;
        *) say "ERROR=unknown-kind kind=$_kind"; return 2 ;;
    esac
    return 0
}

cmd_show() {
    _only="${1:-}"
    say "=== 身份现状（只读）==="
    _rc=0
    for _k in machine-id ssh-hostkey hostname static-ip; do
        [ -n "$_only" ] && [ "$_only" != "$_k" ] && continue
        show_one "$_k" || _rc=2
    done
    say "=== 交代：查了什么 ==="
    say "  · machine-id ：读 $MACHINE_ID 本体（不是「我写过了」）"
    say "  · ssh-hostkey：先数文件（/etc/ssh/ssh_host_*_key[.pub]，去重）再比**指纹**；"
    say "                 ★ 没有 .pub 就用**私钥**算（两头算出来是同一个指纹）—— "
    say "                 「一个都没有」与「算不出指纹」**分开报**（规范 §12.139）"
    say "  · hostname   ：hostname 回读"
    say "  · static-ip   ：ip -4 -o addr show scope global（问**网卡**）"
    return $_rc
}

# --------------------------------------------------------------- 重置（变更）

cmd_reset() {
    _kind="$1"
    shift
    _dry=no
    case "$1" in
        dry|DRY|yes) _dry=yes; shift ;;
    esac
    case "$_kind" in
        hostname)  _name="${1:-}"; [ -n "$_name" ] && shift ;;
        static-ip) _ip="${1:-}"; _gw="${2:-}"; shift 2 2>/dev/null || true ;;
    esac

    case "$_kind" in
        machine-id)     _before=$(machine_id_value)     || _before="" ;;
        ssh-hostkey)    _before=$(ssh_hostkey_fps)      || _before="" ;;
        hostname)       _before=$(hostname_value)       || _before="" ;;
        static-ip)      _before=$(ip_value)             || _before="" ;;
        *) say "ERROR=unknown-kind kind=$_kind"; return 2 ;;
    esac
    say "before_sha256=$(sha_of "$_before")"

    if [ "$_dry" = "yes" ]; then
        say "dry_run=yes  ★ 演练：只跑判据、**不动手** —— 预期判据会红（退出码 3）"
    else
        case "$_kind" in
            machine-id)
                # ★ 顺序有依赖（规范 §12.128 第 2 条）：先本机身份，后网络。
                if command -v systemd-machine-id-setup >/dev/null 2>&1; then
                    truncate -s 0 "$MACHINE_ID" 2>/dev/null || : > "$MACHINE_ID"
                    systemd-machine-id-setup || { say "ERROR=systemd-machine-id-setup 失败"; return 2; }
                else
                    say "ERROR=TOOL_MISSING 这台机器没有 systemd-machine-id-setup"; return 2
                fi
                ;;
            ssh-hostkey)
                rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
                ssh-keygen -A || { say "ERROR=ssh-keygen -A 失败"; return 2; }
                command -v restorecon >/dev/null 2>&1 && restorecon -R /etc/ssh >/dev/null 2>&1
                systemctl restart sshd || { say "ERROR=重启 sshd 失败"; return 2; }
                ;;
            hostname)
                [ -n "$_name" ] || { say "ERROR=缺参数：新主机名"; return 2; }
                hostnamectl set-hostname "$_name" || { say "ERROR=hostnamectl 失败"; return 2; }
                # /etc/hosts 里 127.0.0.1 那行跟着改（否则 sudo/本地解析会不认新名字）
                if [ -f /etc/hosts ]; then
                    _tmp=$(mktemp)
                    awk -v n="$_name" 'BEGIN{FS=OFS=" "} ($1=="127.0.0.1" && $2 ~ /^[a-zA-Z]/){$2=n} {print}' /etc/hosts > "$_tmp" \
                        && cat "$_tmp" > /etc/hosts && rm -f "$_tmp"
                fi
                ;;
            static-ip)
                [ -n "$_ip" ] || { say "ERROR=缺参数：新地址（含掩码）"; return 2; }
                _con=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | awk -F: '$2!=""{print $1; exit}')
                [ -n "$_con" ] || { say "ERROR=找不到活动连接（nmcli）"; return 2; }
                say "connection=$_con"
                if [ -n "$_gw" ]; then
                    nmcli connection modify "$_con" ipv4.method manual ipv4.addresses "$_ip" ipv4.gateway "$_gw" || {
                        say "ERROR=nmcli modify 失败"; return 2; }
                else
                    nmcli connection modify "$_con" ipv4.method manual ipv4.addresses "$_ip" || {
                        say "ERROR=nmcli modify 失败"; return 2; }
                fi
                nmcli connection up "$_con" || { say "ERROR=nmcli up 失败"; return 2; }
                ;;
        esac
    fi

    case "$_kind" in
        machine-id)     _after=$(machine_id_value)     || _after="" ;;
        ssh-hostkey)    _after=$(ssh_hostkey_fps)      || _after="" ;;
        hostname)       _after=$(hostname_value)       || _after="" ;;
        static-ip)      _after=$(ip_value)             || _after="" ;;
    esac
    say "after_sha256=$(sha_of "$_after")"

    # ---------------------------------------------------------- 判据（退出码）
    case "$_kind" in
        machine-id)
            [ -n "$_after" ] || { say "verdict=unreadable"; return 2; }
            [ "${#_after}" = "32" ] || { say "verdict=bad-shape len=${#_after}"; return 3; }
            [ "$_after" != "$_before" ] || { say "verdict=unchanged ★ 还是旧值（串味没消除）"; return 3; }
            say "verdict=changed len=32"; return 0 ;;
        ssh-hostkey)
            [ -n "$_after" ] || { say "verdict=no-host-keys"; return 2; }
            [ "$_after" != "$_before" ] || { say "verdict=unchanged ★ 指纹没变（钥匙还是母机那套）"; return 3; }
            say "verdict=changed count=$(printf '%s\n' "$_after" | wc -l | tr -d ' ')"; return 0 ;;
        hostname)
            [ -n "$_after" ] || { say "verdict=unreadable"; return 2; }
            [ "$_after" = "$_name" ] || { say "verdict=not-applied 期望=$_name 实读=$_after"; return 3; }
            say "verdict=applied value=$_after"; return 0 ;;
        static-ip)
            [ -n "$_after" ] || { say "verdict=unreadable"; return 2; }
            case "$_after" in
                *"$_ip"*) say "verdict=applied ip=$_ip"; return 0 ;;
            esac
            say "verdict=not-applied 期望包含=$_ip"; return 3 ;;
    esac
    return 2
}

# --------------------------------------------------------------- 入口

_cmd="${1:-show}"
shift 2>/dev/null || true
case "$_cmd" in
    show)  cmd_show "$@" ;;
    reset) cmd_reset "$@" ;;
    *) say "ERROR=unknown-command cmd=$_cmd（可用：show / reset）"; exit 2 ;;
esac
