# T8 · K8s 建集群（开题单）

> 状态：**已拍板固化（2026-09-26）｜ ★ 已开工：S0~S4 已完成、S5~S9 待做**（§0.2 进度一屏）
> 起草：Lobe AI ｜ 拍板人：用户（多轮答复，见 §10.2 与 §10.2.1 修订记录）
> 上游依据：`00-项目总纲与路线图.md` §4 T8 ｜ `开发记录\交接\T7-服务治理与扩展点-结题回执.md` §4 遗留 / §5 坑
> 事实依据：`repo\var\artifacts\_manual-对照证据\T8-S0-现状总表-20260926.md`（S0 只读侦察，零变更）
>
> ★ **本文件是 T8 的唯一入口**，读的顺序：开工三步（§★）→ **进度与剩余（§0.2）** →
> 实测口径（§1 · §10.3.1 · §10.3.2）→ 红线与授权（§4 · §10.2）→ 验收（§7）→ **开题语（§13，可直接复制）**。

---

## ★ 开工三步（新话题照做，先复述再动手）

1. 读 `00-项目总纲与路线图.md` → 2. 读 `开发记录\继续工作-看这里.md` → 3. 读本开题单
4. **向用户复述**：本阶段目标 / 验收标准 / 明确不做什么 / 需要用户先提供什么 → **等确认后才动手**

★ **T8 特有的第 0 步**：本阶段要真动 `kubelet` / `containerd` / 内核参数，
**开工前必须先有"还原基线"**（用户拍板：**先在 VMware 里给三台各打一个快照**，见 §10.2 #3 与 §10.3）。

---

## 0. 一句话

> 把「三台裸装 Rocky 10.2 → 一个 Ready 的 K8s 集群」变成工作台里的**一次点击**，
> 顺手把 T7 留下的两条起跑线 —— **内核参数「写 + 持久化」** 与 **`daemon-reload`** —— 补进平台。

### 0.1 继承的宪法（**违反即返工**）

| # | 宪法 | 出处 |
|---|---|---|
| 1 | **先规范后代码** —— 动 `app\` 之前先在 `docs\动作规范.md` 写清口径 | T5~T7 反复验证 |
| 2 | 改了 `app\` **必须重启服务**再验证（`app\` 是内存里加载的） | 同上 |
| 3 | **验证必须在界面真正走的那一层**（`/api/**`）；★ 不许直连 ssh 去改目标机 | 总纲铁律 8 |
| 4 | **`red` 的确认词只能由人输入**；配方确认词与内层动作确认词是**两句** | 总纲铁律 9 |
| 5 | ★★ **代码 diff 不算验收证据** —— 要跑出来、要看终态 | T6 最贵的那个缺陷 |
| 6 | ★★ **判据必须能被证伪**（"写坏了会红"是选写法的唯一标准） | 规范 §12.13.5 / §12.23 |
| 7 | ★★ **回不去的要逐项说清**（包 / 服务状态 / 运行时内存态 / 外部影响，空也要写"无"） | 规范 §12.19 / §12.20 |
| 8 | **数字从账本实时算**（`GET /api/coverage`），注释只作历史对照 | 规范 §11 |
| 9 | **批量不是事务**；**闸门只增不减**（`red` 禁止批量，不提供开关） | 规范 §12.18 / §12.22 |
| 10 | **扩核心代码要有出处**（先过三条判定，再写进规范） | 规范 §12.23 |

---

### 0.2 ★ 进度与剩余任务（一屏 · 截至 2026-09-26 首轮开工结束）

| 块 | 内容 | 状态 | 提交 |
|---|---|---|---|
| **S0** | 只读侦察三台 + 镜像源多轮采样 → 现状总表 + **最小必要清单 A1~A8 逐项点头** + 三个 VM 快照核实 | ✅ | `96e3c22` |
| **S1** | **规范升 v1.9**（§12.24~§12.29）：内核参数「写+持久化」· `daemon-reload` · `reset-failed` · `file.cat` 路径白名单 · 镜像来源记账 · 修订 `net.firewall` | ✅ | `96e3c22` |
| **S2** | **8 个新动作**（动作 53 → **61**）+ 修掉 `net.firewall` 的**假红**；★ 完整自检 **442/442 · 失败 0 · 跳过 0**（T7 遗留的"夹具不在场"被真正打掉） | ✅ | `225f882` |
| **S3** | **旧集群全量留证**：新增只读动作 **`file.manifest`**（规范 §12.30 + 断言 ㊱）→ 12 目录 × 3 台 = **36 次留证**（零截断）+ **52 份配置原文** | ✅ | `2c4a2c6` |
| **S4** | **前提检查一次给全**：42 次批量只读 → 十项判读（**九项已具备**，一项待核） | ✅ | `40f2097` |
| **S5** | containerd 运行时配方（装 / `svc.enable` / 起 / **真探活**，幂等） | ✅ **master01 已跑通**（★ 实测后**收紧**：**一个配置文件都不改**；★★ 镜像路线的实测结论见 §10.2.1 #4）<br>⏳ 尾巴：**自检断言 ㊲~㊴** · **node01/node02 推广** · 收尾留证 | 见 §10.2.1 #4 |
| **S6** | `kubeadm reset` → `init` → `kubeconfig` → `join`（★ `--cri-socket` 显式 / endpoint 写 IPv4） | ⏳ | — |
| **S7** | Calico（★ 按实物：**`mtu = 0`** 不是 1480；+ `portmap` + `bandwidth`）→ 存储类 | ⏳ | — |
| **S8** | 「一键到 Ready」总配方 + 幂等复跑（`changed` 为空 + **关键 Pod `RESTARTS` 不增**）+ 反例 | ⏳ | — |
| **S9** | 证据收口 + 界面**真浏览器**走一遍（CDP）+ **账本四处回填** + 三件交接 | ⏳ | — |

★ **S3 完成后 `kubeadm reset` 的唯一前置已满足**；★ **S5 起每一步都在真机上不可逆** ——
授权（A1~A8）与还原基线（三个 VM 快照）**都已就位**，见 §5 与 §10.2。
★ 四条带进 S5~S8 的**硬约束**（只增不降+一键一文件 / `--cri-socket` 显式 / endpoint 写 IPv4 /
镜像拉取带重试+兜底）见 **§10.3.2 末段**与 `开发记录\继续工作-看这里.md` §1.4。

## 1. ★ 动笔前现场核到的事实（2026-09-26 · 只读侦察）

> 全部经 `/api/actions/<id>/run`，逐条 `changed=False`。证据文件见 §6。

### 1.1 ★★ 最要紧的六条（它们直接决定本话题的形态）

1. **三台上有一个"停着的"完整集群** —— 用户自己的 `k8s-ha-cluster-lab` 现场：
   **v1.34.10** + containerd **2.2.6** + **Calico v3.25.0（IPIP）**；
   Pod `10.244.0.0/16` · Service `10.10.0.0/12` · DNS `203.0.113.10`；
   master01 导出 `/data/nfs` + 两个 StorageClass；还跑过 monitoring / ArgoCD / 自研 exporter。
2. **三台的运行时状态完全一致**：`containerd` **inactive(dead)** · `cri-docker` inactive(dead) ·
   `docker` inactive(dead) · `kubelet` **activating(auto-restart)**（因运行时不在，正在反复重启）；
   端口 **6443 / 10250 / 2379 / 179 全部无监听** ⇒ 集群**整体停着**，不是"半死"。
3. **内核参数已被旧集群调过**（不是默认值）：
   `ip_forward=1` · `vm.swappiness=1` · `net.core.somaxconn=32768` · `fs.file-max=2097152`
   ⇒ 三台上**存在一份旧集群写下的 sysctl 持久化文件**（`/etc/sysctl.d/*.conf`，S3 逐文件留证）。
4. ★★ **镜像源的"出口白名单"逐台不同**（★ 这条推翻了原计划）：

   | 目标 | 三台 K8s | docker-01 | 判读 |
   |---|---|---|---|
   | `registry.aliyuncs.com` | ❌ 000 超时 | ✅ **401 = 活着** | 三台**到不了**，docker-01 到得了 |
   | `registry.k8s.io` | ✅ **401 = 活着** | ❌ 000 | ★ kubeadm 的**默认**源，三台可用 |
   | `registry-1.docker.io` / `quay.io` | ❌ 000 | ❌ 000 | **Calico 的官方源全线不可达** |
   | `ghcr.io` / `registry.cn-hangzhou.aliyuncs.com` | ✅ 401 | ✅ 401 | 两边都通（备用） |
   | 内网 Harbor `192.0.2.60` | ✅ 308 | ✅ 308 | 内网可达 |
   | `mirrors.aliyun.com`（系统源 + k8s rpm） | ✅ 200（偶发抖动） | ✅ 200 | 可用 |

> ★★ **T8·S2 更正（必读）**：上表那一列"❌ 000"是**单次采样**的结果。S2 每台连做 3 轮（共 9 次）复采后，
> **"出口白名单逐台不同"这条结论站不住** —— 真实事实是：**只有 `registry-1.docker.io` 稳定不可达（0/9）**，
> 其余公网仓库**可达但会抖（7/9）**，而 `registry.cn-hangzhou.aliyuncs.com` 与**内网 Harbor** 最稳（9/9）。
> 抖动的形状是 `建连 0.000000s` + 撑满超时（**TCP 没建起来**）而同一时刻 DNS 正常。
> ⇒ 详见 **§10.2.1 修订记录 #2** 与规范 **§12.28.1**；**镜像路线的做法据此改为「主路直拉 + Harbor 兜底 + 拉取重试」**。

5. **前置条件大多已具备**：`swap = 0` · SELinux **Permissive** · `firewalld` 未运行 ·
   `/etc/hosts` 已含四台主机名 · `nameserver 223.5.5.5` 解析正常。
6. **包数与体量**：master01 **478** 包 / node01 **412** / node02 **412**；
   根分区用量 30% / 14% / 18%（45GB）；三台均 4 逻辑核 / 3621MB 内存 / 4 vCPU。

### 1.2 平台今天已经能做什么（★ T8 的起点，别重复造）

- **53 个动作 · 5 份配方**；账本 **52/52（100%）· 加权 246/246（100%）· platform 13/13 · 缺口空**；
  完整自检 **361/361**（跳过 1）；规范 **v1.8**。
- 与 T8 直接相关的现成动作：
  `host.overview` · `svc.list` · `svc.{start,stop,restart,enable,disable}` · `svc.configtest` ·
  `pkg.{installed,search,install,remove,update,outdated,rollback}` · `file.{push,pull,stat,remove,grep}` ·
  **`host.kernelparams`（只读）** · `net.{port,dns,http,ping,firewall,route,addr}` · `disk.*` ·
  `sec.{selinux,avc,cert,ssh-harden}` · `container.overview` · `host.checkup` · `kernel.log` · `log.view`
- 引擎能力：动作与配方**同一个执行引擎**（预检 → 计划 → 执行 → 自证 → 留证）；
  配方有**计划预览 / 三个反向按钮 / 热装载 / 配方批量 / 部署组回退**。

### 1.3 ★★ T7 留下的四条起跑线（★ 用户已拍板：**前两条纳入，后两条顺手做**）

| # | 起跑线（T7 结题回执 §4） | 本次处置 | 为什么 T8 绕不开 |
|---|---|---|---|
| 1 | 平台**没有 `daemon-reload` 动作** | ★ **做**（S2） | kubelet / containerd 的 **drop-in 配置**是这套环境最常见做法；没有它只能改主配置（而主配置 `remove_config` 复原不了 ⇒ 包残缺） |
| 2 | **只有"读"内核参数，没有"写 + 持久化"** | ★ **做**（S2） | 建集群要 `ip_forward` / bridge-nf / conntrack / 句柄；★ 且**改错了会锁住自己** |
| 3 | `reset-failed` 仍无动作 | 顺手做（S2） | 凡"故意失败"的演练都会在体检里长期留痕 |
| 4 | 完整自检有 **1 项显式跳过**（夹具不在场） | 顺手根治（S2 夹具 + 新动作） | 跳过 ≠ 通过 |

### 1.4 ★ S0 顺手挖出的 5 个平台缺口（全部并入 S2）

| # | 缺口 | 影响 |
|---|---|---|
| 1 | 没有"**镜像是否存在 / 可拉取**"的只读动作 | 镜像源方案只能靠人肉试，做不到"拿数据说话" |
| 2 | 没有"**读任意文件原文**"的动作（只有 `file.stat` / `file.grep`） | S3 留证 `/etc/sysctl.d/*`、`/etc/yum.repos.d/*`、`/etc/containerd/*` 时缺手 |
| 3 | 没有"**单查 systemd 单元启停态**"的动作 | 只能从 `svc.list` 的全量留证里筛，间接且笨 |
| 4 | `net.firewall` 在 **firewalld 未运行**时**整条判红**（`VERIFY_FAILED`） | "firewalld 没跑"是**结论**不是故障，现在看起来像故障 |
| 5 | 没有读 **cgroup 版本**的动作 | S4 的"cgroup v2 前提检查"缺一半 |

### 1.5 旧集群"要留证"的残留物（S3 清单来源）

`/etc/kubernetes/`（pki / manifests / kubelet.conf）· `/var/lib/etcd/` ·
`/var/lib/{kubelet,containerd}/`（含镜像缓存）· `/etc/cni/net.d` + `/opt/cni/bin` ·
`/etc/sysctl.d` + `/etc/modules-load.d` · `/etc/yum.repos.d`（含 `kubernetes` 与 `docker-ce-stable`）·
`/etc/containerd/`（含 drop-in）· master01 的 `/data/nfs` **（只读）** +
两个 StorageClass · **旧项目文档**（`github.com/xcl520-GIT/k8s-ha-cluster-lab`）。

★ 注意：master01 上有 **`git-daemon.service` 在跑**，另有 `nfs-*` / `rpc*` 系列 —— **都不在 T8 变更面内**。

---

## 2. 目标（三条主线）

| 主线 | 一句话 | 对应 |
|---|---|---|
| **1 · 平台能力补课** | 把"改错了会锁住自己"的那些动作补上：**内核参数写 + 持久化**、**`daemon-reload`**、**`reset-failed`** + 5 个只读缺口 | T7 起跑线（用户拍板纳入前两条） |
| **2 · 从停着的集群到新集群** | 留证 → 前提检查 → containerd → kubeadm → Calico → 存储类，逐段可停可验 | 总纲 §4 T8 |
| **3 · 一键到 Ready** | 把上面的段落编成**一份配方**：一次点击到三节点 Ready；**再点一次不破坏集群** | 总纲 T8 验收 |

---

## 3. 范围（做什么）

### 3.1 S0 · 现场侦察 + 开题单（★ 本文件）
只读侦察（已完成）→ 现状总表 → **最小必要清单逐项点头**（已完成，§10.2 #1）→ 本开题单。

### 3.2 S1 · 规范升 **v1.9**（★ 先规范后代码）
见 §11。**只改 `repo\docs\动作规范.md`，不碰靶机。**

### 3.3 S2 · 新动作（先过装载期校验，再真跑）
| 新动作 | 风险 | 说明 |
|---|---|---|
| `sysctl.set`（内核参数写 + 持久化） | 🟡 yellow | 现值留证 → 写 → **复读自证** → 落 `/etc/sysctl.d/` → `sysctl --system` 验证 |
| `sysctl.load-module`（模块加载 + 持久化） | 🟡 yellow | `modprobe` + `/etc/modules-load.d/`；★ **必须先加载再写 bridge-nf**（顺序错了写不进去） |
| `svc.daemon-reload` | 🟡 yellow | `systemctl daemon-reload` + **二次自证**（reload 成功 ≠ 服务真用了新配置） |
| `svc.reset-failed` | 🟡 yellow | 只清"失败状态" |
| `file.cat`（读文件原文） | 🟢 green | 路径白名单；S3 留证缺手 |
| `svc.status`（单查单元态） | 🟢 green | active/sub/enabled/unit-file 一次给全 |
| `registry.probe`（镜像可获取性） | 🟢 green | 只读；★ 六条备选源的 401/000 判读口径进规范 |
| `host.cgroup`（cgroup 版本与控制器） | 🟢 green | S4 前提检查的一半 |

★ **顺手修**：缺口 #4（`net.firewall` 在 firewalld 未运行时的判据口径）+ 完整自检的"夹具"项根治。

### 3.4 S3 · 旧集群**全量留证**
按 §1.5 清单逐项归档（目录清单 + sha256 + 原文 + etcd 快照 + 镜像清单 + PV/NFS 目录清单）。
**留证完成是 `kubeadm reset` 的唯一前置。**

### 3.5 S4 · 建集群前提检查（一次给全结论）
cgroup v2 · 内核模块（overlay / br_netfilter / nf_conntrack / ip_tables / **ipip**）·
内核参数 · swap · 端口占用 · SELinux · firewalld · **镜像源可达性** · 主机名解析 · 时间同步。

### 3.6 S5 · containerd 运行时配方
装/确认 `containerd.io` → 写 `/etc/containerd/config.toml`（**`SystemdCgroup = true`**）→
daemon-reload（★ 第一条起跑线的第一个真用例）→ 起 → **真探活**（`ctr version` + `crictl info`），幂等。

### 3.7 S6 · kubeadm 配方
控制面 `kubeadm init`（`--cri-socket` **显式**指向 containerd）→ kubeconfig →
工作节点 `kubeadm join` → 三节点 `Ready` 前的自证。

### 3.8 S7 · Calico + 存储类配方
Calico（对齐旧集群口径：**IPIP `Always`** · Pod `10.244.0.0/16` · MTU 1480）→ 存储类
（对齐 `WaitForFirstConsumer` + `Retain` 口径）。

### 3.9 S8 · 「一键到 Ready」总配方
把 S4~S7 编成一份配方；**幂等复跑**（第二次 `changed=[]` 且集群不重启）；**反例**（写坏了会红）。

### 3.10 S9 · 收口
证据收口（每条主线：正例 + 反例 + 前后对照）· 界面**真浏览器**走一遍 · 账本回填 ·
三件交接（覆盖式 + 归档式 + 总纲 §3 勾选）。

### 3.11 ★ 可能需要动的平台代码（每一处都要走"先规范后代码"）

| 文件 | 改动 | 出处 |
|---|---|---|
| `docs/动作规范.md` | 升 **v1.9**（§11） | S1 |
| `catalog/actions/*.yaml` | §3.3 的 8 个新动作 | S2 |
| `app/parsers.py` | 仅当新动作需要新解析器（**先过 §12.23 三条判定**） | S2 |
| `app/api.py` / `app/recipe.py` | 仅当配方需要新能力（例如"等待 Ready"的自证步骤） | S6~S8 |
| `catalog/recipes/k8s-*.yaml` + `catalog/templates/k8s-*` | 在建配方 | S5~S8 |

### 3.12 证据与交接

- 证据落 `repo\var\artifacts\_manual-对照证据\T8-*`（沿用 T4~T7 惯例）
- 收工三件：`开发记录\继续工作-看这里.md`（覆盖式）· `开发记录\交接\T8-K8s建集群-结题回执.md`（归档式）· 总纲 §3 勾选

---

## 4. **不做什么**（防范围失控）

| # | 不做 | 为什么 |
|---|---|---|
| 1 | **不碰 `/data/nfs`**（永远只读） | 它是旧集群的存储后端；且是用户另一个项目的现场 |
| 2 | **不启停 master01 的 `nfs-*` / `rpc*` / `git-daemon`** | 与本阶段目标无关 |
| 3 | **不改 `sshd`**（含 SSH 加固） | T7 遗留 #5 已定性：改 sshd 有自锁风险，不做"一键加固" |
| 4 | **不动 Harbor 的 9 个生产容器**及其卷 / 网络配置 | docker-01 只做镜像搬运（§10.2 #1 A8） |
| 5 | **不升内核**（仓库里有 `6.12.0-211.58.1`） | 升内核要重启 + 会改内核参数默认值；要升**单独拍板** |
| 6 | **不做 T9 的管理台功能**（节点 drain / 工作负载 / Pod 排障） | 不跨阶段抢跑 |
| 7 | 不做 T10 监控告警 / T11 交付包 | 同上 |
| 8 | **不删任何证书 / etcd 备份**，直到留证完成且用户确认 | 不可逆 |
| 9 | **不批量执行 `red`**；不给配方声明"我要批量" | 规范 §12.18（闸门只增不减） |
| 10 | **不把"只碰 `aoc-` 对象"那条老纪律搬过来** | 它对 T8 的目标**无效**（T8 动的就是集群本身） |

---

## 5. 前置条件（★ 全部满足才允许动第一台机器）

| # | 前置 | 状态 | 依据 |
|---|---|---|---|
| 1 | ★★ **用户在 VMware 里给三台各打一个 VM 快照**（还原基线） | ✅ **已打** | master01 **Snapshot7** / node01 **Snapshot4** / node02 **Snapshot4**（2026-09-26 18:46~18:47，含 4GB 内存镜像 + 增量盘） |
| 2 | 最小必要清单**逐项点头** | ✅ **全部同意（A1~A8）** | §10.2 #6 原文 |
| 3 | 镜像源路线**已定** | ✅ **主路直拉 + 内网 Harbor 兜底 + 拉取重试** | §10.2 #2 + §10.2.1 修订 #2 / #3 |
| 4 | 服务已重启到与仓库一致的版本 | ✅ 控制台在跑（`127.0.0.1:8787`），`/api/health` 报 **T8 · v0.8.0** | `96e3c22` 后重启并复验 |
| 5 | 规范 v1.9 已落（先规范后代码） | ✅ | `96e3c22` |
| 6 | 新动作已过装载期校验并可真跑 | ✅ 动作 **62** 个，`--check` 通过，离线自检 **423/423** | `225f882` / `2c4a2c6` |
| 7 | **旧集群留证完成**（`kubeadm reset` 的**唯一**前置） | ✅ 36 次留证 + 52 份原文 + 口径提取 | `2c4a2c6` · 证据 `T8-S3-*` |
| 8 | 建集群前提检查（十项一次给全） | ✅ **九项已具备**，一项（模块"写了 ≠ 加载了"）在 S5 前逐条核 | 证据 `T8-S4-*` |
| 9 | 同一时间只有一个话题在写本项目目录 | ✅ `git status` 干净，`b6b24a9` 本地 = 远端 | — |

★ **绿灯口径（已满足）**：三项前置（快照 / 清单点头 / 留证完成）全绿 ⇒ 允许执行 A1~A8 的任何一条。
★★ **S3 之前不许 `kubeadm reset`** —— 这条已经过去了；**S5 之后每一步都要逐段留证、可停可验**。

---

## 6. 产出物

| 类别 | 具体 |
|---|---|
| 规范 | `repo\docs\动作规范.md` **v1.9** |
| 动作 | §3.3 的 **8 个新动作**（含顺手修 `net.firewall` 判据） |
| 配方 | `k8s-containerd` / `k8s-init` / `k8s-join` / `k8s-calico-storage` / **`k8s-cluster`（一键到 Ready）** |
| 模板 | `catalog/templates/k8s-*`（containerd.toml · sysctl.conf · modules-load.conf · calico 清单参数 · 存储类 YAML） |
| 留证 | `T8-S3-旧集群留证-*`（etcd 快照 / 目录与 sha256 清单 / 证书清单 / 镜像清单 / PV 与 NFS 清单） |
| 证据 | `T8-S0-*`（已产）· `T8-S4-*` · `T8-S5..S8-*`（每主线：正例 + 反例 + 前后对照）· `T8-S9-*` |
| 交接 | `继续工作-看这里.md`（覆盖式）· `交接\T8-K8s建集群-结题回执.md`（归档式）· 总纲 §3 |

---

## 7. 验收标准（逐条可对照）

| # | 验收标准 | 判据（能被证伪） |
|---|---|---|
| 1 | ★★ **一次点击到 Ready** | 从"停着的旧集群"出发，点一次总配方 → **三节点 `Ready`** + `kube-system` 全 `Running`；★ 截图 + `kubectl get nodes -o wide` 原文 |
| 2 | ★★ **幂等复跑不破坏集群** | 同一配方**再跑一次** → `changed` 为空；集群仍 `Ready`；**关键 Pod 的 `RESTARTS` 没有增加**（★ 这一条才证伪得了"没破坏"） |
| 3 | ★★ **内核参数「写 + 持久化」动作** | 写前留证现值 → 写 → **复读一致** → 持久化文件存在且内容相符 → `sysctl --system` 后仍生效；★★ **反例：写非法值 / 写只读键必须红**（不能假绿） |
| 4 | ★★ **`daemon-reload` 动作** | 改 kubelet 的 drop-in → reload → kubelet **真按新配置起来**；★★ **反例：drop-in 写坏 ⇒ kubelet 起不来必须红**（修掉 T6 定性过的"drop-in 假绿"） |
| 5 | ★ **`reset-failed` 动作** | 故意失败的夹具 → 体检报红 → `reset-failed` → 体检**回归干净** |
| 6 | ★ **完整自检不再有"显式跳过"** | 夹具项做进自检（`up` → 跑 → `down` 自收），跳过数 **= 0** |
| 7 | ★ **旧集群全量留证** | §1.5 清单**逐项有文件**；etcd 快照可读；★ **留证先于 reset**（时间戳可证） |
| 8 | ★ **前提检查一次给全** | cgroup v2 / 模块 / 内核参数 / swap / 端口 / SELinux / firewalld / **镜像源** / 主机名 / 时间同步，一屏结论 + 每项"下一步" |
| 9 | ★ **镜像路线可复现** | 记录**实际用的** `imageRepository` 与 Calico 镜像的**来源 registry + tag**；★ 换人照文档能复现 |
| 10 | ★ **存储类可用** | PVC **真绑定** + Pod **真读写**（不是"对象建出来了"） |
| 11 | ★ **靶机可还原 / 回不去说清** | 给出"回到今天这个现场"的逐项路径 + ★ 明说**回不去**的（etcd 数据 / 证书 / 运行时内存态 / 旧 PV 对象） |
| 12 | ★ **账本回填（四处）** | `map.yaml` 的 `entries` / `platform.done` / `weights` / 页首时点对账；`GET /api/coverage` 实时数字 |
| 13 | ★ **自检不回退且新增** | 完整自检 ≥ 361 且新增断言（§12）；"加动作只加 YAML"哈希不变 |
| 14 | ★ **界面真走一遍** | CDP 路线（`msedge --remote-debugging-port`）截图；★ 收尾只杀自己那个 user-data-dir 的实例 |
| 15 | **三件交接齐** | 覆盖式 + 归档式 + 总纲 §3 勾选 |

---

## 8. 建议实施顺序（每步可停、每步可验）

```
S0 侦察 + 开题单              ← 已完成（本文件 + T8-S0-现状总表）
S1 规范 v1.9                  ← 不碰靶机
S2 8 个新动作 + 顺手修        ← 只在自己的机房里真跑（★ 快照之后再动真机）
S3 旧集群全量留证             ← reset 的唯一前置
S4 前提检查                   ← 只读 + 汇总
────── 以下开始不可逆 ──────
S5 containerd 配方
S6 kubeadm 配方（reset → init → join）
S7 Calico + 存储类配方
S8 一键到 Ready + 幂等 + 反例
S9 证据收口 + 界面走查 + 账本 + 交接
```

---

## 9. 技术要点与坑

### 9.1 继承下来的（**不许再犯**）

| # | 坑 | 一句话 |
|---|---|---|
| 1 | ★★ **"跑完了" ≠ "事情成了"** | 健康 / 收敛检查才是判据 |
| 2 | ★★ **代码 diff 不算证据** | 修一半也会"看着像改完了" |
| 3 | ★★ **库字段名 ≠ 接口字段名** | 中间没映射层就会静默丢数据 |
| 4 | ★★ **别取版本已不再打印的键** | 会多一个假「（无）」 |
| 5 | ★★ **别把表头算进条数** | `lsmod` 有表头 ⇒ `line_count` 差 1 |
| 6 | ★ **扩核心代码要有出处** | 先过三条判定再写规范 |
| 7 | ★ **自检自己搭的夹具自己收** | 否则 `git status` 里冒未跟踪文件 |
| 8 | ★ **回不去的要逐项说清** | 空也要写"无" |

### 9.2 T8 预判的坑（★ 开工后逐条盯着）

| # | 坑 | 预判与对策 |
|---|---|---|
| 1 | ★★ **`cri-docker` 残留会让 kubeadm 选错 CRI socket** | 三台上 `cri-docker.service` 还在（inactive）⇒ **每次 `kubeadm` 都显式 `--cri-socket unix:///run/containerd/containerd.sock`**，并在前提检查里**报出来** |
| 2 | ★★ **`br_netfilter` 没加载时 `bridge-nf-call-*` 写不进去** | `sysctl` 文件写了也会在 `sysctl --system` 时**报错**（看起来"写成功了"）⇒ **必须先 `modprobe br_netfilter` 再写**（动作里固定顺序 + 自证） |
| 3 | ★★ **drop-in 的"假绿"**（T6 定性过） | 写了 drop-in 不 `daemon-reload` ⇒ **不生效但健康检查发现不了** ⇒ 验收 #4 的反例专门打这一点 |
| 4 | ★ **Calico IPIP 需要 `ipip` 模块** | `ipip` 不会自动加载；不加载时 Calico 起得来但**跨节点 Pod 不通**（假绿）⇒ 前提检查 + 模块持久化都要带它 |
| 5 | ★ **`SystemdCgroup` 必须与 kubelet 的 `cgroupDriver` 一致** | 不一致 ⇒ 资源限制失效、Pod 状态混乱（旧集群踩过并记录在案） |
| 6 | ★ **Harbor 是 HTTP→HTTPS 308** | `http://192.0.2.60` 返回 308 ⇒ containerd 拉镜像要配 `insecure_skip_verify` / CA；**先确认它到底是哪个** |
| 7 | ★ **镜像 tag 与版本要对得上** | kubeadm 的 tag 形如 `v1.34.x`；Calico 要定**具体版本**（旧集群是 `v3.25.0`）；把"来源 registry + tag"记进账本 |
| 8 | ★ **`reset` 不删镜像缓存，但 namespace 会变** | 先记 `ctr -n k8s.io images list`（留证），**不删**（删了要重拉，而源不一定通） |
| 9 | ★ **3.6GB 内存** | 控制面 + Calico + CoreDNS 吃得住，但**不要再叠监控栈**（T10 的事） |
| 10 | ★ **旧集群的 sysctl / 模块持久化文件要**"改"**而不是"再写一份"** | 两份 `.conf` 会互相覆盖（后加载的赢）⇒ **同键只留一份**，且**只增不降** |
| 11 | ★ **`registry.aliyuncs.com` 在三台不可达**（已实测） | 任何"照抄旧集群文档"的镜像地址都会**卡住**；★ 这类地址一律**先 probe 再写进配方** |
| 12 | ★ **时间同步** | kubeadm 对时间偏差敏感；三台 `chronyd` 在跑，S4 要**核一次** |

---

## 10. 拍板记录

### 10.1 ✅ 已按"建议"固化（起草时即定，不必再问）

| # | 项 | 已采用 | 理由 |
|---|---|---|---|
| 1 | 引擎路线 | **不引新依赖、不放宽安全契约**（沿用 T5~T7） | 零依赖是这个项目的前提 |
| 2 | 集群形态 | **单控制面（1 control-plane + 2 worker）** | 只有三台；真 HA 要 3 控制面且 3.6GB×3 撑不住控制面 + 工作负载 |
| 3 | 不做自动回滚 | 回退都**人在环** | 规范 §9.2 |
| 4 | 收尾顺序 | **先留证 + 推送 GitHub → 再定是否保留集群** | ★ 与 T5~T7 的"先推送再还原"同源：代码先安全落地 |
| 5 | 靶机纪律 | 见 §10.2 #1（最小必要清单） | — |
| 6 | 不升内核 | 见 §4 #5 | 升内核会改内核参数默认值且要重启 |

### 10.2 ✅ **已拍板（2026-09-26 · 用户三轮答复）**

> 记法沿用 T5~T7 惯例：**保留"当时有哪些备选"**，只把结果标出来 —— 后人看得见权衡过程。

**第一轮（四个叉路口）**

| # | 问题 | 用户拍板 | 备选（留档） |
|---|---|---|---|
| 1 | 旧集群怎么处置 | **先全量留证 → `kubeadm reset` → 重建** | (B) 先救活看现状；(C) 不动旧集群，T8 缩成前提检查；(D) 另给靶子 |
| 2 | 靶机与白名单 | **三台全上（master01 控制面 + node01/node02 工作节点）；★ 先给"最小必要清单"，逐项点头后才动** | (B) 三台一次授权到位；(C) 先只上 node01/node02（★ 建不出集群） |
| 3 | 四条起跑线 | **纳入「内核参数写」+「`daemon-reload`」两条**；`reset-failed` 与自检夹具项**顺手做** | (B) 四条全纳入；(C) 都不做 |
| 4 | 镜像源 | 沿用阿里云源、**开工先验可达** → ★ **一验即被推翻，见第二轮 #5** | — |

**第二轮（S0 侦察完成后，三项）**

| # | 问题 | 用户拍板 | 备选（留档） |
|---|---|---|---|
| 5 | ★★ **镜像源路线**（旧路已实测走不通） | **混合路线**：k8s 组件走三台可达的 **`registry.k8s.io`**（kubeadm 默认，零配置）；**Calico 由 docker-01 从 `registry.aliyuncs.com` 拉下、推进本机 Harbor**，集群从 **Harbor** 拉 | (B) 全部走 Harbor 中转（最一致，但要先搬约十个镜像）；(C) 先做一轮可获取性实测再定（★ 已并入 §10.3 #2，仍然要做）；(D) 用户自己提供镜像 |
| 6 | ★ **最小必要清单是否整体点头** | ★ **全部同意（A1~A8）** —— 原文见下表 | (B) 有几条要改；(C) 先只批只读与平台部分 |
| 7 | ★★ **还原基线** | **用户先在 VMware 里给三台各打一个 VM 快照，再开工** —— ★ 平台**没有**虚拟化动作（属 T16），这一键只能人按 | (B) 不打快照，靠 S3 留证；(C) 只给 master01 打 |

**★ §10.2 #6 的原文（最小必要清单，用户已全部同意）**

| # | 项 | 具体范围 |
|---|---|---|
| A1 | **systemd 单元** | `kubelet` / `containerd` / `cri-docker`（旧 CRI 桥，reset 前停、之后不再启用）/ `docker`（**只许 stop·disable，不许 start**）；新增 kubelet·containerd 的 **drop-in** |
| A2 | **目录（可写）** | `/etc/kubernetes` `/etc/containerd` `/etc/cni/net.d` `/opt/cni/bin` `/etc/sysctl.d` `/etc/modules-load.d` `/var/lib/{kubelet,containerd,etcd}` `/root/.kube` `/etc/yum.repos.d`（仅改 k8s 仓库指向时）`/var/backups/aoc` |
| A3 | **内核参数（写 + 持久化）** | 只许写 `net.ipv4.ip_forward=1`、`net.bridge.bridge-nf-call-iptables=1`、`net.bridge.bridge-nf-call-ip6tables=1`、`net.ipv4.conf.all.forwarding=1`、`vm.swappiness=1`、（如需）`net.netfilter.nf_conntrack_max`；★ **只增不降**，且 §1.1 #3 里那四个**已调好的值不动** |
| A4 | **内核模块** | `overlay` `br_netfilter` `nf_conntrack` `ip_tables` **`ipip`** |
| A5 | **端口 / 端口段** | 6443 · 2379-2380 · 10250 · 10257 · 10259 · 179 · **30000-32767** |
| A6 | **允许装的包** | `kubernetes` 仓库：kubelet/kubeadm/kubectl ｜ `docker-ce-stable`：containerd.io ｜ baseos/appstream：conntrack-tools · socat · ipset · cri-tools · nfs-utils ｜ ★ **不升内核** |
| A7 | **`kubeadm reset`** | 三台各一次（清 `/etc/kubernetes` 与 `/var/lib/etcd` 的集群态）；★ 必须在 **S3 留证之后** |
| A8 | **docker-01 的新增例外** | 允许 `docker pull / tag / push`（镜像搬运与可获取性实测）+ `docker rmi` 清理试验镜像 |

**★ 红线（同一次答复合意，B/C 两组）**

| # | 红线 |
|---|---|
| B1 | `/data/nfs` **永远只读** |
| B2 | master01 的 `nfs-server` / `nfs-*` / `rpc*` / `git-daemon` 不动 |
| B3 | `sshd` 配置不改（含 SSH 加固） |
| B4 | Harbor 的 **9 个生产容器**及其卷 / 网络不动 |
| B5 | 留证完成前**不删**任何证书 / etcd 备份 |
| B6 | 不批量执行 `red`；不跨阶段（T9/T10/T11 不碰） |
| B7 | **不升内核**（除非单独点头） |
| B8 | docker-01 除 A8 外**零变更** |

**★ 回得去 / 回不去（逐项）**

- **回得去**：包（dnf，可 `history undo`）· 配置文件（平台备份 + sha256 自证）· 单元启用状态 · sysctl（原值已留证）· 内核模块（`rmmod`）
- **回不去 / 难回**：`etcd` 数据 · kubelet 证书与 kubeconfig（reset 即删）· Pod 运行时状态 · 旧 PVC/PV **对象**（数据还在 NFS 目录里，对象随 etcd 消失）
- ★ **最稳的还原 = 用户手打的三个 VM 快照**（§10.2 #7）

### 10.2.1 ★ 修订记录（★ 只有"**实测推翻了拍板**"才写这里，逐条追加）

| 日期 | 谁推翻的 | 原文（拍板） | 修订 | 还原 / 边界 |
|---|---|---|---|---|
| 2026-09-26 | T8·**S0 只读侦察** | §10.2 #4「沿用阿里云源（`registry.aliyuncs.com/google_containers`）」 | ★ 三台 **到不了** `registry.aliyuncs.com`（000 超时）；反而 **`registry.k8s.io` 可达** ⇒ 改为**混合路线**（§10.2 #5） | 仅为**只读探测**（`changed=False`）；证据 `T8-S0-镜像源可达性-*` 与 `T8-S0-镜像源备选与DNS-*` |
| 2026-09-26 | T8·**S2 多轮采样** | §10.2 #5「**混合路线**：k8s 组件走 `registry.k8s.io`，Calico 由 docker-01 从 `registry.aliyuncs.com` 拉下推入 Harbor」—— 其**前提**（"三台到不了 `registry.aliyuncs.com`、docker-01 到不了 `registry.k8s.io`"）被推翻 | ★ 每台连做 3 轮（共 9 次）复采：**只有 `registry-1.docker.io` 稳定不可达（0/9）**；`registry.k8s.io` / `registry.aliyuncs.com` / `quay.io` / `ghcr.io` 均 **7/9（可达但会抖）**；`registry.cn-hangzhou.aliyuncs.com` 与**内网 Harbor** **9/9 最稳**。⇒ **路线名义不变、做法要改**：不再需要"docker-01 搬运"作为**唯一**通路，改为「**主路直拉 + 内网 Harbor 兜底 + 拉取必须重试**」（规范 §12.28.1 五条规矩） | 仅为**只读多轮探测**（9 次 `registry.probe`，全部 `changed=False`）；证据 `T8-S2-registry多轮采样-20260926.md` |
| 2026-09-26 | T8·**S3 留证** | 上面 #2 那条"做法"里隐含的读法：**"镜像源可达性" = 这台机器到公网那些仓库通不通** | ★★ **S3 从 `/etc/containerd/certs.d/*/hosts.toml` 的原文里核到**：containerd **根本不直连** `registry.k8s.io` / `docker.io` —— 它按 `certs.d` 走加速地址（`https://m.daocloud.io/registry.k8s.io`、`https://docker.m.daocloud.io`、`https://docker.1ms.run`）。⇒ **"镜像拉不拉得下来"必须按 containerd 实际走的那条路去测**；拿"直连可达性"去推"containerd 能不能拉"是**测了一个没人用的通路**（S2 的采样本身没错，错的是**推论**）。★ 连带一处**硬伤**：`config.toml` 的 `pinned_images.sandbox = registry.aliyuncs.com/google_containers/pause:3.10.1`（7/9 会抖）⇒ **S5/S6 必须先解决沙箱镜像的来源**，且验证要问链路**最末端**（`ctr`/`crictl` 真拉到没有），不是"配置文件写对了" | 留证动作全部**只读**（`file.manifest` / `file.cat`，36 次动作 + 52 份原文，`changed=False`）；证据 `T8-S3-旧集群口径提取-20260926.md` §3.2 / §3.3 |
| 2026-09-26 | T8·**S5 真拉实测**（第三次） | 上面 #3 的**结论句**："**S5/S6 必须先解决沙箱镜像来源**" | ★★ **在链路末端量了一次，才发现这条"硬伤"当前不存在**：① `crictl pull` 那一步回的是 **`Image is up to date for sha256:cd073f4c…`** ⇒ 该镜像**早已在本地镜像库**（旧集群留下的），**全程不联网**；② 而它指向的源 `registry.aliyuncs.com/google_containers` **实测真拉得动**（用同源的真拉了一个未缓存 tag，rc=0）。<br>★★ 同时**第三次推翻"镜像路线"**：`certs.d` 的两条路**都不通** —— 原配加速 `m.daocloud.io/registry.k8s.io` = **403**（★ 有 containerd 自己的证词）；**直连 `registry.k8s.io` = 307 跳到 `*.pkg.dev` 后走 IPv6 ⇒ `network is unreachable`**（★ 根因：DNS 给了 IPv4 也给了 IPv6，`getent hosts` 第一条给 IPv6 —— 与硬约束③ 同一个坑）。⇒ ★★ **改 `certs.d` 不会让任何事变好** ⇒ **正确地不改它**（已从平台护栏检查点**逐字节还原**成进场原文；配方里 `render_certsd` / `restart_containerd` 两步**一并撤掉**）⇒ **`k8s-containerd` 一个配置文件都不改**。<br>★ **给 S6 的口径**：k8s 组件镜像走 **`kubeadm --image-repository registry.aliyuncs.com/google_containers`**（实测可拉；★ 且**旧集群缓存镜像正是这个前缀** = 实物口径），**不要走 `registry.k8s.io`**；Calico（`docker.io/*`）走原配的 `docker.m.daocloud.io`（401 活，但**必须先真拉一次**才算数）。 | 变更动作全部经 `/api/**`、全部有平台留证；反例写坏的那一份**已从备份点逐字节还原**（sha256 一致）；**唯一遗留**：`pkg.install containerd.io` 把包 **2.2.6 → 2.3.6**（★ 平台如实报了 `changed=True`，回退路径 `dnf history undo 11`）—— 证据 `T8-S5-证据总表-20260926.md`·`T8-S5-NETPATH*-*.json`·`T8-S5-REVERT-*.json`·`T8-S5-NEG*.json` |

| 2026-09-26 | T8·**S6 真跑实测** | 上面 #4 的**起始状态**："三台一个**停着的**完整集群"（S0/S4 实测：6443/2379/10250/179 **全空闲**，`kubelet` 在 `activating`） | ★★ **S5 起了 containerd 之后，那个"停着的"集群自己活了**：`kubelet` 拿到运行时后把上一版控制面拉了起来 —— 实测 **6443/2379/2380/10250/10257/10259/179 全部在听**，`etcd` / `kube-apiserver` / `kube-controller-manager` / `kube-scheduler` / `calico-node` / `kube-proxy` / `coredns` / `metrics-server` **全在跑**，三节点 `Ready`（age **62d**），**26 个工作负载 + 13 个 PV/PVC 对象好端端地在里面**。<br>⇒ **S4 的"端口全空闲"结论从 S5 那一刻起就过期了**；★ 也**推翻了"reset 一个死集群"这个默认心理模型** —— 这次是**拆一个正在跑的集群**，比预想的重。<br>★ **能拆的依据不变**：`kubeadm reset` 的前置是**留证完成**（S3 已全部落盘），而 A7 明确授权了三台各一次。<br>★★ **顺带白捡了一份 S3 拿不到的证据**：S3 只能读**磁盘**；现在集群活着，于是用新动作 `k8s.nodes`（只读）把 **`kubectl get nodes -o wide` / `kube-system` 全表 / 全部 StorageClass+PV+PVC / 全部工作负载** 抄了下来 ⇒ 证据 `T8-S6-BEFORE-旧集群-活着的节点树.json` | 只读动作（`k8s.nodes`，green，`changed=False`）＋ 只读的 `net.port` / `svc.status`；★ 目标机零变更 |
| 2026-09-26 | T8·**S6 真跑实测** | §1「一次点击到 Ready」的字面读法（以及 §6 产出物里那份 `k8s-cluster` 总配方） | ★★ **"一键到 Ready"在本平台的形态是"两次点击"，不是"一次"**：① `k8s-init`（控制面一键：运行时 → 拆旧(red) → init → kubeconfig → Calico → 存储类 → 等 Ready）② `k8s-join`（工作节点一键，两台各一次）。<br>★ **为什么做不到"一次"**：**配方只在一台机器上执行**（规范 §12.0 的三层契约），而"一个集群"天然横跨三台；硬做成一次，就得让控制面上的配方去 ssh 另外两台 —— 那等于**在配方层开后门**。<br>★ **第三次点击同一个 `k8s-init`（幂等复跑）才是"三节点一起 Ready"的那一屏** —— 它同时兑现验收 #2（`changed` 为空 + `RESTARTS` 不增）与验收 #1 的判据原文（`kubectl get nodes -o wide`）。★★ **这是口径修正，不是缩水** | — |
| 2026-09-26 | T8·**S6 真跑实测** | §3.8「Calico（IPIP `Always` · Pod `10.244.0.0/16` · **MTU 1480**）→ **存储类**（对齐 `WaitForFirstConsumer` + `Retain` 口径）」 | ★ **MTU**：#10.3.1 第 3 条已经把这条改成了**按实物 `mtu = 0`** ⇒ 本配方照实物。<br>★★ **存储类的后端必须换**：旧集群那两条 StorageClass（`nfs-dynamic` 默认 + `nfs-storage-class`）**都指向 `/data/nfs`**，而 `nfs-dynamic` 会往导出根目录里**新建子目录** —— 那是**红线 B1（`/data/nfs` 永远只读）**。⇒ 我们**不复制 `nfs-dynamic`**，改按 **`nfs-storage-class` 的形状**（`no-provisioner` + `Retain` + `WaitForFirstConsumer` **逐项同参**）做一条 `aoc-local`，**只把后端从 NFS 换成节点本地目录**（`/opt/aoc-k8s/pv01`，本工作台自己的目录）。<br>★ **两项差异如实写明**：① 后端不是 NFS；② 访问模式由 `RWX` 变成 `ReadWriteOnce`（本地卷的语义）。<br>★ **判据不是"对象建出来了"**：一个 **Job** 把宿主机预先写进卷里的那份读出来、写成 receipt，再自己写一份文件；两样都留在宿主机上，**平台用自己的手（`file.cat`）在宿主机上读它们** ⇒ 读、写**两个方向各一份证** | 上述对象**全部由模板渲染 + `k8s.apply` 落到集群**，不碰 `/data/nfs`、不碰 `nfs-*`/`rpc*` |
| 2026-09-26 | T8·**S6 真跑实测** | §3.7「控制面 `kubeadm init` … → 工作节点 `kubeadm join`」里隐含的**参数来源** | ★ 规范 §12.32.3 第 4 条要求"`token` 与 CA 指纹由**参数**给"，但**没说这两样从哪来**。实测定下来：**从 `kubeadm init` 自己打印的那段 join 命令里抄**（平台把它如实留证在任务里）—— ★★ 而不是"上一步输出喂下一步"（那正是这一条要禁的管道）。<br>★ 代价照旧如实写：**token 会进报告与配置** ⇒ 只适用于实验环境；换生产走"短期 token + 手动确认" | 只读地读任务原文（`GET /api/tasks/<id>`） |

### 10.3 ⏳ 开工后第一件要做的事（不用拍板，但必须先做）

> 每条都给了**预期**，实测只是去**确认**或**推翻**它。

| # | 要确认什么 | 预期 | 如果被推翻意味着什么 |
|---|---|---|---|
| 1 | ★★ **三个 VM 快照已打**（用户回话） | 已打 | 未打 ⇒ **不执行 A1~A8 任何一条** |
| 2 | ★★ **镜像到底拉不拉得下来** | `registry.k8s.io` 上有 k8s 1.34 的 tag；`registry.aliyuncs.com/google_containers` 仍有内容（★ 未验证） | 若 `/google_containers` **已空/不存在** ⇒ Calico 的搬运源要改（备选：`registry.cn-hangzhou.aliyuncs.com` / `ghcr.io`），并把"来源 registry"记进账本 |
| 3 | ★ **docker-01 能不能真的 pull + push 进 Harbor** | 能 | 若不能 ⇒ 混合路线退回"全部走 Harbor 中转"或"用户提供镜像" |
| 4 | ★★ **`/etc/sysctl.d` / `/etc/modules-load.d` 里旧集群到底写了什么** | 至少一份含 `ip_forward` / `swappiness` | 若**没有**持久化文件（只是运行时值）⇒ 更说明"写 + 持久化"这条能力**本来就缺**，且**重启就丢** |
| 5 | ★ **`/etc/containerd/config.toml` 现在长什么样**（`SystemdCgroup` 对不对） | 应该是 `true`（旧集群记录过） | 若不对 ⇒ S5 的配方要多一项修正，且要解释"旧集群怎么跑起来的" |
| 6 | ★ **`cri-docker` 的 socket 路径**（`/var/run/cri-dockerd.sock`） | 存在 | 它决定 `--cri-socket` 要**排除**哪个路径 |
| 7 | ★ **Harbor 的目录里到底有什么**（要认证，需要一个新动作或用户在 UI 里看） | 只有 `library/*` 自建镜像 | 决定"搬运"是**从零搬**还是**补几个** |
| 8 | ★ **`net.firewall` 判红的真因**（缺口 #4） | firewalld 装了但没跑 ⇒ `firewall-cmd` 报错 | 确证后按"没跑是结论"改判据（S2） |

---

### ★ 10.3.1 S3 实测答复（2026-09-26 · 逐条对上表）

| # | 预期 | 实测 |
|---|---|---|
| 1 | 三个 VM 快照已打 | ✅ master01 **Snapshot7** / node01 **Snapshot4** / node02 **Snapshot4**（2026-09-26 18:46~18:47，含 4GB 内存镜像） |
| 2 | `registry.k8s.io` 上有 k8s 1.34 的 tag | ✅ 旧集群就在用 **v1.34.10**（S0 侦察）；★ 而且 `certs.d` 显示它当年是**经 `https://m.daocloud.io/registry.k8s.io` 拉的**（见 §10.2.1 #3） |
| 3 | docker-01 能不能真 pull + push 进 Harbor | ⏳ **未验**（S3 用不上它；★ 路线已从"必经"降为"**兜底**"） |
| 4 | `/etc/sysctl.d` 里旧集群到底写了什么 | ✅ **两份**：`k8s.conf`（三台一致）+ `99-k8s-tuning.conf`（master01，**19 个键**，含 `nf_conntrack_max=1048576`）—— 原文已逐份留证 |
| 5 | `/etc/containerd/config.toml` 的 `SystemdCgroup` | ✅ **`true`**（与 kubelet 口径一致）；★ 另核到 `imports = ['/etc/containerd/conf.d/*.toml']` —— **包自带的 drop-in 钩子**，S5 可以不动主配置 |
| 6 | `cri-docker` 的 socket 路径 | ✅ 三台都有 `cri-docker.service`（inactive）；⇒ **显式 `--cri-socket` 的做法照旧保留**（预判坑 #1 不变） |
| 7 | Harbor 目录里有什么 | ⏳ **未验**（同上，已从"必经"降为"兜底"） |
| 8 | `net.firewall` 判红的真因 | ✅ **S2 已修**：真因是 `firewall-cmd --state` 把 `not running` 写到 **stderr**（rc=252）而 `raw` 只读 stdout ⇒ 自证必败；改用 `systemctl is-active`（规范 §12.29 / 检查清单 79） |

★ 另外三条**给 S5~S7 的实测口径**（从实物抄下来的，不是猜的）：

1. **A4 的五个模块已经全在 `/etc/modules-load.d/k8s.conf` 里**（还多一个 `ip_tunnel`）⇒ S4 要核"**写了 ≠ 加载了**"；
   配方**不要再写一份**（§12.24.2 只增不降）。
2. **A3 里「(如需) `nf_conntrack_max`」用不上** —— 旧集群已调到 `1048576`，**不碰**。
3. **Calico 的 `mtu` 是 0**（不是预判的 1480）⇒ S7 按实物对齐：`mtu = 0` + `portmap` + `bandwidth`。

### ★ 10.3.2 S4 前提检查结论（一屏 · 2026-09-26）

> 通道：42 次 `POST /api/batch/run`（十个只读动作 × 3 台）｜★ 未直连 ssh｜★ 目标机零变更。
> 全文：`repo\var\artifacts\_manual-对照证据\T8-S4-前提检查结论-20260926.md`（+ 逐项 JSON）

| # | 前提 | 实测（三台一致） | 判 | 下一步 |
|---|---|---|---|---|
| 1 | cgroup v2 | `/sys/fs/cgroup` = **`cgroup2fs`**；v1 挂载（无） | ✅ | 与 containerd 的 `SystemdCgroup=true` 对口，**不要改** |
| 2 | swap | 共 **0MB** / 已用 0；vmstat `si/so=0` | ✅ | 无需 `swapoff`；★ 有人加了 swap ⇒ kubelet **拒绝启动** |
| 3 | 内核参数 | `ip_forward=1` `swappiness=1` `somaxconn=32768` `file-max=2097152` | ✅ 已调好 | ★ **只增不降**（§12.24.2）：一个都不改 |
| 4 | 内核模块 | master01 **83** 个；`modules-load.d/k8s.conf` 已含 `overlay/br_netfilter/ipip/ip_tunnel/nf_conntrack` | ⚠️ **要核"写了 ≠ 加载了"** | S5 前逐条对；★ `ipip` 不加载 ⇒ 跨节点 Pod 不通（**假绿**） |
| 5 | 端口占用 | ★ **6443/2379/2380/10250/10257/10259/179 全空闲**（master01 的 25 个监听全是 `rpc*`/`chronyd`/`git-daemon`，属**红线 B2**） | ✅ | 新端口不许撞它们 |
| 6 | SELinux | **Permissive**，且与 `/etc/selinux/config` **一致**（没有"临时 setenforce 0"的坑） | ✅ | 与 `enable_selinux=false` 对口 |
| 7 | firewalld | 单元 **inactive**，zone / 规则全（无） | ✅ 结论不是故障（§12.29） | 端口不通**先查原始 nftables/iptables** |
| 8 | 主机名解析 | `/etc/hosts` 三台都含 `.11/.12/.13/.60` | ⚠️ **有一处要盯** | ★★ `getent hosts` 第一条给 **IPv6 link-local** ⇒ `--control-plane-endpoint` **写 IPv4 地址，别写主机名** |
| 9 | 时间同步 | 同步 **yes** / NTP **yes**；偏差 **0.00067 秒** | ✅ | 每次 init/join 前重跑；> 1s 先修时间 |
| 10 | 镜像源 | `registry.k8s.io`/`registry.aliyuncs.com`/`cn-hangzhou`/`quay.io` = **401**；★ **`ghcr.io` 本轮 000**；`registry-1.docker.io` **000**；Harbor **308** | ⚠️ | ★ 401 = **仓库活着**；000 ≠ 没有这个镜像。★ **`ghcr.io` 从 S2 的 7/9 掉到 000** ⇒ 拉取**必须带重试 + 兜底** |

★ 三类单元的启停态（三台逐字相同）：`kubelet` = **activating/auto-restart**（S5 起来运行时会自愈）·
`containerd` = **inactive + disabled**（★ S5 要 enable + 起）· `cri-docker` = inactive + disabled
（★★ 预判坑 #1 坐实：**每次都要显式 `--cri-socket`**）· `docker` = inactive + disabled（不用动）。

**结论**：**九项已具备、一项（模块"写了≠加载了"）在 S5 前逐条核；可以进 S5。**

---

## 11. ★ 规范 v1.9 要写什么（S0 · 先规范后代码）

| 子节 | 内容 |
|---|---|
| §12.x | ★★ **内核参数的「写 + 持久化」**：三件事必须成套 —— ① **现值留证** ② 写入 + **复读自证** ③ 落到 `/etc/sysctl.d/` 且 `sysctl --system` 后仍生效；★ **只增不降**（已调好的键不许改回去）；★ **非法值/只读键必须红**（判据要能证伪） |
| §12.x | ★★ **`daemon-reload` 的语义**：它是"让单元定义生效"的**必要步骤**；★ **"reload 成功" ≠ "服务真用了新配置"** ⇒ 必须配**第二重自证**；drop-in 的路径、命名与**还原**方式 |
| §12.x | ★ **`reset-failed` 的语义**：只清"失败状态"，**不改**单元定义、**不改**运行态；与"失败检出"是一对 |
| §12.x | ★ **模块加载的顺序约束**：`br_netfilter` 必须先于 `bridge-nf-call-*`（顺序写反 ⇒ 假成功） |
| §12.x | ★ **读文件原文动作的路径白名单**（`file.cat`）：哪些目录可读、哪些永远不可读（密钥类） |
| §12.x | ★ **镜像来源的记账口径**：每个镜像记「来源 registry + 仓库 + tag + 拉取方式」；★ 镜像地址**先 probe 再写进配方** |
| §12.x | 新增只读动作 `registry.probe` 的判读口径：**401 = 仓库活着**、000 = 不可达、404 = 仓库不存在；★ 与 §12.15.2 的"源不可达 ⇒ 无法判定"同族 |
| §12.x | ★ **修订** `net.firewall`：firewalld **未运行**是**结论**不是故障（不许整条判红） |
| 清单 / 断言 | 检查清单 **+N** 条、断言 **+N** 条（见 §12） |

---

## 12. ★ 自检要新增哪些断言

| # | 断言 | 证伪的是 |
|---|---|---|
| 1 | `sysctl.set` **写非法值必须红** | "写进去了就算成功" |
| 2 | `sysctl.set` 写完**复读必须一致**，且持久化文件内容与期望值相同 | "以为写进去了" |
| 3 | `sysctl.set` 对**已在期望值**的键 ⇒ 幂等（`changed=False`） | 重复执行造成无谓变更 |
| 4 | `svc.daemon-reload` 必须**存在**且能被真调用 | 起跑线 #1 落空 |
| 5 | `svc.reset-failed` 跑过之后，`svc.list` 的"失败数"必须为 0 | "清了但没真清" |
| 6 | 完整自检 **不再有 `<skip>`**（夹具项自收） | 起跑线 #4 落空 |
| 7 | `file.cat` 对**白名单外**路径必须**拒绝**且说明原因 | 路径白名单形同虚设 |
| 8 | `registry.probe` 的 401/000 判读与文档一致 | 判据与实现不一致 |
| 9 | "**加动作只加 YAML**"哈希仍为 **0 变化** | 引擎被改坏 |
| 10 | 配方装载期：`k8s-*` 配方里**零命令/零表达式** | 声明式被破坏 |

---

---

## 13. ★ 开题语（**可直接复制**；下次接着做 T8 时粘这一段）

> 用途：新开话题/会话时，把下面框里的整段发出去 —— 助手会先读三件套、**先复述再动手**。
> ★ 它自带「四条硬约束」与「红线」，所以**不必再翻别的地方**。

~~~~
接着做 **T8 · K8s 建集群**（第三阶段）。

先读三件（**读完先复述目标/验收/不做什么，再动手**）：
1. `00-项目总纲与路线图.md`
2. `开发记录\继续工作-看这里.md` —— ★ 重点 §一（T8 进度 + 四条硬约束）
3. `阶段开题单\T8-K8s建集群.md` —— ★ 重点 §0.2 进度一屏、§10.3.1/§10.3.2 实测口径、§7 验收

现状一句话：三台 Rocky 10.2（`.11` 控制面 / `.12` / `.13` 工作节点），
**停着的旧集群已全量留证（S3）、前提检查九项已具备（S4）** ⇒ `kubeadm reset` 前置已满足。
**从 S5（containerd 运行时配方）接着做，一路做到 S9**。

规矩（沿用，不许省）：
· 先规范后代码；改了 `app\` **必须重启服务**再验证；
· 验证走 `/api/**`（与界面同一套），**不许直连 ssh**；
· `red` 的手输确认词**只能由人输入**；★ 代码 diff 不算验收证据，要真跑出终态；
· 判据必须能被证伪（"写坏了会红"是选写法的唯一标准）；回不去的要逐项说清（空也要写"无"）；
· 留证落 `repo\var\artifacts\_manual-对照证据\T8-*`（该目录按 .gitignore 不入库）。

★★ 四条硬约束（S3/S4 实测得到）：
① 内核参数/模块**只增不降、一"键"一文件**（`/etc/sysctl.d/99-aoc-<键>.conf`；
   ★ `nf_conntrack_max` 旧集群已调到 1048576 ⇒ A3 里"(如需)"那条**不碰**；
   ★ node02 上已有 3 份 S2 写的 `99-aoc-*.conf`，别覆盖）；
② 每次 kubeadm **显式 `--cri-socket unix:///run/containerd/containerd.sock`**
   （三台都有 `cri-docker.service`，不排除会挑错运行时）；
③ `--control-plane-endpoint` **写 IPv4 地址**（实测 `getent hosts` 第一条给 IPv6 link-local）；
④ 镜像拉取**必须带重试 + 兜底**：containerd 走 `/etc/containerd/certs.d` 的加速
   （`m.daocloud.io` 等），不直连 `registry.k8s.io`/`docker.io`；
   ★ 一处硬伤要先解决：`config.toml` 的
   `pinned_images.sandbox = registry.aliyuncs.com/google_containers/pause:3.10.1`（会抖），
   且验证要问链路**最末端**（`ctr`/`crictl` 真拉到没有），不是"配置文件写对了"。

红线：`/data/nfs` 永远只读 · master01 的 `nfs-*`/`rpc*`/`git-daemon` 不动 · `sshd` 不改 ·
Harbor 9 个容器不动 · 留证完成前不删证书/etcd 备份 · **不升内核** · `red` 不批量。

收工三件：覆盖式更新「继续工作-看这里」+ 归档式「T8-结题回执」+ 总纲 §3/§4 勾选。
~~~~

## 附：T8 的一句话总结

> **T7 把"在装好的东西上安全地动手"的规矩补齐了；T8 要做的，是把这套工作台的手，第一次伸到
> "改错了会锁住自己"的地方 —— 内核参数、容器运行时、集群引导。**
> 所以本话题的验收不止"集群起来了"，还有：
> **写错了必须红**（内核参数 / drop-in）、**再点一次不许坏**（幂等）、**回不去的要逐项说清**（etcd / 证书 / 内存态）。
> ★ 而第一件事不是敲命令，是**先给三台各打一个快照**。
