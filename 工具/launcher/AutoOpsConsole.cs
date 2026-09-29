/* AutoOpsConsole.exe · 一键启动器（T14 期间由用户提出，2026-09-27）
 *
 * ★ 为什么要它：原来的启动方式要记三条命令（cd / 环境变量 / python -m app.server），
 *   而且**窗口一关服务就没了**、**起没起来看不出来**、**旧进程占着端口也不知道**。
 *   用户的抱怨原话：「这样的使用方式太复杂了，需要设计一个 .exe 启动」。
 *
 * ★ 它做六件事（这是"设计"，不是"包一层命令"）：
 *   ① 幂等：已经在跑 ⇒ **不重复起**，直接开浏览器
 *   ② 认人：端口被占着但**不认 /api/auth/ping** ⇒ 那是旧版本（或别的程序）—— 
 *      是**我们自己的旧控制台**就自动换掉；**不是我们的**就拒绝动手并说清原因
 *   ③ 找解释器：AOC_PYTHON 环境变量 → PATH 上的 python → 常见安装位置
 *   ④ 起服务：**不依赖任何窗口**（cmd 包装 + 日志重定向到 var\logs\），
 *      环境变量 PYTHONIOENCODING=utf-8 一并带上
 *   ⑤ 等就绪：轮询 **免鉴权**的 `/api/auth/ping`（★ 正好用上它的"只有它免鉴权"这个性质），
 *      而不是"睡 3 秒就开浏览器"
 *   ⑥ 开浏览器；★ **失败时把窗口留住**并打印 stderr 末尾几行（成功时不留窗口）
 *
 * ★ T18 · S8 补的第 ⑦ 件（"结论两用"那条规矩的**收口**）：
 *   ⑦ **结论只发一次**：子命令只**记**结论（state / pid / 版本 / 错误），
 *      由 `Main` 在**唯一出口**发那一行 JSON，且**字段固定**（没有的给 null）。
 *      ★ 之前是"`status` 自己发、别的走兜底" ⇒ `stop` / `restart` / `shortcut` /
 *      失败的 `start` 都会**发两行**，而「恰好一行」正是脚本那一半赖以成立的东西。
 *      ★ 同时对齐了三件同族的事：`start` 撞上"别人的程序"给**退出码 3**（表里是这么写的）·
 *      `--json` 下**不弹浏览器**（与"不留窗口/不等按键"同一条）·
 *      `AOC_SHORTCUT_DIR` **真的被读**（此前帮助里承诺了它，代码里没有）·
 *      显式 `--port` **不再被 `AOC_PORT` 反超**（命令行 > 环境变量 > 默认值）。
 *
 * ★ T18 · S8 接下 A 级真跑又补的四条（**两条是"报告说了假话"，一条是"崩了"，一条是"抢文件"**）：
 *   ⑧ **拉起子进程不继承任何句柄**（`CreateProcess(bInheritHandles = FALSE)`）——
 *      否则 `cmd.exe` 会攥着调用者的 stdout ⇒ **用管道收输出的脚本永远等不到 EOF**。
 *   ⑨ **日志文件名带上端口**（`console-<端口>.{out,err}.log`）—— 一个端口一个实例，一个实例一组日志。
 *      现场：两个实例抢同一个 `console.out.log` ⇒ **后起的那个被静默掐死**（错误码 `start_timeout`、
 *      白等 138 秒），因为 `cmd` 打不开重定向目标、**子进程根本没被拉起来**。
 *   ⑩ **拉起前一秒确认"日志写得进去"** —— 把上面那条从"138 秒的假结论"变成"1 秒的真话"。
 *   ⑪ 三条**不许说假话 / 不许崩**的小修：`--logdir` 指到一个**已存在的文件**不再崩（原来是
 *      未捕获异常、退出码 `0xE0434352`）；超时**分开报**「**没起来**」与「**起来了不回应**」。
 *
 * ★ 用法：
 *     双击                              → 启动（已在跑则开浏览器）
 *     AutoOpsConsole.exe stop           → 停止
 *     AutoOpsConsole.exe restart        → 重启
 *     AutoOpsConsole.exe status         → 只看状态，什么都不做
 *
 * ★ 它**不碰**项目代码、不落任何凭据 —— 令牌不落盘那条纪律它也守（它根本不管口令）。
 *
 * 编译（本机自带 csc，无需安装任何东西）：
 *   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /target:exe ^
 *       /out:"..\AutoOpsConsole.exe" AutoOpsConsole.cs
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

internal static class AutoOpsConsole
{
    // ★★ T18 · S2（§12.143）：端口 / 日志目录**可注入**。
    //   为什么这不是"功能"，而是"判据的地基"：判据要能在**临时端口 + 临时目录**里
    //   跑交付物**真身**，而不动到用户此刻正在用的那一个控制台
    //   —— 本项目既有硬口径「**判据不许伤到环境**」（T17 §一.4 第 4 条）。
    //   ★ 默认值仍然是**给界面看的**：脚本里要**点名**（`--port` / `AOC_PORT`）。
    //   ★ 平台侧本来就认 `python -m app.server --port N`（server.py 第 505 行起），
    //     所以这一条**不需要改 repo\app\** —— 它只是"把已有的能力用起来"。
    private const int DefaultPort = 8787;
    private const int ReadyTimeoutSec = 45;

    private static int Port = DefaultPort;
    // ★ T18 · S8：记下"端口是不是**命令行点名给的**"。
    //   现场：兜底条件原来只写了 `Port == DefaultPort` ⇒ 显式 `--port 8787` 又设了
    //   `AOC_PORT=9999` 时，**环境变量反超命令行** —— 与 S2 自己定的口径
    //   「命令行 → 环境变量 → 默认值」相反（实测坐实：`--port 8787` ＋ `AOC_PORT=9999` ⇒ 生效的是 9999）。
    private static bool _portFromCli = false;
    private static string Url = "http://127.0.0.1:" + DefaultPort + "/";
    private static string _logDirOverride = null;   // --logdir / AOC_LOGDIR
    // ★ T18 · S5：快捷方式落点也可注入（--shortcut-dir / AOC_SHORTCUT_DIR）。
    //   为什么第 5 次重复同一个理由：**判据不许伤到环境** —— 不给这个口子，
    //   测"建 / 撤"就只能往用户**真的桌面**上写东西。
    private static string _shortcutDirOverride = null;
    private static string _sub = "";                // 第二个位置参数（如 `shortcut add` 的 add）

    // ★★ T18 · S3（§12.141 规矩 2）：结论要**两用** —— 给人看的是人话，
    //   给脚本看的是**退出码 ＋ 一行 JSON**。缺任何一半都不算交付：
    //   只有人话的，没法被断言；只有退出码的，人看不懂。
    private static bool JsonOut = false;
    private static TextWriter _raw = null;   // 真 stdout（JSON 从这里出去；在 Main 里赋值）

    // 退出码表（★ 给脚本读的那一半 —— 也写进 启动器-说明.md）
    private const int RC_OK = 0;           // 在跑，且是我们的控制台
    private const int RC_FAIL = 1;         // 命令本身失败
    private const int RC_NOT_OURS = 3;     // 端口有监听，但它不是我们的控制台
    private const int RC_NOT_RUNNING = 4;  // 没在监听（没在运行）
    private const int RC_STALE = 5;        // 在跑，但**跑着的不是磁盘上那一版**（T13 那个坑）

    // ★★ T18 · S8（「结论两用」这条规矩的**收口**）：**结论只发一次**。
    //   现场（S8 真跑取数照出来的）：`--json` 的「**恰好一行**」此前**只在 `status` 上成立** ——
    //   `stop` / `restart` / `shortcut` / 失败的 `start` 都是**两行**（子函数发一次，
    //   `Main` 末尾又兜底发一次），而且两行**字段还不一样**。
    //   那意味着："读第一行"能跑，但「恰好一行」这条**纪律**已经没人守了 ——
    //   而它正是"给脚本看的那一半"赖以成立的东西（脚本没法说"我读第二行"）。
    //   ★ 修法：子函数只**记**结论（state / pid / 版本 / 错误），由 `Main` 在**唯一出口**
    //     发那一行，**字段固定**（没有的给 null，不给"这一行没有那个键"）。
    private static bool _emitted = false;
    private static string _state = null;   // running / running_stale / not_running / ours_but_old / not_ours / error
    private static List<int> _pids = new List<int>();
    private static string _vVer = null, _vStage = null, _vCfg = null;   // 跑着那一版
    private static string _dVer = null, _dStage = null;                 // 磁盘那一版
    private static string _errWhat = null, _errWhy = null;
    private static string _browser = null;  // opened / suppressed（★ `--json` 下不许弹，见 OpenBrowser）
    private static readonly List<string> _extra = new List<string>();

    /// <summary>子命令特有的字段（如 `shortcut` 的 made/bad）—— 统一由 `EmitFinal` 拼进去。</summary>
    private static void Extra(string key, string jsonValue) { _extra.Add("\"" + key + "\":" + jsonValue); }

    /// <summary>★ T18 · S4：磁盘上的"我是谁"。
    /// ★★ 只认 `repo\app\__init__.py` 的两个常量 —— 那里是**唯一来源**（不另造一份）。</summary>
    private static void ReadDiskVersion(out string ver, out string stage)
    {
        ver = null; stage = null;
        try
        {
            string f = Path.Combine(_repo, "app", "__init__.py");
            if (!File.Exists(f)) return;
            string t = File.ReadAllText(f, Encoding.UTF8);
            Match mv = Regex.Match(t, "__version__\\s*=\\s*\"([^\"]+)\"");
            Match ms = Regex.Match(t, "__stage__\\s*=\\s*\"([^\"]+)\"");
            if (mv.Success) ver = mv.Groups[1].Value;
            if (ms.Success) stage = ms.Groups[1].Value;
        }
        catch { }
    }

    private static string J(string s)
    {
        if (s == null) return "null";
        return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"")
                       .Replace("\r", "").Replace("\n", "\\n") + "\"";
    }

    private static void Emit(string json)
    {
        if (_raw == null) _raw = Console.Out;
        _raw.WriteLine(json);
        _raw.Flush();
    }

    private static string PidsJson()
    {
        return "[" + string.Join(",", _pids.Select(x => x.ToString()).ToArray()) + "]";
    }

    /// <summary>
    /// ★★ T18 · S8：**唯一的一个发口**。`--json` 模式下，stdout 上只有这一行。
    /// ★ 字段**固定**（没有的给 null）—— 脚本才敢"按键取值"，而不是"先看这一行有没有那个键"。
    /// </summary>
    private static void EmitFinal(string mode, int rc)
    {
        if (!JsonOut || _emitted) return;
        _emitted = true;
        if (_state == null) _state = (rc == RC_OK ? "ok" : "error");
        var sb = new StringBuilder();
        sb.Append("{\"ok\":").Append(rc == RC_OK ? "true" : "false");
        sb.Append(",\"action\":").Append(J(mode));
        sb.Append(",\"port\":").Append(Port);
        sb.Append(",\"port_source\":").Append(J(Port == DefaultPort ? "default" : "injected"));
        sb.Append(",\"state\":").Append(J(_state));
        sb.Append(",\"pid\":").Append(PidsJson());
        sb.Append(",\"version\":").Append(J(_vVer));
        sb.Append(",\"stage\":").Append(J(_vStage));
        sb.Append(",\"disk_version\":").Append(J(_dVer));
        sb.Append(",\"disk_stage\":").Append(J(_dStage));
        sb.Append(",\"configured\":").Append(_vCfg == null ? "null" : _vCfg);
        sb.Append(",\"browser\":").Append(J(_browser));
        sb.Append(",\"error\":").Append(J(_errWhat));
        sb.Append(",\"reason\":").Append(J(_errWhy));
        foreach (string kv in _extra) sb.Append(",").Append(kv);
        sb.Append(",\"exit\":").Append(rc).Append("}");
        Emit(sb.ToString());
    }

    private static string _root = "";   // 项目根（含 00-项目总纲与路线图.md）
    private static string _repo = "";   // 代码根（含 app\server.py）
    private static string _logs = "";   // repo\var\logs
    /// <summary>★★ T18 · S8：`--logdir` 用不了时的原因（**不许把启动器搞崩**）。
    /// 现场：`--logdir` 指到一个**已存在的文件** ⇒ `Directory.CreateDirectory` 抛**未捕获异常**
    /// ⇒ **没有结论、没有约定退出码**（退出码是个 .NET 异常码 `0xE0434352`）。</summary>
    private static string _logDirError = null;

    private static int Main(string[] args)
    {
        TryUseUtf8Console();
        // ★ T18 · S3：先存下**真 stdout** —— `--json` 模式下人话会被丢弃，JSON 从 _raw 出去。
        //   （必须在 TryUseUtf8Console() 之后取：那一句会换掉 Console.Out。）
        _raw = Console.Out;

        // ★★ T18 · S3：`--json` **必须先被认出来**。
        //   现场：第一版把它放在下面那个参数循环里 ⇒ `status --port abc --json` 走的是
        //   循环里"遇到坏参数就 break"那条路，排在后面的 `--json` **根本没被看见**
        //   ⇒ 本该给脚本的 JSON 变成了一段人话（而脚本只能拿到退出码）。
        foreach (string a0 in args)
            if (a0 != null && a0.Trim() == "--json") JsonOut = true;

        // ★★ T18 · S2（§12.143）：先解出**注入项**，再干活。
        //   顺序：命令行 → 环境变量 → 默认值（★ 默认值最后，且要在结论里回显实际用的那个）。
        var rest = new List<string>();
        string argErr = null;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i] == null ? "" : args[i].Trim();
            if (a.Length == 0) continue;
            if (a == "--port" || a == "-p")
            {
                if (i + 1 >= args.Length) { argErr = "--port 需要一个整数"; break; }
                string v = args[++i];
                int p;
                if (!int.TryParse(v, out p) || p < 1 || p > 65535) { argErr = "--port 不是合法端口：" + v; break; }
                Port = p;
                _portFromCli = true;
            }
            else if (a == "--logdir")
            {
                if (i + 1 >= args.Length) { argErr = "--logdir 需要一个路径"; break; }
                _logDirOverride = args[++i];
            }
            else if (a == "--shortcut-dir")
            {
                if (i + 1 >= args.Length) { argErr = "--shortcut-dir 需要一个路径"; break; }
                _shortcutDirOverride = args[++i];
            }
            else if (a == "--json")
            {
                JsonOut = true;
            }
            else
            {
                rest.Add(a);
            }
        }
        if (JsonOut) Console.SetOut(TextWriter.Null);   // ★ 人话丢掉，只留那一行 JSON

        if (argErr != null)
        {
            int rc0 = Fail("参数不合法", argErr,
                        "用法：AutoOpsConsole.exe [start|stop|restart|status] [--port N] [--logdir 路径] [--json]");
            EmitFinal("(参数)", rc0);          // ★ S8：唯一发口 —— 失败路径也必须给那一行
            return rc0;
        }

        string mode = (rest.Count > 0 ? rest[0] : "start").Trim().ToLowerInvariant();
        _sub = (rest.Count > 1 ? rest[1] : "").Trim().ToLowerInvariant();

        string envPort = Environment.GetEnvironmentVariable("AOC_PORT");
        // ★ S8：只有"命令行没点名"时才允许环境变量兜底（命令行 > 环境变量 > 默认值）。
        if (!_portFromCli && !string.IsNullOrEmpty(envPort))
        {
            int p;
            if (int.TryParse(envPort.Trim(), out p) && p > 0 && p < 65536) Port = p;
            else
            {
                int rc0 = Fail("AOC_PORT 不是合法端口", envPort, "取 1~65535。");
                EmitFinal(mode, rc0);
                return rc0;
            }
        }
        // ★★ T18 · S8：`AOC_LOGDIR` 有兜底，而 `AOC_SHORTCUT_DIR` **没有** ——
        //   可 `--help` 里明明写着「也可用 AOC_SHORTCUT_DIR」。两条必须一起认账，
        //   否则那句帮助就是**假话**（S8 取数坐实：全文件只有注释与帮助里出现过这个名字）。
        if (string.IsNullOrEmpty(_logDirOverride))
            _logDirOverride = Environment.GetEnvironmentVariable("AOC_LOGDIR");
        if (string.IsNullOrEmpty(_shortcutDirOverride))
            _shortcutDirOverride = Environment.GetEnvironmentVariable("AOC_SHORTCUT_DIR");
        Url = "http://127.0.0.1:" + Port + "/";

        string why;
        if (!Locate(out why))
        {
            int rc0 = Fail("找不到项目目录",
                        why,
                        "把本程序放在 <项目根>\\工具\\ 下（它靠同级的 repo\\app\\server.py 认路）。\n" +
                        "也可以用环境变量 AOC_ROOT 指定项目根。");
            EmitFinal(mode, rc0);
            return rc0;
        }

        int rc;
        try
        {
            switch (mode)
            {
                case "stop": rc = Stop(); break;
                case "restart":
                    // ★ T18 · S4：`restart` 走**同一道**认人 —— 它不许成为绕过它的后门。
                    rc = StopChecked(false);
                    if (rc == RC_OK) rc = Start();
                    break;
                case "status": rc = Status(); break;
                case "shortcut": rc = Shortcut(_sub); break;
                case "start":
                case "": rc = Start(); break;
                case "-h":
                case "--help":
                case "help":
                    PrintHelp(); rc = RC_OK; break;
                default:
                    rc = Fail("不认识的参数：" + mode, "只支持 start / stop / restart / status。", ""); break;
            }
        }
        catch (Exception ex)
        {
            rc = Fail("启动器自己出错了", ex.GetType().Name + ": " + ex.Message,
                      "把上面这句原文发出来即可定位。");
        }
        // ★★ T18 · S8：**唯一的一个发口**，全部子命令共用（含 `status`）。
        //   此前是"`status` 自己发、别的走这里兜底" ⇒ 有四个入口会**发两行**
        //   （S8 取数坐实：`stop --json` / 失败的 `start --json` / `shortcut --json` / `restart --json`）。
        EmitFinal(mode, rc);
        return rc;
    }

    // ------------------------------------------------------------------ 认路

    private static bool Locate(out string why)
    {
        why = "";
        var tries = new List<string>();
        string env = Environment.GetEnvironmentVariable("AOC_ROOT");
        if (!string.IsNullOrEmpty(env)) tries.Add(env);

        string exeDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        tries.Add(exeDir);
        try { tries.Add(Directory.GetParent(exeDir).FullName); } catch { }
        try { tries.Add(Directory.GetParent(Directory.GetParent(exeDir).FullName).FullName); } catch { }

        foreach (string t in tries.Distinct())
        {
            if (string.IsNullOrEmpty(t)) continue;
            // 两种摆法都认：① 根\repo\app\server.py  ② 程序自己就放在 repo\ 里
            string a = Path.Combine(t, "repo", "app", "server.py");
            string b = Path.Combine(t, "app", "server.py");
            if (File.Exists(a)) { _root = t; _repo = Path.Combine(t, "repo"); }
            else if (File.Exists(b)) { _repo = t; _root = Path.GetDirectoryName(t); }
            else continue;
            _logs = Path.Combine(_repo, "var", "logs");
            // ★ T18 · S2：日志目录可注入 —— ★ 这不是"灵活"，是**防误伤**：
            //   `Start()` 会**先删掉**同名的 console-<端口>.{out,err}.log 再拉起，
            //   所以测试若沿用真日志目录，就会把**正在跑的那个控制台**的日志清掉。
            if (!string.IsNullOrEmpty(_logDirOverride)) _logs = _logDirOverride;
            // ★★ T18 · S8：这一句**原来会把启动器直接搞崩** —— 现场：`--logdir` 指到一个
            //   **已存在的文件**时 `Directory.CreateDirectory` 抛未捕获异常 ⇒
            //   **没有结论、没有约定退出码**（rc = `0xE0434352`），只剩下一条看不懂的 .NET 崩溃。
            //   ⇒ 现在只**记下原因**，由 `Start()` 在**动手之前**快速说清楚（不许白等 138 秒）。
            _logDirError = null;
            try { Directory.CreateDirectory(_logs); }
            catch (Exception ex) { _logDirError = ex.GetType().Name + ": " + ex.Message; }
            return true;
        }
        why = "试过这些位置，都没有 repo\\app\\server.py：\n  " + string.Join("\n  ", tries.Distinct().Where(x => x != ""));
        return false;
    }

    // ------------------------------------------------------------------ 探活

    private static bool IsListening()
    {
        try
        {
            using (var c = new TcpClient())
            {
                var ar = c.BeginConnect(IPAddress.Loopback, Port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(700)) return false;
                c.EndConnect(ar);
                return true;
            }
        }
        catch { return false; }
    }

    /// <summary>拿 `/api/auth/ping`（★ 唯一免鉴权的接口，正好用来判"是不是我们的控制台 + 是不是新版本"）。</summary>
    private static string TryPing()
    {
        try
        {
            var req = (HttpWebRequest)WebRequest.Create(Url + "api/auth/ping");
            req.Timeout = 2500;
            req.Method = "GET";
            req.Proxy = null;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                return sr.ReadToEnd();
        }
        catch { return null; }
    }

    /// <summary>是不是"我们自己的控制台"（哪怕旧版本）。旧版本没有 /api/auth/ping，但有 /api/health。</summary>
    private static bool LooksLikeOurConsole()
    {
        foreach (string p in new[] { "api/auth/ping", "api/health" })
        {
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(Url + p);
                req.Timeout = 2500; req.Method = "GET"; req.Proxy = null;
                using (var resp = (HttpWebResponse)req.GetResponse()) { resp.Close(); return true; }
            }
            catch (WebException wex)
            {
                // ★ 401 也算"是我们的" —— 那说明鉴权已经装上了
                var hr = wex.Response as HttpWebResponse;
                if (hr != null && (int)hr.StatusCode == 401) { hr.Close(); return true; }
            }
            catch { }
        }
        return false;
    }

    private static string VersionLine(string pingJson)
    {
        string v = Grab(pingJson, "version"), s = Grab(pingJson, "stage"), c = Grab(pingJson, "configured");
        if (v == null) return "";
        return v + " / " + s + "（口令：" + (c == "true" ? "已设置" : "★ 还没设过 —— 界面会先让你设") + "）";
    }

    private static string Grab(string json, string key)
    {
        if (string.IsNullOrEmpty(json)) return null;
        var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*\"?([^\",}]*)");
        return m.Success ? m.Groups[1].Value.Trim() : null;
    }

    /// <summary>★ T18 · S8：把「在跑」这件事**记成结论**（不再由各处自己发 JSON）——
    /// 跑着那一版的 version / stage / configured 与 PID 一起进同一个发口。
    /// ★ 顺带把**磁盘那一版**也读上：`start` 的结论里也该看得见"跑着的 vs 磁盘上的"，
    ///   否则脚本还得再跑一次 `status` 才知道（`--json` 的字段是固定的，那就别让它有名无实）。</summary>
    private static void MarkRunning(string ping)
    {
        _state = "running";
        _vVer = Grab(ping, "version");
        _vStage = Grab(ping, "stage");
        _vCfg = Grab(ping, "configured");
        ReadDiskVersion(out _dVer, out _dStage);
        _pids = ListenerPids();
    }

    // ------------------------------------------------------------------ 解释器

    private static string _pyExe = null;      // 找到的解释器（可执行文件本身）
    private static string _pyArgsPrefix = ""; // ★ 前缀参数：`py -3` 这种"启动器 + 参数"的写法
    private static int _pyMinor = 0;          // 实测到的 `Python 3.<minor>`
    private static int _pySkipped = 0;        // ★ 在它之前**跳过**了几个候选（进 `--json`，可断言）

    /// <summary>
    /// ★★ T18 · S8（可移植性收口）：**"自动找解释器"要真的自动**，而且要**问得到、说得出**。
    ///
    /// 改造前的样子（S0 §0.3 照出来的）：候选只有四条，最后的兜底是**一条硬编码的机器专属路径**
    /// （`D:\Python311\python.exe`）—— 换台机器就只能靠运气。
    /// 改造后：
    ///   ① `AOC_PYTHON`（用户点名，最高优先）
    ///   ② PATH 上的 `python` / `python3`
    ///   ③ `py -3`（Windows 官方的 **Python Launcher**，装了官方包就有；★ 它**不受**商店别名干扰）
    ///   ④ `%LOCALAPPDATA%\Programs\Python\Python3*`（"只为当前用户安装"的默认落点）
    ///   ⑤ `%ProgramFiles%\Python3*` / `%ProgramFiles(x86)%\Python3*`（全体安装的默认落点）
    ///   ⑥ 硬编码的 `D:\Python311\python.exe`（★ **留作最后的兜底**：本机解释器在这，
    ///      它**不通用**，所以排在最后，并且**只在前面全落空时才用**）
    ///
    /// ★★ 两条硬规矩：
    ///   · **必须校验版本 ≥ 3.10**（本项目的代码用了 `X | Y` 这种类型写法，3.9 跑不了）——
    ///     ★ 而且"版本太低"要**跳过并继续找**，不能当成"没找到"就完事。
    ///   · **失败时要说清试过哪些、各自为什么不合适**（「问不到」≠「不存在」）。
    /// </summary>
    private static string FindPython(out string report)
    {
        var cands = new List<string[]>();
        string env = Environment.GetEnvironmentVariable("AOC_PYTHON");
        if (!string.IsNullOrEmpty(env)) cands.Add(new[] { env, "" });
        cands.Add(new[] { "python", "" });
        cands.Add(new[] { "python3", "" });
        cands.Add(new[] { "py", "-3" });                      // ★ Windows 官方启动器

        foreach (string baseDir in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Programs\\Python",
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + "\\Python",
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + "\\Python",
                 })
        {
            try
            {
                if (!Directory.Exists(baseDir)) continue;
                foreach (string d in Directory.GetDirectories(baseDir, "Python3*").OrderByDescending(x => x))
                    cands.Add(new[] { Path.Combine(d, "python.exe"), "" });
            }
            catch { }
        }
        // ★ 最后的兜底：本机解释器（★ 不通用 —— 排在最后，且注释写清它是什么）
        cands.Add(new[] { @"D:\Python311\python.exe", "" });

        var lines = new List<string>();
        int skipped = 0;
        foreach (string[] c in cands)
        {
            string shown = c[0] + (c[1].Length > 0 ? " " + c[1] : "");
            string ver = null;
            try
            {
                // ★★ 见 RunCapture 的注释：**超时排在前面的那种写法是不作数的**。
                int ec; bool to;
                string so = RunCapture(Cli(c[0], (c[1] + " --version").Trim()), 8000, out ec, out to);
                if (to) { skipped++; lines.Add("  · " + shown + " —— 试了 8 秒没反应，跳过"); continue; }
                if (ec != 0) { skipped++; lines.Add("  · " + shown + " —— 退出码 " + ec + "，跳过"); continue; }
                Match m = Regex.Match(so ?? "", @"Python\s+(\d+)\.(\d+)");
                if (!m.Success) { skipped++; lines.Add("  · " + shown + " —— 有输出了，但不像是 python（" + Trunc(so, 60) + "），跳过"); continue; }
                ver = m.Groups[1].Value + "." + m.Groups[2].Value;
                int major = int.Parse(m.Groups[1].Value), minor = int.Parse(m.Groups[2].Value);
                if (major != 3 || minor < 10)
                {
                    // ★ "版本太低"要**说清**，不能悄悄跳过 —— 这正是"问得到"的那一半
                    skipped++;
                    lines.Add("  · " + shown + " —— 是 Python " + ver
                              + "，但本项目要 **3.10+**（代码里用了 `X | Y` 类型写法），跳过");
                    continue;
                }
                _pyExe = c[0];
                _pyArgsPrefix = c[1];
                _pyMinor = minor;
                _pySkipped = skipped;
                lines.Add("  · " + shown + " —— ✅ Python " + ver);
                report = string.Join("\n", lines.ToArray());
                return c[0];
            }
            catch (Exception ex)
            {
                // ★ 商店别名（Length=0 的重解析点）在这里就是"起不来"—— 如实记一句
                skipped++;
                lines.Add("  · " + shown + " —— 起不来（" + ex.GetType().Name + "），跳过");
            }
        }
        _pySkipped = skipped;
        report = string.Join("\n", lines.ToArray());
        return null;
    }

    private static string Trunc(string s, int n)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " ").Trim();
        return s.Length <= n ? s : s.Substring(0, n) + "…";
    }

    // ------------------------------------------------------------------ 起

    private static int Start()
    {
        Console.WriteLine("── auto-ops-console 启动器 ──");
        Console.WriteLine("  项目根：" + _root);
        // ★ T18 §12.143 规矩 4：结论里要**回显"这次动的是哪个端口"**（第二只眼睛）。
        Console.WriteLine("  端口：" + Port + (Port == DefaultPort ? "（默认）" : "（★ 注入）")
                          + "   日志目录：" + Rel(_logs));

        if (IsListening())
        {
            string ping = TryPing();
            if (ping != null)
            {
                Console.WriteLine("  ✅ 已经在运行（" + VersionLine(ping) + "）—— 不重复启动，直接开浏览器。");
                MarkRunning(ping);
                OpenBrowser();
                return RC_OK;
            }
            if (LooksLikeOurConsole())
            {
                Console.WriteLine("  ⚠️  " + Port + " 被**旧版本**占着（不认 /api/auth/ping）—— 先换掉它。");
                int rc = StopChecked(true);          // ★ 已经认过人了 ⇒ 允许换掉
                if (rc != RC_OK) return rc;
                // ★ T18 · S4：不再靠"睡 1.2 秒"猜它退干净了 —— 等端口**真的**释放。
                for (int i = 0; i < 20 && IsListening(); i++) Thread.Sleep(300);
            }
            else
            {
                // ★★ T18 · S8：退出码**与表对齐**（3 = 端口有监听但不是我们的）。
                //   此前这里走的是 `Fail()` ⇒ 给 1，脚本分不出"别人占着"和"参数错"。
                return FailCode(RC_NOT_OURS, "not_ours",
                            Port + " 被别的程序占着",
                            "它既不认 /api/auth/ping 也不认 /api/health —— 不是本控制台。",
                            "先查是谁占用：  netstat -ano | findstr :" + Port + "\n" +
                            "★ 本启动器**不动别人的进程**（那是纪律，不是能力不足）。");
            }
        }

        string pyReport;
        string py = FindPython(out pyReport);
        if (py == null)
        {
            // ★★「问不到」≠「不存在」：**试过哪些、各自为什么不合适**，一条不许省。
            return FailCode(RC_FAIL, "no_python",
                        "找不到可用的 python 解释器（本项目要 **3.10+**）",
                        "试过这些位置 —— **每一个都写清了为什么不行**：\n" + pyReport,
                        "装了 Python 3.10+ 之后重试；或用环境变量**点名**：\n"
                        + "  set AOC_PYTHON=D:\\path\\to\\python.exe\n"
                        + "★ 也可以直接跑 `工具\\首次使用-安装.cmd`，它会替你把这一圈查一遍。");
        }
        Console.WriteLine("  解释器：" + py + (_pyArgsPrefix.Length > 0 ? " " + _pyArgsPrefix : "")
                          + "（Python 3." + _pyMinor + "）"
                          + (_pySkipped > 0 ? "　★ 在它之前**跳过了 " + _pySkipped + " 个候选**（详见 --json）" : ""));
        // ★★ 把"用哪个解释器、跳过几个"也记进结论 —— 脚本才查得到它（可断言）。
        Extra("python", J(py + (_pyArgsPrefix.Length > 0 ? " " + _pyArgsPrefix : "")));
        Extra("python_minor", _pyMinor.ToString());
        Extra("python_skipped", _pySkipped.ToString());

        // ★★ T18 · S8：拉起之前先确认"**要写的东西能写**"。
        //   现场（A 级真跑照出来的真缺陷，三条对照坐实）：
        //     同一个 root 上已有实例在跑时，日志文件 `console.out.log` 被它占着
        //     ⇒ `cmd` **打不开重定向目标** ⇒ 子进程**根本没被拉起来**
        //     ⇒ 而启动器白等 **138 秒**、还把结论写成「**服务没能在预期时间内回应**」
        //       —— ★★ **假话**：它压根**没起来**（端口上从头到尾没有监听，日志文件也没被创建）。
        //   ★ 对照：把 `--logdir` 换开 ⇒ **2.4 秒**就绿。⇒ 这一条与"端口可注入"是**配套的**。
        //   ★ 顺带把另一条现场一起治了：`--logdir` 指到一个已存在的**文件** ⇒ 原来是**崩溃**。
        if (_logDirError != null)
            return FailCode(RC_FAIL, "logdir_bad", "日志目录用不了：" + _logs, _logDirError,
                        "换一个目录：AutoOpsConsole.exe start --logdir <路径>；\n" +
                        "或用环境变量 AOC_LOGDIR。★ 它必须是一个**目录**，不能是已存在的文件。");

        // ★★ T18 · S8：日志文件名**带上端口** —— 一个端口一个实例，一个实例一组日志。
        //   为什么：两个实例抢同一个日志文件时，**后起的那个会被静默地掐死**（见上面那段现场）。
        string outLog = Path.Combine(_logs, "console-" + Port + ".out.log");
        string errLog = Path.Combine(_logs, "console-" + Port + ".err.log");
        try { if (File.Exists(outLog)) File.Delete(outLog); } catch { }
        try { if (File.Exists(errLog)) File.Delete(errLog); } catch { }
        string logWhy;
        if (!CanWriteLog(outLog, out logWhy))
            return FailCode(RC_FAIL, "log_not_writable", "日志文件写不进去：" + outLog, logWhy,
                        "常见原因：日志目录只读；或这个文件被别的进程占着。\n" +
                        "★ 换一个目录试试：--logdir <路径>（或 AOC_LOGDIR）。");

        // ★ /d /s /c ""prog" args > "log" 2>&1" —— cmd 的标准安全写法：
        //   /s 让 cmd 把最外层那对引号**原样剥掉**，里面的引号不被误解。
        //
        // ★★★ T18 · S8：**拉起方式换成了 `CreateProcess(bInheritHandles = FALSE)`**（见 SpawnDetached）。
        //   原来 `Process.Start(UseShellExecute=false)` 传的是 `bInheritHandles = TRUE`，
        //   于是 `cmd.exe` 会把**调用者给我们的 stdout 管道**一起继承走并攥到 python 退出
        //   ⇒ 任何用管道收输出的脚本**永远等不到 EOF**（探针真跑卡了 180 秒）。
        //   **这条对"接口型调用"是硬伤** —— 而"下载安装即可用"正建立在能被脚本调用上。
        string comspec = Environment.GetEnvironmentVariable("ComSpec");
        if (string.IsNullOrEmpty(comspec))
            comspec = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        // ★ 继承我们的环境块，所以 `PYTHONIOENCODING` 要在**本进程**里先设好（原来走 psi.EnvironmentVariables）。
        try { Environment.SetEnvironmentVariable("PYTHONIOENCODING", "utf-8"); } catch { }
        string childArgs = "/d /s /c \"\"" + py + "\" "
                           + (_pyArgsPrefix.Length > 0 ? _pyArgsPrefix + " " : "")
                           + "-u -m app.server --port " + Port
                           + " > \"" + outLog + "\" 2>&1\"";
        string spawnWhy;
        if (!SpawnDetached(comspec, childArgs, _repo, out spawnWhy))
        {
            return FailCode(RC_FAIL, "spawn_failed", "拉起服务失败", spawnWhy,
                        "把上面这句原文发出来即可定位。");
        }
        Console.WriteLine("  已拉起（不依赖本窗口；日志 -> " + Rel(outLog) + "）");
        Console.Write("  等就绪 ");
        // ★★ T18 · S8：轮询里**先问"端口上有没有人听"，再问 HTTP**。
        //   为什么：对一个**压根没起来**的服务，每次 `TryPing` 在 .NET 里要 ~2 秒才认输
        //   ⇒ 45 次 ≈ **138 秒**，而结论里却印着"等了 45 秒" —— ★ **那句话本身就是假的**
        //   （§12.150 那一族的第 N 次现场：**报告不许说假话**）。
        //   修法两条（一起做才成立）：① 没监听就**不去发 HTTP**（省掉那 2 秒）；
        //   ② 结论里报**真实耗时**（拿表量，不靠"我以为"）。
        var sw = Stopwatch.StartNew();
        // ★★ T18 · S8：循环条件改成**按真实时间**，而不是"跑满 45 轮"。
        //   现场（真跑坐实）：端口上没人听时，每次 `IsListening()` 还要等满它自己的 **700ms**
        //   超时 ⇒ 45 轮 = **77 秒**，与"最多等 45 秒"这个承诺**不符**。
        //   ⇒ 承诺就要按承诺来：**到点就停**，并把这**真实**等了多久写进结论。
        for (int i = 0; sw.Elapsed.TotalSeconds < ReadyTimeoutSec; i++)
        {
            Thread.Sleep(1000);
            string ping = IsListening() ? TryPing() : null;
            if (ping != null)
            {
                Console.WriteLine();
                Console.WriteLine("  ✅ 服务已就绪：" + Url);
                MarkRunning(ping);
                OpenBrowser();
                return RC_OK;
            }
            if (i % 3 == 2) Console.Write(".");
            if (i == 8) Console.WriteLine();
        }
        Console.WriteLine();
        int waited = (int)sw.Elapsed.TotalSeconds;
        // ★★ T18 · S8：超时也要**分开报** —— 「**没起来**」与「**起来了但不回应**」是两件事
        //   （与 §12.144「问不到 ≠ 不存在」同族）。现场：这两件事原来都被写成
        //   「服务没能在预期时间内回应」，于是最该说的那件事（**它根本没启动**）被说丢了。
        bool listening = IsListening();
        if (listening)
            return FailCode(RC_FAIL, "start_timeout",
                        "启动超时（真实等了 " + waited + " 秒）—— 服务**起来了**但**没有回应**",
                        "端口 " + Port + " 上**有**监听，但 " + Url + "api/auth/ping 一直不回。",
                        "看日志末尾：\n  " + Rel(outLog) + "\n  " + Rel(errLog) + "\n" + Tail(errLog, 12));
        return FailCode(RC_FAIL, "start_failed",
                    "服务**没有起来**（真实等了 " + waited + " 秒，端口上**没有**监听）",
                    "★ 这与「起来了但不回应」是**两件事**：这一次是**压根没起来**。\n"
                    + (File.Exists(outLog) ? "     日志文件**在**（去看它的末尾）"
                                           : "     日志文件**根本没被创建** ⇒ 子进程没能启动"),
                    "常见原因：日志目录不可写 / 日志文件被别的进程占着 / 解释器起不来。\n"
                    + "看日志：\n  " + Rel(outLog) + "\n  " + Rel(errLog) + "\n" + Tail(errLog, 12));
    }

    // ------------------------------------------------------------------ 停

    /// <summary>
    /// ★★ T18 · S8：**动手之前先确认"要写的东西能写"**（一句话的护栏，换掉 138 秒的假结论）。
    /// ★ 判据就是"能不能以**写**的方式打开它" —— 与 `cmd` 那条 `>` 重定向要的是同一种权限。
    /// ★ 只探测、不留东西：本来不存在的，探完删掉。
    /// </summary>
    private static bool CanWriteLog(string path, out string why)
    {
        why = null;
        bool existed = File.Exists(path);
        try
        {
            using (new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            {
            }
            if (!existed) { try { File.Delete(path); } catch { } }
            return true;
        }
        catch (Exception ex)
        {
            why = ex.GetType().Name + ": " + ex.Message;
            return false;
        }
    }

    // ------------------------------------------------------------------ 拉起服务（不继承任何句柄）

    /// <summary>
    /// ★★★ T18 · S8：**用 `CreateProcess(bInheritHandles = FALSE)` 把服务拉起来**。
    ///
    /// ★★ 为什么不能用 `Process.Start(..., UseShellExecute = false)`：
    ///   .NET 那条路会传 **`bInheritHandles = TRUE`** ⇒ 子进程继承的是
    ///   「本进程里**所有可继承的句柄**」，而 `.NET Console` 在首次使用 stdout 时会
    ///   `DuplicateHandle(..., bInheritHandle: true)` 出一份可继承的拷贝 ——
    ///   **我们拿这个名字清不掉它**（`GetStdHandle` 返回的不是那一份）⇒
    ///   `cmd.exe`（以及它下面的 python）一直攥着调用者给我们的 stdout 管道
    ///   ⇒ ★★ **任何用管道收启动器输出的脚本，永远等不到 EOF**。
    ///
    /// ★ 真跑定位（四组对照，见证据目录 `T18-S8-管道定位.txt`）：
    ///   `stdout=PIPE / stderr=PIPE` ⇒ 挂住 25 秒；`stdout=PIPE / stderr=DEVNULL` ⇒ **照样挂**；
    ///   `stdout=DEVNULL / stderr=PIPE` ⇒ **2.4 秒返回**；两个都 DEVNULL ⇒ 2.4 秒。
    ///   ⇒ 挂的是 **stdout**；stderr 没事（因为**我们从没写过 `Console.Error`**，那份 dup 根本不存在）。
    ///
    /// ★ 第一次修法（只给子进程加 `RedirectStandardOutput/Error`）**不够**：那只是"多给子进程两条
    ///   它自己的管道"，**并没有**收回被继承出去的那一份 —— 真跑照样卡死。
    ///   **修"结果"不修"根"，症状一点也不少。**
    /// ★★ 这条对**交付形态**是要害：**"下载安装即可用"的前提是"能被脚本/接口型地调用"**，
    ///   而一个凡是被管道收取输出就挂死的启动器，做不到这件事。
    /// </summary>
    private static bool SpawnDetached(string exe, string args, string workdir, out string why)
    {
        why = null;
        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi;
        // ★ 不给 lpEnvironment ⇒ 继承**我们**的环境块（`PYTHONIOENCODING` 已在调用处设好）。
        // ★ CREATE_NO_WINDOW：不依赖任何窗口（与原来 `CreateNoWindow = true` 同一件事）。
        bool ok = CreateProcess(null, "\"" + exe + "\" " + args, IntPtr.Zero, IntPtr.Zero,
                                false, CREATE_NO_WINDOW, IntPtr.Zero, workdir, ref si, out pi);
        if (!ok)
        {
            why = "CreateProcess 失败（Win32 错误码 " + Marshal.GetLastWin32Error() + "）";
            return false;
        }
        try { CloseHandle(pi.hThread); } catch { }
        try { CloseHandle(pi.hProcess); } catch { }
        return true;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_HIDE = 0;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>★ `stop` 命令的入口：**不预设立场**，所以要走完整认人。</summary>
    private static int Stop() { return StopChecked(false); }

    /// <summary>
    /// ★★ T18 · S4：**认人只有一道口径** —— `start` 与 `stop` / `restart` 必须走同一个判定。
    ///
    /// 现场（T18·S0 静态读到 → S4 真跑坐实）：`Start()` 有三级认人，而 `Stop()` **不认人** ——
    /// 它直接找占着端口的 PID 就 `taskkill /F`。而 `restart` = `Stop()` + `Start()`
    /// ⇒ ★★ **`start` 会拒绝的那个「别的程序」，用 `restart` 会把它杀掉。**
    /// 这是本项目「**同一个开口，两处实现都要认账**」的第 3 次现场（T16、T17 各一次）。
    ///
    /// ★ `verifiedOurs` 只由 `Start()` 传 true —— 它在调用前**已经**认过人了
    ///   （那正是"换掉我们自己的旧版本"这条合法路径）。
    /// ★ 拒绝时**不提供 `--force`**：不杀别人的进程是**纪律**，不是能力不足。
    /// </summary>
    private static int StopChecked(bool verifiedOurs)
    {
        Console.WriteLine("── 停止 auto-ops-console ──");
        Console.WriteLine("  端口：" + Port + (Port == DefaultPort ? "（默认）" : "（★ 注入）"));
        var pids = ListenerPids();
        if (pids.Count == 0)
        {
            Console.WriteLine("  （" + Port + " 上没有监听 —— 本来就没在跑）");
            _state = "not_running";          // ★ S8：结论要说清"没在跑"，而不是含糊的 ok
            return RC_OK;
        }
        string pidList = string.Join(",", pids.Select(x => x.ToString()).ToArray());
        if (!verifiedOurs && !LooksLikeOurConsole())
        {
            Console.WriteLine("  ⛔ " + Port + " 上的东西**不是我们的控制台**（既不认 /api/auth/ping 也不认 /api/health）");
            Console.WriteLine("     PID：" + pidList);
            Console.WriteLine("     ★ 本启动器**不动别人的进程**（那是纪律，不是能力不足）。");
            Console.WriteLine("       确认要结束它，请用任务管理器按 PID 结束：" + pidList);
            _state = "not_ours";             // ★ S8：与 `start` 走**同一套**字段（此前两边形状不一样）
            _pids = pids;
            return RC_NOT_OURS;
        }
        Console.WriteLine("  占着 " + Port + " 的进程：PID " + string.Join(", ", pids.Select(x => x.ToString()).ToArray()));
        foreach (int pid in pids)
        {
            using (var p = Process.Start(Cli("taskkill.exe", "/PID " + pid + " /F")))
            {
                string o = (p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()).Trim();
                p.WaitForExit(8000);
                Console.WriteLine("    " + o.Replace("\r\n", "\n    "));
            }
        }
        for (int i = 0; i < 20; i++)
        {
            Thread.Sleep(400);
            if (!IsListening())
            {
                Console.WriteLine("  ✅ 已停止（" + Port + " 已释放）");
                _state = "stopped";
                return RC_OK;
            }
        }
        return FailCode(RC_FAIL, "stop_timeout", "停止超时",
                    "发过 taskkill 了，但 " + Port + " 还在监听。",
                    "可能在别的会话里被拉起；重跑一次本命令，或在任务管理器里结束占用端口的 python.exe。");
    }

    private static int Status()
    {
        Console.WriteLine("── auto-ops-console 状态 ──");
        Console.WriteLine("  端口：" + Port + (Port == DefaultPort ? "（默认）" : "（★ 注入）"));
        Console.WriteLine("  日志目录：" + Rel(_logs));

        if (!IsListening())
        {
            Console.WriteLine("  ⏹  没在运行（" + Port + " 上没有监听）");
            _state = "not_running";
            _pids = new List<int>();
            return RC_NOT_RUNNING;
        }

        _pids = ListenerPids();
        Console.WriteLine("  PID：" + string.Join(", ", _pids.Select(x => x.ToString()).ToArray()));

        string ping = TryPing();
        if (ping != null)
        {
            _vVer = Grab(ping, "version");
            _vStage = Grab(ping, "stage");
            _vCfg = Grab(ping, "configured");
            ReadDiskVersion(out _dVer, out _dStage);
            bool stale = (_dVer != null && _vVer != null && _dVer != _vVer)
                      || (_dStage != null && _vStage != null && _dStage != _vStage);
            Console.WriteLine("  ✅ 运行中：" + VersionLine(ping));
            Console.WriteLine("     磁盘上是：" + (_dVer == null
                              ? "（读不到 —— 按「问不到」报，不当成没事）" : _dVer + " / " + _dStage));
            if (stale)
            {
                // ★★ T13 那个坑：跑着的是**旧进程**，而从外面**看不出来**（当时 `/api/ai/**` 根本不存在）。
                Console.WriteLine("  ⚠️  ★ 两者**不是同一版** ⇒ 你现在看到的界面/接口可能是**旧进程**的"
                                  + "（T13 踩过：跑的是旧代码而看不出）");
            }
            _state = stale ? "running_stale" : "running";
            return stale ? RC_STALE : RC_OK;
        }

        // ★★ 这里必须**分开报**（T17「「问不到」≠「不存在」」同族）：
        //   "是我们的旧版本" 与 "根本不是我们的东西" 是两件事，处置也完全不同。
        if (LooksLikeOurConsole())
        {
            Console.WriteLine("  ⚠️  " + Port + " 被**我们的旧版本**占着（不认 /api/auth/ping，但认 /api/health）"
                              + " ⇒ 跑的是旧代码，需要重启换新");
            _state = "ours_but_old";
        }
        else
        {
            Console.WriteLine("  ⚠️  " + Port + " 被**别的程序**占着（既不认 /api/auth/ping 也不认 /api/health）"
                              + " —— 这不是本控制台；★ 本启动器**不会**去动它");
            _state = "not_ours";
        }
        return RC_NOT_OURS;
    }

    /// <summary>谁的进程占着端口（纯 netstat 解析 —— 不依赖 PowerShell / WMI）。</summary>
    private static List<int> ListenerPids()
    {
        var result = new List<int>();
        try
        {
            using (var p = Process.Start(Cli("netstat.exe", "-ano")))
            {
                string text = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
                foreach (string line in text.Split('\n'))
                {
                    string l = line.Trim();
                    if (!l.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;
                    if (l.IndexOf(":" + Port + " ", StringComparison.Ordinal) < 0) continue;
                    if (l.IndexOf("LISTENING", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    var parts = l.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    int pid;
                    if (parts.Length >= 5 && int.TryParse(parts[parts.Length - 1], out pid) && pid > 0)
                        result.Add(pid);
                }
            }
        }
        catch { }
        return result.Distinct().ToList();
    }

    // ------------------------------------------------------------------ 交付形态：快捷方式

    /// <summary>我们自己的产物 —— "是不是我建的"这条判据就落在"它指向谁"上。</summary>
    private static string OurExe()
    {
        return Path.Combine(_root, "工具", "AutoOpsConsole.exe");
    }

    private static string[] ShortcutPaths()
    {
        if (!string.IsNullOrEmpty(_shortcutDirOverride))
        {
            Directory.CreateDirectory(_shortcutDirOverride);
            return new string[]
            {
                Path.Combine(_shortcutDirOverride, "auto-ops-console.lnk"),
                Path.Combine(_shortcutDirOverride, "auto-ops-console-menu.lnk"),
            };
        }
        return new string[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                         "auto-ops-console.lnk"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),
                         "auto-ops-console.lnk"),
        };
    }

    private static object _wsh = null;

    private static object Wsh()
    {
        if (_wsh == null)
        {
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            if (t == null) throw new InvalidOperationException("这台机器上没有 WScript.Shell（.lnk 建不了）");
            _wsh = Activator.CreateInstance(t);
        }
        return _wsh;
    }

    /// <summary>★ 不引第三方库、不加编译引用：走**反射**调 WScript.Shell（C# 5 可用）。</summary>
    private static object LnkHandle(string path)
    {
        return Wsh().GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null,
                                            _wsh, new object[] { path });
    }

    private static string LnkRead(string path, string prop)
    {
        object lnk = LnkHandle(path);
        object v = lnk.GetType().InvokeMember(prop, BindingFlags.GetProperty, null, lnk, null);
        return v == null ? "" : v.ToString();
    }

    private static void LnkWrite(string path, string target, string workdir)
    {
        object lnk = LnkHandle(path);
        Type lt = lnk.GetType();
        lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { target });
        lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { workdir });
        lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
    }

    /// <summary>
    /// ★★ T18 · S5（§12.145）：交付形态**可建 / 可撤 / 可审计** 三件齐。
    ///
    /// 为什么三件都要：T7 口径「**回不去的要逐项说清**」——
    /// 一个只能"建"、不能说清"建了什么、怎么收回"的东西，不是交付物，是个手雷。
    /// ★★ 撤销**只删自己建的**：判据是「**它指向我们的产物**」，不是"目录里所有 .lnk"、
    ///   更不是"把桌面清一遍"。指向别处的，**一律不动**并说明它是谁。
    /// ★ 默认子命令是 `list`（**非破坏性**）—— 不给参数就不许有副作用。
    /// </summary>
    private static int Shortcut(string sub)
    {
        string mine = OurExe();
        string[] paths = ShortcutPaths();
        Console.WriteLine("── 交付形态：桌面快捷方式 / 开始菜单项 ──");
        Console.WriteLine("  产物：" + mine);
        Console.WriteLine("  落点：" + string.Join("  ｜  ", paths));
        Console.WriteLine("  子命令：" + (sub.Length == 0 ? "list（默认，只看不动）" : sub));

        if (sub.Length == 0 || sub == "list")
        {
            int n = 0;
            foreach (string p in paths)
            {
                if (!File.Exists(p)) { Console.WriteLine("  （没有）" + p); continue; }
                n++;
                try
                {
                    Console.WriteLine("  ✅ " + p);
                    Console.WriteLine("     指向  ：" + LnkRead(p, "TargetPath"));
                    Console.WriteLine("     工作目录：" + LnkRead(p, "WorkingDirectory"));
                    Console.WriteLine("     参数  ：" + LnkRead(p, "Arguments"));
                }
                catch (Exception ex) { Console.WriteLine("     ⚠️  读不动：" + ex.Message); }
            }
            Console.WriteLine("  小结：在场 " + n + " 个");
            _state = "ok";
            Extra("sub", "\"list\"");
            Extra("present", n.ToString());
            return RC_OK;
        }

        if (sub == "add")
        {
            int made = 0, bad = 0;
            foreach (string p in paths)
            {
                try
                {
                    LnkWrite(p, mine, Path.GetDirectoryName(mine));
                    // ★ 建完**读回来**对（.lnk 是二进制且带时间戳 ⇒ 不用逐字节比对，§12.142/§12.145）
                    string back = LnkRead(p, "TargetPath");
                    if (string.Equals(back, mine, StringComparison.OrdinalIgnoreCase))
                    {
                        made++;
                        Console.WriteLine("  ✅ 已建，且**读回一致**：" + p);
                    }
                    else
                    {
                        bad++;
                        Console.WriteLine("  ⚠️  建了但读回**不一致**：" + p + "\n     读回：" + back);
                    }
                }
                catch (Exception ex)
                {
                    bad++;
                    Console.WriteLine("  ❌ 建不了：" + p + "\n     原因：" + ex.Message);
                }
            }
            Console.WriteLine("  小结：建成 " + made + " 个 ｜ 有问题 " + bad + " 个");
            if (bad > 0 && !JsonOut)
                Console.WriteLine("  ★ 建不成的常见原因：桌面/开始菜单目录被策略限制，或 WScript.Shell 不可用。");
            _state = bad == 0 ? "ok" : "error";
            if (bad > 0) { _errWhat = "有些快捷方式建不成"; _errWhy = "建成 " + made + " 个，有问题 " + bad + " 个"; }
            Extra("sub", "\"add\"");
            Extra("made", made.ToString());
            Extra("bad", bad.ToString());
            return bad == 0 ? RC_OK : RC_FAIL;
        }

        if (sub == "remove")
        {
            int removed = 0, foreign = 0;
            foreach (string p in paths)
            {
                if (!File.Exists(p)) { Console.WriteLine("  （没有）" + p); continue; }
                string tgt;
                try { tgt = LnkRead(p, "TargetPath"); }
                catch (Exception ex) { Console.WriteLine("  ⚠️  读不动，所以**不删**：" + p + "\n     原因：" + ex.Message); continue; }
                // ★★ 只删**自己建的**：判据是"它指向我们的产物"。别的一律不碰。
                if (string.Equals(tgt, mine, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(p);
                    removed++;
                    Console.WriteLine("  ✅ 已删（它指向我们的产物）：" + p);
                }
                else
                {
                    foreign++;
                    Console.WriteLine("  ⛔ **不是我们建的**，不动它：" + p + "\n     它指向：" + tgt);
                }
            }
            Console.WriteLine("  小结：删掉 " + removed + " 个 ｜ 不是我们的 " + foreign + " 个");
            _state = "ok";
            Extra("sub", "\"remove\"");
            Extra("removed", removed.ToString());
            Extra("foreign", foreign.ToString());
            return RC_OK;
        }

        return Fail("不认识的子命令：" + sub, "只支持 add / remove / list（不给就是 list）。", "");
    }

    // ------------------------------------------------------------------ 杂项

    /// <summary>
    /// 起一个命令行子进程，并按**控制台 OEM 代码页**读它的输出。
    /// ★ 不这么做的话，`taskkill` 的中文输出会被按 UTF-8 解码 ⇒ 界面上是乱码 ——
    ///   而"乱码"比"没有输出"更糟：它看起来像程序坏了（本项目 T14 自己的口径：
    ///   **报告不许说假话**，含"不许说看不懂的话"）。
    /// </summary>
    private static ProcessStartInfo Cli(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // ★★ T18 · S9：**stdin 也要给一条空管道**。
            //   现场（真跑照出来的真缺陷）：探测解释器时把 `cmd.exe` 当成候选 ⇒
            //   `cmd.exe --version` 会**去读 stdin**，而它的 stdin 是**继承来的**（我们的）
            //   ⇒ cmd 一直等输入 ⇒ 我们卡在 `ReadToEnd()` 上**无限期挂住**。
            RedirectStandardInput = true,
        };
        try
        {
            var oem = Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            psi.StandardOutputEncoding = oem;
            psi.StandardErrorEncoding = oem;
        }
        catch { }
        return psi;
    }

    /// <summary>
    /// ★★ T18 · S9：**带硬超时的"跑一下、收输出"**。
    /// 现场（同上）：`FindPython` 原来先 `ReadToEnd()` 再 `WaitForExit(6000)` ——
    /// ★ **顺序反了**：只要子进程不吐完（或干脆不退出），那个 6 秒超时**根本轮不到**。
    /// ⇒ 改成"**后台线程读 ＋ 主线程等超时 ＋ 到点就杀**"，超时才真的算数。
    /// </summary>
    private static string RunCapture(ProcessStartInfo psi, int ms, out int exitCode, out bool timedOut)
    {
        exitCode = -1;
        timedOut = false;
        var sb = new StringBuilder();
        using (var p = Process.Start(psi))
        {
            var th = new Thread(delegate()
            {
                try { sb.Append(p.StandardOutput.ReadToEnd()); } catch { }
                try { sb.Append(p.StandardError.ReadToEnd()); } catch { }
            });
            th.IsBackground = true;
            th.Start();
            if (!p.WaitForExit(ms))
            {
                timedOut = true;
                try { p.Kill(); } catch { }
                return sb.ToString();
            }
            th.Join(500);
            try { exitCode = p.ExitCode; } catch { }
            return sb.ToString();
        }
    }

    /// <summary>
    /// ★★ T18 · S8：`--json` 模式下**不弹浏览器**。
    /// 现场：S3 那条规矩写了"`--json` 不留窗口、不等按键"，**漏了浏览器** ——
    /// 而它与前两条是同一件事：**脚本模式不许有"给人看"的副作用**。
    /// 判据要能"真 start 一次"（这是本话题唯一能验情形 ①/②/⑥ 的办法），
    /// 而真 start 会在**用户桌面上弹出窗口** ⇒ 撞「判据不许伤到环境」。
    /// ★ 人话模式（双击那条路）一个字都不改 —— 弹浏览器正是它要的。
    /// </summary>
    private static void OpenBrowser()
    {
        if (JsonOut)
        {
            _browser = "suppressed";
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo(Url) { UseShellExecute = true });
            _browser = "opened";
        }
        catch
        {
            _browser = "failed";
            Console.WriteLine("  （浏览器没打开，手工访问 " + Url + " ）");
        }
    }

    private static string Rel(string p)
    {
        try { return p.StartsWith(_root) ? p.Substring(_root.Length).TrimStart('\\') : p; }
        catch { return p; }
    }

    private static string Tail(string file, int lines)
    {
        try
        {
            if (!File.Exists(file)) return "";
            var all = File.ReadAllLines(file);
            var last = all.Skip(Math.Max(0, all.Length - lines));
            return "\n--- 日志末尾 ---\n" + string.Join("\n", last.ToArray());
        }
        catch { return ""; }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("auto-ops-console 启动器");
        Console.WriteLine("  （不带参数）  启动；已在跑就只开浏览器");
        Console.WriteLine("  stop         停止");
        Console.WriteLine("  restart      重启");
        Console.WriteLine("  status       只看状态");
        Console.WriteLine("  shortcut     交付形态：桌面快捷方式 / 开始菜单项");
        Console.WriteLine("                 shortcut list（默认，只看）｜ shortcut add ｜ shortcut remove");
        Console.WriteLine("                 ★ remove **只删自己建的**（判据：它指向我们的产物）");
        Console.WriteLine("  --port N     用这个端口（默认 " + DefaultPort + "；也可用环境变量 AOC_PORT）");
        Console.WriteLine("  --logdir P   日志目录（默认 repo\\var\\logs；也可用 AOC_LOGDIR）");
        Console.WriteLine("                 ★ 日志文件名**带端口**：console-<端口>.{out,err}.log");
        Console.WriteLine("                   （一个端口一个实例、一个实例一组日志 —— 两个实例不许抢同一个文件）");
        Console.WriteLine("  --shortcut-dir P  快捷方式落点（默认 桌面 + 开始菜单；也可用 AOC_SHORTCUT_DIR）");
        Console.WriteLine("                 ★ 给它就是为了让判据能在**临时目录**里跑真身，不碰你的桌面");
        Console.WriteLine("  --json       只输出一行 JSON（给脚本看；★ 不留窗口、不等按键、**不弹浏览器**）");
        Console.WriteLine("");
        Console.WriteLine("  ★ 退出码（脚本可读的那一半）：");
        Console.WriteLine("     0 = 在跑，且是我们的控制台");
        Console.WriteLine("     3 = 端口有监听，但**不是**我们的（旧版本 / 别的程序）");
        Console.WriteLine("         ★ `start` / `stop` / `restart` / `status` **四个入口给的是同一个码**");
        Console.WriteLine("           （S8 之前 `start` 给的是 1 —— 脚本分不出「别人占着」和「参数错」）");
        Console.WriteLine("     4 = 没在运行（端口上没有监听）");
        Console.WriteLine("     5 = 在跑，但**跑着的不是磁盘上那一版**（T13 那个坑）");
        Console.WriteLine("     1 = 命令本身失败（参数错 / 启动失败 / 停止超时）");
        Console.WriteLine("");
        Console.WriteLine("  ★ JSON 的字段是**固定**的（没有的给 null）—— 这与「恰好一行」同一条纪律，");
        Console.WriteLine("    脚本才敢按键取值，而不是先看这一行有没有那个键。");
    }

    private static void TryUseUtf8Console()
    {
        try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
    }

    /// <summary>★ 失败时**把窗口留住**（双击进来的用户要能看见原因）；成功时不留。
    /// ★★ T18 · S3：`--json` 模式下**不许留窗口、不许等按键** —— 那会让脚本**挂死**。</summary>
    private static int Fail(string what, string why, string how)
    {
        return FailCode(RC_FAIL, "error", what, why, how);
    }

    /// <summary>
    /// ★★ T18 · S8：**失败也得分家** —— "不是我们的"是一种**结论**，不是"命令自己坏了"。
    /// 现场（S8 取数坐实）：`start` 撞上"别人的程序占着"时给的是**退出码 1**，
    /// 而启动器自己印的退出码表写着 **3**；`stop` 同一情形给的却是 3 + `state=not_ours`。
    /// ⇒ 脚本**分不出**"端口被别人占着"和"参数写错了"（前者要去找人，后者要改命令）。
    /// ★ 这是「**同一个开口，两处实现都要认账**」在本项目的**第 4 次**现场。
    /// </summary>
    private static int FailCode(int rc, string state, string what, string why, string how)
    {
        _state = state;
        _errWhat = what;
        _errWhy = why;
        // ★ S8：`--json` 下**这里不发** —— 由 `Main` 的唯一发口 `EmitFinal` 发那一行。
        if (JsonOut) return rc;
        Console.WriteLine();
        Console.WriteLine("  ❌ " + what);
        if (!string.IsNullOrEmpty(why)) Console.WriteLine("     原因：" + why.Replace("\n", "\n           "));
        if (!string.IsNullOrEmpty(how)) Console.WriteLine("     建议：" + how.Replace("\n", "\n           "));
        Console.WriteLine();
        // ★ 只有**真的要人看**的失败才留窗口：脚本模式（`--json`）在上面已经 return 了。
        Console.WriteLine("  （按任意键关闭）");
        try { Console.ReadKey(true); } catch { }
        return rc;
    }
}
