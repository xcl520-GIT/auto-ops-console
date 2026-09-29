/* auto-ops-console · 前端（原生 JS，无构建链、无依赖）
 *
 * 设计要点：
 *   · 命令预览是"先看后跑"：参数一改就向后端要一次渲染结果，展示将要执行的**原样命令**
 *   · yellow/red 动作必须先过二次确认弹窗（把后端给的 confirm.body 读给你看）
 *   · 失败时展示的是「原因 + 建议」，裸 stderr 折叠在"技术详情"里
 *   · ★★ T14：**鉴权在服务端**（app/server.py 的唯一漏斗）；这一层只是"门"——
 *     它拿到的 401 是服务端说的真话，前端拦不住也绕不过（红格：闸门只增不减）
 */

const S = {
  health: null,
  // ── T14：鉴权（令牌**只放 sessionStorage**，不进 localStorage / 不写 URL / 不进日志）──
  token: null,
  authInfo: null,
  booted: false,
  actions: [],
  domains: {},
  hosts: [],
  coverage: null,
  current: null,     // 当前动作 id
  params: {},        // 当前参数值
  preview: null,
  // ── T5：服务目录（配方）──
  recipes: [],
  recipeId: null,      // 当前配方 id
  recipeParams: {},    // 当前配方的参数值
  recipePlan: null,    // 最近一次计划预览（含确认词要求）
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* ---------------------------------------------------------------- 基础 */

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function toast(msg, ms = 3200) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), ms);
}

async function api(path, opts) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, authHeaders());
  const res = await fetch(path, Object.assign({ headers }, opts));
  let data;
  try { data = await res.json(); } catch (e) { throw { reason: '服务返回的不是合法 JSON', advice: '看服务端控制台输出。' }; }
  if (!data.ok) {
    const err = data.error || { reason: '未知错误', advice: '' };
    // ★ T14：401 / AUTH_* ⇒ 把门重新亮出来。
    //   ★ 但**不**对 /api/auth/** 自己做这件事 —— 那里返回 401 正是"口令不对"的正常回答，
    //     重绘登录框会把用户刚敲的字冲掉（自己给自己找麻烦）。
    if (!path.startsWith('/api/auth/')) {
      if (err.code === 'AUTH_STORE_BROKEN') showLocked(err);
      else if (res.status === 401 || /^AUTH_/.test(String(err.code || ''))) showLogin(S.authInfo && S.authInfo.configured ? 'login' : 'setup');
    }
    throw err;
  }
  return data.data;
}

/* ---------------------------------------------------------------- 鉴权门（T14）*/

const TOKEN_KEY = 'aoc.token';

function authHeaders() {
  return S.token ? { Authorization: 'Bearer ' + S.token } : {};
}

function setToken(t) {
  S.token = t || null;
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY);
  } catch (e) { /* 隐私模式下 sessionStorage 可能不可用；那就只在内存里留着 */ }
}

function readToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || null; } catch (e) { return null; }
}

/* ★★ T15：带令牌的**文本取回**与**文件下载**
   ─────────────────────────────────────────────────────────────
   ★★ 为什么必须有这两个函数（T15 真跑抓到的真缺陷）：
      T14 给唯一的请求漏斗加了鉴权闸门（含**导出通道**），而界面上的三个导出入口
      一直在用 `window.open` / `location.href` / 裸 `fetch` —— **一个令牌都带不上**
      ⇒ 加鉴权之后它们**全部 401**（T14 遗留 #2「界面走查没做」的必然结果）。
   ★ 修法：令牌**只走请求头**，取回文本后用 Blob 触发下载。
     ★ 刻意**不**支持 `?token=…` 这种写法 —— 令牌进了 URL 就会进浏览器历史与访问日志，
       那是拿安全换方便（§12.97 的口径：这是"把门"，不是"保险柜"）。
*/
async function fetchText(path) {
  const res = await fetch(path, { headers: authHeaders() });
  if (!res.ok) {
    let why = 'HTTP ' + res.status;
    try {
      const j = await res.json();
      if (j && j.error) why = (j.error.reason || why) + (j.error.advice ? '　建议：' + j.error.advice : '');
    } catch (e) { /* 响应不是 JSON：保留 HTTP 状态码 */ }
    if (res.status === 401) showLogin(S.authInfo && S.authInfo.configured ? 'login' : 'setup');
    throw { reason: '取不到这份文本：' + why, advice: '' };
  }
  return res.text();
}

async function downloadText(path, filename) {
  try {
    const text = await fetchText(path);
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'aoc-report.md';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  } catch (e) {
    toast(e.reason || '下载失败');
  }
}

/** 把门亮出来。`mode`：login（登录）· setup（首次设置）· change（改口令）。 */
function showLogin(mode, info) {
  S.authInfo = info || S.authInfo;
  S.authMode = mode || 'login';
  const setup = S.authMode === 'setup';
  const change = S.authMode === 'change';
  $('#login').classList.remove('hidden');
  $('#loginPwOldWrap').classList.toggle('hidden', !change);
  $('#loginPw2Wrap').classList.toggle('hidden', !(setup || change));
  $('#loginPw1Label').textContent = change ? '新口令' : '口令';
  $('#loginTitle').textContent = setup ? '首次使用：设置口令' : (change ? '改控制台口令' : '登录');
  $('#loginBtn').textContent = setup ? '设置口令并进入' : (change ? '改口令' : '登录');
  $('#loginHelp').textContent = setup
    ? '本机还没设过口令 —— 控制台现在是「全拒」状态（红线 11：没口令就不许用，不是「没口令就放行」）。'
    : (change
      ? '改口令必须先验当前口令；改完会吊销所有已发令牌，只保留你现在这一台。'
      : '这一步是给「任何能对 127.0.0.1:8787 说话的进程」立一道门。');
  $('#loginPw').value = ''; $('#loginPw2').value = ''; $('#loginPwOld').value = '';
  $('#loginErr').classList.add('hidden');
  const st = (S.authInfo && S.authInfo.stage) ? ('· ' + S.authInfo.stage) : '';
  $('#loginStage').textContent = st;
  renderAuthNote(S.authMode);
  setTimeout(() => {
    try { (change ? $('#loginPwOld') : $('#loginPw')).focus(); } catch (e) {}
  }, 30);
}

function renderAuthNote(mode) {
  const a = S.authInfo || {};
  const can = (a.can_protect || []).map((x) => '· ' + x).join('');
  const cannot = (a.cannot_protect || []).map((x) => '· ' + x).join('');
  if (mode === 'change') {
    $('#loginNote').innerHTML = '<div class="grp dim">★ 新口令请与你的模型 API key <b>无关</b>：'
      + '两个秘密耦合之后，轮换 key 会让控制台口令悄悄失效，而你看到的只是一句「口令不对」。</div>';
    return;
  }
  $('#loginNote').innerHTML = mode === 'setup'
    ? '<b>设置后请注意：</b>令牌只在服务端内存里，服务重启需要重新登录；口令只存哈希，忘了只能人工处理。'
    : `<div class="grp"><b>这道门能防</b>${esc(can)}</div>
       <div class="grp"><b>这道门不能防</b>${esc(cannot)}</div>
       <div class="grp dim">★ 这是「把门」，不是「保险柜」；「只绑 127.0.0.1」那一层一个字没动。</div>`;
}

function hideLogin() { $('#login').classList.add('hidden'); }

/** 口令文件坏了 ⇒ 整体不可用（fail-closed）。★ 不许提供"就这么进去"的按钮。 */
function showLocked(err) {
  $('#login').classList.remove('hidden');
  $('#loginTitle').textContent = '口令文件坏了 · 控制台整体拒绝服务';
  $('#loginHelp').textContent = (err && err.reason) || '口令文件读不出来。';
  $('#loginForm').querySelectorAll('input,button').forEach((el) => { el.disabled = true; });
  $('#loginErr').classList.remove('hidden');
  $('#loginErr').textContent = ((err && err.advice) || '')
    + '\n\n★ 这里刻意不给「重新设置口令」的入口 —— 那等于把门打开（fail-closed）。';
}

async function doAuthSubmit(ev) {
  ev.preventDefault();
  const mode = S.authMode || 'login';
  const setup = mode === 'setup';
  const change = mode === 'change';
  const pw = $('#loginPw').value;
  const err = $('#loginErr');
  err.classList.add('hidden');
  if (setup || change) {
    const min = (S.authInfo && S.authInfo.min_password_len) || 8;
    if (pw.length < min) { err.textContent = `新口令至少要 ${min} 个字符`; err.classList.remove('hidden'); return; }
    if (pw !== $('#loginPw2').value) { err.textContent = '两次输入不一致'; err.classList.remove('hidden'); return; }
  }
  $('#loginBtn').disabled = true;
  try {
    let d;
    if (setup) {
      d = await api('/api/auth/setup', { method: 'POST', body: JSON.stringify({ password: pw }) });
    } else if (change) {
      d = await api('/api/auth/password', {
        method: 'POST',
        body: JSON.stringify({ old_password: $('#loginPwOld').value, new_password: pw }),
      });
    } else {
      d = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ password: pw }) });
    }
    setToken(d.token);
    hideLogin();
    toast(setup ? '口令已设置；这是「把门」，不是「保险柜」'
      : (change ? `口令已改；其它已发令牌全部失效（吊销 ${d.revoked || 0} 个）` : '已登录'));
    if (!change) await init();   // ★ 改口令时界面本来就是好的，别整页重取一遍
  } catch (e) {
    err.textContent = (e.reason || '操作失败') + (e.advice ? '\n' + e.advice : '');
    err.classList.remove('hidden');
  } finally {
    $('#loginBtn').disabled = false;
  }
}

async function doLogout() {
  try { await api('/api/auth/logout', { method: 'POST', body: JSON.stringify({}) }); } catch (e) { /* 令牌可能已失效 */ }
  setToken(null);
  showLogin('login');
  toast('已清掉本页令牌（服务端会话也一并吊销）');
}

/** 开机流程：先问「有没有设过口令 / 我有没有令牌」，再决定进门还是进控制台。 */
async function boot() {
  if (S.booted) return;
  S.booted = true;
  $('#loginForm').addEventListener('submit', doAuthSubmit);
  $('#btnLogout').addEventListener('click', doLogout);
  $('#btnChangePw').addEventListener('click', () => showLogin('change'));

  let ping = null;
  try {
    ping = await api('/api/auth/ping');
  } catch (e) {
    document.body.innerHTML = `<div style="padding:40px"><h2>无法连接控制台服务</h2>
      <div class="note">${esc(e.reason || '')}\n${esc(e.advice || '')}</div></div>`;
    return;
  }

  if (ping.store_broken) { showLocked({ reason: '口令文件坏了，控制台整体拒绝服务（fail-closed）。', advice: '从备份恢复 var/auth.json；★ 不要删掉它当作「没设过口令」。' }); return; }
  if (!ping.configured && !ping.setup_allowed) { showLocked({ reason: '口令状态异常：既没配置又不允许设置。', advice: '记录这个状态并上报。' }); return; }

  const t = readToken();
  if (ping.configured && t) {
    setToken(t);
    try {
      const st = await api('/api/auth/status');
      S.authInfo = Object.assign({}, st, ping);
      hideLogin();
      await init();
      return;
    } catch (e) {
      setToken(null); // 过期 / 被吊销 ⇒ 回到登录门
    }
  } else if (ping.configured) {
    try { S.authInfo = Object.assign({}, await api('/api/auth/ping'), {}); } catch (e) {}
  }

  showLogin(ping.configured ? 'login' : 'setup', ping);
}

function riskBadge(risk) {
  const label = { green: '只读', yellow: '可恢复变更', red: '破坏性' }[risk] || risk;
  return `<span class="badge ${risk}">${label}</span>`;
}

function statusBadge(status) {
  const map = { ok: '成功', failed: '失败', timeout: '超时', rejected: '被拒绝', skipped: '未执行', aborted: '已中止' };
  const cls = status === 'ok' ? 'ok' : (status === 'skipped' ? '' : 'failed');
  return `<span class="badge ${cls}">${map[status] || status}</span>`;
}

function hostLabel(h) { return `${h.name}（${h.user}@${h.address}:${h.port}）`; }

function currentHostId() { return $('#hostSelect').value; }

/* ---------------------------------------------------------------- 初始化 */

async function init() {
  try {
    S.health = await api('/api/health');
  } catch (e) {
    // ★★ T14：`init()` 只可能走**已经过了门**的路径。
    //   这里再冒出 AUTH_* ⇒ 只可能是"页面开着的时候令牌过期 / 被吊销"。
    //   ★ 这时**绝不能**像原来那样 `document.body.innerHTML = …` ——
    //     那会把登录门一起清掉，用户连重新登录的机会都没有。
    //     （原代码是 T1 写的"服务连不上"兜底，那时没有门，所以想得不周全。）
    if (/^AUTH_/.test(String(e.code || ''))) {
      setToken(null);
      showLogin('login');
      toast('令牌已失效（过期或被吊销）—— 重新登录');
      return;
    }
    document.body.innerHTML = `<div style="padding:40px"><h2>无法连接控制台服务</h2>
      <div class="note">${esc(e.reason || '')}\n${esc(e.advice || '')}</div></div>`;
    return;
  }
  $('#stage').textContent = S.health.stage + ' · v' + S.health.version;

  S.hosts = S.health.hosts;
  $('#hostSelect').innerHTML = S.hosts
    .map((h) => `<option value="${esc(h.id)}">${esc(hostLabel(h))}</option>`).join('');

  const a = await api('/api/actions');
  S.actions = a.actions; S.domains = a.domains || {};
  renderActionList();

  S.coverage = (await api('/api/coverage')).coverage;
  renderCoverage();

  loadHistory();

  $('#hostSelect').addEventListener('change', () => { if (S.current) doPreview(); });
  $('#btnCheckHost').addEventListener('click', () => checkHost(false));
  $('#btnTrustHost').addEventListener('click', () => checkHost(true));
  $$('.tab').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));

  // 支持 #action=<动作id> 直达，方便收藏、也方便自动化截图留证
  const m = location.hash.match(/^#action=(.+)$/);
  if (m) selectAction(decodeURIComponent(m[1]));
}

function switchTab(name) {
  $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  // ★★ T16（规范 §12.121）：★ **三处齐的第三处就是这里** —— 漏了它，`pane-vm` 永远不会被取消
  //    `hidden`（另外两处在 `web\index.html`：页签按钮 ＋ `pane-vm` 容器）。
  //    ★ 这正是"新增页签"最容易漏的一处：按钮看得见、点下去也没报错，**只是主区永远是空白**。
  ['actions', 'recipes', 'checkup', 'history', 'batches', 'gaps', 'k8s', 'mon', 'chat', 'pending', 'reports', 'vm'].forEach((n) => {
    $('#pane-' + n).classList.toggle('hidden', n !== name);
  });
  if (name === 'recipes') loadRecipes();
  if (name === 'checkup') renderCheckup();
  if (name === 'history') loadHistory();
  if (name === 'batches') loadBatches();
  if (name === 'gaps') renderCoverage();
  if (name === 'k8s') renderK8s();
  if (name === 'mon') renderMon();
  if (name === 'chat') renderChat();
  // ★★ T14·S4：「待确认」—— 每次进来都重取一次（别让人对着一张过期的卡片做决定）
  if (name === 'pending') loadPending();
  // ★★ T15：报告与知识沉淀（规范 §12.104）
  if (name === 'reports') renderReports();
  if (name === 'vm') loadVm();
}

/* ---------------------------------------------------------------- 动作列表 */

function renderActionList() {
  const groups = {};
  S.actions.forEach((a) => { (groups[a.domain] = groups[a.domain] || []).push(a); });
  const keys = Object.keys(groups).sort();
  $('#pane-actions').innerHTML = keys.map((d) => {
    const name = S.domains[d] || d;
    const cards = groups[d].map((a) => `
      <div class="card ${a.id === S.current ? 'active' : ''}" data-id="${esc(a.id)}"
           role="button" tabindex="0" aria-label="${esc(a.title)}：${esc(a.summary)}">
        <h4>${esc(a.title)}</h4>
        <p>${esc(a.summary)}</p>
        <div class="row">${riskBadge(a.risk)}
          <span class="badge">${esc(a.priority)}</span>
          <span class="badge">${a.step_count} 步</span>
          <span class="badge">${a.verify_count} 断言</span>
        </div>
      </div>`).join('');
    return `<div class="group-title">域 ${esc(d)} · ${esc(name)}</div>${cards}`;
  }).join('');

  $$('#pane-actions .card').forEach((el) => {
    el.addEventListener('click', () => selectAction(el.dataset.id));
    // 键盘可达（role=button 必须配键盘操作，否则只是"看起来像按钮"）
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectAction(el.dataset.id); }
    });
  });
}

async function selectAction(id) {
  S.current = id;
  S.params = {};
  const d = await api('/api/actions/' + encodeURIComponent(id));
  const a = d.action;
  renderActionList();

  if (a.note) { /* 只读动作的维护者说明，折叠展示 */ }

  $('#content').innerHTML = `
    <h2>${esc(a.title)} ${riskBadge(a.risk)}</h2>
    <div class="sub">${esc(a.summary)}</div>
    ${a.note ? `<div class="note">ℹ️ ${esc(a.note)}</div>` : ''}

    <div class="section">
      <h3>参数</h3>
      <div id="form">${a.params.length ? a.params.map(renderField).join('') : '<div class="sub">本动作无参数</div>'}</div>
    </div>

    <div class="section">
      <h3>命令预览（执行前先看清楚要跑什么）</h3>
      <div id="preview"><div class="sub">修改参数后自动刷新…</div></div>
    </div>

    <div class="section">
      <h3>执行</h3>
      <div class="actions-row">
        <button class="primary" id="btnRun">${a.risk === 'green' ? '执行' : '执行（需二次确认）'}</button>
        <button id="btnBatch"${a.risk === 'red' ? ' disabled title="red 级动作禁止批量执行（T3 硬规矩，规范 §9.3）"' : ''}>批量执行（多选机器）</button>
        <span class="sub" id="runHint"></span>
      </div>
      ${a.risk === 'red'
        ? '<div class="help">★ red 级动作<b>禁止批量</b>：不可 undo 的操作必须逐台执行并手输确认词（T3 定下的硬规矩，服务端也会拒绝）</div>'
        : '<div class="help">批量 = 同一动作 + 同一份参数铺到多台，每台产出独立任务、失败隔离</div>'}
    </div>

    <div class="section" id="result"></div>
  `;

  a.params.forEach((p) => { S.params[p.name] = p.default == null ? '' : p.default; });
  $$('#form input, #form select').forEach((el) => {
    el.addEventListener('input', onParamChange);
    el.addEventListener('change', onParamChange);
  });
  $('#btnRun').addEventListener('click', () => runAction(a));
  const btnBatch = $('#btnBatch');
  if (btnBatch) btnBatch.addEventListener('click', () => batchRun(a));

  doPreview();
}

function renderField(p) {
  let input;
  if (p.type === 'enum') {
    input = `<select data-param="${esc(p.name)}">${p.choices.map((c) =>
      `<option value="${esc(c)}" ${c === p.default ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>`;
  } else if (p.type === 'int') {
    input = `<input type="number" data-param="${esc(p.name)}" value="${esc(p.default == null ? '' : p.default)}"
              min="${p.min != null ? p.min : ''}" max="${p.max != null ? p.max : ''}">`;
  } else {
    input = `<input type="text" data-param="${esc(p.name)}" value="${esc(p.default == null ? '' : p.default)}"
              placeholder="${esc(p.placeholder || '')}">`;
  }
  return `<div class="field">
    <label>${esc(p.label)} ${p.required ? '<span class="req">*</span>' : ''}</label>
    ${input}
    ${p.help ? `<div class="help">${esc(p.help)}</div>` : ''}
  </div>`;
}

let previewTimer = null;
function onParamChange() {
  $$('#form input, #form select').forEach((el) => { S.params[el.dataset.param] = el.value; });
  clearTimeout(previewTimer);
  previewTimer = setTimeout(doPreview, 220);
}

async function doPreview() {
  if (!S.current) return;
  const box = $('#preview');
  if (!box) return;
  try {
    const d = await api(`/api/actions/${encodeURIComponent(S.current)}/preview`,
      { method: 'POST', body: JSON.stringify({ host_id: currentHostId(), params: S.params }) });
    S.preview = d;

    const norm = Object.entries(d.params || {})
      .filter(([, v]) => v !== '' && v != null)
      .map(([k, v]) => `${k} = ${v}`).join('　');

    box.innerHTML = `
      ${norm ? `<div class="kv" style="font-size:12px;color:#8a9aab;margin-bottom:8px">规范化后的参数：${esc(norm)}</div>` : ''}
      ${d.commands.map((c) => `
        <div style="margin-bottom:8px">
          <div class="kv">${esc(c.title)}</div>
          <pre class="cmd">${esc(c.command || c.note || '')}</pre>
        </div>`).join('')}
      <div class="kv">共 ${d.commands.length} 步；带循环的步骤在真正执行时才知道具体命令。</div>
    `;
  } catch (e) {
    box.innerHTML = `<div class="banner bad"><h3>参数未通过校验</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
  }
}

/* ---------------------------------------------------------------- 执行 */

async function runAction(a) {
  let confirmText = '';
  if (a.risk !== 'green') {
    const body = (S.preview && S.preview.confirm) ? S.preview.confirm
      : { title: '确认执行', body: '该动作风险等级高于 green，需要二次确认。', confirm_text: '我已确认' };
    // ★ 只有 red 级要求"手输确认词"（规范 §2.5：red = 二次确认 + 影响面提示 + 手输确认词）。
    //   yellow 的语义是"看清楚再点"，让 yellow 也打字属于**把门槛立错了地方** ——
    //   它会让日常操作变得烦人，进而促使人们去绕过闸门，那才是最糟的结果。
    const ans = await modalConfirm(body, { requireText: a.risk === 'red' });
    if (!ans) return;                 // 用户取消
    confirmText = ans.confirm_text || '';
  }

  const btn = $('#btnRun');
  btn.disabled = true;
  btn.textContent = '执行中…';
  // ★★ T16（规范 §12.115）：**执行面由动作自己声明**（`channel: ssh|local`）——
  //   原来这里写死"通过 SSH 在目标机上执行"：对 M 域的动作（跑在**宿主机**上的 `vmrun.exe`）
  //   就是**界面在说假话** —— 与 §12.53.4「结论像这台机器的、其实是另一台」同族。
  //   ★ 一句话的成本，换的是"用户第一眼就知道这条命令**在哪台机器上跑**"。
  const plane = a.channel === 'local'
    ? '正在本机（宿主机）上执行：vmrun.exe，不走 ssh，请稍候…'
    : '正在通过 SSH 在目标机上执行，请稍候…';
  $('#result').innerHTML = `<div class="sub">${esc(plane)}</div>`;

  try {
    const d = await api(`/api/actions/${encodeURIComponent(S.current)}/run`,
      {
        method: 'POST',
        // ★ T3：把确认词一起交给服务端 —— red 级动作由 **engine.run** 校验它，
        //   前端这里只是"让用户打出来"，不是闸门本身。
        body: JSON.stringify({
          host_id: currentHostId(), params: S.params, confirm: true, confirm_text: confirmText,
        }),
      });
    renderResult(d);
    loadHistory();
  } catch (e) {
    $('#result').innerHTML = `<div class="banner bad"><h3>执行被拒绝</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = a.risk === 'green' ? '执行' : '执行（需二次确认）';
  }
}

/* 二次确认弹窗。
 *
 * ★ opts.requireText=true 时才要求「手输确认词」（red 级与恢复操作）。
 *   确认词的**权威校验在服务端**（engine.run / restore_backup），
 *   前端只负责把确认文案念给用户听、并让他在需要时把它打出来。
 *
 * 返回：取消 → null；确认 → { confirm_text }
 */
function modalConfirm(c, opts) {
  return new Promise((resolve) => {
    const needText = !!(opts && opts.requireText) && !!(c.confirm_text || '').trim();
    const m = $('#modal');
    m.classList.remove('hidden');
    m.innerHTML = `<div class="box">
      <h3>${esc(c.title || '确认执行')}</h3>
      <div class="body">${esc(c.body || '')}</div>
      ${needText ? `<div class="field" style="margin-top:12px">
        <label>请手工输入确认词（必须与下面这行完全一致）</label>
        <div class="help" style="user-select:all;font-size:14px;padding:6px 8px;background:#1b232c;border-radius:4px">${esc(c.confirm_text)}</div>
        <input type="text" id="mText" placeholder="在这里输入确认词" autocomplete="off" spellcheck="false">
      </div>` : ''}
      <div class="actions-row">
        <button class="primary" id="mOk" ${needText ? 'disabled' : ''}>${esc(c.confirm_text || '我已确认')}</button>
        <button id="mNo">取消</button>
      </div>
    </div>`;

    const okBtn = $('#mOk');
    const txt = $('#mText');
    if (txt) {
      const recheck = () => { okBtn.disabled = txt.value.trim() !== String(c.confirm_text).trim(); };
      txt.addEventListener('input', recheck);
      recheck();
      txt.focus();
    }
    okBtn.onclick = () => {
      m.classList.add('hidden');
      resolve({ confirm_text: txt ? txt.value : '' });
    };
    $('#mNo').onclick = () => { m.classList.add('hidden'); resolve(null); };
  });
}

/* ---------------------------------------------------------------- 结果渲染 */

/* 改动前备份区块（T3 · 规范 §9.1 / §9.2）
 *
 * 为什么单独成块、而不是塞进"步骤留证"里：备份是**护栏**，不是流程细节。
 * 变更动作跑完后，人第一眼要判断的是"**能不能撤回**" —— 所以它排在结论/自证之后、步骤之前。
 * 「恢复此文件」走 /api/backups/<id>/restore，同样要求手输确认词（服务端校验，与 red 动作一套逻辑）。
 */
function renderBackups(rows) {
  if (!rows || !rows.length) return '';
  const item = (b) => `
    <div class="gap-row">
      <span class="badge ${b.status === 'ok' ? 'ok' : (b.status === 'missing' ? '' : 'failed')}">
        ${b.status === 'ok' ? '已备份' : (b.status === 'missing' ? '本就没有' : '失败')}
      </span>
      <span><code>${esc(b.orig_path)}</code></span>
      <span class="dim">${b.kind === 'dir' ? esc(b.file_count || 0) + ' 个文件 · ' : ''}${b.size || 0} B${b.sha256 ? ' · ' + esc(String(b.sha256).slice(0, 16)) + '…' : ''}</span>
      ${b.status === 'ok' ? `<button class="ghost tiny" data-restore="${b.id}" data-path="${esc(b.orig_path)}">恢复此文件</button>` : ''}
    </div>`;
  return `<div class="section">
    <h3>改动前备份（护栏：能不能撤回，看这里）</h3>
    <div class="dim" style="color:#8a9aab;font-size:12px;margin-bottom:6px">
      备份落在两处：目标机 <code>/var/backups/aoc/&lt;任务ID&gt;/</code> 与管理机 <code>repo/var/backups/&lt;任务ID&gt;/</code>；
      「本就没有」表示该路径原本不存在（不需要备份）。
      <b>备份没成功时，变更步骤根本不会执行</b>。
    </div>
    ${rows.map(item).join('')}
  </div>`;
}

/* 恢复：🔴 级操作 —— 必须手输确认词「确认恢复」，且由**服务端**校验 */
async function restoreBackup(backupId, origPath) {
  const ans = await modalConfirm({
    title: '恢复此文件到变更前',
    body: `即将把备份恢复回：${origPath}\n\n`
        + '会发生什么：该路径的当前内容会被备份覆盖（这正是"回到变更前"的含义）。\n'
        + '影响面：如果这个文件在变更之后又被改过，那些改动会丢失。\n'
        + '自证：恢复后服务端会重新计算 sha256 与备份逐字节比对。',
    confirm_text: '确认恢复',
    // ★ 必须显式 requireText —— 这是被自己踩掉过一次的地方：
    //   modalConfirm 改成"只有 requireText 才要打字"之后，此处忘了标记，
    //   于是界面交上去的是空确认词，而服务端照样校验 → **恢复按钮 100% 被拒**。
    //   恢复是 red 级（覆盖现网文件、不可 undo），它属于"必须动手打字"的那一类。
  }, { requireText: true });
  if (!ans) return;
  try {
    const d = await api(`/api/backups/${encodeURIComponent(backupId)}/restore`, {
      method: 'POST',
      body: JSON.stringify({ confirm_text: ans.confirm_text }),
    });
    toast(d.ok ? '✅ 已恢复（sha256 逐字节校验通过）' : '恢复未成功：请看新的任务记录');
    replayTask(d.task_id);
    loadHistory();
  } catch (e) {
    await modalConfirm({
      title: '恢复被拒绝',
      body: `${e.reason || ''}\n\n建议：${e.advice || ''}`,
      confirm_text: '知道了',
    });
  }
}

/* ------------------------------------------------------------ T3：批量执行 */

/* 主机多选弹窗：返回选中的 host_id 数组；取消 → null */
function pickHosts(opts = {}) {
  return new Promise((resolve) => {
    const m = $('#modal');
    m.classList.remove('hidden');
    m.innerHTML = `<div class="box">
      <h3>${esc(opts.title || '选择要批量执行的机器')}</h3>
      <div class="body">${esc(opts.body || '同一动作、同一份参数会铺到选中的每一台；每台产出独立任务（可单独回放）。')}</div>
      <div style="margin:10px 0">
        ${S.hosts.map((h) => `<label style="display:block;margin:6px 0;cursor:pointer">
          <input type="checkbox" class="mHost" value="${esc(h.id)}">
          ${esc(hostLabel(h))} <span class="dim" style="color:#8a9aab">${esc(h.role || '')}</span>
        </label>`).join('')}
      </div>
      <div class="actions-row">
        <button id="mAll">全选</button>
        <button class="primary" id="mGo">执行选中</button>
        <button id="mNo">取消</button>
      </div>
    </div>`;
    $('#mAll').onclick = () => $$('.mHost').forEach((c) => { c.checked = true; });
    $('#mGo').onclick = () => {
      const v = $$('.mHost').filter((c) => c.checked).map((c) => c.value);
      m.classList.add('hidden');
      resolve(v);
    };
    $('#mNo').onclick = () => { m.classList.add('hidden'); resolve(null); };
  });
}

/* 批量执行入口：red 直接挡掉（服务端也会挡，这里只是不让人白点） */
async function batchRun(a) {
  if (a.risk === 'red') {
    await modalConfirm({
      title: 'red 级动作禁止批量执行',
      body: '批量会把一次手误同时放大到多台，而 red 恰好是不可 undo 的那一类。\n'
          + '请逐台执行并手输确认词 —— 这是 T3 定下的硬规矩（规范 §9.3），没有开关可以放开。',
      confirm_text: '知道了',
    });
    return;
  }
  const hosts = await pickHosts();
  if (!hosts || !hosts.length) return;

  if (a.risk !== 'green') {
    const ans = await modalConfirm({
      title: `确认批量执行（${hosts.length} 台）`,
      body: `即将在 ${hosts.length} 台机器上执行「${a.title}」，参数与当前表单一致。\n`
          + '每台独立执行、失败隔离（一台失败不影响其他）。',
      confirm_text: '我已确认要批量执行',
    });
    if (!ans) return;
  }

  $('#result').innerHTML = `<div class="sub">正在对 ${hosts.length} 台并发执行，请稍候…</div>`;
  try {
    const d = await api('/api/batch/run', {
      method: 'POST',
      body: JSON.stringify({ action_id: S.current, host_ids: hosts, params: S.params, confirm: true }),
    });
    renderBatch(d);
    loadHistory();
    loadBatches();   // 让「批次」页签立刻能看到这一批（否则要手动切页签才刷新）
  } catch (e) {
    $('#result').innerHTML = `<div class="banner bad"><h3>批量被拒绝</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
  }
}

/* 横向对比表：★ 差异才是重点 —— 4 台里只有 1 台不一样，那一台就该被看见 */
function renderBatch(d) {
  const rows = d.results.map((r) => `
    <tr>
      <td>${esc(r.host_name)}</td>
      <td>${statusBadge(r.status)}</td>
      <td>${r.verify_result === 'ok' ? '<span class="badge ok">通过</span>' : esc(r.verify_result || '-')}</td>
      <td class="dim">${r.duration_ms || 0}ms / ${r.step_total || 0} 步</td>
      <td>${r.task_id ? `<button class="ghost tiny" data-task="${esc(r.task_id)}">回放</button>` : '<span class="dim">未产生任务</span>'}</td>
    </tr>
    <tr><td colspan="5" style="padding:0 0 10px 0">
      ${r.error
        ? `<div class="banner bad" style="margin:0"><div>${esc(r.error.reason)}</div>
             ${r.error.advice ? `<div class="advice">建议：${esc(r.error.advice)}</div>` : ''}</div>`
        : `<pre class="concl" style="max-height:190px;overflow:auto;margin:0">${esc((r.conclusion || '（无结论）').slice(0, 700))}</pre>`}
    </td></tr>`).join('');

  const diff = d.diff || { consistent: true, differences: [], groups: [] };
  const diffHtml = diff.consistent
    ? '<div class="banner ok" style="margin:8px 0"><div>各台结论一致（按「任务状态 + 自证结果」判定，无差异列需要高亮）</div></div>'
    : diff.differences.map((x) => `<div class="banner bad" style="margin:8px 0">
        <div>⚠️ ${x.count}/${d.results.length} 台与其他不同：${esc(x.hosts.join('、'))}</div>
        <div class="advice">它们的状态是：${esc(x.conclusion)}</div></div>`).join('');

  $('#result').innerHTML = `
    <div class="banner ${d.status === 'ok' ? 'ok' : 'bad'}">
      <h3>批量执行结果 <span class="badge">批次 ${esc(d.batch_id)}</span></h3>
      <div>动作「${esc(d.action_title)}」× ${d.results.length} 台 ｜ 状态 ${esc(d.status)}</div>
      <div class="sub">每台都是独立任务：点「回放」看它自己的命令原文与逐步留证。</div>
    </div>
    ${diffHtml}
    <div class="section">
      <h3>横向对比</h3>
      <table class="bt"><thead><tr>
        <th>主机</th><th>状态</th><th>自证</th><th>耗时 / 步数</th><th>操作</th>
      </tr></thead><tbody>${rows}</tbody></table>
      <div class="dim" style="color:#8a9aab;font-size:12px;margin-top:6px">${esc((diff.note || ''))}</div>
    </div>`;
  $$('#result [data-task]').forEach((el) => {
    el.addEventListener('click', () => replayTask(el.dataset.task));
  });
}

function renderResult(d) {
  const t = d.task;
  const okAll = t.status === 'ok';
  const err = t.error;

  const verify = (t.verify_detail || []).map((v) => `
    <div class="gap-row">
      <span class="badge ${v.ok ? 'ok' : (v.severity === 'warn' ? 'warn' : 'failed')}">${v.ok ? '通过' : (v.severity === 'warn' ? '警告' : '不通过')}</span>
      <span>${esc(v.name)}</span>
      <span class="dim">来自 ${esc(v.from)}${v.field ? '.' + esc(v.field) : ''}</span>
    </div>`).join('');

  const steps = d.steps.map((s) => `
    <details class="step">
      <summary>
        ${statusBadge(s.status)}
        <b>${esc(s.title)}</b>
        ${s.iter ? `<span class="badge">${esc(s.iter)}</span>` : ''}
        <span class="dim" style="margin-left:auto;color:#8a9aab;font-size:12px">
          退出码 ${s.exit_code == null ? '-' : s.exit_code} · ${s.duration_ms}ms${s.optional ? ' · 可选' : ''}
        </span>
      </summary>
      <div class="body">
        ${s.error ? `<div class="banner bad" style="margin:8px 0">
            <div>${esc(s.error.reason)}</div>
            ${s.error.advice ? `<div class="advice">建议：${esc(s.error.advice)}</div>` : ''}
          </div>` : ''}
        <div class="kv">命令原文（实际交给 ssh 的字符串）：</div>
        <pre class="cmd">${esc(s.command)}</pre>
        ${s.parsed != null ? `<div class="kv">解析结果：</div><pre class="out">${esc(JSON.stringify(s.parsed, null, 2))}</pre>` : ''}
        ${s.stdout ? `<div class="kv">stdout：</div><pre class="out">${esc(s.stdout)}</pre>` : ''}
        ${s.stderr ? `<div class="kv">stderr：</div><pre class="out">${esc(s.stderr)}</pre>` : ''}
      </div>
    </details>`).join('');

  $('#result').innerHTML = `
    <div class="banner ${okAll ? 'ok' : 'bad'}">
      <h3>${okAll ? '✅ 执行成功' : '❌ ' + (t.status === 'aborted' ? '动作未执行（中止）' : '执行失败')}
        <span class="badge">任务 ${esc(t.id)}</span></h3>
      ${err ? `<div><b>原因：</b>${esc(err.reason)}</div>
               ${err.advice ? `<div class="advice"><b>建议：</b>${esc(err.advice)}</div>` : ''}
               ${err.detail ? `<details class="detail"><summary>技术详情</summary><pre class="out">${esc(err.detail)}</pre></details>` : ''}`
            : `<div class="sub">用时 ${t.duration_ms}ms ｜ ${t.started_at} → ${t.ended_at} ｜ 目标机 ${esc(t.host_name)}</div>`}
    </div>

    ${t.conclusion ? `<div class="section"><h3>结论（一屏给全）</h3>
        <pre class="concl">${esc(t.conclusion)}</pre></div>` : ''}

    ${verify ? `<div class="section"><h3>自证（verify）</h3>${verify}</div>` : ''}

    ${renderBackups(d.backups)}

    <div class="section">
      <h3>步骤留证（${d.steps.length} 步）</h3>
      ${steps}
    </div>

    <div class="section">
      <h3>计划原文（执行前就已确定）</h3>
      <pre class="out">${esc(t.command_preview || '')}</pre>
    </div>

    <div class="section">
      <h3>导出（T2 验收 #4「结果可导出」）</h3>
      <div class="actions-row">
        <button id="btnExportTxt">导出报告（.txt）</button>
        <button id="btnExportMd">复制为 Markdown</button>
        <span class="sub" id="exportHint">两种格式都会在服务端归档一份到 <code>var/artifacts/exports/</code></span>
      </div>
    </div>
  `;

  // 导出按钮要等 innerHTML 落到 DOM 之后再挂事件（顺序反了会拿到 null）
  const exportUrl = (fmt, download) =>
    `/api/tasks/${encodeURIComponent(t.id)}/export?format=${fmt}${download ? '&download=1' : ''}`;
  const bTxt = $('#btnExportTxt');
  // ★★ T15 修：导出通道**过了鉴权闸门** ⇒ 不能再 `window.open`（那样带不上令牌，必然 401）
  if (bTxt) bTxt.addEventListener('click', () => downloadText(
    exportUrl('txt', true), `aoc-${t.id}-${t.action_id || 'action'}.txt`));
  const bMd = $('#btnExportMd');
  if (bMd) bMd.addEventListener('click', () => copyMarkdown(t.id));

  // T3：备份的「恢复此文件」按钮（同样必须等 innerHTML 落到 DOM 之后再挂事件）
  $$('#result [data-restore]').forEach((el) => {
    el.addEventListener('click', () => restoreBackup(el.dataset.restore, el.dataset.path));
  });
}

/* 复制为 Markdown：优先用剪贴板 API（127.0.0.1 属安全上下文），否则退回 textarea 方案 */
async function copyMarkdown(taskId) {
  const hint = $('#exportHint');
  const url = `/api/tasks/${encodeURIComponent(taskId)}/export?format=md`;
  try {
    // ★★ T15 修：这里原来是个**裸 fetch**（不带令牌）—— 加鉴权之后必然 401。
    const res = await fetch(url, { headers: authHeaders() });
    if (!res.ok) { if (res.status === 401) showLogin(S.authInfo && S.authInfo.configured ? 'login' : 'setup'); throw new Error('HTTP ' + res.status); }
    const text = await res.text();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    if (hint) hint.textContent = `已复制 Markdown（${text.length} 字符）到剪贴板，可直接粘进工单/文档`;
    toast('已复制为 Markdown');
  } catch (e) {
    if (hint) hint.textContent = '复制失败：' + (e && e.message ? e.message : e) + '（可改用「导出报告」下载文件）';
    toast('复制失败，可用「导出报告（.txt）」下载');
  }
}

/* ---------------------------------------------------------------- 历史 */

async function loadHistory() {
  const d = await api('/api/tasks?limit=60');
  $('#pane-history').innerHTML = d.tasks.length ? d.tasks.map((t) => `
    <div class="task-item" data-id="${esc(t.id)}" role="button" tabindex="0"
         aria-label="回放任务 ${esc(t.id)}：${esc(t.action_title || t.action_id)}，${esc(t.status)}">
      <div><b>${esc(t.action_title || t.action_id)}</b> ${t.status === 'ok' ? '<span class="badge ok">成功</span>' : '<span class="badge failed">' + esc(t.status) + '</span>'}</div>
      <div class="dim" style="color:#8a9aab">${esc(t.host_name || '')} · ${esc(t.started_at || '')} · ${t.duration_ms || 0}ms · ${t.step_total || 0} 步</div>
      <div class="id">${esc(t.id)}</div>
    </div>`).join('') : '<div class="sub">还没有执行记录</div>';

  $$('#pane-history .task-item').forEach((el) => {
    el.addEventListener('click', () => replayTask(el.dataset.id));
    // 键盘可达（与动作卡片同一套约定：role=button 必须能按 Enter/Space 触发）
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); replayTask(el.dataset.id); }
    });
  });
}

async function replayTask(id) {
  const d = await api('/api/tasks/' + encodeURIComponent(id));
  switchTab('actions');
  $('#content').innerHTML = `<h2>任务回放</h2>
    <div class="sub">任务 ${esc(id)} —— 这是从数据库里读回来的历史记录，不是重新执行。</div>
    <div id="result"></div>`;
  // 复用同一个渲染器：历史记录与刚跑完的结果结构一致
  // ★ 必须把 backups 一起传进去：任务详情接口本来就返回了它（store.list_backups），
  //   少传一个字段的后果是「改动前备份」区块在**历史回放里永远消失** ——
  //   备份只在刚跑完那一次可见，一刷新就再也看不到，也就点不到「恢复此文件」。
  renderResult({ task: d.task, steps: d.steps, backups: d.backups });
  $('#result').scrollIntoView({ behavior: 'smooth' });
}

/* ------------------------------------------------------------ 批次（T3 的批量证据持久化） */

/* 为什么要有这个页签：批量跑完那张「横向对比」是**证据**，不是一次性弹窗。
 * 以前它只活在 #result 里，一刷新即丢 —— 证据丢了，"每台可回放"就退化成串行任务列表，
 * 而"4 台里只有 1 台不一样"这个最该被看见的结论也就没了。
 * 这里把 /api/batches 列出来，点开复用 renderBatch 的**同一张**对比表。 */
async function loadBatches() {
  const d = await api('/api/batches');
  $('#pane-batches').innerHTML = d.batches.length ? d.batches.map((b) => {
    const total = b.total || 0;
    const okN = b.ok_count || 0;
    const rate = total ? Math.round(okN * 100 / total) : 0;
    const cls = b.status === 'ok' ? 'ok' : (b.status === 'partial' ? 'warn' : 'failed');
    const label = { ok: '全部成功', partial: '部分成功', failed: '全部失败' }[b.status] || b.status;
    return `<div class="task-item" data-batch="${esc(b.id)}" role="button" tabindex="0"
                 aria-label="批次 ${esc(b.id)}：${esc(b.action_title || b.action_id)}，${esc(b.status)}">
      <div><b>${esc(b.action_title || b.action_id)}</b> <span class="badge ${cls}">${esc(label)}</span></div>
      <div class="dim" style="color:#8a9aab">${okN}/${total} 台成功（${rate}%）· ${esc(b.started_at || '')} · ${b.duration_ms || 0}ms</div>
      <div class="id">${esc(b.id)}</div>
    </div>`;
  }).join('') : '<div class="sub">还没有批量执行记录</div>';

  $$('#pane-batches .task-item').forEach((el) => {
    el.addEventListener('click', () => replayBatch(el.dataset.batch));
    // 键盘可达（与动作卡片/历史同一套约定）
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); replayBatch(el.dataset.batch); }
    });
  });
}

/* 批次回放：服务端按当时的任务记录**重算**对比表与差异分组（不是缓存的一张图），
 * 所以返回结构与刚跑完时一模一样 —— 前端直接复用 renderBatch，不养第二套渲染逻辑。 */
async function replayBatch(batchId) {
  const d = await api('/api/batches/' + encodeURIComponent(batchId));
  switchTab('actions');
  $('#content').innerHTML = `<h2>批次回放</h2>
    <div class="sub">批次 ${esc(batchId)} —— 从数据库读回的历史批次；差异分组由服务端重算，不是存档快照。</div>
    <div id="result"></div>`;
  renderBatch(d);
  $('#result').scrollIntoView({ behavior: 'smooth' });
}

/* ---------------------------------------------------------------- 一键体检（T4） */

const LV_COLOR = { crit: '#ff6b6b', warn: '#f0c040', ok: '#5ec26a', unknown: '#8a9aab' };

function renderCheckup() {
  const hosts = S.hosts || [];
  $('#pane-checkup').innerHTML = `
    <div class="cov-box" style="padding:8px">
      <div class="group-title">一键体检（只读）</div>
      <div style="color:#8a9aab;font-size:12px;margin-bottom:8px;line-height:1.6">
        12 项只读体检 → 「总判 + 每项判定 + 先去查什么」。<br>
        勾 <b>1 台</b>出单机报告；勾 <b>多台</b>并排对比（走批量框架，失败隔离）。
      </div>
      <div id="ckHosts">
        ${hosts.map((h) => `
          <label style="display:flex;align-items:center;gap:8px;padding:4px 2px;cursor:pointer">
            <input type="checkbox" value="${esc(h.id)}" ${h.id === currentHostId() ? 'checked' : ''}>
            <span>${esc(h.id)}</span>
            <span style="color:#8a9aab;font-size:12px">${esc(h.role || '')}</span>
          </label>`).join('')}
      </div>
      <button class="primary" id="btnRunCheckup" style="margin-top:8px">开始体检</button>
      <div id="ckHint" style="color:#8a9aab;font-size:12px;margin-top:6px">
        单机约 5 秒；4 台并发约 6 秒（采集是"4 台并发 + 单机顺序"，不是 12 项并发）。
      </div>
    </div>`;
  $('#btnRunCheckup').addEventListener('click', runCheckup);
}

async function runCheckup() {
  const ids = $$('#ckHosts input:checked').map((i) => i.value);
  if (!ids.length) { toast('至少勾一台机器'); return; }
  const btn = $('#btnRunCheckup');
  btn.disabled = true;
  btn.textContent = `体检中…（${ids.length} 台）`;
  $('#ckHint').textContent = '正在采集 12 项数据…完成后右侧会出现报告。';
  try {
    const d = await api('/api/checkup/run', { method: 'POST', body: JSON.stringify({ host_ids: ids }) });
    renderCheckupReports(d);
    toast(`体检完成：${d.hosts_total} 台`);
  } catch (e) {
    $('#content').innerHTML = `<div class="card"><div class="group-title">体检失败</div>
      <div class="note">${esc(e.reason || '')}\n${esc(e.advice || '')}</div></div>`;
    toast('体检失败：' + (e.reason || '未知'));
  } finally {
    btn.disabled = false;
    btn.textContent = '开始体检';
    $('#ckHint').textContent = '单机约 5 秒；4 台并发约 6 秒。';
  }
}

function renderCheckupReports(d) {
  const agg = d.aggregate || {};
  const th = d.thresholds && d.thresholds.values ? d.thresholds.values : null;
  const aggLine = Object.keys(LV_COLOR)
    .map((lv) => `<span style="color:${LV_COLOR[lv]}">${lv === 'crit' ? '🔴' : lv === 'warn' ? '🟡' : lv === 'ok' ? '🟢' : '⚠️'} ${agg[lv] || 0} 项${({ crit: '要处理', warn: '注意', ok: '通过', unknown: '无法判定' })[lv]}</span>`)
    .join(' · ');
  const thLine = th ? `<div style="color:#8a9aab;font-size:12px;margin-top:6px">
      本次判定用的阈值：容量 ≥${th.disk_pct_warn}% 黄 / ≥${th.disk_pct_crit}% 红 ｜ inode ≥${th.inode_pct_warn}% 黄 / ≥${th.inode_pct_crit}% 红
      ｜ 失败服务 ≥${th.failed_service_warn} 个黄 ｜ 内核错误 ≥${th.kernel_err_warn} 条黄 ｜ 出现 OOM 红<br>
      来源：config.yaml → checkup.thresholds（改阈值不用改代码）</div>` : '';

  $('#content').innerHTML = `
    <div class="card">
      <div class="group-title">一键体检 · ${d.hosts_total} 台（批次 ${esc(d.batch_id || '—')}）</div>
      <div style="font-size:14px;margin:6px 0">汇总：${aggLine}</div>
      ${thLine}
    </div>
    ${(d.reports || []).map(renderCheckupCard).join('')}`;
}

function renderCheckupCard(rp) {
  const h = rp.host || {};
  const items = rp.items || [];
  const head = `<div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
      <b>${esc(h.name || h.id || '')}</b>
      <span style="color:#8a9aab;font-size:12px">${esc(h.address || '')} · role=${esc(h.role || '-')}</span>
      <span style="margin-left:auto;color:${LV_COLOR[rp.overall] || '#8a9aab'}">${esc(rp.overall_icon || '')} ${esc(rp.summary || '')}</span>
    </div>`;

  if (!items.length) {
    const err = rp.error || {};
    return `<div class="card">${head}
      <div class="note">${esc(err.reason || '没有可展示的判定项')}\n${esc(err.advice || '')}</div></div>`;
  }

  const rows = items.map((it) => `
    <div style="border-left:3px solid ${LV_COLOR[it.level] || '#8a9aab'};padding:6px 0 6px 10px;margin:8px 0">
      <div><b style="color:${LV_COLOR[it.level] || '#8a9aab'}">${esc(it.icon || '')} ${it.no}. ${esc(it.title)}</b>
        <span style="margin-left:8px">${esc(it.verdict || '')}</span></div>
      ${(it.evidence || []).map((e) => `<div style="color:#8a9aab;font-size:12px;margin-top:2px">${esc(e)}</div>`).join('')}
      ${it.advice ? `<div style="font-size:12px;margin-top:4px">→ ${esc(it.advice)}</div>` : ''}
      ${(it.next_action || it.next_hint)
        ? `<div style="font-size:12px;margin-top:2px;color:#8fb8e8">↳ 先去查：${esc(it.next_action || '')} ${esc(it.next_action_title || it.next_hint || '')}</div>` : ''}
    </div>`).join('');

  const exportBtns = rp.task_id ? `
      <button class="ghost tiny" onclick="downloadText('/api/checkup/${encodeURIComponent(rp.task_id)}/export?format=md&download=1','aoc-checkup-${encodeURIComponent(rp.task_id)}.md')">导出报告 .md</button>
      <button class="ghost tiny" onclick="downloadText('/api/checkup/${encodeURIComponent(rp.task_id)}/export?format=txt&download=1','aoc-checkup-${encodeURIComponent(rp.task_id)}.txt')">.txt</button>
      <span style="color:#8a9aab;font-size:12px">任务 ${esc(rp.task_id)} · 采集 ${rp.duration_ms || 0} ms</span>` : '';

  return `<div class="card">${head}
    ${rows}
    <div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">${exportBtns}</div>
  </div>`;
}

/* ---------------------------------------------------------------- 覆盖率 */

function renderCoverage() {
  const c = S.coverage;
  if (!c) return;
  const w = c.weighted || { w_done: 0, w_all: 0, rate: 0, by_src: {}, missing: [], items_total: 0, items_done: 0, platform_total: 0, platform_done: 0 };
  $('#covTip').textContent =
    `覆盖率 · 条数 ${c.done}/${c.total}（${c.rate}%）｜加权(反推) ${w.w_done}/${w.w_all}（${w.rate}%）· P0 ${c.p0_done}/${c.p0_total}`;

  // 权重角标：悬停显示 weight_why（★ 明确标「反推」，不冒充用户原话 —— 规范 §10.3.3）
  const SRC = { infer: '反推·记录点名', fallback: '兜底·按优先级', user: '用户提供' };
  const chip = (r) => `<span style="display:inline-block;padding:0 6px;border-radius:8px;background:#1d2a3a;color:#8fb8e8;font-size:11px;margin-left:6px;cursor:help" title="${esc(r.weight_why || '')}">w${r.weight} · ${esc(SRC[r.weight_src] || r.weight_src || '')}</span>`;

  const srcRows = Object.entries(w.by_src || {}).map(([k, v]) => `
      <div class="dim" style="color:#8a9aab;font-size:12px">
        ${esc(SRC[k] || k)}：${v.count} 条 · 权重 ${v.w_done}/${v.w_all}（${v.w_all ? Math.round(v.w_done * 100 / v.w_all) : 0}%）
      </div>`).join('');

  const domainRows = Object.entries(c.by_domain || {}).map(([d, v]) => `
    <div style="margin-bottom:10px">
      <div>域 ${esc(d)} · ${esc(v.name)}　<b>条数 ${v.done}/${v.total}</b>（${v.rate}%）　
        <span class="dim" style="color:#8a9aab">加权 ${v.w_done}/${v.w_all}（${v.w_rate}%）</span></div>
      <div class="bar"><i style="width:${v.rate}%"></i></div>
    </div>`).join('');

  const platRows = (c.platform || []).map((r) => `<div class="gap-row">
        <span class="badge ${r.done ? 'ok' : ''}">${r.done ? '✓' : '缺口'}</span>
        <span>${esc(r.label)}${chip(r)}</span>
        <span class="dim">${esc(r.id)} · since ${esc(r.stage || '-')}</span>
      </div>`).join('');

  const wMissing = (w.missing || []).map((m) => `<div class="gap-row">
        <span class="badge">${esc(m.priority || '平台')}</span>
        <span>${esc(m.label)}${chip(m)}</span>
        <span class="dim">${esc(m.id)} · ${m.kind === 'platform' ? '平台能力' : '计划 ' + esc(m.stage || '-')}</span>
      </div>`).join('');

  $('#pane-gaps').innerHTML = `
    <div class="cov-box" style="padding:6px">
      <div style="margin-bottom:12px">
        <b>口径 A · 条数：${c.done}/${c.total}（${c.rate}%）</b>
        <span class="dim" style="color:#8a9aab">P0 ${c.p0_done}/${c.p0_total}（${c.p0_rate}%）· 只数"一个动作一条"</span>
        <div class="bar"><i style="width:${c.rate}%"></i></div>
      </div>
      <div style="margin-bottom:12px">
        <b>口径 B · 加权（反推）：${w.w_done}/${w.w_all}（${w.rate}%）</b>
        <span class="dim" style="color:#8a9aab">条目 ${w.items_done}/${w.items_total}（含平台能力 ${w.platform_done}/${w.platform_total}）</span>
        <div class="bar"><i style="width:${w.rate}%"></i></div>
        <div class="dim" style="color:#8a9aab;font-size:12px;margin-top:6px">
          ★ 权重<b>不是用户原话</b>，是由 T1~T3 记录<b>反推</b>的（基准 P0=4 / P1=3 / P2=2 / P3=1，平台能力 4；
          只有"记录里有名有姓的点名"才 +1）。每条权重的出处见 w 角标，鼠标悬停可见。
        </div>
        ${srcRows}
      </div>
      ${domainRows}
      <div class="group-title" style="margin-top:16px">平台能力（${w.platform_done}/${w.platform_total} · 已纳入加权分母）</div>
      <div class="dim" style="color:#8a9aab;font-size:12px;margin-bottom:8px">
        这些不是"一个动作"，所以不进条数口径；但它们是天天在用的东西 —— 加权口径里必须算它们。
      </div>
      ${platRows}
      <div class="group-title" style="margin-top:16px">加权缺口（${(w.missing || []).length} 项 · 按权重降序）</div>
      <div class="dim" style="color:#8a9aab;font-size:12px;margin-bottom:8px">
        设计要的效果：<b>高权重还没做</b>的东西一眼可见，而不是被平摊进"还差 4 条"。
      </div>
      ${wMissing}
      <div class="group-title" style="margin-top:16px">缺口清单（条数口径 · ${c.missing.length} 项）</div>
      <div class="dim" style="color:#8a9aab;font-size:12px;margin-bottom:8px">
        这是设计要的效果：不做完也知道还差什么，换人接手一眼看清。
      </div>
      ${c.missing.map((m) => `<div class="gap-row">
        <span class="badge">${esc(m.priority || '')}</span>
        <span>${esc(m.label)}</span>
        <span class="dim">${esc(m.id)} · 计划 ${esc(m.stage || '-')}</span>
      </div>`).join('')}
      <div class="group-title" style="margin-top:16px">已实现（${c.implemented.length} 项）</div>
      ${c.implemented.map((m) => `<div class="gap-row">
        <span class="badge ok">✓</span>
        <span>${esc(m.label)}</span>
        <span class="dim">${esc(m.id)}</span>
      </div>`).join('')}
    </div>`;
}

/* ------------------------------------------------------------ T5：服务目录（配方） */

/* 服务目录 = "选服务 → 填参数 → 一键跑完"。它与动作页签走**同一套执行引擎**，
 * 区别只在：配方把多个动作编排成"一件完整的事"，并且必须给出**反向操作**。
 * 三条设计宪法在界面上的落点：
 *   ① 配方只声明期望 → 界面上的"前置检查 / 健康检查"是**判定结果**，不是可编辑的规则
 *   ② 「没变」可断言 → 报告把 变更 / 未变更 / ★无法判定 三段分开列（★不许把"判不出来"混进"没变更"）
 *   ③ 反向操作齐备 → 停止 / 卸载·保留数据 / 卸载·全删 三个按钮
 */

const MODE_LABEL = {
  deploy: '部署', stop: '停止服务',
  uninstall_keep: '卸载·保留数据', uninstall_purge: '卸载·全删',
};

async function loadRecipes() {
  try {
    const d = await api('/api/recipes');
    S.recipes = d.recipes;
    S.recipeLoad = d.load;          // ★ T7：装载报告（规范 §12.17 不许静默少装载）
    renderRecipeList();
  } catch (e) {
    $('#pane-recipes').innerHTML = `<div class="banner bad"><div>${esc(e.reason || '')}</div></div>`;
  }
}

/* ★ T7 新增（规范 §12.17）：配方是**磁盘上的文件**，改完不用重启控制台 ——
 *   「重新装载」走的是与启动时**同一套**装载期校验（重载不是绕过校验的后门）。
 *   两个必须显式给人看的东西：
 *     · 装了几份（loaded）
 *     · ★ 哪几份**没装进来**、为什么（failed：一份一段，带行号/键名）
 *   没有它，"重载"就变成一次许愿：用户改完配方不知道到底进没进去。 */
function recipeLoadBox(load) {
  if (!load) return '';
  const rows = (load.failed || []).map((f) => `
    <div class="banner bad" style="margin:8px 0">
      <h3>${esc(f.file)} 没有装载</h3>
      <div>${(f.errors || []).map(esc).join('<br>')}</div>
      ${f.detail ? `<details class="detail"><summary>技术详情</summary><pre class="out">${esc(f.detail)}</pre></details>` : ''}
    </div>`).join('');
  const head = load.ok
    ? `<div class="row"><button class="ghost tiny" id="btnReloadRecipes">重新装载配方</button>
         <span class="dim">已装载 ${(load.loaded || []).length} 份${load.at ? ' · ' + esc(load.at) : ''}</span></div>`
    : `<div class="row"><button class="ghost tiny" id="btnReloadRecipes">重新装载配方</button>
         <span class="badge failed">${(load.failed || []).length} 份没装进来</span>
         <span class="dim">已装载 ${(load.loaded || []).length} 份</span></div>`;
  return head + rows;
}

async function reloadRecipes() {
  try {
    const d = await api('/api/recipes/reload', { method: 'POST', body: '{}' });
    S.recipes = d.recipes;
    S.recipeLoad = d.load;
    renderRecipeList();
    toast(d.load.ok
      ? `重新装载完成：${d.load.loaded.length} 份`
      : `重新装载完成，但有 ${d.load.failed.length} 份没装进来（见左侧红条）`);
  } catch (e) {
    toast('重新装载失败：' + (e.reason || '未知原因'));
  }
}

function renderRecipeList() {
  const el = $('#pane-recipes');
  const box = recipeLoadBox(S.recipeLoad);
  if (!S.recipes.length) {
    el.innerHTML = box + '<div class="placeholder">还没有配方。在 <code>catalog/recipes/</code> 下放一份 YAML，然后点上面的「重新装载配方」即可（不用重启控制台）。</div>';
    bindRecipeLoadBox();
    return;
  }
  el.innerHTML = box + S.recipes.map((r) => {
    const last = r.last_run;
    const lastTxt = last
      ? `<span class="badge ${last.status === 'ok' ? 'ok' : 'failed'}">上次${last.status === 'ok' ? '成功' : '失败'}</span>
         <span class="dim">${esc(last.host_name || '')} · ${esc(last.started_at || '')} · 变更 ${(last.changed_steps || []).length} 项</span>`
      : '<span class="badge">从未部署</span>';
    return `<div class="card ${r.id === S.recipeId ? 'active' : ''}" data-rid="${esc(r.id)}" role="button" tabindex="0">
      <h4>${esc(r.name)} <span class="dim">配方 v${esc(r.version)}</span></h4>
      <p>${esc(r.summary)}</p>
      <div class="row">${riskBadge(r.risk)}<span class="badge">${r.steps.length} 步</span>
        <span class="badge">${r.params.length} 个参数</span></div>
      <div class="row">${lastTxt}</div>
    </div>`;
  }).join('');
  $$('#pane-recipes .card').forEach((el) => {
    el.addEventListener('click', () => selectRecipe(el.dataset.rid));
  });
  bindRecipeLoadBox();
}

function bindRecipeLoadBox() {
  const b = $('#btnReloadRecipes');
  if (b) b.addEventListener('click', reloadRecipes);
}

async function selectRecipe(id) {
  S.recipeId = id;
  S.recipeParams = {};
  renderRecipeList();
  $('#content').innerHTML = '<div class="placeholder">正在生成计划预览…</div>';
  try {
    const d = await api(`/api/recipes/${encodeURIComponent(id)}/plan`, {
      method: 'POST',
      body: JSON.stringify({ host_id: currentHostId(), params: {}, mode: 'deploy' }),
    });
    S.recipePlan = d;
    renderRecipePage(d);
  } catch (e) {
    $('#content').innerHTML = `<div class="banner bad"><h3>无法生成计划</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}
      ${e.detail ? `<details class="detail"><summary>技术详情</summary><pre class="out">${esc(e.detail)}</pre></details>` : ''}</div>`;
  }
}

function recipeField(p, val) {
  const v = val == null ? '' : String(val);
  const help = p.help ? `<div class="help">${esc(p.help)}</div>` : '';
  if (p.type === 'enum' && p.choices && p.choices.length) {
    const opts = p.choices.map((c) => `<option value="${esc(c)}"${c === v ? ' selected' : ''}>${esc(c)}</option>`).join('');
    return `<div class="field"><label>${esc(p.label)}${p.required ? ' <span class="req">*</span>' : ''}</label>
      <select data-param="${esc(p.name)}">${opts}</select>${help}</div>`;
  }
  const isInt = p.type === 'int';
  return `<div class="field"><label>${esc(p.label)}${p.required ? ' <span class="req">*</span>' : ''}</label>
    <input type="text" data-param="${esc(p.name)}" value="${esc(v)}"
      placeholder="${esc(p.placeholder || '')}" autocomplete="off" spellcheck="false"
      ${isInt ? 'inputmode="numeric"' : ''}>${help}</div>`;
}

/* ★ T7·S5（规范 §12.21）：配方体检 —— **不连目标机**的静态检查。
 * 三态：ok / warn（能跑，但有条边界要知道）/ fail（别拿去跑）。
 * ★ 为什么要它：自己写配方的人最怕的不是"报错"，而是"跑起来看起来没事"。
 *   体检把"判得出来没有"这件事提前摆到台面上（尤其"健康检查只有旁证"这种。 */
async function recipeLint(rid) {
  const box = $('#lintBox');
  if (!box) return;
  box.innerHTML = '<div class="dim">正在体检…</div>';
  try {
    const d = await api(`/api/recipes/${encodeURIComponent(rid)}/lint`);
    const l = d.lint;
    const badge = { ok: 'ok', warn: 'warn', fail: 'failed' };
    const rows = l.items.map((i) => `<div class="gap-row">
      <span class="badge ${badge[i.level] || ''}">${esc(i.level)}</span>
      <span>${esc(i.name)}</span>
      <span class="dim">${esc(i.detail)}</span></div>`).join('');
    box.innerHTML = `<div class="banner ${l.overall === 'fail' ? 'bad' : (l.overall === 'warn' ? '' : 'ok')}"
        style="margin-top:8px">
        <div>体检结论：<b>${esc(l.overall)}</b> ｜ ok ${l.ok} · warn ${l.warn} · fail ${l.fail}</div>
      </div>${rows}`;
  } catch (e) {
    box.innerHTML = `<div class="banner bad" style="margin-top:8px"><div>${esc(e.reason || '体检失败')}</div></div>`;
  }
}

function renderRecipePage(d) {
  const r = d.recipe;
  const form = r.params.map((p) => recipeField(p, d.params[p.name])).join('');

  const expectRow = (e) => `<div class="gap-row"><span class="badge">${esc(e.kind)}</span>
    <span>${esc((e.spec && e.spec.kind) || e.kind)}</span>
    <span class="dim">${esc(JSON.stringify(e.spec_rendered || e.spec))}${e.fail_reason ? ' ｜ 拦截语：' + esc(e.fail_reason) : ''}</span></div>`;

  const stepRow = (s) => `<div class="gap-row">
    <span class="badge">${esc(s.kind === 'template' ? '渲染模板' : (s.action || '-'))}</span>
    <span><b>${esc(s.title)}</b></span>
    <span class="dim">${s.kind === 'template'
      ? esc(s.template || '') + ' → ' + esc(s.dest_rendered || s.dest || '') + '（幂等：内容相同就不写）'
      : esc((s.args_rendered && JSON.stringify(s.args_rendered)) || '')}</span></div>`;

  $('#content').innerHTML = `
    <div class="section">
      <h3>${esc(r.name)} <span class="badge">配方 v${esc(r.version)}</span> ${riskBadge(r.risk)}</h3>
      <div class="sub">${esc(r.summary)}</div>
      ${r.note ? `<details class="detail"><summary>这份配方为什么这么写（维护者说明）</summary><pre class="out">${esc(r.note)}</pre></details>` : ''}
      <div class="actions-row"><button class="ghost tiny" id="btnRecipeLint" data-rid="${esc(r.id)}">配方体检（不连目标机）</button>
        <span class="dim">检查"写全了没有 / 判得出来没有"—— 改完配方点一下，比跑一条奇怪的失败便宜</span></div>
      <div id="lintBox"></div>
    </div>

    <div class="section" id="recipeParams">
      <h3>填参数（${r.params.length} 个，已填默认值，可改）</h3>
      <div class="actions-row" style="flex-wrap:wrap">${form}</div>
    </div>

    <div class="section">
      <h3>前置检查 preflight（不成立就不动手）</h3>
      ${(d.preflight || []).map(expectRow).join('') || '<div class="sub">（无）</div>'}
    </div>

    <div class="section">
      <h3>执行计划（普通步骤）</h3>
      ${(d.steps || []).map(stepRow).join('') || '<div class="sub">（无）</div>'}
    </div>

    ${(d.trigger_steps || []).length ? `<div class="section">
      <h3>条件步骤（★ 只在被 notify 唤起时执行）</h3>
      <div class="sub">这些步骤**不会**无条件跑 —— 只有它上游那一步「内容真的变了」才会触发。</div>
      ${d.trigger_steps.map(stepRow).join('')}
    </div>` : ''}

    <div class="section">
      <h3>健康检查 health（不过就算失败）</h3>
      ${(d.health || []).map(expectRow).join('') || '<div class="sub">（无）</div>'}
    </div>

    <div class="section">
      <h3>操作</h3>
      <div class="actions-row">
        <button class="primary" id="btnRecipeDeploy">部署 / 收敛（幂等）</button>
        <button id="btnRecipeProbe">检测当前状态（只读）</button>
        <button id="btnRecipeStop">停止服务</button>
        <button class="danger" id="btnRecipeKeep">卸载·保留数据</button>
        <button class="danger" id="btnRecipePurge">卸载·全删</button>
      </div>
      <div class="sub">卸载会删掉什么、保留什么，都写在配方里；「全删」与「停止」需要**手输确认词**。</div>
      <div class="actions-row" style="margin-top:8px">
        <select id="batchMode" title="这一批要跑哪种模式">
          <option value="deploy">部署 / 收敛</option>
          <option value="stop">停止服务</option>
          <option value="uninstall_keep">卸载·保留数据</option>
          <option value="uninstall_purge">卸载·全删</option>
        </select>
        <button id="btnRecipeBatch"${r.risk === 'red' ? ' disabled title="red 级配方禁止批量执行（T3 硬规矩，规范 §12.18）"' : ''}>批量执行（多选机器）</button>
        <span class="dim">同一份配方 + 同一份参数铺到多台，每台一个**独立执行**、失败隔离</span>
      </div>
      ${r.risk === 'red'
        ? '<div class="help">★ red 级配方<b>禁止批量</b>：批量会把一次手误同时放大到多台，而 red 恰好是不可 undo 的那一类（服务端也会拒绝，这里只是不让人白点）。</div>'
        : '<div class="help">★ 闸门：<b>red 禁止批量</b>（无开关）｜yellow 批量要<b>二次确认</b>｜「停止 / 全删」这类模式照样要<b>手输确认词</b>（服务端逐台校验）。横向对照按「执行状态 + 收敛检查结果」判，<b>不看变更步数</b>。</div>'}
    </div>
    <div id="result"></div>
  `;

  $$('#recipeParams [data-param]').forEach((el) => {
    el.addEventListener('change', () => {
      S.recipeParams[el.dataset.param] = el.value;
      refreshRecipePlan();
    });
  });
  $('#btnRecipeDeploy').addEventListener('click', () => runRecipe('deploy'));
  $('#btnRecipeProbe').addEventListener('click', recipeProbe);
  $('#btnRecipeStop').addEventListener('click', () => runRecipe('stop'));
  $('#btnRecipeKeep').addEventListener('click', () => runRecipe('uninstall_keep'));
  $('#btnRecipePurge').addEventListener('click', () => runRecipe('uninstall_purge'));
  const btnRB = $('#btnRecipeBatch');
  if (btnRB && !btnRB.disabled) btnRB.addEventListener('click', recipeBatchRun);
  const btnLint = $('#btnRecipeLint');
  if (btnLint) btnLint.addEventListener('click', () => recipeLint(btnLint.dataset.rid));
  S.recipeParams = Object.assign({}, d.params_machine);
}

async function refreshRecipePlan() {
  try {
    const d = await api(`/api/recipes/${encodeURIComponent(S.recipeId)}/plan`, {
      method: 'POST',
      body: JSON.stringify({ host_id: currentHostId(), params: S.recipeParams, mode: 'deploy' }),
    });
    S.recipePlan = d;
    // 只刷新"参数回显"以外的部分：重建整页最省事，且表单值已经收进 S.recipeParams
    const keep = Object.assign({}, S.recipeParams);
    renderRecipePage(d);
    S.recipeParams = keep;
  } catch (e) {
    toast(e.reason || '计划刷新失败');
  }
}

async function recipeProbe() {
  $('#result').innerHTML = '<div class="sub">正在只读探测…</div>';
  try {
    const d = await api(`/api/recipes/${encodeURIComponent(S.recipeId)}/probe`, {
      method: 'POST',
      body: JSON.stringify({ host_id: currentHostId(), params: S.recipeParams }),
    });
    const rows = (d.checks || []).map((c) => `<div class="gap-row">
      <span class="badge ${c.state === 'pass' ? 'ok' : (c.state === 'fail' ? 'failed' : 'warn')}">${esc(c.state)}</span>
      <span>${esc(c.expected)}</span><span class="dim">实际：${esc(c.actual || '（无）')}</span></div>`).join('');
    $('#result').innerHTML = `<div class="section"><h3>当前状态（只读）</h3>
      <div class="banner ${d.healthy ? 'ok' : 'bad'}"><div>${esc(d.summary)}</div></div>
      ${rows}</div>`;
  } catch (e) {
    $('#result').innerHTML = `<div class="banner bad"><div>${esc(e.reason || '')}</div></div>`;
  }
}

async function runRecipe(mode) {
  let d = S.recipePlan;
  if (!d) return;
  // ★ 闸门强度**按本次要跑的模式**现取（规范 §12.6.2）：
  //   复用 selectRecipe() 那份（deploy）会让"停止 / 全删"丢掉手输确认词的要求 ——
  //   服务端仍然拦得住，但界面就成了"点一下就以为确认过"。
  try {
    d = await api(`/api/recipes/${encodeURIComponent(S.recipeId)}/plan`, {
      method: 'POST',
      body: JSON.stringify({ host_id: currentHostId(), params: S.recipeParams, mode }),
    });
  } catch (e) {
    $('#result').innerHTML = `<div class="banner bad"><h3>无法生成计划</h3>
      <div>${esc(e.reason || '')}</div>${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
    return;
  }
  const needText = (d.confirm_text_required || '').trim();
  const body = {
    title: `${MODE_LABEL[mode] || mode}：${d.recipe.name}`,
    body: `即将在「${d.host.name}」上执行「${MODE_LABEL[mode] || mode}」。\n\n`
      + (mode === 'deploy' ? '这是幂等操作：内容没变就不会写盘、也不会重启服务。' : '')
      + (mode === 'stop' ? '服务会被停掉，但配置与数据都保留。' : '')
      + (mode === 'uninstall_keep'
        ? `会删掉：${(d.uninstall.remove_config_rendered || []).join('、')}\n`
          + `保留的数据（不会被删）：${(d.uninstall.keep_data_rendered || d.uninstall.keep_data || []).join('、')}`
        : '')
      + (mode === 'uninstall_purge'
        ? `★ 全删会把下面这些都删掉：\n`
          + `　· 配置：${(d.uninstall.remove_config_rendered || []).join('、')}\n`
          + `　· 数据：${(d.uninstall.purge_paths_rendered || d.uninstall.purge_paths || []).join('、')}\n`
          + `　· 软件包：${(d.uninstall.remove_packages || []).join('、')}`
        : ''),
    confirm_text: needText || '我已确认',
  };
  const ans = await modalConfirm(body, { requireText: !!needText });
  if (!ans) return;

  const btn = $('#btnRecipeDeploy');
  if (btn) { btn.disabled = true; btn.textContent = '执行中…'; }
  $('#result').innerHTML = '<div class="sub">正在执行（每个步骤都会落库留证）…</div>';
  try {
    const run = await api(`/api/recipes/${encodeURIComponent(S.recipeId)}/run`, {
      method: 'POST',
      body: JSON.stringify({
        host_id: currentHostId(), params: S.recipeParams, mode,
        confirm: true, confirm_text: ans.confirm_text || '',
      }),
    });
    renderRecipeReport(run);
    loadRecipes();
  } catch (e) {
    $('#result').innerHTML = `<div class="banner bad"><h3>执行被拒绝</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '部署 / 收敛（幂等）'; }
  }
}

function renderRecipeReport(run) {
  const okAll = run.status === 'ok';
  const names = (arr) => (arr && arr.length) ? arr.join('、') : '（无）';
  const steps = (run.steps || []).map((s) => `
    <details class="step">
      <summary>
        ${statusBadge(s.status)}
        <b>${esc(s.title)}</b>
        <span class="badge ${s.changed === true ? 'yellow' : (s.changed === false ? 'ok' : 'warn')}">
          ${s.changed === true ? '变了' : (s.changed === false ? '没变' : '★无法判定')}</span>
        ${s.triggered_by ? '<span class="badge">被触发</span>' : ''}
        ${s.optional ? '<span class="badge">可选</span>' : ''}
        <span class="dim" style="margin-left:auto;font-size:12px">${esc(s.kind)}${s.task_id ? ' · 任务 ' + esc(s.task_id) : ''}</span>
      </summary>
      <div class="body">
        ${s.changed_rule ? `<div class="kv">变更判定口径：${esc(s.changed_rule)}</div>` : ''}
        ${s.error ? `<div class="banner bad" style="margin:8px 0"><div>${esc(s.error.reason)}</div>
          ${s.error.advice ? `<div class="advice">建议：${esc(s.error.advice)}</div>` : ''}</div>` : ''}
        ${s.conclusion ? `<pre class="concl">${esc(s.conclusion)}</pre>` : ''}
        ${s.task_id ? `<div class="actions-row"><button data-task="${esc(s.task_id)}">打开这一步的任务留证</button></div>` : ''}
      </div>
    </details>`).join('');

  const health = (run.health || []).map((h) => `<div class="gap-row">
    <span class="badge ${h.state === 'pass' ? 'ok' : (h.state === 'fail' ? 'failed' : 'warn')}">${esc(h.state)}</span>
    <span>${esc(h.expected)}</span><span class="dim">${esc(h.actual || '')}${h.collect_task ? ' ｜ 采集任务 ' + esc(h.collect_task) : ''}</span>
    </div>`).join('');

  const cps = (run.checkpoints || []).map((c) => `<div class="gap-row">
      <span class="badge">可回滚点</span>
      <span>${esc(c.label)}</span>
      <span class="dim"><code>${esc(c.orig_path || '')}</code></span>
      <button class="tiny" data-restore="${esc(c.backup_id)}" data-path="${esc(c.orig_path || '')}">恢复此文件</button>
    </div>`).join('');
  $('#result').innerHTML = `
    <div class="banner ${okAll ? 'ok' : 'bad'}">
      <h3>${okAll ? '✅ 成功' : (run.status === 'aborted' ? '⛔ 未开始执行（前置条件不满足）' : '❌ 失败')}
        <span class="badge">执行号 ${esc(run.run_id)}</span>
        <span class="badge">${esc(MODE_LABEL[run.mode] || run.mode)}</span></h3>
      ${run.error ? `<div><b>原因：</b>${esc(run.error.reason)}</div>
        ${run.error.advice ? `<div class="advice"><b>建议：</b>${esc(run.error.advice)}</div>` : ''}
        ${run.error.detail ? `<details class="detail"><summary>技术详情</summary><pre class="out">${esc(run.error.detail)}</pre></details>` : ''}`
      : `<div class="sub">用时 ${run.duration_ms}ms ｜ ${esc(run.started_at)} → ${esc(run.ended_at)} ｜ 目标机 ${esc(run.host_name)}</div>`}
    </div>

    <div class="section">
      <h3>本次变更清单（幂等就是看这张表下次会不会空）</h3>
      <div class="gap-row"><span class="badge yellow">变了 ${run.changed_steps.length}</span><span>${esc(names(run.changed_steps))}</span></div>
      <div class="gap-row"><span class="badge ok">没变 ${run.unchanged_steps.length}</span><span>${esc(names(run.unchanged_steps))}</span></div>
      <div class="gap-row"><span class="badge warn">★无法判定 ${run.unknown_steps.length}</span>
        <span>${esc(names(run.unknown_steps))}</span>
        <span class="dim">"判不出来"**不等于**"没变更" —— 这一栏非空就不能声称幂等</span></div>
    </div>

    ${run.conclusion ? `<div class="section"><h3>结论</h3><pre class="concl">${esc(run.conclusion)}</pre></div>` : ''}
    ${health ? `<div class="section"><h3>健康检查</h3>${health}</div>` : ''}
    ${cps ? `<div class="section"><h3>检查点（可回滚到哪）</h3>
      <div class="sub">不自动回滚 —— 要不要回到变更前由你决定：可以逐项点「恢复此文件」，
      也可以一次点「回到这次部署前」（★ <b>逐项</b>执行、逐项自证，仍然要手输确认词）。</div>
      <div class="actions-row"><button class="primary" id="btnGroupRollback" data-run="${esc(run.run_id)}">回到这次部署前（逐项）</button></div>
      ${cps}</div>` : ''}
    <div class="section"><h3>步骤留证（${(run.steps || []).length} 步）</h3>${steps}</div>
  `;
  $$('#result [data-task]').forEach((el) => {
    el.addEventListener('click', () => replayTask(el.dataset.task));
  });
  $$('#result [data-restore]').forEach((el) => {
    el.addEventListener('click', () => restoreBackup(el.dataset.restore, el.dataset.path));
  });
  const gr = $('#btnGroupRollback');
  if (gr) gr.addEventListener('click', () => groupRollback(gr.dataset.run));
}

/* ★ T7·S4（规范 §12.20）：部署组回退 —— 「回到这次部署前」。
 *
 * 与单点的区别只有一件事：**一次确认、逐项执行**。四条规矩都体现在这段代码里：
 *   ① 先拿**只读**的逐项计划（GET .../rollback-plan），把"要动哪几项"摆出来再让人决定；
 *   ② ★★ 计划里必须带上「**回不去的**」四类（包 / 服务状态 / 运行时内存态 / 外部影响）——
 *      这一段**就算全是"无"也要显示**：空白会被读成"都回得去"，那是最危险的误解；
 *   ③ 确认词由**服务端**校验（前端只负责把它交上去 —— 拦不住也必须被拦）；
 *   ④ 结果**逐项**回显（哪一项没回去、为什么），一项失败不影响其它项。
 */
async function groupRollback(runId) {
  let plan;
  try {
    plan = await api(`/api/recipe-runs/${encodeURIComponent(runId)}/rollback-plan`);
  } catch (e) {
    toast('拿不到回退计划：' + (e.reason || '未知原因'));
    return;
  }
  if (!plan.items.length) {
    toast('这次执行没有登记任何可回滚点（它没覆盖过既有文件）—— 没有能"回去"的东西');
    return;
  }
  const itemTxt = plan.items.map((i) => `  ${i.can_restore ? '[可回去]' : '[回不去]'} ${i.label}\n`
    + `      ${i.orig_path}\n`
    + `      期望指纹 ${String(i.expect_sha256 || '（无）').slice(0, 24)}…`
    + (i.can_restore ? '' : '\n      ★ ' + i.why_not)).join('\n');
  const cannotTxt = plan.cannot_restore.map((u) => `  · ${u.kind}：${u.items}\n      ${u.why}`).join('\n');
  const ans = await modalConfirm({
    title: '回到这次部署前（逐项）',
    body: `即将把这一次执行（${plan.recipe_title || plan.recipe_id} @ ${plan.host_name}）登记过的检查点**逐项**恢复：\n\n`
        + `${itemTxt}\n\n`
        + '会发生什么：上面每一项的**当前内容**会被它自己的备份覆盖（那些路径在变更之后的改动会丢失）。\n'
        + '自证：每项恢复后由**单点恢复那条路**做 sha256 逐字节比对（目录 = 逐文件指纹汇总）。\n\n'
        + `★★ 这些**回不去**（逐项列清，空也要看一遍）：\n${cannotTxt}\n\n`
        + `${plan.boundary}\n\n`
        + '★ 本入口**不是**"撤销这次执行"，也不是自动回滚 —— 只有你点下去才算。',
    confirm_text: plan.confirm_text,
  }, { requireText: true });
  if (!ans) return;
  try {
    const d = await api(`/api/recipe-runs/${encodeURIComponent(runId)}/rollback`, {
      method: 'POST',
      body: JSON.stringify({ confirm_text: ans.confirm_text }),
    });
    const bad = d.failed_count || 0;
    await modalConfirm({
      title: bad ? `逐项回退完成：${d.ok_count}/${d.ok_count + bad} 项回去` : `✅ 全部回去（${d.ok_count} 项）`,
      body: d.conclusion,
      confirm_text: '知道了',
    });
    loadHistory();
  } catch (e) {
    await modalConfirm({
      title: '回退被拒绝',
      body: `${e.reason || ''}\n\n建议：${e.advice || ''}`,
      confirm_text: '知道了',
    });
  }
}

/* ★ T7·S6（规范 §12.18 / §12.22）：配方批量 —— 同一份配方 + 同一份参数铺到 N 台。
 *
 * 四件事必须在界面上看得见，否则"批量"就成了一次无法复核的许愿：
 *   ① **闸门**：red 直接把按钮禁掉（**服务端也会拒** —— 这里只是不让人白点）；yellow 走二次确认；
 *   ② **先看再跑**：先调**只读**的 `batch-plan`，把"这一批会怎么做 / 每台是谁"摆出来再决定；
 *   ③ **手输确认词**：停止 / 全删这类模式，服务端要**手输那一句**（点一下不算）；
 *   ④ **逐台结果**：每台自己一行（状态 / 变更 / 收敛检查 / 执行号），
 *      差异**按「执行状态 + 收敛检查结果」高亮**（★ 不按"命令返回 0"、不看变更步数），
 *      并**明说这批不落地批次快照**（留证单元 = 每台那一次配方执行）。
 */
async function recipeBatchRun() {
  const plan = S.recipePlan;
  const risk = (plan && plan.recipe) ? plan.recipe.risk : 'green';
  if (risk === 'red') {
    await modalConfirm({
      title: 'red 级配方禁止批量执行',
      body: '批量会把一次手误同时放大到多台，而 red 恰好是不可 undo 的那一类。\n'
          + '请逐台执行并手输确认词 —— 这是 T3 定下的硬规矩（规范 §9.3 / §12.18），没有开关可以放开。',
      confirm_text: '知道了',
    });
    return;
  }
  const modeEl = $('#batchMode');
  const mode = modeEl ? modeEl.value : 'deploy';
  const hosts = await pickHosts({
    title: '选择要批量执行的机器（配方）',
    body: '同一份配方 + 同一份参数会铺到选中的每一台；每台是一个**独立的配方执行**'
        + '（独立执行号 / 独立留证 / 可单独回放），单台失败不影响其它台。',
  });
  if (!hosts || !hosts.length) return;

  // ② 先看再跑：只读预检（不碰目标机）
  let bp;
  try {
    bp = await api(`/api/recipes/${encodeURIComponent(S.recipeId)}/batch-plan`, {
      method: 'POST',
      body: JSON.stringify({ host_ids: hosts, mode }),
    });
  } catch (e) {
    toast('拿不到批量预检：' + (e.reason || '未知原因'));
    return;
  }
  if (!bp.gate.allowed) {
    await modalConfirm({ title: '批量被拒绝', body: `${bp.gate.reason}\n\n${bp.gate.advice || ''}`,
      confirm_text: '知道了' });
    return;
  }
  const hostTxt = bp.hosts.map((h) => `  · ${h.host_name}（${h.target || '—'}）`
    + (h.error ? `\n      ★ 这台有问题：${h.error.reason}` : '')).join('\n');
  const needText = (bp.confirm_text || '').trim();
  const needConfirm = !!bp.gate.needs_confirm;
  const ans = await modalConfirm({
    title: `批量${MODE_LABEL[mode] || mode}（${bp.hosts.length} 台）`,
    body: `即将把配方「${bp.recipe_title}」（v${bp.recipe_version} · 风险 ${bp.risk}）用当前参数铺到：\n\n`
        + `${hostTxt}\n\n`
        + '每台是**一个独立的配方执行**（独立执行号 / 独立留证 / 可单独回放）；'
        + '单台失败或不可达**不影响其它台**。\n'
        + '★ 这一批**不落地批次快照** —— 横向对照表只活在当前页面；每一台的执行号都留着，可单独打开。\n'
        + (needConfirm ? '\n★ 这是一份 yellow 配方：批量需要你**二次确认**。\n' : ''),
    confirm_text: needText || (needConfirm ? '我已确认要批量执行' : '我已确认'),
  }, { requireText: !!needText });
  if (!ans) return;

  $('#result').innerHTML = `<div class="sub">正在按顺序对 ${bp.hosts.length} 台执行（每台都会落库留证）…</div>`;
  try {
    const d = await api(`/api/recipes/${encodeURIComponent(S.recipeId)}/batch-run`, {
      method: 'POST',
      body: JSON.stringify({
        host_ids: hosts, params: S.recipeParams, mode,
        confirm: true, confirm_text: ans.confirm_text || '',
      }),
    });
    renderRecipeBatch(d);
    loadRecipes();          // 让左侧卡片的"上次成功 / 上次失败"立刻跟上
  } catch (e) {
    $('#result').innerHTML = `<div class="banner bad"><h3>批量被拒绝</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
  }
}

/* 横向对照表：★ 差异才是重点 —— N 台里只有 1 台不一样，那一台就该被看见 */
function renderRecipeBatch(d) {
  const s = d.summary || {};
  const rows = (d.items || []).map((i) => `
    <tr>
      <td>${esc(i.host_name)}</td>
      <td>${statusBadge(i.status)}</td>
      <td>${(i.changed_steps || []).length
            ? `<span class="badge yellow">变了 ${i.changed_steps.length}</span>`
            : (i.status === 'ok' ? '<span class="badge ok">零变更</span>' : '<span class="dim">—</span>')}</td>
      <td>${i.checks_total
            ? `${i.checks_total - (i.checks_failed || 0)}/${i.checks_total}`
            : '<span class="dim">—</span>'}</td>
      <td>${i.checkpoints || '<span class="dim">—</span>'}</td>
      <td class="dim">${i.duration_ms || 0}ms</td>
      <td>${i.run_id
            ? `<button class="ghost tiny" data-run="${esc(i.run_id)}">打开这次执行</button>`
            : '<span class="dim">没有产生执行</span>'}</td>
    </tr>
    <tr><td colspan="7" style="padding:0 0 10px 0">
      ${i.error
        ? `<div class="banner bad" style="margin:0"><div>${esc(i.error.reason)}</div>
             ${i.error.advice ? `<div class="advice">建议：${esc(i.error.advice)}</div>` : ''}</div>`
        : `<pre class="concl" style="max-height:180px;overflow:auto;margin:0">${esc((i.conclusion || '（无结论）').slice(0, 700))}</pre>`}
    </td></tr>`).join('');

  const diffHtml = s.consistent
    ? '<div class="banner ok" style="margin:8px 0"><div>各台结论一致（按「执行状态 + 收敛检查结果」判定，没有差异列需要高亮）</div></div>'
    : (s.differences || []).map((x) => `<div class="banner bad" style="margin:8px 0">
        <div>⚠️ ${x.count}/${s.total} 台与其他不同：${esc((x.hosts || []).join('、'))}</div>
        <div class="advice">它们是：${esc(x.conclusion)}`
        + (x.reasons && x.reasons.length ? ` ｜ ${esc(x.reasons.join(' ； '))}` : '')
        + '</div></div>').join('');

  $('#result').innerHTML = `
    <div class="banner ${s.failed ? 'bad' : 'ok'}">
      <h3>配方批量结果
        <span class="badge">${esc(d.recipe_title || '')} · ${esc(MODE_LABEL[d.mode] || d.mode)}</span></h3>
      <div>${s.ok || 0}/${s.total || 0} 台成功 ｜ 收敛检查全过 ${s.healthy || 0} 台
        ｜ 本次有变更的 ${(s.changed_hosts || []).length} 台</div>
      <div class="sub">每台都是**独立执行**：点「打开这次执行」看它自己的步骤留证 / 健康检查 / 检查点。</div>
    </div>
    ${diffHtml}
    <div class="section">
      <h3>横向对照</h3>
      <table class="bt"><thead><tr>
        <th>主机</th><th>状态</th><th>变更</th><th>收敛检查</th><th>检查点</th><th>耗时</th><th>操作</th>
      </tr></thead><tbody>${rows}</tbody></table>
      <div class="dim" style="color:#8a9aab;font-size:12px;margin-top:6px">${esc(s.note || '')}</div>
      ${d.boundary ? `<div class="banner" style="margin-top:8px"><div>${esc(d.boundary)}</div></div>` : ''}
    </div>`;
  $$('#result [data-run]').forEach((el) => {
    el.addEventListener('click', () => replayRecipeRun(el.dataset.run));
  });
}

/* 打开某一次配方执行（从数据库读回来 —— 不是重新执行）。
 * ★ 这条路顺带把 T7·S4 抓到并修掉的那个旧缺陷用起来了：库里的 `steps_json` 那套
 *   与接口要的公开名之间**必须有映射**，否则"刷新后从历史打开"的三段全是空的。 */
async function replayRecipeRun(runId) {
  let d;
  try {
    d = await api('/api/recipe-runs/' + encodeURIComponent(runId));
  } catch (e) {
    toast('打不开这次执行：' + (e.reason || '未知原因'));
    return;
  }
  switchTab('recipes');
  $('#content').innerHTML = `<h2>配方执行回放</h2>
    <div class="sub">执行号 ${esc(runId)} —— 从数据库读回来的历史记录，不是重新执行。</div>
    <div id="result"></div>`;
  renderRecipeReport(d.run);
  $('#result').scrollIntoView({ behavior: 'smooth' });
}

/* ---------------------------------------------------------------- 主机自检 */

async function checkHost(trust, force) {
  const path = `/api/hosts/${encodeURIComponent(currentHostId())}/${trust ? 'trust' : 'check'}`;
  try {
    const d = await api(path, { method: 'POST', body: JSON.stringify({ force: !!force }) });
    if (d.reachable) {
      if (force) {
        const dr = (d.trust && d.trust.dropped) || {};
        const added = (d.trust && d.trust.known_hosts_added) || [];
        toast(`✅ 已接受新指纹（撤掉旧记录 ${dr.removed || 0} 条 · 收进新记录 ${added.length} 条`
          + `${dr.backup ? ' · 旧文件已逐字节备份' : ''}）`);
      } else {
        toast('✅ 目标机可达，SSH 免密登录成功');
      }
      return;
    }
    const code = (d.error && d.error.code) || '';
    /* ★★ T17·S8（规范 §12.139 第 2 条）：**指纹变了**要单独走一条路。
     *   它不是"连不上"，是"我认不出你了" —— 而 `accept-new` 对"指纹变了"**一样拒**
     *   （它只认"没见过的主机"）⇒ 老版本只能让用户自己去改 `~/.ssh/known_hosts`，
     *   那正是本项目一直在消灭的"让人手改文件"。
     *   ⇒ 这里给一个**人点过的台阶**：先看清新旧差异，亲手打确认词，
     *     再由平台**逐字节备份**旧记录、撤掉那两条、重新接受新指纹。
     *   ★ 平台**不会**自己决定接受一个指纹 —— 这一下只能是人点的。
     */
    if (code === 'SSH_HOSTKEY_UNKNOWN' && !force) {
      const ok = await modalConfirm({
        requireText: true,
        title: '⚠️ 这台机器的指纹变了（或从未被信任过）',
        body: [
          (d.error && d.error.reason) || '目标机的主机指纹与记录里的不一致。',
          '',
          '★ 什么情况下会这样：虚拟机被**克隆 / 重装**，或者你刚刚对它跑过「重置 SSH host key」。',
          '★ 确认这一下会做什么：',
          '   ① 先把管理机的 known_hosts **逐字节备份**（可回退）；',
          '   ② 只撤掉**这一台**的两条旧记录（别的机器一行不动）；',
          '   ③ 再把**新指纹**收进来 —— 之后这条链上的 ssh 步骤才能继续。',
          '',
          '★ 如果你**没有**做过上面那两件事，就先别接受：那可能意味着你连到了别的机器。',
          '',
          '技术细节：',
          ((d.error && d.error.detail) || d.probe.stderr || '（无）'),
        ].join('\n'),
        confirm_text: '接受新指纹',
      });
      if (ok) await checkHost(true, true);
      return;
    }
    await modalConfirm({
      title: '⚠️ 目标机连不上',
      body: [d.error.reason, '', '建议：', d.error.advice, '',
        '技术细节：', (d.error.detail || d.probe.stderr || '（无）')].join('\n'),
      confirm_text: '知道了',
    });
  } catch (e) {
    toast('自检失败：' + (e.reason || '未知'));
  }
}

/* ---------------------------------------------------------------- K8s 管理台（T9 · S6）
 *
 * ★★ 设计口径（规范 §12.37 ~ §12.50）：
 *   · **界面不自己算结论** —— 「一键取结论」跑的是**已有动作**，把动作自己的结论原文念出来；
 *     每张卡片的「原始证据」与结论来自**同一次任务**，带上任务号，可逐字复核（§12.39.1）；
 *   · **变更类动作不在这里直接执行** —— 点「打开」跳到「动作」页，
 *     复用既有的**参数表单 + 命令预览 + 二次确认弹窗 + red 手输确认词**（§12.6.1：闸门只有一处）；
 *   · **日志是快照式**：界面上明写「不是流式」（§12.42）；真流式是架构事件，单独立题。
 */

const K8S_CARDS = [
  { key: 'nodes', icon: '🖥', title: '节点', action: 'k8s.nodes',
    desc: '三节点的就绪状态、kube-system 组件、存储对象（判据：等所有节点 Ready）' },
  { key: 'workloads', icon: '📦', title: '工作负载', action: 'k8s.workloads',
    desc: 'Deployment / StatefulSet / DaemonSet / Job / CronJob 的「期望 vs 就绪」' },
  { key: 'pods', icon: '🫛', title: 'Pod', action: 'k8s.pods',
    desc: '全量 Pod（-o wide）＋ 按节点分布 ＋ 不健康高亮（★ 健康是正向白名单）' },
  { key: 'config', icon: '🔧', title: '配置存储', action: 'k8s.config',
    desc: 'ConfigMap / Secret（★ 只给键名与条数，不给值）/ PVC / StorageClass' },
  { key: 'diagnose', icon: '🩺', title: '排障', action: 'k8s.diagnose',
    desc: '扫全集群的不健康对象 → 成因清单（每条挂可复核证据；换了成因清单必须跟着换）' },
  { key: 'certs', icon: '🎫', title: '证书', action: 'k8s.certs',
    desc: 'kubeadm 证书到期体检（★ 只读，不含 renew）＋ admin.conf' },
];

// 变更类：这里只给**入口**，真正的闸门在「动作」页那套通道里（一处闸门，不给第二条路）
const K8S_WRITE = [
  { id: 'k8s.scale', title: '扩缩容', hint: '判据是等 readyReplicas 到位；★ 回退值（原副本数）写进报告' },
  { id: 'k8s.rollout-restart', title: '滚动重启', hint: '判据是 generation 前进；★ 回不去「没重启过」这个状态' },
  { id: 'k8s.set-image', title: '换镜像', hint: '判据是「读回来的镜像逐字相符」＋ 滚动完成；★ 旧镜像进报告' },
  { id: 'k8s.rollout-undo', title: '回滚到上一版', hint: '按 revision 回退；★ 有 revisionHistoryLimit 深度限制' },
  { id: 'k8s.node-drain', title: '排空节点', hint: '判据是 spec.unschedulable=true ＋ 非 DaemonSet 的 Pod 已迁走' },
  { id: 'k8s.node-resume', title: '恢复调度', hint: 'uncordon；★ 它不会把排空时丢掉的东西带回来' },
  { id: 'k8s.delete-workload', title: '删除对象', hint: '判据是 get 退出码 1；★ 裸 Pod（无 owner）删了永久消失' },
  { id: 'k8s.delete-namespace', title: '删除命名空间', hint: '🔴 整片环境；★ 白名单只放行 aoc-* / t9-*' },
  { id: 'k8s.exec', title: '容器内只读体检', hint: '★ 非交互、不经 shell、只读白名单（不做 exec -it）' },
];

const K8S_ESCAPE = {
  id: 'k8s.kubectl', title: 'kubectl 只读逃生口',
  hint: '★ 它是逃生口、不是终端 —— 只有只读子命令（get / describe / logs / events / top / explain / version…）；写操作请用上面的动作',
};

function k8sTaskHtml(d) {
  const t = d.task || {};
  const cls = t.status === 'ok' ? 'ok' : 'bad';
  const steps = (d.steps || []).map((s) => `
    <details class="step"><summary>${statusBadge(s.status)}
      <b>${esc(s.name)}</b>
      <span class="kv">rc=${s.exit_code == null ? '—' : s.exit_code}</span>
      <span class="kv">${esc(s.title || '')}</span></summary>
      <div class="body">
        <div class="kv">命令：${esc(Array.isArray(s.argv) ? s.argv.join(' ') : (s.command || '（非命令步骤）'))}</div>
        <pre class="out">${esc(s.stdout || '（stdout 为空 —— 空输出本身可能就是结论）')}</pre>
        ${s.stderr ? `<pre class="out" style="color:#ffb3b3">${esc(s.stderr)}</pre>` : ''}
      </div></details>`).join('');
  /* ★★ T10·S8 抓到的真缺陷 ⑨：**中止/失败时，界面上看不到"为什么"** ——
   *   这条卡片原来只渲染「横幅 + 结论」，而 `aborted` 的任务**结论是空的**
   *   ⇒ 用户只看到「已中止 · 步骤失败 1/1」，一个字的原因都没有。
   *   ★ 平台的 `task.error` 里其实**有** reason + advice（验收 #3 要求"未成功必须给原因+建议"），
   *     只是界面把它丢了。这里补上 —— ★ 这是**共用**渲染器，两个页签一起受益。 */
  const errHtml = t.error ? `
    <div class="banner bad">
      <h3>${esc(t.error.code || '未成功')}</h3>
      <div>${esc(t.error.reason || '')}</div>
      ${t.error.advice ? `<div class="advice">建议：${esc(t.error.advice)}</div>` : ''}
      ${t.error.detail ? `<pre class="out">${esc(t.error.detail)}</pre>` : ''}
    </div>` : '';
  return `
    <div class="banner ${cls}">
      ${statusBadge(t.status)}
      <span class="kv">任务 ${esc(t.id)}</span>
      <span class="kv">changed=${t.changed}</span>
      <span class="kv">自证=${esc(t.verify_result || '—')}</span>
      <span class="kv">步骤失败 ${t.step_failed}/${t.step_total}</span>
      <span class="kv">${t.duration_ms == null ? '' : (t.duration_ms / 1000).toFixed(1) + 's'}</span>
    </div>
    ${errHtml}
    <pre class="concl">${esc(t.conclusion || '')}</pre>
    <details><summary class="sub">原始证据（${(d.steps || []).length} 步 · 可逐字复核）</summary>${steps}</details>`;
}

function k8sOpenAction(id) {
  switchTab('actions');
  selectAction(id);
  toast('已切到「动作」页：参数、命令预览与二次确认闸门都在那里');
}

/* ★★ T16（规范 §12.121）：第 4 个参数 `overrides` = 由**调用页签**给的整组参数值
 *   （「虚拟机」页签用它把"本页签选中的那台 VM"填进 `vm` 参数）。
 *   ★ 刻意**不另写一套**取结论的代码 —— 闸门与执行路径**只有一条**（§12.6.1）：
 *     复制一份出来，就有了"某一边偷偷放宽"的余地。
 *   ★ 只覆盖**动作真的有的参数**（`k in params`）：多塞一个键就是另一种"界面骗平台"。
 */
async function k8sRunRead(actionId, btn, box, overrides) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '取结论中…';
  if (box) box.innerHTML = '<div class="sub">正在取结论（只读），请稍候…</div>';
  try {
    const d = await api('/api/actions/' + encodeURIComponent(actionId));
    // ★★ 只读卡片只跑 green 的动作；非 green **一律不在这里执行** —— 闸门只有一处（§12.6.1）
    if (d.action.risk !== 'green') { k8sOpenAction(actionId); return; }
    const params = {};
    d.action.params.forEach((p) => { params[p.name] = p.default == null ? '' : p.default; });
    if (overrides) Object.keys(overrides).forEach((k) => { if (k in params) params[k] = overrides[k]; });
    // ★ T16：执行面按**动作声明的通道**说 —— `channel: local` 的动作跑在本机（vmrun.exe），
    //   不是 ssh 到目标机。写死"通过 SSH"对虚拟化域就是界面在说假话（§12.115）。
    if (box) box.innerHTML = `<div class="sub">${esc(d.action.channel === 'local'
      ? '正在本机（宿主机）上执行（只读 · vmrun.exe · 不走 ssh），请稍候…'
      : '正在通过 SSH 在目标机上执行（只读），请稍候…')}</div>`;
    const res = await api(`/api/actions/${encodeURIComponent(actionId)}/run`, {
      method: 'POST',
      body: JSON.stringify({ host_id: currentHostId(), params, confirm: true, confirm_text: '' }),
    });
    if (box) box.innerHTML = k8sTaskHtml(res);
    loadHistory();
  } catch (e) {
    if (box) box.innerHTML = `<div class="banner bad"><h3>取结论失败</h3>
      <div>${esc(e.reason || '')}</div>
      ${e.advice ? `<div class="advice">建议：${esc(e.advice)}</div>` : ''}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function renderK8s() {
  // 侧栏：六块跳转 ＋ 变更类/逃生口直通「动作」页
  $('#pane-k8s').innerHTML = `
    <div class="group-title">六块 · 每块一键取结论</div>
    ${K8S_CARDS.map((c) => `<div class="card" data-goto="${esc(c.key)}" role="button" tabindex="0">
        <h4>${c.icon} ${esc(c.title)}</h4><p>${esc(c.action)}</p></div>`).join('')}
    <div class="group-title">直通「动作」页（带闸门）</div>
    ${K8S_WRITE.concat([K8S_ESCAPE]).map((w) => `<div class="card" data-openact="${esc(w.id)}"
        role="button" tabindex="0"><h4>${esc(w.title)}</h4><p>${esc(w.id)}</p></div>`).join('')}`;

  $$('#pane-k8s .card').forEach((el) => {
    const go = () => {
      if (el.dataset.goto) {
        const t = $('#k8s-card-' + el.dataset.goto);
        if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        k8sOpenAction(el.dataset.openact);
      }
    };
    el.addEventListener('click', go);
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); }
    });
  });

  // 主区：六块卡片（每块 = 一键取结论 ＋ 结论区 ＋ 原始证据可展开）
  $('#content').innerHTML = `
    <h2>K8s 管理台 <span class="badge green">只读为主</span></h2>
    <div class="sub">六块 = 总纲 §4 T9 卡片要求的 6 件事。★ 界面不自己算结论：
      它跑的是已有动作，然后把动作自己的结论原文念出来。</div>
    <div class="note">★★ 日志是快照式：一次取一段，不是流式（要「再取一段」就再点一次）——
      真流式（SSE / 长连接）是平台的架构事件，单独立题（规范 §12.42）。<br>
      ★ 目标机：<b>${esc(currentHostId())}</b>（★ 管理动作跑在控制面；工作节点上没有 kubeconfig）</div>
    ${K8S_CARDS.map((c) => `
      <div class="section" id="k8s-card-${esc(c.key)}">
        <div class="card k8s-card">
          <h4>${c.icon} ${esc(c.title)} <span class="badge">${esc(c.action)}</span></h4>
          <p>${esc(c.desc)}</p>
          <div class="row">
            <button class="primary tiny k8s-run" data-action="${esc(c.action)}" data-key="${esc(c.key)}">一键取结论</button>
            <button class="ghost tiny k8s-open" data-action="${esc(c.action)}">打开动作（参数 / 命令预览）</button>
          </div>
          <div class="k8s-out" id="k8s-out-${esc(c.key)}"><div class="sub">还没取过。</div></div>
        </div>
      </div>`).join('')}
    <div class="section">
      <h3>变更类动作（★ 带参数表单与闸门）</h3>
      <div class="sub">点「打开」跳到「动作」页执行 —— 那里才有命令预览、二次确认与 red 手输确认词。
        ★ 一条闸门，不给第二条路（规范 §12.6.1）。</div>
      ${K8S_WRITE.map((w) => `<div class="card">
          <h4>${esc(w.title)} ${riskBadge('yellow')} <span class="badge">${esc(w.id)}</span></h4>
          <p>${esc(w.hint)}</p>
          <div class="row"><button class="ghost tiny k8s-open" data-action="${esc(w.id)}">打开（带闸门）</button></div>
        </div>`).join('')}
    </div>
    <div class="section">
      <h3>逃生口</h3>
      <div class="card">
        <h4>${esc(K8S_ESCAPE.title)} ${riskBadge('yellow')} <span class="badge">${esc(K8S_ESCAPE.id)}</span></h4>
        <p>${esc(K8S_ESCAPE.hint)}</p>
        <div class="row"><button class="ghost tiny k8s-open" data-action="${esc(K8S_ESCAPE.id)}">打开</button></div>
      </div>
    </div>`;

  $$('#content .k8s-run').forEach((b) => b.addEventListener('click', () => {
    k8sRunRead(b.dataset.action, b, $('#k8s-out-' + b.dataset.key));
  }));
  $$('#content .k8s-open').forEach((b) => b.addEventListener('click', () => k8sOpenAction(b.dataset.action)));
}

/* ---------------------------------------------------------------- 监控告警（T10 · S6）
 *
 * ★★ 设计口径（规范 §12.53 ~ §12.63）：
 *   · **界面不自己算结论** —— 「一键取结论」跑的是**已有动作**，把动作自己的结论原文念出来；
 *     每张卡片的「原始证据」与结论来自**同一次任务**，带上任务号，可去「历史」逐字复核（§12.39.1）；
 *   · ★★★ **抑制的落点在 Alertmanager，不在 Prometheus**（§12.56.1）—— 界面把这件事**写在明面上**：
 *     「当前告警」读 Prometheus，它**判不了抑制**；「抑制状态」单独一张卡去问 Alertmanager。
 *     ★ 因为**Prometheus 里被抑制的那条照样是 `firing`**（抑制是**投递前**的决定）
 *       ⇒ 拿 Prometheus 验抑制会得出**相反的错误结论**。
 *   · **变更类不在这里直接执行** —— 点「打开」跳到「动作」页，复用既有的
 *     参数表单 + 命令预览 + 二次确认弹窗 + red 手输确认词（§12.6.1：闸门只有一处）；
 *   · ★ **「没做」要说出来**（§12.58）：Grafana 首次改密**只能人在环**，界面上明写，不假装已完成。
 */

const MON_CARDS = [
  { key: 'overview', icon: '📊', title: '总览（版本 / 单元 / 监听面 / 存储）', action: 'mon.overview',
    desc: '四个组件的真 `--version` 输出 · 五个单元活性 · ★★ 监听面读**内核** /proc/net/tcp（命中 00000000 即判红）· 保留期与落盘' },
  { key: 'targets', icon: '🎯', title: '抓取目标（在采没在采）', action: 'mon.targets',
    desc: '读 **Prometheus 自己的** `api/v1/targets`：几条 up、几条 down。★ 判据内建：有一条 down 就判红；★ "在采"不看配置文件' },
  { key: 'rules', icon: '📐', title: '告警规则生效面（在判没在判）', action: 'mon.rules',
    desc: '文件条数 vs `api/v1/rules` 条数**逐条对账** ＋ 有没有"没带 for"的规则。★ 只改文件不 reload ⇒ 两个数对不上' },
  { key: 'alerts', icon: '🔔', title: '当前告警（在响什么）', action: 'mon.alerts',
    desc: '读 Prometheus `api/v1/alerts`：firing / pending 各几条。★ 它是「for 有没有等」的判据家（造条件前后各查一次的三跳）' },
  { key: 'am', icon: '🛡', title: '抑制状态（★ 问 Alertmanager）', action: 'mon.am-alerts',
    desc: '读 Alertmanager **`api/v2/alerts`**：几条 active、几条 suppressed。★★ 抑制**只能**在这里看 —— Prometheus 里被抑制的那条照样 firing' },
  { key: 'received', icon: '📥', title: '收端已收到（送出去了没有）', action: 'mon.alerts-received',
    desc: '读 Webhook 收端的 append-only JSONL。★★ **这是"送达"的唯一判据** —— 配了地址不算、Alertmanager 日志说完成也不算' },
];

// 变更类：只给**入口**，闸门在「动作」页（一处闸门，不给第二条路）
const MON_WRITE = [
  { id: 'mon.reload', title: '重载配置与规则', hint: '判据是 `prometheus_config_last_reload_successful` = 1（★ **不是** curl 返回 200）；动作自带"等就绪"（§12.55.1）' },
  { id: 'mon.target-add', title: '注册抓取目标（扩展点）', hint: '写一个 `aoc-mon-*.json` 到 file_sd 目录；★ 每 10 秒自动重读 ⇒ **不需要 reload**（§12.62）' },
  { id: 'mon.target-remove', title: '注销抓取目标', hint: '★ 可正可反的另一半 —— 只验"加了"不验"删了" ⇒ **不合格**（§12.62）' },
  { id: 'mon.selftest-metric', title: '人造自检指标（告警靶子）', hint: '往 textfile 目录写 `aoc-mon-*.prom`：**1 ⇒ 只有 Warning 响**；**2 ⇒ Critical 响且 Warning 被抑制**（§12.59）' },
  { id: 'mon.unpack', title: '上传并解包组件', hint: '★ 大文件走这条（`file.push` 覆盖前会备份，撞 `backup.max_file_mb` ⇒ **大包推不了第二遍**，§12.64 ④）' },
];

// ★★ 这一版的监控栈装在 node-03 上（开题单 §10.2 #1 的拍板）。
//   ★★★ 为什么要把它写成一个常量并**当面比对**：T10·S8 界面真走时抓到了**真缺陷 ⑧** ——
//     页首原来写死「目标机：node-03」，而真正执行用的是**顶栏下拉框里选中的那台**
//     （默认是 `node-01`）⇒ 结论整篇是「（无）」，**横幅却写着「成功」**。
//     ★ 那把报告读起来像「监控装了但没起来」，真相是「**这台机器上压根没有监控栈**」。
//     ⇒ **界面在说假话** —— 必须当面纠正，不能靠用户自己猜。
const MON_HOST = 'node-03';

function renderMon() {
  const cur = currentHostId();
  const onRight = cur === MON_HOST;
  // 侧栏：六块跳转 ＋ 变更类直通「动作」页
  $('#pane-mon').innerHTML = `
    <div class="group-title">六块 · 每块一键取结论</div>
    ${MON_CARDS.map((c) => `<div class="card" data-goto="${esc(c.key)}" role="button" tabindex="0">
        <h4>${c.icon} ${esc(c.title)}</h4><p>${esc(c.action)}</p></div>`).join('')}
    <div class="group-title">直通「动作」页（带闸门）</div>
    ${MON_WRITE.map((w) => `<div class="card" data-openact="${esc(w.id)}"
        role="button" tabindex="0"><h4>${esc(w.title)}</h4><p>${esc(w.id)}</p></div>`).join('')}`;

  $$('#pane-mon .card').forEach((el) => {
    const go = () => {
      if (el.dataset.goto) {
        const t = $('#mon-card-' + el.dataset.goto);
        if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        k8sOpenAction(el.dataset.openact);
      }
    };
    el.addEventListener('click', go);
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); }
    });
  });

  // 主区：六块卡片（每块 = 一键取结论 ＋ 结论区 ＋ 原始证据可展开）
  $('#content').innerHTML = `
    <h2>监控告警 <span class="badge green">只读为主</span></h2>
    <div class="sub">六块 = 开题单 §2 块5 要求的"监控栈一次给全结论"。★ 界面不自己算结论：
      它跑的是已有动作，然后把动作自己的结论原文念出来。</div>
    ${onRight ? '' : `
    <div class="banner bad">
      <h3>★ 当前目标机不是监控栈所在的那一台</h3>
      <div>顶栏选中的是 <b>${esc(cur)}</b>，而这一版的监控栈装在 <b>${esc(MON_HOST)}</b> 上。
        ★ 在这台机器上点「一键取结论」，拿到的是**一台没装监控的机器**的结论
        —— 版本会一片「（无）」，那不是"监控没起来"，是"这台机器上没有"。</div>
      <div class="row"><button class="primary tiny" id="monSwitchHost">切到 ${esc(MON_HOST)}</button></div>
    </div>`}
    <div class="note">★★★ <b>抑制只能问 Alertmanager</b>：Prometheus 的 <code>api/v1/alerts</code> 里，
      <b>被抑制的那条照样是 firing</b>（抑制是<b>投递前</b>的决定）—— 所以抑制单独一张卡问
      <code>api/v2/alerts</code>。★ 用错 API 会得出"抑制没生效"这个<b>错误</b>结论（规范 §12.56.1）。<br>
      ★ 装机走「服务目录」里的配方：<b>monitoring-stack</b>（三件套 + 采集器 + 收端）·
      <b>monitoring-agent</b>（只铺采集器）。<br>
      ★ <b>首次登录 Grafana 要改密（只能人做）</b> —— 这一步界面**不假装已完成**（规范 §12.58）。<br>
      ★ 目标机：<b>${esc(cur)}</b>${onRight ? '（★ 就是监控栈所在的那一台）'
        : `（★ 监控栈在 <b>${esc(MON_HOST)}</b> 上 —— 这一栏是**动态**的，界面上不再写死）`}</div>
    ${MON_CARDS.map((c) => `
      <div class="section" id="mon-card-${esc(c.key)}">
        <div class="card mon-card">
          <h4>${c.icon} ${esc(c.title)} <span class="badge">${esc(c.action)}</span></h4>
          <p>${esc(c.desc)}</p>
          <div class="row">
            <button class="primary tiny mon-run" data-action="${esc(c.action)}" data-key="${esc(c.key)}">一键取结论</button>
            <button class="ghost tiny mon-open" data-action="${esc(c.action)}">打开动作（参数 / 命令预览）</button>
          </div>
          <div class="mon-out" id="mon-out-${esc(c.key)}"><div class="sub">还没取过。</div></div>
        </div>
      </div>`).join('')}
    <div class="section">
      <h3>变更类动作（★ 带参数表单与闸门）</h3>
      <div class="sub">点「打开」跳到「动作」页执行 —— 那里才有命令预览、二次确认与手输确认词。
        ★ 一条闸门，不给第二条路（规范 §12.6.1）。</div>
      ${MON_WRITE.map((w) => `<div class="card">
          <h4>${esc(w.title)} ${riskBadge('yellow')} <span class="badge">${esc(w.id)}</span></h4>
          <p>${esc(w.hint)}</p>
          <div class="row"><button class="ghost tiny mon-open" data-action="${esc(w.id)}">打开（带闸门）</button></div>
        </div>`).join('')}
    </div>
    <div class="section">
      <h3>这一版"回不去"的东西（规范 §12.60）</h3>
      <div class="card">
        <p>时序数据（Prometheus TSDB）· 收端已收到的告警记录（append-only 的现场证据）·
        <b>Grafana 里人手工改过的面板</b>（它不在我们的模板里，但卸载删库会连它一起删）·
        Alertmanager 的<b>静默记录</b>（★ 它消失<b>不会有人来提醒你</b>）。<br>
        ★ 卸载时「保留数据」是一条<b>承诺</b> —— 报告里会念出"服务没了、数据还在"这一档。</p>
      </div>
    </div>`;

  const sw = $('#monSwitchHost');
  if (sw) {
    sw.addEventListener('click', () => {
      $('#hostSelect').value = MON_HOST;
      switchTab('mon');
      toast('已把目标机切到 ' + MON_HOST + '（★ 结论要重取，之前那份是另一台机器的）');
    });
  }
  $$('#content .mon-run').forEach((b) => b.addEventListener('click', () => {
    monRunRead(b.dataset.action, b, $('#mon-out-' + b.dataset.key));
  }));
  $$('#content .mon-open').forEach((b) => b.addEventListener('click', () => k8sOpenAction(b.dataset.action)));
}

/* ★ 只读卡片跑的是**已有动作**：与 K8s 管理台同一条路（`k8sRunRead`）——
 *   非 green 一律不在这里执行，转去「动作」页走闸门。这样"闸门只有一处"这条口径
 *   在两个页签上是**同一份实现**，不会出现"某一边偷偷放宽"。 */
function monRunRead(actionId, btn, box) {
  k8sRunRead(actionId, btn, box);
}

/* ============================================================ T12 · 「对话」页签（五·AI 助手）
 * ★ 本页签的主题：**AI 说的话必须与工作台判定成对出现**（规范 §12.73）。
 *   · 上面一条气泡 = AI 的说法；下面「工作台怎么判」= 结论 + 自证 + 任务号。
 *   · ★ 界面**不自己算结论**，也不改写任何一边：它把 `/api/ai/ask` 的返回原样摆出来。
 *   · 冲突（AI 说成了 / 工作台没证成）⇒ 挂**分歧横幅**，并**以工作台为准**（§12.73.2）。
 *   · key 只存内存：输入框是 password，保存后只显示掩码；★ 不做"显示明文"按钮（§12.79）。
 *   · 外流档位**可见**：A = 只发结论 + 动作 ID + 参数；B/C/D 是**置灰占位**（§12.78）。
 */
const CHAT = { session: null, status: null, busy: false, last: '' };

async function renderChat() {
  let st = null;
  let sess = [];
  try { st = await api('/api/ai/status'); } catch (e) { st = null; }
  try { sess = (await api('/api/ai/sessions')).sessions || []; } catch (e) { sess = []; }
  CHAT.status = st;
  const key = (st && st.key) || {};
  const set = (st && st.settings) || {};
  const bud = set.budgets || {};
  const tiers = (set.tiers || []).map((t) => (t.enabled
    ? `<span class="badge green" title="发出去的就是这个档">${esc(t.key)} · ${esc(t.label)}</span>`
    : `<span class="badge chat-off" title="${esc(t.why || '')}">${esc(t.key)} · ${esc(t.label)}（未实现）</span>`
  )).join(' ');

  $('#pane-chat').innerHTML = `
    <div class="group-title">AI 助手 · 只读对话</div>
    <div class="card">
      <h4>模型 API key ${key.configured ? '<span class="badge green">已配置</span>' : '<span class="badge">未配置</span>'}</h4>
      <p>当前：<code>${esc(key.mask || '（未配置）')}</code> ${key.source ? `（来源 ${esc(key.source)}）` : ''}</p>
      <div class="row">
        <input type="password" id="chatKey" placeholder="sk-…（只存本进程内存）">
        <button class="primary tiny" id="chatKeySave">保存</button>
        <button class="ghost tiny" id="chatKeyClear">清除</button>
      </div>
      <div class="note">★ <b>四不落</b>：不写盘 · 不进日志 · 不进 Git · 不进截图（规范 §12.79）。
        界面只显示掩码，重启即失效；开发/演示也可用环境变量注入（<code>config.yaml</code> 的 <code>ai.key_env</code>）。</div>
    </div>
    <div class="card">
      <h4>数据外流档位</h4>
      <p>${tiers}</p>
      <div class="note">★ <b>A 档 ≠ 匿名化</b>：结论里本来就带主机名 / IP / 路径（规范 §12.78.1）。
        换档必须人显式操作 —— 本期没有别的档可换。</div>
    </div>
    <div class="card">
      <h4>预算与上限</h4>
      <p class="sub">模型 <code>${esc(set.model || '-')}</code> · 轮数上限 ${esc(String(bud.max_rounds))} ·
        单次回传 ${esc(String(bud.max_tool_result_bytes))} B · 会话上限 ${esc(String(bud.max_session_tokens))} token</p>
      <div class="note">★ 超限会<b>停下问人</b>，不静默继续（规范 §12.81）。</div>
    </div>
    <div class="group-title">历史会话（${sess.length}）</div>
    ${sess.slice(0, 8).map((s) => `<div class="card chat-sess" data-sid="${esc(s.id)}" role="button" tabindex="0">
      <h4>${esc(String(s.title || '（无标题）').slice(0, 26))}</h4>
      <p class="sub">${esc(s.created_at)} · ${esc(s.model)} · 档位 ${esc(s.tier)}</p></div>`).join('')
      || '<div class="sub">还没有会话。</div>'}`;

  $('#content').innerHTML = `
    <h2>对话 <span class="badge green">只读</span> <span class="badge">AI 与点击走同一条路</span></h2>
    <div class="sub">用<b>人话</b>驱动已有的只读动作面。★ 每次工具调用都挂<b>任务号</b>（可点开原始输出）；
      ★ AI 的说法与工作台判定<b>并列显示</b>，冲突时以工作台为准。</div>
    ${st && st.enabled ? '' : '<div class="banner bad"><h3>AI 助手被关掉了</h3><div><code>ai.enabled</code> 现在是 false。</div></div>'}
    <div class="section">
      <div class="row">
        <input id="chatInput" placeholder="例如：哪台机器磁盘快满了？">
        <button class="primary" id="chatSend">发送</button>
        <button class="ghost tiny" id="chatNew">新会话</button>
      </div>
      <div class="note">★ 主机范围由平台判定（说「全部」或点名某台）；没指明机器时它<b>会回问你</b>。
        ★ AI 只能跑只读动作；想跑变更类会被<b>拒</b>并告诉你去哪个页签（铁律 9）。</div>
    </div>
    <div id="chatLog">${CHAT.last}</div>`;

  const on = (sel, ev, fn) => { const el = $(sel); if (el) el.addEventListener(ev, fn); };
  on('#chatKeySave', 'click', async () => {
    const v = ($('#chatKey').value || '').trim();
    if (!v) { toast('先填一个 key'); return; }
    try {
      await api('/api/ai/key', { method: 'POST', body: JSON.stringify({ key: v }) });
      toast('key 已保存（只在内存里）');
      renderChat();
    } catch (e) { toast(e.reason || '保存失败'); }
  });
  on('#chatKeyClear', 'click', async () => {
    try {
      await api('/api/ai/key/clear', { method: 'POST', body: JSON.stringify({}) });
      toast('已清除（环境变量注入的会保留）');
      renderChat();
    } catch (e) { toast(e.reason || '清除失败'); }
  });
  on('#chatSend', 'click', chatSend);
  on('#chatInput', 'keydown', (ev) => { if (ev.key === 'Enter') chatSend(); });
  on('#chatNew', 'click', () => { CHAT.session = null; CHAT.last = ''; $('#chatLog').innerHTML = ''; toast('已开新会话'); });
  $$('#pane-chat .chat-sess').forEach((el) => {
    const open = () => chatOpenSession(el.dataset.sid);
    el.addEventListener('click', open);
    el.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') open(); });
  });
}

function chatBubble(role, html) {
  const cls = role === 'user' ? 'chat-user' : (role === 'sys' ? 'chat-sys' : 'chat-ai');
  const who = role === 'user' ? '你' : (role === 'sys' ? '平台' : 'AI（说法）');
  return `<div class="chat-msg ${cls}"><div class="chat-who">${who}</div><div class="chat-body">${html}</div></div>`;
}

async function chatSend() {
  if (CHAT.busy) return;
  const input = $('#chatInput');
  const text = (input.value || '').trim();
  if (!text) { toast('先说点什么'); return; }
  CHAT.busy = true;
  input.value = '';
  const log = $('#chatLog');
  log.insertAdjacentHTML('beforeend', chatBubble('user', esc(text)));
  log.insertAdjacentHTML('beforeend', chatBubble('sys', '…正在跑（选域 → 选动作 → 执行 → 汇总）'));
  $('#chatSend').disabled = true;
  try {
    const d = await api('/api/ai/ask', {
      method: 'POST',
      body: JSON.stringify({ text: text, session_id: CHAT.session }),
    });
    CHAT.session = d.session_id;
    $$('#chatLog .chat-sys').forEach((el) => el.remove());
    log.insertAdjacentHTML('beforeend', chatBubble('ai', esc(d.answer || '（没有回答）').replace(/\n/g, '<br>')));
    log.insertAdjacentHTML('beforeend', chatDual(d));
    /* ★ T13：定位表 / 三段交代 / 截断与预算标注（平台算的，不是模型复述的） */
    log.insertAdjacentHTML('beforeend', chatLocate(d));
    /* ★★ T14·S4：AI **提了一张变更卡片** ⇒ 明确说"我还没做"，并把人送到「待确认」 */
    log.insertAdjacentHTML('beforeend', chatRequest(d));
    bindChatTasks();
    bindChatPending();
    CHAT.last = log.innerHTML;
  } catch (e) {
    $$('#chatLog .chat-sys').forEach((el) => el.remove());
    log.insertAdjacentHTML('beforeend', chatBubble('sys',
      `<b>没跑起来：</b>${esc(e.reason || '')}<br><span class="sub">建议：${esc(e.advice || '')}</span>`));
  } finally {
    CHAT.busy = false;
    if ($('#chatSend')) $('#chatSend').disabled = false;
    log.scrollIntoView({ block: 'end', behavior: 'smooth' });
  }
}

/* ★ 双结论对照区：**AI 的说法在上面，这里摆"工作台怎么判"**（规范 §12.73.2）。 */
function chatDual(d) {
  const calls = d.tool_calls || [];
  const conflicts = d.conflicts || [];
  const hint = d.need_hosts ? '（等你说清要查哪台）'
    : ((d.need_params && d.need_params.length) ? `（还差参数：${d.need_params.join('、')}）` : '');
  const rows = calls.map((c) => {
    const proven = c.ok && c.verify_result === 'ok';
    return `<tr>
      <td><code>${esc(c.action_id)}</code></td>
      <td>${esc(c.host_id)}</td>
      <td>${proven ? '<span class="badge green">已证成</span>' : '<span class="badge warn">未证成</span>'}
        ${esc(c.status)} / ${esc(c.verify_result || 'none')}</td>
      <td><a href="#" class="chat-task" data-task="${esc(c.task_id)}">${esc(c.task_id || '（无任务号）')}</a></td>
    </tr>${c.explain ? `<tr><td colspan="4" class="sub">↳ 本地译文：${esc(c.explain)}</td></tr>` : ''}`;
  }).join('');
  return `<div class="dual">
    <div class="group-title">工作台怎么判（★ 以这一份为准${d.outflow_tier ? ' · 外流档位 ' + esc(d.outflow_tier) : ''}）</div>
    ${conflicts.length ? `<div class="banner bad"><h3>★ 发现分歧 ⇒ 按工作台为准</h3>${conflicts.map((x) => `<div>${esc(x)}</div>`).join('')}</div>` : ''}
    ${d.no_tool_calls ? `<div class="banner warn"><h3>这一轮没有调用任何工具</h3><div>结论<b>没有证据支撑</b>${esc(hint)}。</div></div>` : ''}
    ${rows ? `<table class="dual-table"><thead><tr><th>动作</th><th>主机</th><th>状态 / 自证</th>
      <th>任务号（可点开原始输出）</th></tr></thead><tbody>${rows}</tbody></table>` : ''}
    <div class="sub">用量：${esc(JSON.stringify(d.usage || {}))}</div>
  </div>`;
}

/* ★ T13 · 定位表 ＋ 范围交代 ＋ 截断标注（规范 §12.86 / §12.88 / §12.90）——
   ★ 这三块全部来自**平台算出来的字段**（不是让模型复述），所以它们和"AI 怎么说"是两份东西。
   ★ 三种情形在这里是**三种不同的提示**，不许混成一句（§12.88）：
     查过了没有 / 没查成（没查到）/ 查了但可能不全。 */
function chatLocate(d) {
  const loc = d.locate || [];
  const r = d.retrieval || {};
  const sc = d.scope || {};
  const flags = [];
  if (d.need_confirm) {
    const why = (d.stopped_reason === 'AI_BUDGET_STOP')
      ? '已到本次会话的 token 预算上限 —— 上面查到的东西**都还在**。要接着查请说一声（或把范围收窄、把问题拆小）。'
      : '平台要你先确认一件事（见上面的问题）。';
    flags.push(`<div class="banner warn"><h3>★ 停下等你确认</h3><div>${esc(why)}</div></div>`);
  }
  if ((sc.not_searched || []).length) {
    flags.push(`<div class="banner bad"><h3>★ 有机器没查到（结论不完整）</h3>
      ${(sc.not_searched || []).map((x) => `<div>${esc(x.host)} ｜ <code>${esc(x.action_id)}</code> ｜ ${esc(x.reason)}</div>`).join('')}
      <div class="sub">★ 这是「<b>没查到</b>」，不是「这台上没有」。</div></div>`);
  }
  if (r.possible_incomplete) {
    /* ★ 真跑抓到的界面缺陷（S8 截图当场看出来）：同一句「动作自带显示上限…」
       会**按台重复**（4 台 4 遍）—— 提示变成了噪音。⇒ 按文案去重 + 计数。
       ★ 为什么不是"只显示第一条"：那会丢掉"4 台都有这个上限"这个事实。 */
    const noteMap = new Map();
    [].concat(sc.truncated || [], sc.limits || []).forEach((t) => {
      const k = t.note || '';
      noteMap.set(k, (noteMap.get(k) || 0) + 1);
    });
    const notes = Array.from(noteMap).map(([n, c]) => esc(n) + (c > 1 ? `（${c} 台各一条）` : ''));
    flags.push(`<div class="banner warn"><h3>★ 看到的可能不是全部</h3><div>${notes.join('；')}</div></div>`);
  }
  const trs = loc.map((x) => `<tr>
      <td>${esc(x.host)}</td>
      <td><code>${esc(x.where)}</code></td>
      <td>${esc(String(x.what || '').slice(0, 240))}${x.kind === 'summary' ? ' <span class="badge">未结构化</span>' : ''}</td>
      <td><a href="#" class="chat-task" data-task="${esc(x.task_id)}">${esc(x.task_id || '（无）')}</a></td>
    </tr>`).join('');
  const counts = `命中 <b>${r.hit_count || 0}</b> 条 ｜ 涉及 <b>${r.host_count || 0}</b> 台`
    + (((r.no_hit_hosts || []).length) ? ` ｜ <b>确实没有</b>：${esc((r.no_hit_hosts || []).join('、'))}` : '');
  const hasAny = loc.length || flags.length || (r.hit_count || 0) || (r.note && (sc.searched || []).length);
  if (!hasAny) return '';
  return `<div class="dual">
    <div class="group-title">★ 定位表（T13：找东西的答案 = 哪台 / 在哪 / 是什么 / 任务号）</div>
    ${flags.join('')}
    <div class="sub">${counts}${r.note ? '　' + esc(r.note) : ''}</div>
    ${trs ? `<table class="dual-table"><thead><tr><th>哪台</th><th>在哪</th><th>是什么</th><th>任务号</th></tr></thead><tbody>${trs}</tbody></table>` : ''}
    ${sc.text ? `<details><summary>范围交代（查了什么 / 没查到什么 / 哪里可能不全）</summary><pre class="sub">${esc(sc.text)}</pre></details>` : ''}
  </div>`;
}

async function chatOpenSession(sid) {
  try {
    const d = await api('/api/ai/sessions/' + encodeURIComponent(sid));
    const turns = (d.turns || []).map((t) => chatBubble(
      t.role === 'user' ? 'user' : (t.role === 'system' ? 'sys' : 'ai'),
      esc(String(t.text || '').slice(0, 800)).replace(/\n/g, '<br>')
        + (t.conflict ? '<br><span class="badge warn">★ 这一轮有分歧</span>' : '')
    )).join('');
    const calls = (d.tool_calls || []).map((c) => `<tr><td><code>${esc(c.action_id)}</code></td>
      <td>${esc(c.host_id)}</td><td>${esc(c.status)} / ${esc(c.verify || 'none')}</td>
      <td><a href="#" class="chat-task" data-task="${esc(c.task_id)}">${esc(c.task_id || '（无）')}</a></td></tr>`).join('');
    $('#chatLog').innerHTML = `<div class="group-title">历史会话 ${esc(sid)}（只读回放）</div>${turns}
      <div class="dual"><div class="group-title">这一会话的工具调用</div>
      <table class="dual-table"><thead><tr><th>动作</th><th>主机</th><th>状态 / 自证</th><th>任务号</th></tr></thead>
      <tbody>${calls}</tbody></table>
      <div class="sub">用量：${esc(JSON.stringify(d.usage || {}))}</div></div>`;
    bindChatTasks();
    toast('已载入历史会话（★ AI 的原话也在里面 —— 它和判定是两份东西）');
  } catch (e) { toast(e.reason || '载入失败'); }
}

function bindChatTasks() {
  $$('#chatLog .chat-task').forEach((a) => a.addEventListener('click', (ev) => {
    ev.preventDefault();
    const id = a.dataset.task;
    if (!id) return;
    switchTab('history');
    setTimeout(() => replayTask(id), 80);
  }));
}

/* ★★ T14·S4：「待确认」页签 —— 人在环的那一下
 *   ★ 「请求」是 AI 的权利，「执行」不是：**这一页是唯一能把卡片变成任务的地方**。
 *   ★ 卡片上那五段话全部是**平台写的**（`app/ai/requests.py`），前端只负责**原样显示** ——
 *     所以这里没有一句话是"前端润色"出来的（§12.98.2）。
 */
const PENDING = { rows: [], busy: false, open: null, detail: null };

async function loadPending() {
  let data = { requests: [], pending: 0 };
  try { data = await api('/api/ai/requests'); } catch (e) { toast(e.reason || '取不到待确认队列'); }
  PENDING.rows = data.requests || [];
  const badge = $('#pendingBadge');
  if (badge) {
    const n = data.pending || 0;
    badge.textContent = String(n);
    badge.classList.toggle('hidden', n === 0);
  }
  renderPendingPane();
  if (PENDING.open) await pendingOpen(PENDING.open, true);
  else renderPendingContent();
}

/* AI 提了一张卡片之后，在对话里明说"我还没做"（★ 红线 10 / §12.96.2 规矩 3） */
function chatRequest(d) {
  const r = d && d.request;
  if (!r) return '';
  const card = r.card || {};
  return `<div class="dual">
    <div class="banner warn">
      <h3>★ 我**还没有做**任何事 —— 这里只有一张待确认的卡片</h3>
      <div>${esc(String(r.card_text || '').split('\n').slice(0, 4).join('\n')).replace(/\n/g, '<br>')}</div>
      <div class="sub">请求号 <code>${esc(r.request_id || '')}</code> ｜ ★ 执行要人在「待确认」页签点确认
        —— AI 那边<b>结构上没有</b>这个能力（规范 §12.99）。</div>
      <div class="row"><button class="primary tiny" id="chatGoPending">去「待确认」看这张卡片</button></div>
    </div>
  </div>`;
}

function bindChatPending() {
  const b = $('#chatGoPending');
  if (b) b.addEventListener('click', () => { switchTab('pending'); });
}

function pendingVerdict(rev) {
  if (!rev) return '';
  if (rev.verdict === 'not_run') return '<span class="badge warn">未复核</span>';
  return rev.proved ? '<span class="badge green">已证实</span>' : '<span class="badge warn">未证实</span>';
}

function renderPendingPane() {
  const rows = PENDING.rows || [];
  const todo = rows.filter((r) => r.status === 'pending').length;
  $('#pane-pending').innerHTML = `
    <div class="group-title">待确认的变更（${todo} 条待办 / 共 ${rows.length} 条）</div>
    <div class="note">★ AI <b>只能「请求」</b>，<b>执行要你点</b>。卡片上的字全部由平台生成。</div>
    ${rows.length ? rows.map((r) => `<div class="card pending-row ${esc(r.status)}" data-rid="${esc(r.id)}" role="button" tabindex="0">
      <h4>${esc(r.action_id)} <span class="badge ${r.status === 'pending' ? 'warn' : (r.status === 'approved' ? 'green' : '')}">${esc(r.status)}</span></h4>
      <p class="sub">${esc(r.host_id)} · ${esc(r.created_at)}</p>
      <p class="sub">${esc(String(r.reason || '').slice(0, 56))}</p>
    </div>`).join('') : '<div class="sub">还没有任何变更请求。<br>★ 去「对话」页签，让 AI 提一条（例如"在 docker-01 上装个 ncdu"）试试。</div>'}`;
  $$('#pane-pending .pending-row').forEach((el) => {
    const open = () => pendingOpen(el.dataset.rid);
    el.addEventListener('click', open);
    el.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') open(); });
  });
}

async function pendingOpen(rid, keepPane) {
  PENDING.open = rid;
  try {
    PENDING.detail = await api('/api/ai/requests/' + encodeURIComponent(rid));
  } catch (e) { toast(e.reason || '取不到这条请求'); PENDING.detail = null; }
  if (!keepPane) renderPendingPane();
  renderPendingContent();
}

function renderPendingContent() {
  const d = PENDING.detail;
  const box = $('#content');
  if (!d) {
    box.innerHTML = `<h2>待确认 <span class="badge">人在环</span></h2>
      <div class="sub">左边选一条 → 看卡片五要素 → 点「确认执行」或「驳回」。</div>
      <div class="section"><div class="note">★★ 「请求」是 AI 的权利，「执行」不是（规范 §12.96）。
        执行走的是<b>既有那条路</b>（和界面点「执行」同一个入口）：留证 / 护栏 / 覆盖率账本自动生效。</div></div>`;
    return;
  }
  const c = d.card || {};
  const w = c.what || {}, im = c.impact || {}, un = c.undo || {}, cr = c.criteria || {};
  const params = (w.params || []).map((p) => `<tr><td><code>${esc(p.name)}</code></td>
    <td>${esc(String(p.value))}</td><td class="sub">${esc(p.source)}</td></tr>`).join('');
  const cannot = (c.cannot_undo || []).map((x) => `<li>${esc(x)}</li>`).join('') || '<li>无</li>';
  const paths = (im.paths || []).length ? esc(im.paths.join('、')) : '（动作 YAML 里没有声明要改的文件）';
  const rev = d.review || c.review || null;
  const critParams = Object.entries(cr.params || {}).map(([k, v]) => k + '=' + v).join('、');
  box.innerHTML = `
    <h2>变更卡片 <span class="badge ${d.status === 'pending' ? 'warn' : 'green'}">${esc(d.status)}</span>
      ${pendingVerdict(rev)}</h2>
    <div class="sub">请求号 <code>${esc(d.id)}</code> · 成立于 ${esc(d.created_at)} ·
      ${d.decided_by ? '决定人 ' + esc(d.decided_by) + '（' + esc(d.decided_at) + '）' : '<b>还没有人做决定</b>'}</div>

    <div class="section card"><h4>① 要做什么</h4>
      <p><b>${esc(w.title || '')}</b>（<code>${esc(w.action_id || '')}</code>）· 目标机 <b>${esc(im.host || d.host_id)}</b></p>
      <table class="dual-table"><thead><tr><th>参数</th><th>值</th><th>来源</th></tr></thead>
      <tbody>${params || '<tr><td colspan="3" class="sub">（这个动作没有参数）</td></tr>'}</tbody></table>
    </div>
    <div class="section card"><h4>② 影响面</h4>
      <p>${esc(im.text || '')}</p>
      <p class="sub">会改动的文件：${paths}${(im.services || []).length ? ' ｜ 涉及服务：' + esc(im.services.join('、')) : ''}</p>
    </div>
    <div class="section card"><h4>③ 怎么撤</h4>
      <p>${esc(un.how || '')}</p>
      ${un.by_action ? `<p class="sub">撤法动作：<code>${esc(un.by_action)}</code>（风险 ${esc(un.by_risk || '?')}）${
        un.human_confirm_required ? ' <span class="badge bad">撤也要人手动输确认词</span>' : ''}</p>` : ''}
    </div>
    <div class="section card"><h4>④ 撤不回来的是什么</h4><ul class="sub">${cannot}</ul></div>
    <div class="section card"><h4>⑤ 判据（变更之后看哪个只读动作）</h4>
      <p><code>${esc(cr.action_id || '')}</code>${critParams ? '（' + esc(critParams) + '）' : ''}</p>
      <p class="sub">${esc(cr.pass || '')}</p>
    </div>
    ${rev ? `<div class="section card ${rev.proved ? 'verb-ok' : 'verb-warn'}">
      <h4>复核结果：${rev.proved ? '<span class="badge green">已证实</span>' : '<span class="badge warn">未证实</span>'}</h4>
      <p>${esc(rev.basis || '')}</p>
      <p class="sub">复核任务：<a href="#" class="pend-task" data-task="${esc(rev.task_id)}">${esc(rev.task_id || '（无）')}</a>
        ｜ 只读动作 <code>${esc(rev.action_id || '')}</code> ｜ 自证 ${esc(rev.verify_result || 'none')}</p>
    </div>` : ''}
    ${c.run && c.run.task_id ? `<p class="sub">变更任务：<a href="#" class="pend-task" data-task="${esc(c.run.task_id)}">${esc(c.run.task_id)}</a>
      （${esc(c.run.status)} / 自证 ${esc(c.run.verify_result)}）</p>` : ''}
    ${d.note ? `<div class="note">${esc(d.note)}</div>` : ''}
    <div class="section">
      ${d.status === 'pending' ? `<div class="row">
        <button class="primary" id="pendApprove">确认执行</button>
        <button class="ghost" id="pendReject">驳回</button>
      </div>
      <div class="note">★★ 只有你这一下能把卡片变成任务 —— AI 那边<b>结构上没有</b>这个能力（规范 §12.99）。
        执行完之后平台会**自动跑一遍复核**，判「已证实 / 未证实」，再回到这张卡片上。</div>`
      : '<div class="note">这张卡片已经处理过了（同一张只许点一次）。</div>'}
    </div>`;
  const on = (sel, ev, fn) => { const el = $(sel); if (el) el.addEventListener(ev, fn); };
  on('#pendApprove', 'click', () => pendingApprove(d));
  on('#pendReject', 'click', () => pendingReject(d));
  $$('#content .pend-task').forEach((a) => a.addEventListener('click', (ev) => {
    ev.preventDefault();
    const id = a.dataset.task;
    if (!id) return;
    switchTab('history');
    setTimeout(() => replayTask(id), 80);
  }));
}

async function pendingApprove(d) {
  if (PENDING.busy) return;
  /* ★ 沿 T1 的老规矩：yellow 要过一道二次确认 —— 而且读的是**后端渲染好的**确认正文
     （`/api/actions/<id>/preview`），不是我在这里另写一段。 */
  let body = '', title = '确认执行';
  try {
    const pv = await api(`/api/actions/${encodeURIComponent(d.action_id)}/preview`, {
      method: 'POST', body: JSON.stringify({ host_id: d.host_id, params: d.params || {} }),
    });
    const cf = pv.confirm || {};
    body = (cf.body || '') + '\n\n★ 这一步之后，平台会自动跑一遍复核（判「已证实 / 未证实」）。';
    title = cf.title || title;
  } catch (e) {
    body = '（拿不到后端渲染的确认正文：' + String(e.reason || '') + '）';
  }
  const answer = await modalConfirm({ title: title, body: body, confirm_text: '我已确认' });
  if (!answer) return;
  PENDING.busy = true;
  toast('正在执行…（★ 卡片不会自己跑，是你刚点的这一下）');
  try {
    const r = await api(`/api/ai/requests/${encodeURIComponent(d.id)}/approve`, {
      method: 'POST', body: JSON.stringify({ by: '人在界面点了确认' }),
    });
    toast(r.status === 'approved' ? '执行完成 —— 复核结果见卡片' : '执行失败（★ 没做复核，先看任务）');
    await loadPending();
    await pendingOpen(d.id, true);
  } catch (e) {
    toast(e.reason || '执行失败');
  } finally {
    PENDING.busy = false;
  }
}

async function pendingReject(d) {
  try {
    const r = await api(`/api/ai/requests/${encodeURIComponent(d.id)}/reject`, {
      method: 'POST', body: JSON.stringify({ reason: '人在界面上驳回' }),
    });
    toast(r.note || '已驳回');
    await loadPending();
    await pendingOpen(d.id, true);
  } catch (e) { toast(e.reason || '驳回失败'); }
}

/* ---------------------------------------------------------------- 报告与知识（T15 · 规范 §12.104 / §12.106 / §12.107）*/

const REPORTS = { sessions: [], picked: '', text: '', kb: null, cand: null };

async function renderReports() {
  let data = { sessions: [] };
  try { data = await api('/api/ai/reports'); } catch (e) { toast(e.reason || '取不到会话列表'); }
  REPORTS.sessions = data.sessions || [];
  if (!REPORTS.picked && REPORTS.sessions.length) REPORTS.picked = REPORTS.sessions[0].session_id;
  renderReportsPane();
  if (REPORTS.picked) await reportPreview(REPORTS.picked); else renderReportsContent();
}

function renderReportsPane() {
  const rows = REPORTS.sessions || [];
  $('#pane-reports').innerHTML = `
    <div class="group-title">报告 · 一次对话 = 一份带证据链的报告</div>
    <div class="card">
      <div class="note">★ 报告里<b>每一条结论</b>都能点回任务号与原始输出；★ 它<b>不内嵌</b>目标机原文
        （原文走归档与 <code>/api/tasks/&lt;id&gt;/export</code>）。★ 本期只做 <b>md</b>，PDF 记为遗留。</div>
      <input id="kbQ" placeholder="查「上次这类问题是怎么解决的」…">
      <div class="row">
        <button class="primary tiny" id="kbGo">本地检索</button>
        <button class="ghost tiny" id="candGo">扫 Recipe 候选</button>
      </div>
      <div class="note">★ 检索只查<b>本地结构化记录</b>（会话 / 人的问句 / 工具调用 / 变更请求 / 任务结论）；
        ★ <b>不含</b> AI 自己的历史回答；命中不到会明说「没有记录」并交代查了哪些范围。</div>
    </div>
    <div class="group-title">会话（${rows.length}）</div>
    ${rows.map((s) => `<div class="card chat-sess${s.session_id === REPORTS.picked ? ' active' : ''}" data-sid="${esc(s.session_id)}" role="button" tabindex="0">
      <h4>${esc(String(s.title || '（无标题）').slice(0, 24))}</h4>
      <p class="sub">${esc(s.created_at)} · 调用 ${esc(String(s.tool_calls))}（成功 ${esc(String(s.tool_ok))}）· 请求 ${esc(String(s.requests))} · ${esc(String(s.tokens))} token</p></div>`).join('')
      || '<div class="sub">还没有会话 —— 先在「对话」页签聊一次。</div>'}`;

  $$('#pane-reports .chat-sess').forEach((el) => {
    el.addEventListener('click', () => {
      REPORTS.picked = el.dataset.sid;
      renderReportsPane();
      reportPreview(el.dataset.sid);
    });
  });
  const kb = $('#kbGo'); if (kb) kb.addEventListener('click', kbSearch);
  const cg = $('#candGo'); if (cg) cg.addEventListener('click', genCandidates);
  const q = $('#kbQ');
  if (q) q.addEventListener('keydown', (e) => { if (e.key === 'Enter') kbSearch(); });
}

async function reportPreview(sid) {
  try {
    REPORTS.text = await fetchText('/api/ai/reports/' + encodeURIComponent(sid) + '/export?format=md');
  } catch (e) {
    REPORTS.text = '';
    toast(e.reason || '取不到报告');
  }
  renderReportsContent();
}

function renderReportsContent() {
  const sid = REPORTS.picked;
  const kb = REPORTS.kb;
  const cand = REPORTS.cand;
  $('#content').innerHTML = `
    <h2>报告 <span class="badge green">md</span> <span class="badge">过鉴权闸门</span></h2>
    <div class="sub">会话 <code>${esc(sid || '（未选）')}</code> —— 下面这段就是报告正文（纯文本预览）。</div>
    <div class="actions-row">
      <button class="ghost tiny" id="repDl"${sid ? '' : ' disabled'}>下载 .md</button>
      <button class="ghost tiny" id="repCopy"${REPORTS.text ? '' : ' disabled'}>复制全文</button>
      <span class="sub">导出走 <code>/api/ai/reports/&lt;会话&gt;/export</code> —— ★ 无令牌 401</span>
    </div>
    <pre class="report-pre">${esc(REPORTS.text || '（还没有报告：左边选一个会话）')}</pre>
    ${kb ? `<h3>本地知识检索 · <code>${esc(kb.query)}</code> <span class="badge ${kb.hit_count ? 'green' : 'warn'}">命中 ${esc(String(kb.hit_count))}</span></h3>
      <div class="card"><pre class="report-pre">${esc(kb.text || '')}</pre></div>` : ''}
    ${cand ? `<h3>Recipe 候选草案 <span class="badge ${(cand.candidates || []).length ? 'green' : 'warn'}">${esc(String((cand.candidates || []).length))} 个</span>
      <span class="badge ${cand.recipes_untouched ? 'green' : 'red'}">catalog/recipes 未被改动：${esc(String(cand.recipes_untouched))}</span></h3>
      <div class="card"><div class="note">${esc(cand.note || '')}<br>落点：<code>${esc(cand.out_dir || '')}</code></div>
      <ul>${(cand.candidates || []).map((c) => `<li><code>${esc(c.id)}</code>：${esc((c.actions || []).join(' → '))}（支持度 ${esc(String((c.support || []).length))}）</li>`).join('') || '<li>（没有候选）</li>'}</ul></div>` : ''}`;

  const dl = $('#repDl');
  if (dl && sid) dl.addEventListener('click', () => downloadText(
    '/api/ai/reports/' + encodeURIComponent(sid) + '/export?format=md&download=1', 'aoc-report-' + sid + '.md'));
  const cp = $('#repCopy');
  if (cp && REPORTS.text) cp.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(REPORTS.text); toast('报告全文已复制'); }
    catch (e) { toast('复制失败（浏览器不给剪贴板）'); }
  });
}

async function kbSearch() {
  const el = $('#kbQ');
  const q = ((el && el.value) || '').trim();
  if (!q) { toast('先写一句要查的东西'); return; }
  try { REPORTS.kb = await api('/api/ai/knowledge?q=' + encodeURIComponent(q)); }
  catch (e) { toast(e.reason || '检索失败'); return; }
  renderReportsContent();
}

async function genCandidates() {
  try {
    REPORTS.cand = await api('/api/ai/recipes/candidates', { method: 'POST', body: JSON.stringify({}) });
  } catch (e) { toast(e.reason || '生成候选失败'); return; }
  toast(`候选 ${(REPORTS.cand.candidates || []).length} 个 · ★ 只在草案区，没有生效`);
  renderReportsContent();
}

/* ============================================================ T16 · 「虚拟机」页签（六·虚拟化层）
 *
 * ★★ 设计口径（规范 §12.115 ~ §12.121 ／ 红线 12~17）：
 *   · **界面不自己算结论** —— 「一键取结论」跑的是 `vm.*` **已有动作**，把动作自己的结论原文念出来；
 *     每张卡的「原始证据」与结论来自**同一次任务**，带任务号，可去「历史」逐字复核（§12.39.1）；
 *   · ★★★ **执行面要说清**：这些动作跑在**宿主机**上（本机 `vmrun.exe`，动作声明 `channel: local`），
 *     与顶栏选中的目标机**无关** —— 不说清就会变成 T10 那颗「结论像这台机器的、其实是另一台」
 *     （§12.53.4 同族）。★ 所以本页首**当面**写这句，不用人自己猜；
 *   · ★★ **靶子纪律写在明面上**（红线 12）：能操作的 = `hosts.yaml` 里登记了 `vm.vmx` 的机器
 *     ∪ `config.yaml` 的 `vm.extra_allow`（**当次点名**，写进文件即留痕）；
 *     其余**只读可见、不可操作** —— ★ 这是**保护**，不是故障；
 *   · ★ **变更类不在这里直接执行**：点「打开」跳「动作」页，复用参数表单 + 命令预览 +
 *     二次确认 + red 手输确认词（§12.6.1：闸门只有一处，不给第二条路）；
 *   · 🔴 `vm.stop-hard` / `vm.snapshot-revert` **永远 red**：不可逆、禁批量，
 *     ★ 且 **AI 侧连请求都不许发**（§12.120）；`vm.start` 可以**请求**
 *     （人点确认那一下 = 红线 16 的「人点头」）。
 *
 * ★★ T17（规范 §12.127 ~ §12.135）在本页签上**只加页内入口**（页签数不变，§12.135 第 3 条）：
 *   · 「造一台靶子机」表单（源 / 新 id / 初始地址 / 最终地址）—— ★ 它**不执行任何东西**：
 *     整链走**配方** `vm-provision`，只克隆那一跳走**动作** `vm.clone`，
 *     两条路都跳到既有那一套闸门里去点（§12.6.1「闸门只有一处」）；
 *   · ★★ **克隆是 `red`**：这一页**不会**给人"点一下就造出机器"的按钮 ——
 *     必须先看命令预览，再在二次确认弹窗里**手输确认词**；
 *   · ★★ **主题句当场写在页面上**：`vmrun clone` 返回 0 只说明**磁盘上多了几个文件** ——
 *     直到身份被换掉，它才算一台新机器（§12.129）。
 */

const VM_READ = [
  { key: 'list', icon: '🗂', title: '虚拟机清单（含归属）', action: 'vm.list',
    desc: '在跑的有哪些 · 全部有几台 · 哪些归本项目管 · ★ 并交代"查了哪些键"（规范 §12.122：「问不到」≠「不存在」）' },
  { key: 'status', icon: '🔌', title: '虚拟机状态（电源 / 归属 / 快照链）', action: 'vm.status',
    desc: '★ 电源状态问的是 **VMware 自己**（`vmrun list`）—— 不是"vmx 文件在不在"，也不是"上次任务成功过"' },
  { key: 'ip', icon: '🌐', title: 'guest 报告的地址', action: 'vm.ip',
    desc: '经 VMware Tools 问 guest 要 IP：它同时证明"Tools 在跑"。★ 但**不证明 ssh 通** —— 那是另一件事' },
  { key: 'snaps', icon: '🧷', title: '快照链', action: 'vm.snapshot-list',
    desc: '整机回滚的落点。★ 快照名**逐字**匹配（实测链上有中文与空格）；★ 对**已关机**的 VM 也能读' },
  { key: 'ready', icon: '⏳', title: '等 guest 就绪', action: 'vm.wait-guest',
    desc: '★★ 本话题最值钱的一步：`vmrun start` 返回 0 只是**收条**，"起来了"要等 guest 报出地址；超时即判红' },
];

// 变更类：这里只给**入口**，真正的闸门在「动作」页那套通道里（一处闸门，不给第二条路）
const VM_WRITE = [
  { id: 'vm.start', title: '启动虚拟机', hint: 'yellow。★ 判据不是"命令返回 0"，而是**再问一次 VMware**（它出现在 `vmrun list` 里）；对已运行的 VM = 零变更' },
  { id: 'vm.stop', title: '优雅关机（soft）', hint: 'yellow。走 guest 优雅关机（要 Tools 在跑）。★ "关机了"同样问 VMware，不看文件时间戳' },
  { id: 'vm.snapshot-create', title: '拍摄快照（变更前的那件护栏）', hint: 'yellow。护栏四件套第 4 件（§12.118）；★ 显式触发、占磁盘、**会改变快照链**；判据是"链上真有这个名字"' },
];

// 🔴 永远 red（§12.120）：手输确认词 + 禁批量 + ★ AI 侧**结构上不可请求**
const VM_RED = [
  { id: 'vm.stop-hard', title: '强制断电（hard）', hint: '🔴 等价于**拔电源**：guest 里未落盘的数据会丢。禁批量；★ AI 连请求都不许发（§12.120）' },
  { id: 'vm.snapshot-revert', title: '回滚到快照', hint: '🔴 会把虚拟机**当前状态整个覆盖掉**（含别人做的、与本项目无关的改动）。禁批量；★ 被覆盖掉的现状**没有回收站**' },
];

/* ============================================================ T17 · 「造一台靶子机」
 * ★★ 这一块回答的是**一句话**：「给我来一台干净的 Rocky 10 靶子机」（§12.127）。
 *    而它的主题句是：**「克隆给出的是拷贝件 —— 直到身份被换掉，它才算一台新机器。」**（§12.129）
 *
 * ★★★ 界面在这里**一条捷径都不开**（§12.135 第 1 条）：
 *    · 「只克隆这一跳」→ 跳「动作」页跑 `vm.clone`（🔴 red：手输确认词）；
 *    · 「一键整链」    → 跳「配方」页跑 `vm-provision`（★ 它第一跳就是克隆 ⇒ 同样要手输确认词）；
 *    · 身份重置四项 / 登记 / 体检：**都在整链里**，界面只把它们**列出来**（看得见在跑什么），
 *      真要单独跑某一步，走「动作」页那套通道。
 *   ★ 理由：**闸门只有一处**（§12.6.1）。多开一条"造机专用"的路，就等于多一处可以忘掉确认词的地方。
 */
const VM_PROV_FIELDS = [
  { key: 'mother', label: '母机（源虚拟机）', ph: 'Rocky Linux 64 位',
    help: '★ 只有「已登记」或「当次点名」（config.yaml 的 vm.extra_allow）的才允许操作（红线 12）' },
  { key: 'new_id', label: '新机 id（目录名 / 文件名 / 主机名 / 登记 id 四合一）', ph: 'aoc-tpl-01',
    help: '形状只许 [A-Za-z0-9][A-Za-z0-9._-]{1,38} —— 它同时是路径与主机名，形状由平台统一的唯一来源定（§12.130 第 6 条）' },
  { key: 'initial_address', label: '★ 克隆机刚起来时的地址（= 母机的地址）', ph: '203.0.113.130',
    help: '克隆会**连 MAC 一起复制** ⇒ DHCP 会给它母机那个租约。★ 不确定就先跑一次「guest 报告的地址」看一眼' },
  { key: 'address', label: '★ 新机的最终静态地址（链尾那一跳用）', ph: '192.0.2.14',
    help: '来源只有两个：人点名，或平台只读扫描后挑；★ 必须避开 DHCP 池（.128~.254）—— 扫描只是当天事实，真跑前再扫（§12.132）' },
];

//: 整链会经过的步骤（★ 只是**列出来给人看**，不是这里的按钮 —— 每一步都有任务号，可去「历史」逐字复核）
const VM_PROV_STEPS = [
  ['①', '给母机打一条快照', 'vm.snapshot-create', '克隆靠的是**源状态**，源状态要可回（唯一的回退点）'],
  ['②', '克隆（🔴 red · 手输确认词）', 'vm.clone', '★ 收条 ≠ 判据：判据是**文件系统上真的多了一个 .vmx**'],
  ['③', '先登记进 hosts.yaml', 'host.register', '★ 不登记就不能开它（归属判定只认登记或当次点名）；写前备份 / 逐字节可回退'],
  ['④', '开机', 'vm.start', '★ 判据是**再问一次 VMware**（它出现在 vmrun list 里）'],
  ['⑤', '等 guest 就绪', 'vm.wait-guest', '★ "起来了"：等 guest 报出地址；★ 它 **≠** "能 ssh 进去"'],
  ['⑥', '等 SSH 就绪', 'wait（配方步骤）', '★ 判据：**22 端口真的开了**（不是"等了几十秒"）'],
  ['⑦', '先读一次身份（对照前半段）', 'host.identity-show', '★★ 此刻读到的就是**母机的身份** —— 它是后面"变了没有"的对照物'],
  ['⑧', '重置身份 ① ② ③', 'host.machine-id-reset / host.ssh-hostkey-reset / host.hostname-set', '★ 每项的判据都是**"与动手前不同"**（§12.128）'],
  ['⑨', '再读一次身份（对照后半段）', 'host.identity-show', '★ 四项应**全都不一样**；第 5 项（UUID / MAC）见下面那张只读卡'],
  ['⑩', '体检 12 项', 'host.checkup', '★ "连得上"之后才是"查得通"；失败**如实红**'],
  ['⑪', '（可选）关回去', 'vm.stop', '★ 默认**保持开机** —— "造完就关掉"不是默认行为'],
];

const VM_PROV_TAIL = [
  { id: 'host.static-ip-set', title: '第 4 项身份：改成静态地址（链外单独跑）',
    hint: '★★ 它**刻意不在整链里**：地址一改，管理机到它的那条 ssh 就换了，而配方的健康检查是**按登记地址**问的 ⇒ 塞进链里会问到一个已经没人的地址（**假红**，比不做更坏，§12.128 第 2 条）' },
  { id: 'host.register', title: '登记改成最终地址（链外单独跑）',
    hint: '与上一步配对：改完地址立刻把登记里的 address 换成新的（update_mode=address）—— ★ 两件事各自留一个任务号' },
];

const VMP = { pick: '' };   // 本页签选中的虚拟机（值 = `hosts.yaml` 里的**登记 id**）

function vmRegistered() { return (S.hosts || []).filter((h) => h && h.vm && h.vm.vmx); }

function currentVm() {
  const reg = vmRegistered();
  if (!reg.length) return 'node-03';
  if (!VMP.pick || !reg.some((h) => h.id === VMP.pick)) VMP.pick = reg[0].id;
  return VMP.pick;
}

/* ★ 只读卡片跑的是**已有动作**，与 K8s 管理台 / 监控页**同一条**取结论的路（`k8sRunRead`）——
 *   非 green 一律转去「动作」页走闸门。★ 只有一处实现，就不会出现"某一边偷偷放宽"。
 *   ★ 唯一的差别：把**本页签选中的那台 VM** 作为 `vm` 参数交上去。 */
function vmRunRead(actionId, btn, box) {
  return k8sRunRead(actionId, btn, box, { vm: currentVm() });
}

async function vmOpenAction(id, extra) {
  switchTab('actions');
  await selectAction(id);
  // ★ 把本页签选中的那台 VM（以及 T17 造机表单收上来的值）填进表单
  //   —— ★ 用户**仍可改**，也仍要先看清命令预览再跑；这里只是"少敲几下"，**不是**替代闸门
  const vals = Object.assign({ vm: currentVm() }, extra || {});
  Object.keys(vals).forEach((k) => {
    const el = document.querySelector(`#form [data-param="${k}"]`);
    if (el && vals[k] != null && String(vals[k]) !== '') { el.value = vals[k]; S.params[k] = vals[k]; }
  });
  doPreview();
  toast('已切到「动作」页：参数、命令预览与二次确认闸门都在那里');
}

/* ------------------------------------------------------------ T17 · 造机表单 → 既有闸门 */
function vpGet() {
  const out = {};
  VM_PROV_FIELDS.forEach((f) => {
    const el = document.getElementById('vp-' + f.key);
    out[f.key] = el ? String(el.value || '').trim() : '';
  });
  return out;
}

/* ★ 只克隆这一跳（🔴 red）⇒ 跳到「动作」页；**这一页不提供"直接跑"**（§12.135 第 1 条） */
async function vmOpenClone() {
  const v = vpGet();
  if (!v.mother) { toast('先把「母机（源虚拟机）」填上'); return; }
  await vmOpenAction('vm.clone', { vm: v.mother, new_id: v.new_id });
  toast('🔴 克隆是 red：看清命令预览，再在确认弹窗里**手输确认词**才跑得起来');
}

/* ★ 一键整链 ⇒ 跳到「配方」页跑 vm-provision（参数按表单预填；第一跳就是 🔴 克隆） */
async function vmOpenProvision() {
  const v = vpGet();
  switchTab('recipes');
  await selectRecipe('vm-provision');
  const keep = Object.assign({}, S.recipeParams);
  ['mother', 'new_id', 'initial_address', 'address'].forEach((k) => {
    if (v[k]) keep[k] = v[k];
  });
  S.recipeParams = keep;
  await refreshRecipePlan();
  toast('已切到「配方」页：参数按你填的值预填 —— 整链第一跳就是 🔴 克隆，所以同样要手输确认词');
}

function loadVm() { renderVm(); }

function renderVm() {
  const reg = vmRegistered();
  const cur = currentVm();

  // 侧栏：五块跳转 ＋ 变更类/red 类直通「动作」页 ＋ ★ T17：造机入口（跳「配方」页）
  $('#pane-vm').innerHTML = `
    <div class="group-title">五块 · 每块一键取结论</div>
    ${VM_READ.map((c) => `<div class="card" data-goto="${esc(c.key)}" role="button" tabindex="0">
        <h4>${c.icon} ${esc(c.title)}</h4><p>${esc(c.action)}</p></div>`).join('')}
    <div class="group-title">★ T17 · 造一台靶子机</div>
    <div class="card" data-goto="prov" role="button" tabindex="0">
      <h4>🏗 造机链（克隆 → 身份重置 → 纳管 → 体检）</h4><p>vm-provision</p></div>
    <div class="group-title">直通「动作」页（带闸门）</div>
    ${VM_WRITE.concat(VM_RED).map((w) => `<div class="card" data-openact="${esc(w.id)}"
        role="button" tabindex="0"><h4>${esc(w.title)}</h4><p>${esc(w.id)}</p></div>`).join('')}`;

  $$('#pane-vm .card').forEach((el) => {
    const go = () => {
      if (el.dataset.goto) {
        const t = $('#vm-card-' + el.dataset.goto);
        if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        vmOpenAction(el.dataset.openact);
      }
    };
    el.addEventListener('click', go);
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); }
    });
  });

  // 主区：五块卡片（每块 = 一键取结论 ＋ 结论区 ＋ 原始证据可展开）
  $('#content').innerHTML = `
    <h2>虚拟机 <span class="badge green">只读为主</span> <span class="badge">域 M</span></h2>
    <div class="sub">五块 = 总纲 §4.2 第六阶段 T16 要求的「VM 生命周期一次给全结论」。★ 界面不自己算结论：
      它跑的是 <code>vm.*</code> 已有动作，然后把动作自己的结论原文念出来。</div>

    <div class="banner ok">
      <h3>★ 这些动作跑在「宿主机」上，不是顶栏那台机器</h3>
      <div>虚拟化层的执行面是<b>本机</b>（<code>vmrun.exe</code>，动作声明 <code>channel: local</code>）——
        顶栏选中的目标机<b>与本页签无关</b>，任务记录里记的也是宿主机（规范 §12.115 规矩 2）。
        ★ 换个说法：这一页回答的是「<b>哪台虚拟机在跑</b>」，不是「顶栏那台机器怎么样」。</div>
    </div>

    <div class="section">
      <h3>靶子纪律：能碰的只有这些（红线 12）</h3>
      <div class="sub">唯一来源 = <code>hosts.yaml</code> 里登记了 <code>vm.vmx</code> 的机器；
        确实要动别的，把它加进 <code>config.yaml</code> 的 <code>vm.extra_allow</code>
        （当次点名，写进文件即留痕）。★ 没登记的**只读可见、不可操作** —— 那是<b>保护</b>，不是故障。</div>
      ${reg.length ? `
      <div class="card">
        <div class="row"><span class="sub" style="margin:0">本页签操作的虚拟机（会填进 <code>vm</code> 参数）</span></div>
        <select id="vmPick">${reg.map((h) => `<option value="${esc(h.id)}"${h.id === cur ? ' selected' : ''}>${esc(h.id)}（${esc(h.name)}）</option>`).join('')}</select>
        <table class="dual-table">
          <tr><th>登记 id</th><th>vmx（登记的那一份）</th><th>角色</th></tr>
          ${reg.map((h) => `<tr><td>${esc(h.id)}</td><td><code>${esc((h.vm || {}).vmx || '')}</code></td><td>${esc(h.role || '')}</td></tr>`).join('')}
        </table>
        <div class="note">★ 表里是「归本项目管」的那一份 —— 它的来源是登记，不是"磁盘上看着像"。
          ★★ 全盘有多少台、哪些与本项目无关：跑下面那张「虚拟机清单」看它们自己的结论。</div>
      </div>` : `
      <div class="banner bad">
        <h3>没有任何已登记的虚拟机</h3>
        <div><code>hosts.yaml</code> 里一台 <code>vm.vmx</code> 都没有 ⇒
          <b>vm.* 动作对任何虚拟机都会被拒绝</b>（闸门在平台侧，§12.116）。</div>
        <div>补法：给受管机加 <code>vm: {provider, vmx}</code> 登记；确实只想动一次的，
          写进 <code>config.yaml</code> 的 <code>vm.extra_allow</code>（当次点名）。</div>
      </div>`}
    </div>

    ${VM_READ.map((c) => `
      <div class="section" id="vm-card-${esc(c.key)}">
        <div class="card vm-card">
          <h4>${c.icon} ${esc(c.title)} ${riskBadge('green')} <span class="badge">${esc(c.action)}</span></h4>
          <p>${esc(c.desc)}</p>
          <div class="row">
            <button class="primary tiny vm-run" data-action="${esc(c.action)}" data-key="${esc(c.key)}">一键取结论</button>
            <button class="ghost tiny vm-open" data-action="${esc(c.action)}">打开动作（参数 / 命令预览）</button>
          </div>
          <div class="vm-out" id="vm-out-${esc(c.key)}"><div class="sub">还没取过。</div></div>
        </div>
      </div>`).join('')}

    <div class="section" id="vm-prov">
      <h3>🏗 造一台靶子机 <span class="badge">T17</span> <span class="badge red">克隆是 red</span></h3>
      <div class="banner">
        <h3>★ 主题句：克隆给出的是「拷贝件」</h3>
        <div><code>vmrun clone</code> 返回 0，只说明<b>磁盘上多了几个文件</b> —— 它<b>不</b>说明
          machine-id / SSH host key / 主机名 / 静态 IP / UUID·MAC 已经是新的（默认整盘复制 ⇒ 五项与母机<b>完全相同</b>）。
          ★ <b>直到身份被换掉，它才算一台新机器</b>（规范 §12.129）。</div>
      </div>
      <div class="sub">这一块<b>不执行任何东西</b>：整链走配方 <code>vm-provision</code>，
        只克隆那一跳走动作 <code>vm.clone</code> —— 两条路都跳到既有那一套闸门里点
        （命令预览 ＋ 二次确认 ＋ red 手输确认词）。★ 闸门只有一处，不给第二条路（§12.6.1）。</div>
      <div class="card">
        <div class="row"><span class="sub" style="margin:0">表单：只用于<b>预填</b>下一跳的参数（不在这里执行）</span></div>
        ${VM_PROV_FIELDS.map((f) => `<div class="field"><label>${esc(f.label)}</label>
          <input type="text" id="vp-${esc(f.key)}" value="" placeholder="${esc(f.ph)}"
            autocomplete="off" spellcheck="false">
          <div class="help">${esc(f.help)}</div></div>`).join('')}
        <div class="row">
          <button class="primary tiny" id="btnVpProvision">一键整链：打开配方（vm-provision）</button>
          <button class="ghost tiny" id="btnVpClone">只做克隆这一跳（🔴 手输确认词）</button>
        </div>
      </div>

      <div class="card vm-card">
        <h4>🆔 第 5 项身份：VMware UUID / MAC（只读） <span class="badge">vm.vmx-read</span></h4>
        <p>★ 前四项身份由 <code>host.*</code> 重置，这一项<b>只能读</b> ——
          红线 13 不许改 <code>.vmx</code>。★「<b>读得到</b>」与「<b>改得动</b>」是两件事：
          实测 <code>vmrun clone</code> 会<b>换 UUID</b> 但<b>不换 MAC</b>（MAC 在首次开机那一刻才由 VMware 换），
          换不掉的那些就<b>如实写成"本平台的边界"</b>，不许硬改、也不许拿"去 GUI 手工改"冒充自动化（§12.133）。</p>
        <div class="row">
          <button class="primary tiny vm-run" data-action="vm.vmx-read" data-key="prov-vmx">一键取结论</button>
          <button class="ghost tiny vm-open" data-action="vm.vmx-read">打开动作</button>
        </div>
        <div class="vm-out" id="vm-out-prov-vmx"><div class="sub">还没取过。</div></div>
      </div>

      <div class="card">
        <h4>整链会经过哪些步骤（★ 每一步都有任务号，可去「历史」逐字复核）</h4>
        <table class="dual-table">
          <tr><th>#</th><th>做什么</th><th>动作</th><th>★ 判据是什么（不是"命令返回 0"）</th></tr>
          ${VM_PROV_STEPS.map((s) => `<tr><td>${esc(s[0])}</td><td>${esc(s[1])}</td>
            <td><code>${esc(s[2])}</code></td><td>${esc(s[3])}</td></tr>`).join('')}
        </table>
      </div>

      <div class="card">
        <h4>★ 链外单独跑的两件事（★ 顺序纪律，不是遗漏）</h4>
        ${VM_PROV_TAIL.map((t) => `<div class="gap-row">
          <span class="badge">${esc(t.id)}</span><span>${esc(t.title)}</span>
          <span class="dim">${esc(t.hint)}</span></div>`).join('')}
        <div class="note">★ 两份留证要<b>成对</b>：改地址一个任务号、改登记一个任务号 ——
          只跑一半，就会留下"登记里的地址没人应答"这种更坏的局面。</div>
      </div>

      <div class="card">
        <h4>这一块「回不去」的东西（★ 逐项说清，空也写「无」）</h4>
        <p>· <b>母机那条快照</b>会一直占磁盘（本次唯一的回退点）；<br>
        · ★ <b>平台没有"删虚拟机"这个动作</b>：克隆出来的靶子机不想要了，请<b>人工在 VMware 里删</b>
          —— 删除比克隆更不可逆，刻意不做（红线 15 / §12.130）；<br>
        · <b>旧身份不回</b>：machine-id / host key / 旧主机名 / 母机那个地址 ——
          它们正是要消除的"串味"本身；<br>
        · <b>克隆本身占一份整盘空间</b>（精简置备：母机实际占多少，克隆就长多少）。</p>
      </div>
    </div>

    <div class="section">
      <h3>变更类动作（★ 带参数表单与闸门）</h3>
      <div class="sub">点「打开」跳到「动作」页执行 —— 那里才有命令预览、二次确认与手输确认词。
        ★ 一条闸门，不给第二条路（规范 §12.6.1）。</div>
      ${VM_WRITE.map((w) => `<div class="card">
          <h4>${esc(w.title)} ${riskBadge('yellow')} <span class="badge">${esc(w.id)}</span></h4>
          <p>${esc(w.hint)}</p>
          <div class="row"><button class="ghost tiny vm-open" data-action="${esc(w.id)}">打开（带闸门）</button></div>
        </div>`).join('')}
    </div>

    <div class="section">
      <h3>🔴 永远 red（不可逆 · 禁批量 · AI 连请求都不许发）</h3>
      <div class="sub">★ 它们<b>不会</b>在这里被"一键"完成：必须切到「动作」页，先看命令预览，
        再在二次确认弹窗里<b>手输确认词</b>；服务端还会拒绝对它们做批量（§9.3 / §12.120）。
        ★ 第 3 件 red 是 <code>vm.clone</code> —— 它在上面那个「造一台靶子机」块里，规矩一样。</div>
      ${VM_RED.map((w) => `<div class="card">
          <h4>${esc(w.title)} ${riskBadge('red')} <span class="badge">${esc(w.id)}</span></h4>
          <p>${esc(w.hint)}</p>
          <div class="row"><button class="ghost tiny vm-open" data-action="${esc(w.id)}">打开（手输确认词）</button></div>
        </div>`).join('')}
    </div>

    <div class="section">
      <h3>这一页"回不去"的东西（规范 §12.118）</h3>
      <div class="card">
        <p>· <b>回滚覆盖掉的现状</b>：快照回滚会把虚拟机当前状态整个换掉，被覆盖的那一份
        <b>没有回收站</b>（除非它恰好被另一条更晚的快照记着）；<br>
        · <b>快照会一直占着磁盘</b>：删掉它之前，这部分空间一直不在你手里；<br>
        · <b><code>vm.stop-hard</code> 丢掉的未落盘数据</b>：等价于拔电源，guest 里没写完的东西就是没了；<br>
        · ★ <b>快照与文件级备份并列、不互相替代</b>：快照回的是"整台机器当时的样子"，
        文件级备份回的是"某一个文件"。</p>
      </div>
    </div>`;

  const pick = $('#vmPick');
  if (pick) {
    pick.addEventListener('change', () => {
      VMP.pick = pick.value;
      toast('已把本页签的虚拟机切成 ' + VMP.pick + '（★ 结论要重取：之前那份是另一台的）');
    });
  }
  $$('#content .vm-run').forEach((b) => b.addEventListener('click', () => {
    vmRunRead(b.dataset.action, b, $('#vm-out-' + b.dataset.key));
  }));
  $$('#content .vm-open').forEach((b) => b.addEventListener('click', () => vmOpenAction(b.dataset.action)));
  // ★ T17：造机入口的两个按钮 —— 都只是**跳到既有闸门**，这一页自己不执行（§12.135 第 1 条）
  const bp = $('#btnVpProvision');
  if (bp) bp.addEventListener('click', vmOpenProvision);
  const bc = $('#btnVpClone');
  if (bc) bc.addEventListener('click', vmOpenClone);
}

// ★ T14：入口从 `init()` 换成 `boot()` —— 先过门，再进控制台。
boot();
