// ​‌​​​​‌‌‍​‌‌​‌‌‌‌‍​‌‌​​‌‌​‍​‌‌​​‌‌​‍​​‌‌​​​​‍​‌‌‌‌​​​‍​‌‌​​​‌‌‍Code generated; DO NOT EDIT.

package webui

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LobsterGuard — 安全评估工具</title>
  <link rel="stylesheet" href="app.css">
</head>
<body>
  <header id="header">
    <span class="logo">🦞 LobsterGuard v4.1.0</span>
    <span class="subtitle">OpenClaw 安全评估工具</span>
    <span class="header-badge" id="header-badge">就绪</span>
  </header>

  <div id="controls">
    <div class="target-group">
      <label>目标:</label>
      <textarea id="target" rows="2" placeholder="支持多种格式，逗号或换行分隔:&#10;192.168.1.100:3002, 10.0.0.5:18789&#10;192.168.1.0/24  10.0.0.1-50  (自动扫描默认端口)"></textarea>
    </div>
    <div class="ctrl-row">
      <label>令牌: <input type="text" id="token" placeholder="Gateway 认证令牌"></label>
      <label class="checkbox-label"><input type="checkbox" id="tls"><span class="checkbox-text">加密连接</span></label>
      <label>超时: <input type="number" id="timeout" value="10" min="1" max="120" style="width:60px">秒</label>
      <label>模式:
        <select id="mode">
          <option value="scan">🔍 完整扫描</option>
          <option value="exploit">⚔️ 攻击链</option>
          <option value="fingerprint">🔎 指纹识别</option>
          <option value="auth">🔑 认证检测</option>
          <option value="recon">📡 信息收集</option>
          <option value="audit">📋 配置审计</option>
        </select>
      </label>
      <div class="btn-group">
        <button id="btn-scan" onclick="startScan()">▶ 开始扫描</button>
        <button id="btn-cancel" onclick="cancelScan()" disabled>■ 取消</button>
        <button id="btn-export" onclick="exportReport()" disabled>⬇ 导出报告</button>
      </div>
    </div>
    <div class="port-hint">默认端口: 3002, 18789, 8080, 8443, 3000, 3001, 8000, 8888, 9090（输入纯 IP/CIDR 时自动扫描）</div>
  </div>

  <div id="main">
    <div id="progress-panel">
      <div class="panel-title"><span class="panel-icon">⛓</span> 攻击链进度</div>
      <div id="progress-bar-container">
        <div id="progress-bar"></div>
        <span id="progress-text">0%</span>
      </div>
      <div id="chain-list"></div>
    </div>
    <div id="findings-panel">
      <div class="panel-title"><span class="panel-icon">🐛</span> 漏洞发现 <span id="findings-count" class="count-badge">0</span></div>
      <table id="findings-table">
        <thead><tr><th>#</th><th>等级</th><th>模块</th><th>标题</th></tr></thead>
        <tbody id="findings-body"></tbody>
      </table>
      <div id="findings-empty">暂无发现，等待扫描...</div>
    </div>
  </div>

  <div id="log-resize-handle"></div>
  <div id="log-panel">
    <div class="panel-title"><span class="panel-icon">📜</span> 实时日志</div>
    <div id="log-content"></div>
  </div>

  <div id="statusbar">
    <span id="status-state" class="idle">● 就绪</span>
    <span id="status-counts">严重:0 高危:0 中危:0 低危:0 信息:0</span>
    <span id="status-elapsed"></span>
  </div>

  <script src="app.js"></script>
</body>
</html>
`

const appCSS = `:root {
  --bg: #282A36; --bg-dark: #21222C; --bg-light: #44475A;
  --fg: #F8F8F2; --dim: #6272A4;
  --red: #FF5555; --orange: #FFB86C; --yellow: #F1FA8C;
  --green: #50FA7B; --cyan: #8BE9FD; --purple: #BD93F9; --pink: #FF79C6;
  --shadow: 0 2px 8px rgba(0,0,0,0.3);
  --radius: 6px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  width: 100vw; height: 100vh; overflow: hidden;
  display: flex; flex-direction: column;
  background: var(--bg-dark); color: var(--fg);
  font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', Consolas, monospace;
  font-size: 14px;
}

/* ── Header ── */
#header {
  background: linear-gradient(135deg, var(--bg-light) 0%, #383A59 100%);
  padding: 10px 20px; display: flex; align-items: center; gap: 16px;
  box-shadow: var(--shadow); z-index: 10;
}
#header .logo {
  font-weight: bold; color: var(--red); font-size: 1.3em;
  text-shadow: 0 0 12px rgba(255,85,85,0.3);
}
#header .subtitle { color: var(--dim); font-size: 0.9em; }
.header-badge {
  margin-left: auto; padding: 2px 10px; border-radius: 12px;
  font-size: 0.75em; font-weight: bold;
  background: rgba(80,250,123,0.15); color: var(--green); border: 1px solid rgba(80,250,123,0.3);
}
.header-badge.active {
  background: rgba(241,250,140,0.15); color: var(--yellow); border-color: rgba(241,250,140,0.3);
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }

/* ── Controls ── */
#controls {
  background: var(--bg); padding: 10px 20px;
  display: flex; flex-flow: row wrap; gap: 12px; align-items: center;
  border-bottom: 1px solid var(--bg-light);
}
#controls label { color: var(--dim); font-size: 0.85em; display: flex; align-items: center; gap: 4px; }
#controls input, #controls select {
  background: var(--bg-dark); color: var(--fg);
  border: 1px solid var(--bg-light); border-radius: var(--radius); padding: 5px 10px;
  font-family: inherit; font-size: 0.85em;
  transition: border-color 0.2s, box-shadow 0.2s;
}
#controls input:focus, #controls select:focus {
  outline: none; border-color: var(--purple);
  box-shadow: 0 0 0 2px rgba(189,147,249,0.2);
}
.checkbox-label { cursor: pointer; }
.checkbox-label input[type="checkbox"] {
  accent-color: var(--purple); width: 14px; height: 14px; cursor: pointer;
}
.checkbox-text { color: var(--dim); }
.btn-group { display: flex; gap: 6px; margin-left: auto; }
#controls button {
  padding: 6px 16px; border: none; border-radius: var(--radius);
  cursor: pointer; font-weight: bold; font-family: inherit; font-size: 0.85em;
  transition: all 0.2s; position: relative; overflow: hidden;
}
#controls button:hover:not(:disabled) { transform: translateY(-1px); box-shadow: var(--shadow); }
#controls button:active:not(:disabled) { transform: translateY(0); }
#btn-scan { background: var(--green); color: var(--bg-dark); }
#btn-scan:hover:not(:disabled) { background: #6BFF96; }
#btn-cancel { background: var(--red); color: var(--fg); }
#btn-cancel:hover:not(:disabled) { background: #FF7777; }
#btn-export { background: var(--purple); color: var(--fg); }
#btn-export:hover:not(:disabled) { background: #D0AAFF; }
button:disabled { opacity: 0.35; cursor: default; }

/* ── Target textarea & controls layout ── */
.target-group {
  display: flex; align-items: flex-start; gap: 6px; width: 100%;
}
.target-group label { color: var(--dim); font-size: 0.85em; padding-top: 6px; white-space: nowrap; }
.target-group textarea {
  flex: 1; background: var(--bg-dark); color: var(--fg);
  border: 1px solid var(--bg-light); border-radius: var(--radius); padding: 5px 10px;
  font-family: inherit; font-size: 0.82em; resize: vertical; min-height: 40px;
  transition: border-color 0.2s, box-shadow 0.2s; line-height: 1.4;
}
.target-group textarea:focus {
  outline: none; border-color: var(--purple);
  box-shadow: 0 0 0 2px rgba(189,147,249,0.2);
}
.target-group textarea::placeholder { color: var(--dim); opacity: 0.6; font-size: 0.9em; }
.ctrl-row {
  display: flex; flex-flow: row wrap; gap: 12px; align-items: center; width: 100%;
}
.port-hint {
  width: 100%; font-size: 0.72em; color: var(--dim); opacity: 0.7;
  padding-left: 40px;
}

/* ── Main Grid ── */
#main {
  flex: 1; display: grid; grid-template-columns: 50% 50%;
  gap: 0; overflow: hidden; min-height: 0;
}
#progress-panel, #findings-panel {
  overflow-y: auto; padding: 12px; position: relative;
}
#progress-panel { border-right: 1px solid var(--bg-light); background: var(--bg); }
#findings-panel { background: var(--bg); }
.panel-title {
  color: var(--purple); font-weight: bold; margin-bottom: 10px;
  border-bottom: 1px solid var(--bg-light); padding-bottom: 6px;
  font-size: 0.9em; display: flex; align-items: center; gap: 6px;
}
.panel-icon { font-size: 1em; }
.count-badge {
  background: var(--bg-light); color: var(--fg); padding: 1px 8px;
  border-radius: 10px; font-size: 0.8em; min-width: 24px; text-align: center;
}

/* ── Progress Bar ── */
#progress-bar-container {
  height: 26px; background: var(--bg-dark); border-radius: var(--radius);
  position: relative; margin-bottom: 12px; overflow: hidden;
  border: 1px solid var(--bg-light);
}
#progress-bar {
  height: 100%; border-radius: var(--radius);
  background: linear-gradient(90deg, var(--green), var(--cyan));
  transition: width 0.4s ease; width: 0%;
  box-shadow: 0 0 12px rgba(80,250,123,0.3);
}
#progress-bar.active {
  background: linear-gradient(90deg, var(--green), var(--cyan), var(--green));
  background-size: 200% 100%;
  animation: shimmer 2s linear infinite;
}
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
#progress-text {
  position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  color: var(--fg); font-size: 0.8em; font-weight: bold;
  text-shadow: 0 1px 2px rgba(0,0,0,0.5);
}

/* ── Chain List ── */
#chain-list { font-size: 0.82em; }
.chain-item {
  padding: 3px 6px; border-radius: 3px; margin-bottom: 1px;
  transition: background 0.15s;
}
.chain-item:hover { background: rgba(255,255,255,0.03); }
.chain-done { color: var(--green); }
.chain-running {
  color: var(--yellow); background: rgba(241,250,140,0.06);
  border-left: 2px solid var(--yellow); padding-left: 4px;
}
.chain-pending { color: var(--dim); }
.chain-error { color: var(--red); }
.chain-skip { color: var(--dim); text-decoration: line-through; opacity: 0.6; }

/* ── Findings Table ── */
#findings-table { width: 100%; border-collapse: collapse; font-size: 0.82em; }
#findings-table th {
  text-align: left; color: var(--purple); font-size: 0.9em;
  border-bottom: 2px solid var(--bg-light); padding: 6px 8px;
  position: sticky; top: 0; background: var(--bg); z-index: 1;
}
#findings-table td { padding: 5px 8px; border-bottom: 1px solid rgba(68,71,90,0.3); }
#findings-table tbody tr { transition: background 0.15s; cursor: pointer; }
#findings-table tbody tr:hover { background: rgba(68,71,90,0.4); }
.row-num { color: var(--dim); font-size: 0.85em; width: 30px; }
.sev-严重 { color: var(--red); font-weight: bold; text-shadow: 0 0 6px rgba(255,85,85,0.3); }
.sev-高危 { color: var(--orange); font-weight: bold; }
.sev-中危 { color: var(--yellow); }
.sev-低危 { color: var(--cyan); }
.sev-信息 { color: var(--dim); }
.finding-detail {
  display: none; background: var(--bg-dark); padding: 10px 12px;
  margin: 4px 0; border-radius: var(--radius); font-size: 0.85em;
  white-space: pre-wrap; border-left: 3px solid var(--purple);
  line-height: 1.6;
}
.finding-detail.open { display: block; animation: fadeIn 0.2s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
#findings-empty {
  color: var(--dim); text-align: center; padding: 40px 0;
  font-size: 0.9em;
}
#findings-empty.hidden { display: none; }

/* ── Log Panel ── */
#log-resize-handle {
  height: 4px; background: var(--bg-light); cursor: ns-resize;
  transition: background 0.2s;
}
#log-resize-handle:hover { background: var(--purple); }
#log-panel {
  height: 200px; display: flex; flex-direction: column;
  background: var(--bg-dark);
}
#log-panel .panel-title {
  padding: 6px 12px; margin-bottom: 0;
  background: var(--bg); border-bottom: 1px solid var(--bg-light);
}
#log-content {
  flex: 1; overflow-y: auto; padding: 6px 12px;
  font-size: 0.78em; line-height: 1.6;
}
#log-content div { padding: 1px 0; }
.log-success { color: var(--green); }
.log-warn { color: var(--orange); }
.log-error { color: var(--red); font-weight: bold; }
.log-dim { color: var(--dim); }
.log-sep { color: var(--purple); font-weight: bold; letter-spacing: 2px; }

/* ── Status Bar ── */
#statusbar {
  background: var(--bg-light); padding: 5px 20px;
  display: flex; justify-content: space-between; align-items: center;
  font-size: 0.8em; color: var(--dim);
  border-top: 1px solid rgba(255,255,255,0.05);
}
#status-state { display: flex; align-items: center; gap: 4px; }
#status-state.scanning { color: var(--yellow); font-weight: bold; }
#status-state.idle { color: var(--green); }
#status-state.error { color: var(--red); }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--bg-light); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--dim); }

/* ── Selection ── */
::selection { background: rgba(189,147,249,0.3); color: var(--fg); }
`

const appJS = `let ws = null;
let scanning = false;
let findings = [];
let chains = {};
let totalNodes = 0;
let doneNodes = 0;
let scanStartTime = null;
let elapsedTimer = null;
let sevCounts = { '严重': 0, '高危': 0, '中危': 0, '低危': 0, '信息': 0 };
const SEV_MAP = ['信息', '低危', '中危', '高危', '严重'];
const SEV_ICON = { '严重': '🔴', '高危': '🟠', '中危': '🟡', '低危': '🔵', '信息': '⚪' };

// 英文→中文翻译词典
const DICT = {
  // 常见描述片段
  'No auth required': '无需认证即可访问',
  'without auth': '无需认证',
  'accessible without authentication': '无需认证即可访问',
  'rate limiting': '速率限制',
  'no rate limiting': '无速率限制',
  'Rate limiting may be disabled': '速率限制可能已禁用',
  'rate limiting may be disabled entirely': '速率限制可能已完全禁用',
  'rapid requests without returning HTTP 429': '快速请求未返回 HTTP 429',
  'exposed': '暴露',
  'leaked': '泄露',
  'enumerable': '可枚举',
  'accessible': '可访问',
  'confirmed': '已确认',
  'detected': '已检测到',
  'vulnerable': '存在漏洞',
  'injection': '注入',
  'traversal': '遍历',
  'bypass': '绕过',
  'unauthorized': '未授权',
  'unauthenticated': '未认证',
  'disclosure': '信息泄露',
  'endpoint': '端点',
  'memory collections': '内存集合',
  'collection names': '集合名称',
  'attacker can discover': '攻击者可发现',
  'target specific': '针对特定',
  'agent/session memory stores': '代理/会话内存存储',
  'Platform identity': '平台身份信息',
  'error response': '错误响应',
  'unique endpoint signatures': '唯一端点签名',
  'Health endpoint exposes instance info': '健康检查端点暴露实例信息',
  'challenge gate active': '挑战门控已启用',
  'methods not enumerable': '方法不可枚举',
  'Pairing code entropy': '配对码熵值',
  'combinations': '种组合',
  'concurrent': '并发',
  'Code space': '码空间',
  'validation has no rate limiting': '验证无速率限制',
  'DM pairing code': 'DM 配对码',
  // 修复建议
  'Enable global rate limiting': '启用全局速率限制',
  'hard cap across all scopes': '对所有范围设置硬性上限',
  'Require authentication': '要求认证',
  'Restrict access': '限制访问',
  'Remove or restrict': '移除或限制',
  'Disable debug': '禁用调试',
  'Add authentication': '添加认证',
  'Implement rate limiting': '实施速率限制',
  'Use HTTPS': '使用 HTTPS',
  'Validate input': '验证输入',
  'Sanitize output': '净化输出',
  'Apply least privilege': '应用最小权限原则',
  'Rotate credentials': '轮换凭据',
  'Update to latest version': '更新到最新版本',
  'Patch immediately': '立即修补',
  'with a hard cap': '设置硬性上限',
};

function zhTranslate(text) {
  if (!text) return '';
  var result = text;
  // 按长度降序排列 key，避免短 key 先匹配破坏长 key
  var keys = Object.keys(DICT).sort(function(a, b) { return b.length - a.length; });
  for (var i = 0; i < keys.length; i++) {
    if (result.indexOf(keys[i]) >= 0) {
      result = result.split(keys[i]).join(DICT[keys[i]]);
    }
  }
  return result;
}

function connectWS() {
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen = function() { addLog('[*] 通信链路已建立', 'success'); };
  ws.onclose = function() {
    addLog('[!] 连接断开，3秒后重连...', 'warn');
    setTimeout(connectWS, 3000);
  };
  ws.onerror = function() {};
  ws.onmessage = function(e) {
    var msg = JSON.parse(e.data);
    switch (msg.type) {
      case 'progress': handleProgress(msg.data); break;
      case 'log': handleLog(msg.data); break;
      case 'finding': handleFinding(msg.data); break;
      case 'complete': handleComplete(msg.data); break;
      case 'error': handleError(msg.data); break;
      case 'status': handleStatus(msg.data); break;
    }
  };
}

function startScan() {
  var target = document.getElementById('target').value.trim();
  if (!target) { alert('请输入目标地址'); return; }
  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: target,
      token: document.getElementById('token').value.trim(),
      tls: document.getElementById('tls').checked,
      timeout: parseInt(document.getElementById('timeout').value) || 10,
      mode: document.getElementById('mode').value
    })
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) { addLog('[!] ' + d.error, 'error'); return; }
    scanning = true;
    findings = []; chains = {}; totalNodes = 0; doneNodes = 0;
    sevCounts = { '严重': 0, '高危': 0, '中危': 0, '低危': 0, '信息': 0 };
    document.getElementById('findings-body').innerHTML = '';
    document.getElementById('chain-list').innerHTML = '';
    document.getElementById('findings-empty').className = '';
    document.getElementById('btn-scan').disabled = true;
    document.getElementById('btn-cancel').disabled = false;
    document.getElementById('btn-export').disabled = true;
    document.getElementById('progress-bar').className = 'active';
    setBadge('扫描中', true);
    updateProgress(0, 0);
    updateStatus('scanning');
    scanStartTime = Date.now();
    elapsedTimer = setInterval(updateElapsed, 1000);
  });
}

function cancelScan() {
  fetch('/api/cancel', { method: 'POST' }).then(function(r) { return r.json(); }).then(function(d) {
    addLog('[!] ' + (d.message || '已取消'), 'warn');
  });
}

function exportReport() {
  window.open('/api/export?format=json', '_blank');
}

function handleProgress(data) {
  var id = data.task_id;
  if (!chains[id]) { chains[id] = { id: id, name: data.name, status: 'pending' }; totalNodes++; }
  var prev = chains[id].status;
  chains[id].status = data.status;
  if (data.elapsed) chains[id].elapsed = data.elapsed;
  if (prev !== 'done' && prev !== 'error' && prev !== 'skip') {
    if (data.status === 'done' || data.status === 'error' || data.status === 'skip') doneNodes++;
  }
  updateProgress(doneNodes, totalNodes);
  renderChains();
}

function handleLog(data) { addLog(data.message); }

function handleFinding(data) {
  findings.push(data);
  var sev = data.severity;
  var sevStr = (typeof sev === 'number') ? (SEV_MAP[sev] || '信息') : sev;
  if (sevCounts[sevStr] !== undefined) sevCounts[sevStr]++;
  document.getElementById('findings-empty').className = 'hidden';
  addFindingRow(data, sevStr);
  updateSevCounts();
}

function handleComplete(data) {
  scanning = false;
  clearInterval(elapsedTimer);
  document.getElementById('btn-scan').disabled = false;
  document.getElementById('btn-cancel').disabled = true;
  document.getElementById('progress-bar').className = '';
  if (findings.length > 0) document.getElementById('btn-export').disabled = false;
  updateProgress(totalNodes, totalNodes);
  updateStatus('idle');
  setBadge('完成', false);
  addLog('════════════════════════════════════════════', 'sep');
  var targetInfo = data.total_targets > 1 ? ' (' + data.total_targets + ' 个目标)' : '';
  if (findings.length > 0) {
    addLog('🔴 扫描完成 — 发现 ' + findings.length + ' 个安全问题！' + targetInfo + ' 耗时 ' + (data.elapsed || ''), 'error');
  } else {
    addLog('✅ 扫描完成 — 未发现安全问题。' + targetInfo + ' 耗时 ' + (data.elapsed || ''), 'success');
  }
  addLog('════════════════════════════════════════════', 'sep');
}

function handleError(data) {
  addLog('[!] 错误: ' + (data.message || JSON.stringify(data)), 'error');
  updateStatus('error');
  setBadge('错误', false);
}

function handleStatus(data) {
  if (data.scanning) {
    scanning = true;
    document.getElementById('btn-scan').disabled = true;
    document.getElementById('btn-cancel').disabled = false;
    updateStatus('scanning');
    setBadge('扫描中', true);
  }
  if (data.target) document.getElementById('target').value = data.target;
  if (data.token) document.getElementById('token').value = data.token;
}

function addLog(text, cls) {
  var el = document.getElementById('log-content');
  var line = document.createElement('div');
  if (!cls) {
    if (text.indexOf('[+]') >= 0) cls = 'success';
    else if (text.indexOf('[!]') >= 0) cls = 'error';
    else if (text.indexOf('[*]') >= 0) cls = 'dim';
    else if (text.charAt(0) === '═') cls = 'sep';
  }
  if (cls) line.className = 'log-' + cls;
  line.textContent = text;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function addFindingRow(f, sevStr) {
  var tbody = document.getElementById('findings-body');
  var idx = findings.length;
  var tr = document.createElement('tr');
  var icon = SEV_ICON[sevStr] || '⚪';
  var title = zhTranslate(f.title || '');
  tr.innerHTML = '<td class="row-num">' + idx + '</td><td class="sev-' + sevStr + '">' + icon + ' ' + sevStr + '</td><td>' + esc(f.module || '') + '</td><td>' + esc(title) + '</td>';
  var detailTr = document.createElement('tr');
  var detailTd = document.createElement('td');
  detailTd.colSpan = 4;
  var detail = document.createElement('div');
  detail.className = 'finding-detail';
  var t = '';
  if (f.description) t += '📝 描述: ' + zhTranslate(f.description) + '\n';
  if (f.evidence) t += '🔍 证据: ' + zhTranslate(f.evidence) + '\n';
  if (f.remediation) t += '🛡️ 修复: ' + zhTranslate(f.remediation) + '\n';
  if (f.target) t += '🎯 目标: ' + f.target;
  detail.textContent = t;
  detailTd.appendChild(detail);
  detailTr.appendChild(detailTd);
  tr.onclick = function() { detail.classList.toggle('open'); };
  tbody.appendChild(tr);
  tbody.appendChild(detailTr);
  document.getElementById('findings-count').textContent = findings.length;
}

function renderChains() {
  var el = document.getElementById('chain-list');
  var sorted = Object.values(chains).sort(function(a, b) { return a.id - b.id; });
  el.innerHTML = sorted.map(function(c) {
    var icon = '○', cls = 'chain-pending';
    if (c.status === 'running') { icon = '▸'; cls = 'chain-running'; }
    else if (c.status === 'done') { icon = '✓'; cls = 'chain-done'; }
    else if (c.status === 'error') { icon = '✗'; cls = 'chain-error'; }
    else if (c.status === 'skip') { icon = '—'; cls = 'chain-skip'; }
    var elapsed = c.elapsed ? ' (' + fmtDur(c.elapsed) + ')' : '';
    return '<div class="chain-item ' + cls + '">' + icon + ' #' + String(c.id).padStart(2, '0') + ' ' + esc(c.name) + elapsed + '</div>';
  }).join('');
}

function updateProgress(done, total) {
  var pct = total > 0 ? Math.round(done / total * 100) : 0;
  document.getElementById('progress-bar').style.width = pct + '%';
  document.getElementById('progress-text').textContent = done + '/' + total + ' (' + pct + '%)';
}

function updateSevCounts() {
  document.getElementById('status-counts').textContent =
    '严重:' + sevCounts['严重'] + '  高危:' + sevCounts['高危'] +
    '  中危:' + sevCounts['中危'] + '  低危:' + sevCounts['低危'] + '  信息:' + sevCounts['信息'];
}

function updateStatus(state) {
  var el = document.getElementById('status-state');
  el.className = state;
  if (state === 'scanning') el.innerHTML = '<span class="dot-pulse"></span> 扫描中...';
  else if (state === 'error') el.textContent = '● 错误';
  else el.textContent = '● 就绪';
}

function updateElapsed() {
  if (!scanStartTime) return;
  var sec = Math.floor((Date.now() - scanStartTime) / 1000);
  var m = Math.floor(sec / 60), s = sec % 60;
  document.getElementById('status-elapsed').textContent = '耗时 ' + m + '分' + s + '秒';
}

function setBadge(text, active) {
  var el = document.getElementById('header-badge');
  el.textContent = text;
  el.className = active ? 'header-badge active' : 'header-badge';
}

function fmtDur(ns) {
  if (typeof ns === 'string') return ns;
  var ms = Math.round(ns / 1e6);
  if (ms < 1000) return ms + '毫秒';
  return (ms / 1000).toFixed(1) + '秒';
}

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// Log panel resize
(function() {
  var handle = document.getElementById('log-resize-handle');
  var logPanel = document.getElementById('log-panel');
  var startY, startH;
  handle.addEventListener('mousedown', function(e) {
    startY = e.clientY; startH = logPanel.offsetHeight;
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    e.preventDefault();
  });
  function onMove(e) {
    var h = startH + (startY - e.clientY);
    if (h >= 80 && h <= 600) logPanel.style.height = h + 'px';
  }
  function onUp() {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
  }
})();

window.addEventListener('DOMContentLoaded', function() {
  connectWS();
  fetch('/api/status').then(function(r) { return r.json(); }).then(function(d) {
    if (d.target) document.getElementById('target').value = d.target;
    if (d.token) document.getElementById('token').value = d.token;
    if (d.tls) document.getElementById('tls').checked = true;
    if (d.timeout) document.getElementById('timeout').value = d.timeout;
  }).catch(function() {});
});
`

