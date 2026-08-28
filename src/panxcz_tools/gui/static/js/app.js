/* ═══════════════════════════════════════════════════════════════
   Panxcz Tools — Frontend JavaScript
   ═══════════════════════════════════════════════════════════════ */

const API = '';  // Same origin

let currentFile = null;
let functionsData = [];
let stringsData = [];

// ─── API Helpers ─────────────────────────────────────────────────

async function api(path, opts = {}) {
  const url = API + path;
  const resp = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  return resp.json();
}

function status(msg) {
  document.getElementById('status-left').textContent = msg;
}

// ─── File Operations ─────────────────────────────────────────────

function openFile() {
  document.getElementById('open-modal').style.display = 'flex';
  document.getElementById('open-path').focus();
}

function closeModal() {
  document.getElementById('open-modal').style.display = 'none';
}

async function confirmOpen() {
  const path = document.getElementById('open-path').value.trim();
  if (!path) return;

  status('Loading ' + path + '…');
  closeModal();

  try {
    const result = await api('/api/open', {
      method: 'POST',
      body: JSON.stringify({ path }),
    });

    if (result.error) {
      status('Error: ' + result.error);
      return;
    }

    currentFile = path;
    document.getElementById('filename').textContent = path;
    status('Loaded: ' + path);

    // Display file info
    displayInfo(result.info);

    // Auto-analyze
    runAnalysis();
  } catch (e) {
    status('Error: ' + e.message);
  }
}

// Enter key in path input
document.addEventListener('DOMContentLoaded', () => {
  const pathInput = document.getElementById('open-path');
  if (pathInput) {
    pathInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') confirmOpen();
      if (e.key === 'Escape') closeModal();
    });
  }
});

// ─── Analysis ────────────────────────────────────────────────────

async function runAnalysis() {
  if (!currentFile) { openFile(); return; }

  status('Analyzing…');

  try {
    const data = await api('/api/analyze');

    // File info
    if (data.file_info) displayInfo(data.file_info);

    // Functions
    if (data.functions) {
      functionsData = data.functions;
      renderFunctions(data.functions);
    }

    // Imports
    if (data.imports) renderImports(data.imports);

    // Disasm
    disassemble();

    // Strings
    loadStrings();

    // Sections
    if (data.sections) renderSections(data.sections);

    status('Analysis complete — ' + (data.functions?.length || 0) + ' functions');
  } catch (e) {
    status('Analysis error: ' + e.message);
  }
}

function displayInfo(info) {
  const el = document.getElementById('file-info');
  if (!info || !info.bin) {
    el.innerHTML = '<div class="info-placeholder">No info available</div>';
    return;
  }

  const bin = info.bin || {};
  const core = info.core || {};

  el.innerHTML = `
    <div class="row"><span class="key">Arch</span><span class="val">${bin.arch || '?'}</span></div>
    <div class="row"><span class="key">Bits</span><span class="val">${bin.bits || '?'}</span></div>
    <div class="row"><span class="key">Endian</span><span class="val">${bin.endian || '?'}</span></div>
    <div class="row"><span class="key">OS</span><span class="val">${bin.os || '?'}</span></div>
    <div class="row"><span class="key">Machine</span><span class="val">${bin.machine || '?'}</span></div>
    <div class="row"><span class="key">Format</span><span class="val">${bin.class || '?'}</span></div>
    <div class="row"><span class="key">Strips</span><span class="val">${bin.stripped ? 'Yes' : 'No'}</span></div>
    <div class="row"><span class="key">Static</span><span class="val">${bin.static ? 'Yes' : 'No'}</span></div>
  `;
}

// ─── Disassembly ─────────────────────────────────────────────────

async function disassemble(addr) {
  if (!currentFile) return;

  const el = document.getElementById('disasm-output');
  el.textContent = 'Loading disassembly…';

  try {
    const url = addr ? `/api/disasm?addr=${addr}` : '/api/disasm';
    const data = await api(url);
    el.textContent = data.disassembly || 'No output';
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

async function disasmEntry() {
  disassemble('entry0');
}

async function disasmMain() {
  disassemble('main');
}

function disasmFromInput() {
  const addr = document.getElementById('disasm-addr').value.trim();
  if (addr) disassemble(addr);
}

// Enter key in disasm address input
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('disasm-addr');
  if (input) input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') disassemble(e.target.value.trim());
  });
});

// ─── Functions ───────────────────────────────────────────────────

function renderFunctions(funcs) {
  const el = document.getElementById('func-list');
  if (!funcs || !Array.isArray(funcs)) {
    el.innerHTML = '<div class="info-placeholder">No functions</div>';
    return;
  }

  el.innerHTML = funcs.map(f => {
    const name = f.name || f.realname || '?';
    const offset = f.offset || f.addr || 0;
    const size = f.size || 0;
    return `<div class="item" onclick="disassemble('0x${offset.toString(16)}')">
      <span class="addr">0x${offset.toString(16)}</span>
      <span class="name">${escHtml(name)}</span>
      <span class="size">${size}</span>
    </div>`;
  }).join('');
}

function filterFunctions() {
  const q = document.getElementById('func-search').value.toLowerCase();
  const filtered = functionsData.filter(f =>
    (f.name || '').toLowerCase().includes(q) ||
    (f.realname || '').toLowerCase().includes(q)
  );
  renderFunctions(filtered);
}

// ─── Imports ─────────────────────────────────────────────────────

function renderImports(imports) {
  const el = document.getElementById('import-list');
  if (!imports || !Array.isArray(imports)) {
    el.innerHTML = '<div class="info-placeholder">No imports</div>';
    return;
  }

  el.innerHTML = imports.map(imp => {
    const name = imp.name || '?';
    const addr = imp.plt || imp.addr || 0;
    return `<div class="item">
      <span class="addr">0x${addr.toString(16)}</span>
      <span class="name">${escHtml(name)}</span>
    </div>`;
  }).join('');
}

// ─── Hex View ────────────────────────────────────────────────────

async function loadHex(offset) {
  if (!currentFile) return;

  offset = offset || parseInt(document.getElementById('hex-offset').value) || 0;
  document.getElementById('hex-offset').value = offset;

  const el = document.getElementById('hex-output');
  el.textContent = 'Loading hex…';

  try {
    const data = await api(`/api/hex?offset=${offset}&size=512`);
    el.textContent = data.hexdump || 'No output';
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

async function searchHex() {
  const q = document.getElementById('hex-search').value.trim();
  if (!q) return;

  try {
    const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
    if (Array.isArray(data) && data.length > 0) {
      const first = data[0];
      const offset = first.offset || first.vaddr || 0;
      document.getElementById('hex-offset').value = parseInt(offset, 16) || 0;
      loadHex(parseInt(offset, 16) || 0);
      status(`Found at 0x${parseInt(offset, 16).toString(16)}`);
    } else {
      status('Not found: ' + q);
    }
  } catch (e) {
    status('Search error: ' + e.message);
  }
}

// ─── Strings ─────────────────────────────────────────────────────

async function loadStrings() {
  if (!currentFile) return;

  try {
    const minLen = document.getElementById('strings-min')?.value || 4;
    const data = await api(`/api/strings?min_len=${minLen}`);
    stringsData = Array.isArray(data) ? data : [];
    renderStrings(stringsData);
  } catch (e) {
    status('Strings error: ' + e.message);
  }
}

function renderStrings(strings) {
  const tbody = document.querySelector('#strings-table tbody');
  tbody.innerHTML = strings.slice(0, 500).map(s => `
    <tr>
      <td class="offset">${s.offset || '?'}</td>
      <td>${s.type || '?'}</td>
      <td>${escHtml(s.string || '')}</td>
    </tr>
  `).join('');
}

function filterStrings() {
  const q = document.getElementById('strings-filter').value.toLowerCase();
  const filtered = stringsData.filter(s => (s.string || '').toLowerCase().includes(q));
  renderStrings(filtered);
}

// ─── Sections ────────────────────────────────────────────────────

function renderSections(sections) {
  const tbody = document.querySelector('#sections-table tbody');
  if (!sections || !Array.isArray(sections)) {
    tbody.innerHTML = '<tr><td colspan="4" class="loading">No sections</td></tr>';
    return;
  }

  tbody.innerHTML = sections.map(s => `
    <tr>
      <td>${s.name || '?'}</td>
      <td class="offset">0x${(s.vaddr || 0).toString(16)}</td>
      <td>${s.size || 0}</td>
      <td>${s.perm || '?'}</td>
    </tr>
  `).join('');
}

// ─── Security ────────────────────────────────────────────────────

async function loadSecurity() {
  if (!currentFile) return;

  try {
    const data = await api('/api/security');
    const el = document.getElementById('security-output');

    let html = '<h3 style="color:var(--accent);margin-bottom:8px">🛡️ Security Analysis</h3>';

    // Hashes
    if (data.hashes) {
      html += '<div style="margin-bottom:12px"><b>Hashes:</b><br>';
      for (const [k, v] of Object.entries(data.hashes)) {
        html += `<div class="row"><span class="key">${k}</span><span class="val" style="font-size:10px">${v}</span></div>`;
      }
      html += '</div>';
    }

    // Protections
    if (data.protections) {
      html += '<div style="margin-bottom:12px"><b>Protections:</b><br>';
      for (const [k, v] of Object.entries(data.protections)) {
        html += `<div class="row"><span class="key">${k}</span><span class="val">${v ? '✅' : '❌'}</span></div>`;
      }
      html += '</div>';
    }

    // Anti-debug
    if (data.anti_debug?.length) {
      html += `<div style="margin-bottom:12px"><b>Anti-Debug (${data.anti_debug.length}):</b><br>`;
      for (const ad of data.anti_debug.slice(0, 15)) {
        html += `<div class="row"><span class="key" style="color:var(--orange)">⚠</span><span class="val">${escHtml(ad.description)} @ ${ad.offset}</span></div>`;
      }
      html += '</div>';
    }

    // Crypto
    if (data.crypto?.length) {
      html += `<div><b>Crypto (${data.crypto.length}):</b><br>`;
      for (const c of data.crypto.slice(0, 15)) {
        html += `<div class="row"><span class="key" style="color:var(--cyan)">🔑</span><span class="val">${escHtml(c.description)} @ ${c.offset}</span></div>`;
      }
      html += '</div>';
    }

    el.innerHTML = html;
  } catch (e) {
    status('Security error: ' + e.message);
  }
}

// ─── Vulnerabilities ─────────────────────────────────────────────

async function loadVulns() {
  if (!currentFile) return;

  try {
    const data = await api('/api/vulns');
    const tbody = document.querySelector('#vulns-table tbody');

    if (!Array.isArray(data) || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="loading">No vulnerabilities found</td></tr>';
      return;
    }

    tbody.innerHTML = data.map(v => `
      <tr>
        <td class="severity-${v.severity || 'low'}">${(v.severity || '?').toUpperCase()}</td>
        <td>${v.type || '?'}</td>
        <td>${escHtml(v.description || '?')}</td>
        <td class="offset">${v.address || '?'}</td>
      </tr>
    `).join('');
  } catch (e) {
    status('Vulns error: ' + e.message);
  }
}

// ─── Patch ───────────────────────────────────────────────────────

async function applyPatch() {
  const offset = document.getElementById('patch-offset').value.trim();
  const hex = document.getElementById('patch-hex').value.trim();
  const statusEl = document.getElementById('patch-status');

  if (!offset || !hex) {
    statusEl.textContent = 'Fill in offset and hex data';
    statusEl.className = 'error';
    return;
  }

  try {
    const result = await api('/api/patch', {
      method: 'POST',
      body: JSON.stringify({
        offset: parseInt(offset, 16),
        hex: hex,
      }),
    });

    statusEl.textContent = '✅ Patch applied at ' + offset;
    statusEl.className = 'ok';
    status('Patch applied at ' + offset);
  } catch (e) {
    statusEl.textContent = '❌ Error: ' + e.message;
    statusEl.className = 'error';
  }
}

// ─── Terminal ────────────────────────────────────────────────────

async function execR2Cmd() {
  const input = document.getElementById('terminal-input');
  const cmd = input.value.trim();
  if (!cmd) return;

  const output = document.getElementById('terminal-output');
  output.innerHTML += `<span style="color:var(--green)">$ ${escHtml(cmd)}</span>\n`;

  try {
    const data = await api('/api/r2cmd', {
      method: 'POST',
      body: JSON.stringify({ command: cmd }),
    });
    output.textContent += data.output || '(no output)';
    output.textContent += '\n';
  } catch (e) {
    output.textContent += 'Error: ' + e.message + '\n';
  }

  output.scrollTop = output.scrollHeight;
  input.value = '';
}

// ─── Tab Switching ───────────────────────────────────────────────

function showTab(name) {
  // Hide all panels
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

  // Show selected
  const panel = document.getElementById('panel-' + name);
  if (panel) panel.classList.add('active');

  // Activate tab
  document.querySelectorAll('.tab').forEach(t => {
    if (t.textContent.toLowerCase().includes(name.substring(0, 4))) {
      t.classList.add('active');
    }
  });

  // Lazy load
  if (name === 'security' && currentFile) loadSecurity();
  if (name === 'vulns' && currentFile) loadVulns();
  if (name === 'hex' && currentFile) loadHex();
}

// ─── Utility ─────────────────────────────────────────────────────

function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Keyboard Shortcuts ──────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  // Ctrl+O: Open
  if (e.ctrlKey && e.key === 'o') { e.preventDefault(); openFile(); }
  // Ctrl+G: Analyze
  if (e.ctrlKey && e.key === 'g') { e.preventDefault(); runAnalysis(); }
  // Ctrl+D: Disasm
  if (e.ctrlKey && e.key === 'd') { e.preventDefault(); showTab('disasm'); }
  // Ctrl+H: Hex
  if (e.ctrlKey && e.key === 'h') { e.preventDefault(); showTab('hex'); }
  // Ctrl+T: Terminal
  if (e.ctrlKey && e.key === 't') { e.preventDefault(); showTab('terminal'); }
  // Escape: Close modal
  if (e.key === 'Escape') closeModal();
});

// ─── Init ────────────────────────────────────────────────────────

console.log('Panxcz Tools v1.0 — Reverse Engineering Platform');
