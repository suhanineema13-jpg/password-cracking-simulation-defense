/* ═══════════════════════════════════════════════════════
   Password Cracking Simulation & Defense  —  app.js
   SHA-256 via Web Crypto API
   Open with VS Code Live Server (right-click index.html)
   ═══════════════════════════════════════════════════════ */
'use strict';

/* ─── State ─────────────────────────────────────────── */
const DB = [];
let bRun = false, bTimer = null;
let dRun = false, dTimer = null;
let bTgt = null,  dTgt  = null;
let defAtt = {}, defLock = {};

/* ─── Character sets ─────────────────────────────────── */
const CHARSETS = {
  lower:    'abcdefghijklmnopqrstuvwxyz',
  lowernum: 'abcdefghijklmnopqrstuvwxyz0123456789',
  alnum:    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  full:     'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
};

/* ─── Dictionary wordlist ────────────────────────────── */
const DICT = [
  'sun','abc7','pass','hi','cat','dog','god','hot','red','yes',
  'no','ok','love','hate','war','sky','sea','key','box','fox',
  'test','root','user','boot','dark','star','fire','wind','rain',
  'ice','snow','fast','slow','big','top','new','old','run','jump',
  'stop','go','tag','bat','pad','map','web','net','bit','pin','zip'
].filter(w => w.length <= 5);

/* ─── Defense config ─────────────────────────────────── */
const DEFENSE_CONFIG = [
  { id: 'lockout',   label: 'Account lockout',   desc: 'Lock after 3 failed attempts', on: true },
  { id: 'ratelimit', label: 'Rate limiting',      desc: 'Slow repeated requests',       on: true },
  { id: 'hashing',   label: 'SHA-256 + salt',    desc: 'Show hash comparison on login',on: true },
  { id: 'monitor',   label: 'Anomaly detection',  desc: 'Alert on repeated failures',   on: true },
];
const DS = {};
DEFENSE_CONFIG.forEach(d => DS[d.id] = d.on);

/* ═══════════════ CRYPTO HELPERS ═══════════════════════ */

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

function randSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map(b => b.toString(16).padStart(2,'0')).join('');
}

/* ═══════════════ STRENGTH ══════════════════════════════ */

function calcStrength(pw) {
  let s = 0;
  if (pw.length >= 3) s++;
  if (pw.length >= 5) s++;
  if (/[a-z]/.test(pw)) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s += 2;
  return Math.min(6, s);
}

function strengthMeta(score) {
  if (score <= 2) return { label: 'Weak',   color: '#dc2626', badge: 'b-weak'   };
  if (score <= 4) return { label: 'Medium', color: '#d97706', badge: 'b-medium' };
  return              { label: 'Strong', color: '#16a34a', badge: 'b-strong' };
}

function liveStr() {
  const pw = document.getElementById('reg-pass').value;
  const sc = calcStrength(pw);
  const m  = strengthMeta(sc);
  const fill = document.getElementById('reg-sf');
  fill.style.width      = Math.round((sc / 6) * 100) + '%';
  fill.style.background = m.color;
  document.getElementById('reg-sl').textContent = pw
    ? `Strength: ${m.label} — ${pw.length}/5 chars`
    : 'Enter a password (1–5 characters)';
}

/* ═══════════════ REGISTER ══════════════════════════════ */

function qf(user, pw) {
  document.getElementById('reg-user').value = user;
  document.getElementById('reg-pass').value = pw;
  liveStr();
}

async function registerUser() {
  const username = document.getElementById('reg-user').value.trim();
  const password = document.getElementById('reg-pass').value;
  const msgEl    = document.getElementById('reg-msg');

  if (!username || !password) {
    return setMsg(msgEl, 'Please fill in both username and password.', false);
  }
  if (password.length > 5) {
    return setMsg(msgEl, 'Password must be 5 characters or fewer.', false);
  }
  if (DB.find(u => u.username === username)) {
    return setMsg(msgEl, `Username "${username}" already exists.`, false);
  }

  const salt     = randSalt();
  const hash     = await sha256(password + salt);
  const strength = calcStrength(password);
  DB.push({ username, password, salt, hash, strength, created: new Date().toLocaleTimeString() });
  setMsg(msgEl, `"${username}" registered! SHA-256 hash stored in database.`, true);

  document.getElementById('reg-user').value    = '';
  document.getElementById('reg-pass').value    = '';
  document.getElementById('reg-sf').style.width = '0%';
  document.getElementById('reg-sl').textContent = 'Enter a password (1–5 characters)';
  refreshAll();
}

function setMsg(el, text, ok) {
  el.style.color  = ok ? '#16a34a' : '#dc2626';
  el.textContent  = text;
}

/* ═══════════════ DATABASE ══════════════════════════════ */

function refreshDB() {
  const el = document.getElementById('db-view');
  if (!DB.length) {
    el.innerHTML = `<div class="empty-db"><div class="icon">&#128274;</div>No users registered yet.</div>`;
    return;
  }
  el.innerHTML = `<div class="db-table-wrap"><table class="db-tbl">
    <thead><tr>
      <th>#</th><th>Username</th><th>Password</th><th>Salt (hex)</th>
      <th>SHA-256 hash (salted)</th><th>Strength</th><th>Registered</th>
    </tr></thead><tbody>
    ${DB.map((u, i) => {
      const m = strengthMeta(u.strength);
      return `<tr>
        <td>${i + 1}</td>
        <td><strong>${u.username}</strong></td>
        <td class="pass-cell">${u.password}</td>
        <td class="salt-cell">${u.salt}</td>
        <td class="hash-cell">${u.hash}</td>
        <td><span class="badge ${m.badge}">${m.label}</span></td>
        <td class="time-cell">${u.created}</td>
      </tr>`;
    }).join('')}
    </tbody></table></div>`;
}

/* ═══════════════ SHARED HELPERS ════════════════════════ */

function refreshAll() {
  refreshDB();
  refreshBruteTargets();
  refreshDictTargets();
  refreshDefUsers();
}

function makeTargetBtns(containerId, selectedVarName, onClickFnName) {
  const el = document.getElementById(containerId);
  if (!DB.length) {
    el.innerHTML = `<span class="no-users">No users yet — register some first.</span>`;
    return;
  }
  el.innerHTML = DB.map(u => `
    <button class="target-btn ${window[selectedVarName] === u.username ? 'sel' : ''}"
            onclick="${onClickFnName}('${u.username}')">
      ${u.username}
    </button>`).join('');
}

function refreshBruteTargets() { makeTargetBtns('brute-targets', 'bTgt', 'selectBruteTgt'); }
function refreshDictTargets()  { makeTargetBtns('dict-targets',  'dTgt', 'selectDictTgt');  }

function selectBruteTgt(username) {
  bTgt = username;
  refreshBruteTargets();
  const user = DB.find(u => u.username === username);
  const hint = document.getElementById('brute-hint');
  hint.style.display = 'block';
  hint.textContent   = `Target: ${username}  |  Password length: ${user.password.length} char(s)  |  Hash: ${user.hash.slice(0, 24)}…`;
  clearLog('ba-log', 'li', `[*] Target set to "${username}" — hash loaded.`);
}

function selectDictTgt(username) {
  dTgt = username;
  refreshDictTargets();
  renderChips();
  const user = DB.find(u => u.username === username);
  const hint = document.getElementById('dict-hint');
  hint.style.display = 'block';
  hint.textContent   = `Target: ${username}  |  Hash: ${user.hash.slice(0, 24)}…`;
  clearLog('da-log', 'li', `[*] Target set to "${username}" — attack will compare SHA-256 hashes.`);
}

function clearLog(id, cls, msg) {
  document.getElementById(id).innerHTML = `<span class="${cls}">${msg}</span>`;
}

function addLog(id, msg, cls) {
  const el = document.getElementById(id);
  const d  = document.createElement('div');
  d.className   = cls || '';
  d.textContent = msg;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}

function renderChips() {
  document.getElementById('da-size').textContent  = DICT.length;
  document.getElementById('dict-chips').innerHTML =
    DICT.map(w => `<span class="chip" id="chip-${w}">${w}</span>`).join('');
}

/* ═══════════════ TAB SWITCHING ═════════════════════════ */

function switchTab(name, btn) {
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
  if (name === 'database') refreshDB();
  if (name === 'brute')    refreshBruteTargets();
  if (name === 'dict')     { renderChips(); refreshDictTargets(); }
  if (name === 'login')    { renderDefGrid(); refreshDefUsers(); }
}

/* ═══════════════ BRUTE FORCE ═══════════════════════════ */

function* bruteGen(charset, maxLen) {
  for (let len = 1; len <= maxLen; len++) {
    const idx = new Array(len).fill(0);
    while (true) {
      yield idx.map(i => charset[i]).join('');
      let pos = len - 1;
      while (pos >= 0) {
        idx[pos]++;
        if (idx[pos] < charset.length) break;
        idx[pos] = 0;
        pos--;
      }
      if (pos < 0) break;
    }
  }
}

function startBrute() {
  if (bRun) return;
  if (!bTgt) { addLog('ba-log', '[!] Select a target user first.', 'lw'); return; }

  const user    = DB.find(u => u.username === bTgt);
  const charset = CHARSETS[document.getElementById('brute-cs').value];
  const maxLen  = user.password.length;
  const total   = Math.pow(charset.length, maxLen);

  clearLog('ba-log', 'li', `[*] Brute force attack on "${user.username}"`);
  addLog('ba-log', `[*] Salt:    ${user.salt}`, 'lm');
  addLog('ba-log', `[*] Hash:    ${user.hash}`, 'lm');
  addLog('ba-log', `[*] Charset: ${charset.length} chars  |  Max length: ${maxLen}  |  Keyspace: ${total.toLocaleString()}`, 'li');

  document.getElementById('ba-banner').classList.remove('show');
  ['ba-att','ba-time'].forEach(id => document.getElementById(id).textContent = '0');
  document.getElementById('ba-cur').textContent = '—';
  document.getElementById('ba-spd').textContent = '—';
  document.getElementById('ba-bar').style.width = '0%';

  const gen   = bruteGen(charset, maxLen);
  let   count = 0;
  const t0    = Date.now();
  const salt  = user.salt;
  const tHash = user.hash;
  bRun = true;

  async function runBatch() {
    if (!bRun) return;
    const guesses = [];
    for (let i = 0; i < 300; i++) {
      const r = gen.next();
      if (r.done) { finishBrute(false, '', 0, t0, user, tHash); return; }
      guesses.push(r.value);
    }
    const hashes = await Promise.all(guesses.map(g => sha256(g + salt)));
    for (let i = 0; i < guesses.length; i++) {
      count++;
      if (hashes[i] === tHash) { finishBrute(true, guesses[i], count, t0, user, tHash); return; }
    }
    const elapsed = (Date.now() - t0) / 1000;
    const speed   = Math.round(count / Math.max(0.01, elapsed));
    document.getElementById('ba-att').textContent  = count.toLocaleString();
    document.getElementById('ba-cur').textContent  = guesses[guesses.length - 1];
    document.getElementById('ba-spd').textContent  = speed.toLocaleString() + '/s';
    document.getElementById('ba-time').textContent = elapsed.toFixed(1) + 's';
    document.getElementById('ba-bar').style.width  = Math.min(99, (count / total) * 100).toFixed(1) + '%';
    if (count % 3000 === 0)
      addLog('ba-log', `[~] ${count.toLocaleString()} hashes computed… last: "${guesses[guesses.length - 1]}"`, 'lf');
    bTimer = setTimeout(runBatch, 0);
  }

  function finishBrute(found, guess, att, t0, u, tHash) {
    bRun = false;
    const el = ((Date.now() - t0) / 1000).toFixed(2);
    const bn = document.getElementById('ba-banner');
    if (found) {
      document.getElementById('ba-bar').style.width  = '100%';
      document.getElementById('ba-att').textContent  = att.toLocaleString();
      document.getElementById('ba-time').textContent = el + 's';
      addLog('ba-log', `[!!!] PASSWORD CRACKED — "${guess}" found after ${att.toLocaleString()} hashes in ${el}s`, 'ls');
      addLog('ba-log', `[*]  SHA-256("${guess}" + "${u.salt}") = ${tHash}`, 'lm');
      bn.textContent = `Cracked "${u.username}" — password: "${guess}"  |  ${att.toLocaleString()} hashes in ${el}s`;
      bn.className   = 'banner show b-crack';
    } else {
      addLog('ba-log', '[x] Password not found. Try a wider charset.', 'lw');
      bn.textContent = 'Not found. Try a wider charset.';
      bn.className   = 'banner show b-safe';
    }
  }

  runBatch();
}

function stopBrute() {
  bRun = false;
  clearTimeout(bTimer);
  addLog('ba-log', '[!] Attack stopped by user.', 'lw');
}

/* ═══════════════ DICTIONARY ATTACK ════════════════════ */

function startDict() {
  if (dRun) return;
  if (!dTgt) { addLog('da-log', '[!] Select a target user first.', 'lw'); return; }

  const user  = DB.find(u => u.username === dTgt);
  renderChips();
  clearLog('da-log', 'li', `[*] Dictionary attack on "${user.username}"`);
  addLog('da-log', `[*] Salt:  ${user.salt}`, 'lm');
  addLog('da-log', `[*] Hash:  ${user.hash}`, 'lm');
  addLog('da-log', `[*] Wordlist size: ${DICT.length}`, 'li');

  document.getElementById('da-banner').classList.remove('show');
  document.getElementById('da-att').textContent = '0';
  document.getElementById('da-cur').textContent = '—';
  document.getElementById('da-bar').style.width = '0%';

  dRun = true;
  let idx     = 0;
  const salt  = user.salt;
  const tHash = user.hash;

  async function step() {
    if (!dRun || idx >= DICT.length) {
      if (idx >= DICT.length && dRun) {
        dRun = false;
        addLog('da-log', '[x] Password not found in dictionary.', 'lw');
        const bn = document.getElementById('da-banner');
        bn.textContent = 'Not found in dictionary — relatively safe from this attack.';
        bn.className   = 'banner show b-safe';
      }
      return;
    }
    const word  = DICT[idx];
    const hash  = await sha256(word + salt);
    const match = (hash === tHash);

    document.getElementById('da-att').textContent = idx + 1;
    document.getElementById('da-cur').textContent = word;
    document.getElementById('da-bar').style.width = (((idx + 1) / DICT.length) * 100).toFixed(0) + '%';

    const chip = document.getElementById('chip-' + word);
    if (chip) chip.className = 'chip ' + (match ? 'found' : 'tried');

    addLog('da-log', `[~] "${word}"  →  ${hash.slice(0, 18)}…  ${match ? 'MATCH!' : 'no match'}`, match ? 'ls' : 'lf');

    if (match) {
      dRun = false;
      addLog('da-log', `[!!!] PASSWORD CRACKED — "${word}" at position ${idx + 1}!`, 'ls');
      addLog('da-log', `[*]  SHA-256("${word}" + "${salt}") = ${hash}`, 'lm');
      document.getElementById('da-bar').style.width = '100%';
      const bn = document.getElementById('da-banner');
      bn.textContent = `Cracked "${user.username}" — password: "${word}" (position ${idx + 1})`;
      bn.className   = 'banner show b-crack';
      return;
    }
    idx++;
    dTimer = setTimeout(step, 60);
  }

  step();
}

function stopDict() {
  dRun = false;
  clearTimeout(dTimer);
  addLog('da-log', '[!] Attack stopped by user.', 'lw');
}

/* ═══════════════ LOGIN / DEFENSE ═══════════════════════ */

function renderDefGrid() {
  document.getElementById('def-grid').innerHTML = DEFENSE_CONFIG.map(d => `
    <div class="def-item ${DS[d.id] ? 'on' : 'off'}">
      <div>
        <div class="def-label">${d.label}</div>
        <div class="def-desc">${d.desc}</div>
      </div>
      <div class="toggle ${DS[d.id] ? 'on' : ''}" onclick="toggleDef('${d.id}')"></div>
    </div>`).join('');
}

function toggleDef(id) {
  DS[id] = !DS[id];
  renderDefGrid();
  addLog('def-log', `[*] ${id} ${DS[id] ? 'ENABLED' : 'DISABLED'}`, 'li');
}

function refreshDefUsers() {
  const sel  = document.getElementById('def-usel');
  const prev = sel.value;
  sel.innerHTML = DB.map(u => `<option value="${u.username}">${u.username}</option>`).join('');
  if (prev && DB.find(u => u.username === prev)) sel.value = prev;
}

async function defLogin() {
  const username = document.getElementById('def-usel').value;
  const password = document.getElementById('def-pass').value;
  const user     = DB.find(u => u.username === username);

  if (!user)  { addLog('def-log', '[!] No users in database. Register first.', 'lw'); return; }
  if (!defAtt[username]) defAtt[username] = 0;

  if (defLock[username] && DS.lockout) {
    addLog('def-log', `[LOCKED] "${username}" is locked out. Click "Reset lockouts".`, 'lw');
    return;
  }

  const guessHash = await sha256(password + user.salt);

  if (DS.hashing) {
    addLog('def-log', `[SHA-256] SHA-256("${password}" + "${user.salt}")`, 'lm');
    addLog('def-log', `  computed : ${guessHash}`, 'lm');
    addLog('def-log', `  stored   : ${user.hash}`, 'lm');
    addLog('def-log', `  match    : ${guessHash === user.hash ? 'YES ✓' : 'NO ✗'}`, guessHash === user.hash ? 'ls' : 'lf');
  }

  if (guessHash === user.hash) {
    defAtt[username] = 0;
    addLog('def-log', `[SUCCESS] Login successful for "${username}"!`, 'ls');
  } else {
    defAtt[username]++;
    addLog('def-log', `[FAIL] Wrong password for "${username}" (attempt ${defAtt[username]})`, 'lf');
    if (DS.lockout && defAtt[username] >= 3) {
      defLock[username] = true;
      addLog('def-log', `[LOCKOUT] "${username}" locked after 3 failed attempts.`, 'lw');
    }
    if (DS.ratelimit && defAtt[username] >= 2)
      addLog('def-log', '[RATE LIMIT] Throttling active — too many failed requests.', 'lw');
    if (DS.monitor && defAtt[username] >= 2)
      addLog('def-log', '[ALERT] Anomaly detected — repeated login failures flagged.', 'lw');
  }
}

function defReset() {
  defAtt = {}; defLock = {};
  addLog('def-log', '[*] All accounts unlocked and attempt counters reset.', 'li');
}

/* ═══════════════ INIT ══════════════════════════════════ */
renderDefGrid();
renderChips();
