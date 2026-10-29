/* ════════════════════════════════════
   PhishGuard — Frontend Logic
   ════════════════════════════════════ */
'use strict';
// ── DOM refs ──
const urlInput       = document.getElementById('url-input');
const scanBtn        = document.getElementById('scan-btn');
const btnText        = scanBtn.querySelector('.btn-text');
const btnArrow       = scanBtn.querySelector('.btn-arrow');
const btnLoader      = scanBtn.querySelector('.btn-loader');
const resultsSection = document.getElementById('results-section');
// ── Allow Enter key ──
urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') scanURL();
});
// ── Paste-and-clean ──
urlInput.addEventListener('paste', () => {
  setTimeout(() => {
    urlInput.value = urlInput.value.trim();
  }, 0);
});
// ── Set example URL ──
function setExample(url) {
  urlInput.value = url;
  urlInput.focus();
  scanURL();
}
// ── Loading state ──
function setLoading(loading) {
  scanBtn.disabled = loading;
  btnText.classList.toggle('hidden', loading);
  btnArrow.classList.toggle('hidden', loading);
  btnLoader.classList.toggle('hidden', !loading);
}
// ── Main scan function ──
async function scanURL() {
  const raw = urlInput.value.trim();
  if (!raw) {
    shake(urlInput);
    return;
  }
  setLoading(true);
  resultsSection.classList.add('hidden');
  try {
    const response = await fetch('/api/check', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: raw })
    });
    if (!response.ok) throw new Error(`Server error ${response.status}`);
    const data = await response.json();
    if (data.error) {
      showToast(data.error, 'danger');
      return;
    }
    renderResults(data);
  } catch (err) {
    console.error(err);
    showToast('Unable to reach the server. Is Flask running?', 'danger');
  } finally {
    setLoading(false);
  }
}
// ── Render results ──
function renderResults(data) {
  const { score, risk_level, verdict, findings, stats, url, has_https } = data;
  /* Verdict banner */
  const banner = document.getElementById('verdict-banner');
  banner.className = `verdict-banner risk-${risk_level}`;
  const iconMap = {
    safe:   { emoji: '✅', bg: 'rgba(34,197,94,0.15)', color: '#22c55e' },
    low:    { emoji: '⚠️', bg: 'rgba(245,158,11,0.15)', color: '#f59e0b' },
    medium: { emoji: '🚨', bg: 'rgba(249,115,22,0.15)', color: '#fb923c' },
    high:   { emoji: '☠️', bg: 'rgba(239,68,68,0.15)', color: '#ef4444' }
  };
  const iconInfo = iconMap[risk_level] || iconMap.medium;
  const verdictIcon = document.getElementById('verdict-icon');
  verdictIcon.textContent = iconInfo.emoji;
  verdictIcon.style.background = iconInfo.bg;
  verdictIcon.style.fontSize   = '2rem';
  document.getElementById('verdict-label').textContent = verdict;
  document.getElementById('verdict-label').style.color = iconInfo.color;
  document.getElementById('verdict-url').textContent   = url;
  /* Risk meter */
  const fillColorMap = {
    safe:   'linear-gradient(90deg,#22c55e,#16a34a)',
    low:    'linear-gradient(90deg,#f59e0b,#d97706)',
    medium: 'linear-gradient(90deg,#fb923c,#ea580c)',
    high:   'linear-gradient(90deg,#ef4444,#b91c1c)'
  };
  const fill = document.getElementById('risk-fill');
  fill.style.background = fillColorMap[risk_level];
  // Animate fill after small delay
  setTimeout(() => {
    fill.style.width = Math.min(score, 100) + '%';
  }, 100);
  document.getElementById('risk-score-text').textContent = `${score}/100`;
  document.getElementById('risk-score-text').style.color = iconInfo.color;
  /* Stats */
  document.getElementById('stat-length-val').textContent     = stats.url_length;
  document.getElementById('stat-entropy-val').textContent    = stats.entropy;
  document.getElementById('stat-subdomains-val').textContent = stats.subdomain_count;
  document.getElementById('stat-keywords-val').textContent   = stats.keyword_hits;
  colorStat('stat-length',    stats.url_length > 150 ? 'danger' : stats.url_length > 75 ? 'warn' : 'safe');
  colorStat('stat-entropy',   stats.entropy > 3.8 ? 'warn' : 'safe');
  colorStat('stat-subdomains',stats.subdomain_count >= 3 ? 'danger' : stats.subdomain_count >= 2 ? 'warn' : 'safe');
  colorStat('stat-keywords',  stats.keyword_hits >= 3 ? 'danger' : stats.keyword_hits >= 1 ? 'warn' : 'safe');
  /* Findings */
  const list = document.getElementById('findings-list');
  list.innerHTML = '';
  findings.forEach((f, i) => {
    const li = document.createElement('li');
    li.className = `finding-item type-${f.type}`;
    li.style.animationDelay = `${i * 0.06}s`;
    const badgeMap = { safe: '✓', warning: '!', danger: '✕' };
    li.innerHTML = `
      <div class="finding-badge">${badgeMap[f.type] || '?'}</div>
      <div class="finding-msg">${escapeHTML(f.message)}</div>
    `;
    list.appendChild(li);
  });
  document.getElementById('findings-count').textContent = `${findings.length} checks`;
  /* Recommendation */
  const rec = document.getElementById('recommendation');
  const recMap = {
    safe:   { cls: 'rec-safe',   msg: '✅ This URL appears legitimate. Always stay vigilant—double-check the domain before entering sensitive information.' },
    low:    { cls: 'rec-low',    msg: '⚠️ Exercise caution. Some suspicious signals were detected. Do not enter passwords or payment details unless you are absolutely certain this is legitimate.' },
    medium: { cls: 'rec-medium', msg: '🚨 This URL shows multiple phishing indicators. We strongly recommend NOT proceeding. Report it to your IT/security team.' },
    high:   { cls: 'rec-high',   msg: '☠️ HIGH DANGER — Do NOT open this URL. This is very likely a phishing attempt designed to steal your credentials or install malware. Close this link immediately.' }
  };
  const recInfo = recMap[risk_level];
  rec.className   = `recommendation ${recInfo.cls}`;
  rec.textContent = recInfo.msg;
  /* Show section */
  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function colorStat(id, level) {
  const el = document.getElementById(id);
  const valEl = el.querySelector('.stat-value');
  const colorMap = { safe: '#22c55e', warn: '#f59e0b', danger: '#ef4444' };
  valEl.style.color = colorMap[level] || '#f0f0ff';
}
// ── Shake animation ──
function shake(el) {
  el.animate([
    { transform: 'translateX(0)' },
    { transform: 'translateX(-8px)' },
    { transform: 'translateX(8px)' },
    { transform: 'translateX(-4px)' },
    { transform: 'translateX(0)' }
  ], { duration: 400, easing: 'ease' });
}
// ── Toast notifications ──
function showToast(message, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  Object.assign(toast.style, {
    position:     'fixed',
    bottom:       '30px',
    left:         '50%',
    transform:    'translateX(-50%) translateY(30px)',
    background:   type === 'danger' ? 'rgba(239,68,68,0.15)' : 'rgba(99,102,241,0.15)',
    border:       `1px solid ${type === 'danger' ? 'rgba(239,68,68,0.4)' : 'rgba(99,102,241,0.4)'}`,
    color:        type === 'danger' ? '#f87171' : '#a5b4fc',
    padding:      '12px 24px',
    borderRadius: '100px',
    fontSize:     '0.85rem',
    fontWeight:   '500',
    zIndex:       '9999',
    backdropFilter: 'blur(20px)',
    transition:   'transform 0.3s ease, opacity 0.3s ease',
    fontFamily:   'Inter, sans-serif'
  });
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.transform = 'translateX(-50%) translateY(0)';
    toast.style.opacity   = '1';
  }, 10);
  setTimeout(() => {
    toast.style.transform = 'translateX(-50%) translateY(30px)';
    toast.style.opacity   = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
// ── HTML escape ──
function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}