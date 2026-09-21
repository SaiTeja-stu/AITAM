import type { CsMessage, PageContext, PageVerdict, RiskLevel } from './types';

const MAX_HTML = 60_000;

function pageContext(): PageContext {
  const selection = (window.getSelection()?.toString() || '').trim();
  let html = '';
  try {
    html = document.documentElement.outerHTML.slice(0, MAX_HTML);
  } catch {
    html = '';
  }
  return {
    url: location.href,
    title: document.title,
    html,
    selection,
    linkCount: document.querySelectorAll('a[href]').length,
  };
}

const HOST_KEY = 'cybershield-allow:' + location.hostname;
const ALLOW_MS = 30 * 60 * 1000;

function allowed(): boolean {
  try {
    const t = Number(sessionStorage.getItem(HOST_KEY) || 0);
    return t > Date.now();
  } catch {
    return false;
  }
}

function allowNow(): void {
  try {
    sessionStorage.setItem(HOST_KEY, String(Date.now() + ALLOW_MS));
  } catch {
    /* ignore */
  }
}

const send = <T>(msg: unknown): Promise<T | null> =>
  new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (res) => resolve(chrome.runtime.lastError ? null : (res as T)));
    } catch {
      resolve(null);
    }
  });

function showWarning(level: RiskLevel, score: number, reasons: string[]): void {
  if (allowed() || document.getElementById('cybershield-warning')) return;
  const severe = level === 'HIGH_RISK' || level === 'MALICIOUS';
  const host = document.createElement('div');
  host.id = 'cybershield-warning';
  host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;';
  const root = host.attachShadow({ mode: 'open' });
  const color = severe ? '#F87171' : '#FDE047';
  const label = level.replace('_', ' ');
  const layout = severe
    ? 'inset:0;display:flex;align-items:center;justify-content:center;background:rgba(8,12,26,.97)'
    : 'top:0;left:0;right:0;background:#1e2540;border-bottom:3px solid ' + color;
  root.innerHTML = `
    <style>
      *{box-sizing:border-box;font-family:system-ui,Segoe UI,Arial,sans-serif}
      .wrap{pointer-events:auto;position:fixed;${layout}}
      .card{max-width:560px;margin:16px;padding:28px;border-radius:16px;background:#0f1530;border:2px solid ${color};color:#e8ecf8}
      .bar{padding:10px 16px;color:#e8ecf8;display:flex;gap:12px;align-items:center;justify-content:space-between;font-size:14px;width:100%}
      h1{margin:0 0 6px;font-size:24px;color:${color}}
      .score{font-size:14px;opacity:.8;margin-bottom:14px}
      ul{padding-left:20px;margin:0 0 20px;line-height:1.5;font-size:14px}
      button{cursor:pointer;border:0;border-radius:10px;padding:11px 18px;font-size:15px;font-weight:600;margin:0 10px 8px 0}
      .safe{background:#34D399;color:#062}
      .go{background:transparent;color:#aab3d0;border:1px solid #445}
      .unlock{background:#FB923C;color:#221}
      #gate{display:none;margin-top:12px;padding-top:14px;border-top:1px solid #334}
      #gate p{margin:0 0 10px;font-size:14px;line-height:1.4}
      input{width:100%;padding:10px;margin:0 0 8px;border-radius:8px;border:1px solid #445;background:#0a0f24;color:#e8ecf8;font-size:15px}
      #msg{color:#F87171;font-size:13px;min-height:18px;margin-bottom:6px}
    </style>
    <div class="wrap">
      ${
        severe
          ? `<div class="card"><h1>\u26A0 Secure Me blocked this page</h1><div class="score">${label} \u00B7 risk ${score}/100</div><ul id="why"></ul>
             <button class="safe" id="back">Take me back to safety</button><button class="go" id="go">I still want to continue</button>
             <div id="gate"><p id="gatetext"></p><input id="pw" type="password" autocomplete="off" placeholder="Password" /><input id="pw2" type="password" autocomplete="off" placeholder="Repeat password" style="display:none" /><div id="msg"></div><button class="unlock" id="unlock">Unlock this site</button></div></div>`
          : `<div class="bar"><span><b style="color:${color}">Caution (${label}, ${score}/100):</b> <span id="why"></span></span><button class="go" id="go">Dismiss</button></div>`
      }
    </div>`;
  const $ = (id: string) => root.getElementById(id) as HTMLElement;
  const why = $('why');
  if (severe) {
    reasons.forEach((r) => {
      const li = document.createElement('li');
      li.textContent = r;
      why.appendChild(li);
    });
  } else {
    why.textContent = reasons[0] ?? 'This page looks suspicious.';
  }
  const prevOverflow = document.documentElement.style.overflow;
  if (severe) document.documentElement.style.overflow = 'hidden';
  const close = () => {
    allowNow();
    document.documentElement.style.overflow = prevOverflow;
    host.remove();
  };

  if (!severe) {
    $('go').addEventListener('click', close);
  } else {
    let creating = false;
    $('back').addEventListener('click', () => {
      if (history.length > 1) history.back();
      else location.href = 'about:blank';
    });
    $('go').addEventListener('click', async () => {
      const res = await send<{ set: boolean }>({ kind: 'HAS_OVERRIDE' });
      creating = !res?.set;
      $('gatetext').textContent = creating
        ? 'To continue to a blocked site you need an override password. Create one now (you will be asked for it each time).'
        : 'Enter your Secure Me password to continue to this blocked site.';
      ($('pw2') as HTMLElement).style.display = creating ? 'block' : 'none';
      $('gate').style.display = 'block';
      ($('pw') as HTMLInputElement).focus();
    });
    $('unlock').addEventListener('click', async () => {
      const pw = ($('pw') as HTMLInputElement).value;
      const msg = $('msg');
      msg.textContent = '';
      if (creating) {
        if (pw.length < 4) return void (msg.textContent = 'Use at least 4 characters.');
        if (pw !== ($('pw2') as HTMLInputElement).value) return void (msg.textContent = 'Passwords do not match.');
        const r = await send<{ ok: boolean }>({ kind: 'SET_OVERRIDE', password: pw });
        if (r?.ok) close();
        else msg.textContent = 'Could not save the password.';
      } else {
        const r = await send<{ ok: boolean; wait?: number }>({ kind: 'VERIFY_OVERRIDE', password: pw });
        if (r?.ok) close();
        else msg.textContent = r?.wait ? `Too many attempts. Try again in ${r.wait}s.` : 'Wrong password.';
      }
    });
  }
  document.documentElement.appendChild(host);
}

chrome.runtime.onMessage.addListener((msg: CsMessage, _sender, sendResponse) => {
  if (msg.kind === 'GET_PAGE_CONTEXT') {
    sendResponse(pageContext());
  } else if (msg.kind === 'GET_SELECTION') {
    sendResponse({ selection: (window.getSelection()?.toString() || '').trim() });
  }
  return true;
});

// Automatic check: every top-level page reports itself as it loads; risky ones are warned or blocked.
async function autoScan(): Promise<void> {
  if (window !== window.top || !/^https?:$/.test(location.protocol) || allowed()) return;
  const v = await send<PageVerdict>({ kind: 'PAGE_LOADED', ctx: pageContext() });
  if (v && v.score >= 25) showWarning(v.level, v.score, v.reasons);
}
void autoScan();
