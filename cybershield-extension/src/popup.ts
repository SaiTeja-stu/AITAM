import { analyze, AuthError, getSettings, report } from './api';
import type { AnalyzeResponse, ContentType, PageContext } from './types';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const LEVEL_CLR: Record<string, string> = {
  MALICIOUS: '#F87171',
  HIGH_RISK: '#FB923C',
  SUSPICIOUS: '#FDE047',
  SAFE: '#34D399',
};
const SEV_CLR: Record<string, string> = {
  CRITICAL: '#F87171',
  HIGH: '#FB923C',
  MEDIUM: '#FDE047',
  LOW: '#93a0bc',
  TRUST: '#34D399',
};

let lastAnalyzed: { type: ContentType; content: string } | null = null;

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function pageContext(tabId: number): Promise<PageContext | null> {
  try {
    return await chrome.tabs.sendMessage(tabId, { kind: 'GET_PAGE_CONTEXT' });
  } catch {
    return null; // content script not present (chrome:// pages etc.)
  }
}

function show(id: string, on: boolean) {
  $(id).classList.toggle('hidden', !on);
}

function render(r: AnalyzeResponse) {
  show('loading', false);
  show('result', true);
  show('error', false);

  const clr = LEVEL_CLR[r.riskLevel] || '#93a0bc';
  const badge = $('badge');
  badge.textContent = `${r.priority} · ${r.riskLevel.replace('_', ' ')}`;
  badge.style.background = clr + '22';
  badge.style.color = clr;

  $('wording').textContent = `“${r.wording}”`;
  const score = $('score');
  score.textContent = String(r.riskScore);
  score.style.color = clr;
  $('meta').textContent = `confidence ${r.confidence}${r.initiatesPayment ? ' · initiates payment' : ''}`;

  if (r.payment) {
    show('paymentCard', true);
    $('paymentBody').textContent =
      `${r.payment.scheme} ${r.payment.action} → ${r.payment.payeeName ?? '—'} (${r.payment.payeeVpa ?? '—'})` +
      `\nAmount: ${r.payment.amount ?? 'not set'} ${r.payment.currency ?? ''}` +
      (r.payment.pullPayment ? '  · PULL request' : '');
  } else {
    show('paymentCard', false);
  }

  $('explanation').textContent = r.explanation;

  const sig = $('signals');
  sig.innerHTML = '';
  r.signals.forEach((s) => {
    const div = document.createElement('div');
    div.className = 'sig';
    div.innerHTML =
      `<div><span class="sev" style="color:${SEV_CLR[s.severity] || '#93a0bc'}">${s.severity}</span> ` +
      `<span class="name"></span></div><div class="detail"></div>`;
    (div.querySelector('.name') as HTMLElement).textContent = s.name;
    (div.querySelector('.detail') as HTMLElement).textContent = s.detail;
    sig.appendChild(div);
  });
  if (r.signals.length === 0) sig.textContent = 'No suspicious indicators found.';

  const recs = $('recs');
  recs.innerHTML = '';
  r.recommendations.forEach((t) => {
    const li = document.createElement('li');
    li.textContent = t;
    recs.appendChild(li);
  });

  show('report', true);
}

function renderError(e: unknown) {
  show('loading', false);
  show('result', false);
  if (e instanceof AuthError) {
    show('needLogin', true);
    return;
  }
  show('error', true);
  $('error').textContent = e instanceof Error ? e.message : 'Something went wrong.';
}

async function run() {
  show('needLogin', false);
  show('error', false);
  show('result', false);
  show('loading', true);

  const { token } = await getSettings();
  if (!token) {
    show('loading', false);
    show('needLogin', true);
    return;
  }

  const tab = await activeTab();
  if (!tab?.id || !tab.url || !/^https?:/.test(tab.url)) {
    renderError(new Error('This page cannot be checked (not a normal web page).'));
    return;
  }

  const ctx = await pageContext(tab.id);
  const selection = ctx?.selection?.trim() || '';
  show('scanSelection', selection.length > 0);

  const type: ContentType = 'WEBPAGE';
  const content = ctx?.html && ctx.html.length > 40 ? ctx.html : tab.url;
  lastAnalyzed = { type, content };

  try {
    const r = await analyze({ type, content, pageUrl: tab.url, source: 'popup' });
    render(r);
  } catch (e) {
    renderError(e);
  }
}

$('recheck').addEventListener('click', run);
$('toOptions').addEventListener('click', () => chrome.runtime.openOptionsPage());
$('dashboard').addEventListener('click', async () => {
  const { baseUrl } = await getSettings();
  chrome.tabs.create({ url: baseUrl.replace(/\/$/, '') + '/swagger-ui.html' });
});
$('scanSelection').addEventListener('click', async () => {
  const tab = await activeTab();
  if (!tab?.id) return;
  const ctx = await pageContext(tab.id);
  const sel = ctx?.selection?.trim();
  if (!sel) return;
  show('loading', true);
  show('result', false);
  lastAnalyzed = { type: 'SOCIAL', content: sel };
  try {
    render(await analyze({ type: 'SOCIAL', content: sel, source: 'popup-selection' }));
  } catch (e) {
    renderError(e);
  }
});
$('report').addEventListener('click', async () => {
  if (!lastAnalyzed) return;
  const btn = $('report') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Reporting…';
  try {
    await report(lastAnalyzed.type, lastAnalyzed.content, 'reported from extension');
    btn.textContent = 'Reported ✓';
  } catch {
    btn.textContent = 'Report failed';
    btn.disabled = false;
  }
});

run();
