import { analyze, AuthError } from './api';
import type { AnalyzeResponse, BgMessage, PageContext, PageVerdict, RiskLevel } from './types';

const BADGE: Record<RiskLevel, { text: string; color: string }> = {
  SAFE: { text: '', color: '#34D399' },
  SUSPICIOUS: { text: '!', color: '#FDE047' },
  HIGH_RISK: { text: '!!', color: '#FB923C' },
  MALICIOUS: { text: '✕', color: '#F87171' },
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scan-selection',
    title: 'Secure Me: check selected text',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'scan-link',
    title: 'Secure Me: check this link',
    contexts: ['link'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  try {
    if (info.menuItemId === 'scan-selection' && info.selectionText) {
      notify(await analyze({ type: 'SOCIAL', content: info.selectionText, source: 'context-menu' }), 'Selected text');
    } else if (info.menuItemId === 'scan-link' && info.linkUrl) {
      notify(await analyze({ type: 'URL', content: info.linkUrl, source: 'context-menu' }), info.linkUrl);
    }
  } catch (e) {
    notifyError(e);
  }
});

// ---- override password (parental-control style) ----
const enc = new TextEncoder();
let failedTries = 0;
let lockedUntil = 0;

function toB64(buf: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf as ArrayBuffer)));
}
function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function derive(password: string, salt: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations: 150_000 }, key, 256);
  return toB64(bits);
}
async function hasOverride(): Promise<boolean> {
  const { override } = await chrome.storage.local.get('override');
  return !!override;
}
async function setOverride(password: string): Promise<boolean> {
  if (password.length < 4) return false;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  await chrome.storage.local.set({ override: { salt: toB64(salt), hash: await derive(password, salt) } });
  return true;
}
async function verifyOverride(password: string): Promise<{ ok: boolean; wait?: number }> {
  const now = Date.now();
  if (now < lockedUntil) return { ok: false, wait: Math.ceil((lockedUntil - now) / 1000) };
  const { override } = await chrome.storage.local.get('override');
  if (!override) return { ok: false };
  const ok = (await derive(password, fromB64(override.salt))) === override.hash;
  if (ok) {
    failedTries = 0;
    return { ok: true };
  }
  if (++failedTries >= 5) {
    failedTries = 0;
    lockedUntil = now + 60_000;
  }
  return { ok: false };
}

// ---- automatic page check: pages report themselves when they load ----
async function checkPage(ctx: PageContext, tabId: number | undefined): Promise<PageVerdict> {
  const r = await analyze(
    ctx.html.length > 40
      ? { type: 'WEBPAGE', content: ctx.html, pageUrl: ctx.url, source: 'auto' }
      : { type: 'URL', content: ctx.url, source: 'auto' },
  );
  if (tabId !== undefined) {
    const badge = BADGE[r.riskLevel];
    chrome.action.setBadgeText({ tabId, text: badge.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  }
  const reasons = r.signals.filter((s) => s.weight > 0).map((s) => `${s.name}: ${s.detail}`).slice(0, 4);
  return { level: r.riskLevel, score: r.riskScore, reasons };
}

chrome.runtime.onMessage.addListener((msg: BgMessage, sender, sendResponse) => {
  (async () => {
    switch (msg.kind) {
      case 'PAGE_LOADED':
        if (!/^https?:/.test(msg.ctx.url)) return sendResponse(null);
        return sendResponse(await checkPage(msg.ctx, sender.tab?.id));
      case 'HAS_OVERRIDE':
        return sendResponse({ set: await hasOverride() });
      case 'SET_OVERRIDE':
        return sendResponse({ ok: await setOverride(msg.password) });
      case 'VERIFY_OVERRIDE':
        return sendResponse(await verifyOverride(msg.password));
    }
  })().catch(() => sendResponse(null));
  return true; // async response
});

// After installing / reloading the extension, put the content script into tabs that are already open.
chrome.runtime.onInstalled.addListener(async () => {
  const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
  for (const t of tabs) {
    if (t.id === undefined) continue;
    try {
      await chrome.scripting.executeScript({ target: { tabId: t.id }, files: ['content.js'] });
    } catch {
      /* restricted page (Chrome Web Store, etc.) */
    }
  }
});

function notify(r: AnalyzeResponse, subject: string): void {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: `${r.priority} · ${r.riskLevel.replace('_', ' ')} (${r.riskScore}/100)`,
    message: `${subject}\n\n${r.explanation}`.slice(0, 400),
    priority: r.riskLevel === 'MALICIOUS' ? 2 : 1,
  });
}

function notifyError(e: unknown): void {
  const msg = e instanceof AuthError ? e.message : e instanceof Error ? e.message : 'Check failed';
  chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon128.png', title: 'Secure Me', message: msg });
}
