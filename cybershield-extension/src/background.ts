import { analyze, AuthError, getSettings } from './api';
import type { AnalyzeResponse, RiskLevel } from './types';

const BADGE: Record<RiskLevel, { text: string; color: string }> = {
  SAFE: { text: '', color: '#34D399' },
  SUSPICIOUS: { text: '!', color: '#FDE047' },
  HIGH_RISK: { text: '!!', color: '#FB923C' },
  MALICIOUS: { text: '✕', color: '#F87171' },
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scan-selection',
    title: 'Cyber Shield: check selected text',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'scan-link',
    title: 'Cyber Shield: check this link',
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

// Passive check: colour the toolbar badge for the loaded page.
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url || !/^https?:/.test(tab.url)) return;
  const { token } = await getSettings();
  if (!token) return;
  try {
    const r = await analyze({ type: 'URL', content: tab.url, source: 'auto' });
    const b = BADGE[r.riskLevel];
    chrome.action.setBadgeText({ tabId, text: b.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  } catch {
    /* stay quiet on background checks */
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
  chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon128.png', title: 'Cyber Shield', message: msg });
}
