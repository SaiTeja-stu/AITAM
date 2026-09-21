import type { AnalyzeRequest, AnalyzeResponse } from './types';
import { localAnalyze } from './local';

const DEFAULT_BASE = 'http://localhost:8899';

interface Settings {
  baseUrl: string;
  token: string;
}

export async function getSettings(): Promise<Settings> {
  const s = await chrome.storage.local.get(['baseUrl', 'token']);
  return {
    baseUrl: (s.baseUrl as string) || DEFAULT_BASE,
    token: (s.token as string) || '',
  };
}

export async function setSettings(patch: Partial<Settings>): Promise<void> {
  await chrome.storage.local.set(patch);
}

export class AuthError extends Error {}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const { baseUrl, token } = await getSettings();
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Client': 'chrome-ext' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(baseUrl.replace(/\/$/, '') + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (res.status === 401) throw new AuthError('Not signed in — open the extension options to log in.');

  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const msg = (data && (data.detail || data.message)) || res.statusText;
    throw new Error(msg);
  }
  return data as T;
}

export async function login(username: string, password: string): Promise<void> {
  const { baseUrl } = await getSettings();
  let res: Response;
  try {
    res = await fetch(baseUrl.replace(/\/$/, '') + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ login: username, password }),
    });
  } catch {
    throw new Error('Cannot reach ' + baseUrl + '. Check the URL. On the Render free plan the first request can take about a minute to wake the server; try again.');
  }
  if (!res.ok) throw new Error(res.status === 401 || res.status === 400 ? 'Invalid username or password.' : 'Server error (' + res.status + '). Try again.');
  const data = await res.json();
  await setSettings({ token: data.accessToken });
}

export async function logout(): Promise<void> {
  await setSettings({ token: '' });
}

/**
 * Always runs the offline checks (piracy / betting / crack sites, lookalike domains ...) and, when
 * signed in and reachable, merges them with the server verdict, keeping whichever is riskier.
 */
export async function analyze(payload: AnalyzeRequest): Promise<AnalyzeResponse> {
  const local = localAnalyze(payload);
  const { token } = await getSettings();
  if (!token) return local;
  let server: AnalyzeResponse;
  try {
    server = await req<AnalyzeResponse>('POST', '/api/v1/analyze', payload);
  } catch {
    return local; // backend down / signed out
  }
  if (local.riskScore <= server.riskScore) return server;
  const seen = new Set(server.signals.map((s) => s.policyId));
  return {
    ...server,
    riskScore: local.riskScore,
    riskLevel: local.riskLevel,
    priority: local.priority,
    wording: local.wording,
    confidence: Math.max(server.confidence, local.confidence),
    signals: [...server.signals, ...local.signals.filter((s) => !seen.has(s.policyId))],
    explanation: local.explanation.replace('  (offline check — backend not connected)', ''),
    recommendations: [...new Set([...local.recommendations, ...server.recommendations])],
  };
}

export function report(type: string, content: string, note: string): Promise<unknown> {
  return req('POST', '/api/v1/report', { type, content, note });
}
