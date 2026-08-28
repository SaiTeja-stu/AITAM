import type { AnalyzeRequest, AnalyzeResponse } from './types';

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
  const res = await fetch(baseUrl.replace(/\/$/, '') + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error('Invalid username or password.');
  const data = await res.json();
  await setSettings({ token: data.accessToken });
}

export async function logout(): Promise<void> {
  await setSettings({ token: '' });
}

export function analyze(payload: AnalyzeRequest): Promise<AnalyzeResponse> {
  return req<AnalyzeResponse>('POST', '/api/v1/analyze', payload);
}

export function report(type: string, content: string, note: string): Promise<unknown> {
  return req('POST', '/api/v1/report', { type, content, note });
}
