// Thin fetch wrapper. In dev, Vite proxies /api and /auth to the backend.
// In production (served by Spring Boot) they are same-origin.

const TOKEN_KEY = 'cybershield.token';

export function getToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}
export function setToken(t) {
  try { t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }

  if (!res.ok) {
    const detail = (data && (data.detail || data.message)) || res.statusText;
    const err = new Error(detail);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const api = {
  login: (login, password) => request('POST', '/auth/login', { login, password }),
  register: (email, username, displayName, password) =>
    request('POST', '/auth/register', { email, username, displayName, password }),
  verifyEmail: (email, code) => request('POST', '/auth/verify-email', { email, code }),
  forgotPassword: (email) => request('POST', '/auth/forgot-password', { email }),
  resetPassword: (email, code, newPassword) =>
    request('POST', '/auth/reset-password', { email, code, newPassword }),
  analyze: (payload) => request('POST', '/api/v1/analyze', payload),
  report: (payload) => request('POST', '/api/v1/report', payload),
  stats: () => request('GET', '/api/v1/stats'),
  trends: () => request('GET', '/api/v1/stats/trends'),
  recentScans: (params = '') => request('GET', `/api/v1/admin/scans${params}`),
  reports: (status) => request('GET', `/api/v1/admin/reports${status ? `?status=${status}` : ''}`),
  confirmReport: (id) => request('POST', `/api/v1/admin/reports/${id}/confirm`),
  rejectReport: (id) => request('POST', `/api/v1/admin/reports/${id}/reject`),
  education: () => request('GET', '/api/v1/education/modules'),
};
