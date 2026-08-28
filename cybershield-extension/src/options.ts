import { getSettings, login, logout, setSettings } from './api';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function setStatus(msg: string, ok: boolean) {
  const el = $('status');
  el.textContent = msg;
  el.className = 'status ' + (ok ? 'ok' : 'err');
}

async function refresh() {
  const s = await getSettings();
  ($('baseUrl') as HTMLInputElement).value = s.baseUrl;
  setStatus(s.token ? 'Signed in.' : 'Not signed in.', !!s.token);
}

$('saveUrl').addEventListener('click', async () => {
  const url = ($('baseUrl') as HTMLInputElement).value.trim();
  if (!/^https?:\/\//.test(url)) {
    setStatus('URL must start with http:// or https://', false);
    return;
  }
  await setSettings({ baseUrl: url });
  setStatus('Backend URL saved.', true);
});

$('login').addEventListener('click', async () => {
  const username = ($('username') as HTMLInputElement).value.trim();
  const password = ($('password') as HTMLInputElement).value;
  if (!username || !password) {
    setStatus('Enter a username and password.', false);
    return;
  }
  try {
    await login(username, password);
    ($('password') as HTMLInputElement).value = '';
    setStatus('Signed in.', true);
  } catch (e) {
    setStatus(e instanceof Error ? e.message : 'Sign-in failed.', false);
  }
});

$('logout').addEventListener('click', async () => {
  await logout();
  setStatus('Signed out.', true);
});

refresh();
