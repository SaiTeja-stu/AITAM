import type { AnalyzeRequest, AnalyzeResponse, RiskLevel, Signal } from './types';

/**
 * Offline analyzer: lets the extension work with no backend running.
 * A compact port of the main URL / text heuristics. When the backend is reachable
 * (and signed in) its verdict is used instead.
 */

const BRANDS: Record<string, string[]> = {
  paypal: ['paypal.com'],
  google: ['google.com', 'google.co.in', 'gmail.com', 'youtube.com'],
  amazon: ['amazon.com', 'amazon.in'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
  apple: ['apple.com', 'icloud.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  netflix: ['netflix.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
  hdfcbank: ['hdfcbank.com'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  icicibank: ['icicibank.com'],
  axisbank: ['axisbank.com'],
  kotak: ['kotak.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  irctc: ['irctc.co.in'],
  uidai: ['uidai.gov.in'],
  incometax: ['incometax.gov.in'],
};

const TRUSTED = new Set(Object.values(BRANDS).flat().concat(['wikipedia.org', 'github.com', 'linkedin.com', 'twitter.com', 'x.com']));
const BAD_TLDS = new Set(['cc', 'vip', 'bet', 'casino', 'win', 'pw', 'sbs', 'cfd', 'bid', 'loan', 'gdn', 'xyz', 'top', 'click', 'zip', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'rest', 'cyou', 'buzz', 'work', 'support', 'country']);
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at']);
const SLD_LIKE = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'nic', 'edu']);

const SCAM_TEXT = [
  'you have won', 'lottery', 'lucky draw', 'claim your prize', 'kyc will be blocked', 'account will be suspended',
  'update your pan', 'click here to verify', 'urgent action', 'work from home', 'earn daily', 'loan approved',
  'part time job', 'install this app', 'digital arrest', 'scan to receive', 'refund',
];
const PIRACY_HOST = /(movierulz|tamilrockers|tamilmv|tamilyogi|isaimini|filmyzilla|filmywap|filmyhit|filmy4|9xmovies|9xflix|moviesflix|vegamovies|hdhub4u|bolly4u|khatrimaza|mkvcinemas|worldfree4u|7starhd|jiorockers|ibomma|kuttymovies|1337x|thepiratebay|piratebay|fmovies|soap2day|123movies|putlocker|tamilblasters|movies4u|moviesda|klwap|desiremovies|mp4moviez|cinevood|skymovieshd)/i;
const PIRACY_TEXT = ['480p', '720p', '1080p', '300mb', 'dual audio', 'web-dl', 'webrip', 'hdrip', 'camrip', 'hdcam', 'bluray', 'torrent', 'magnet:', 'hindi dubbed', 'free download', 'download bollywood'];
const GAMBLING_TEXT = ['real cash', 'betting', 'satta', 'teen patti', 'online casino', 'rummy', 'jackpot', 'deposit bonus', 'ipl betting'];
const CRACK_TEXT = ['crack', 'keygen', 'serial key', 'full version free', 'activator', 'patch'];

const PIRACY_NAME = /^(movies?|films?|filmy|bolly|holly|tamil|telugu|hindi|kannada|malayalam|mkv|hd|cine|cinema)[a-z0-9-]*(4u|wap|zilla|rulz|hub|flix|mad|world|mkv|hd|junction|blasters|rockers|verse|zone|point|base|4k|hit|bazaar|mp4)[a-z0-9]*$/i;

function countHits(t: string, words: string[]): number {
  return words.filter((w) => t.includes(w)).length;
}

const OTP_THEFT = ['share the otp', 'send the otp', 'share your pin', 'give your otp', 'share otp with', 'tell the otp'];

function lev(a: string, b: string): number {
  const dp: number[] = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length];
}

function registeredDomain(host: string): string {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const n = parts.length;
  const take = parts[n - 1].length === 2 && SLD_LIKE.has(parts[n - 2]) ? 3 : 2;
  return parts.slice(-take).join('.');
}

function sig(policyId: string, name: string, detail: string, severity: Signal['severity'], weight: number): Signal {
  return { policyId, name, detail, severity, weight };
}

function urlSignals(raw: string, html: string): Signal[] {
  const out: Signal[] = [];
  let u: URL;
  try {
    u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : 'http://' + raw);
  } catch {
    return out;
  }
  const host = u.hostname.toLowerCase();
  const reg = registeredDomain(host);
  const sld = reg.split('.')[0];
  const tld = host.split('.').pop() ?? '';

  if (TRUSTED.has(reg)) {
    out.push(sig('L-TRUST', 'Known legitimate domain', `${reg} is a well-known official domain.`, 'TRUST', -30));
    return out;
  }
  if (u.protocol === 'http:') out.push(sig('L-HTTP', 'No HTTPS', 'The page is not encrypted.', 'MEDIUM', 15));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) out.push(sig('L-IP', 'IP address host', 'Legitimate sites rarely use a raw IP.', 'HIGH', 30));
  if (host.includes('xn--')) out.push(sig('L-PUNY', 'Punycode / lookalike characters', 'Possible homoglyph domain.', 'HIGH', 30));
  if (raw.includes('@') && /^[a-z]+:\/\/[^/]*@/i.test(raw)) out.push(sig('L-AT', '@ in URL', 'Hides the real destination.', 'HIGH', 25));
  if (BAD_TLDS.has(tld)) out.push(sig('L-TLD', 'Risky top-level domain', `.${tld} is heavily abused for phishing.`, 'MEDIUM', 20));
  if (SHORTENERS.has(reg)) out.push(sig('L-SHORT', 'URL shortener', 'The real destination is hidden.', 'MEDIUM', 15));
  if (host.split('.').length >= 5) out.push(sig('L-SUBS', 'Many subdomains', host, 'LOW', 10));
  if ((sld.match(/-/g) || []).length >= 3) out.push(sig('L-HYPH', 'Many hyphens in domain', sld, 'LOW', 10));
  if (/[a-z]{3,}\d{2,}$/.test(sld)) out.push(sig('L-NUM', 'Brand name ending in numbers', `${sld} - throwaway-style name common on betting, piracy and scam sites.`, 'LOW', 10));
  if (/(login|verify|update|secure|kyc|account|wallet)/.test(u.pathname.toLowerCase() + host)) {
    out.push(sig('L-KEY', 'Credential / verification wording', 'Common in phishing pages.', 'LOW', 8));
  }

  for (const [brand, reals] of Object.entries(BRANDS)) {
    if (reals.includes(reg)) continue;
    if (host.includes(brand)) {
      out.push(sig('L-BRAND', 'Brand impersonation', `Uses "${brand}" but is not ${reals[0]}.`, 'HIGH', 40));
      break;
    }
    if (sld.length >= 5 && lev(sld, brand) === 1) {
      out.push(sig('L-TYPO', 'Typosquatting', `"${sld}" is one character away from "${brand}".`, 'HIGH', 40));
      break;
    }
  }

  if (PIRACY_HOST.test(host) || PIRACY_NAME.test(sld)) {
    out.push(sig('L-PIRACY', 'Piracy / illegal streaming site', 'Illegal under the Copyright Act. These sites are full of malicious ads, fake download buttons and drive-by installs.', 'HIGH', 50));
  }
  if (html) {
    const low = html.toLowerCase();
    if (!(PIRACY_HOST.test(host) || PIRACY_NAME.test(sld)) && countHits(low, PIRACY_TEXT) >= 3) {
      out.push(sig('L-PIRACY', 'Looks like a pirated-movie site', 'Pirated releases (480p / 720p / dual audio / web-dl) are typically bundled with malware and scam ads.', 'HIGH', 50));
    }
    if (countHits(low, GAMBLING_TEXT) >= 2) {
      out.push(sig('L-GAMBLE', 'Betting / gambling content', 'Real-money betting sites are a common front for payment fraud and are banned in many states.', 'MEDIUM', 30));
    }
    if (countHits(low, CRACK_TEXT) >= 3) {
      out.push(sig('L-CRACK', 'Cracked software / keygen site', 'Cracks and keygens very often carry malware and stealers.', 'HIGH', 45));
    }
    const hasPwd = /<input[^>]+type=["']?password/i.test(html);
    if (hasPwd && u.protocol === 'http:') out.push(sig('L-PWD', 'Password field without HTTPS', 'Credentials would be sent unencrypted.', 'HIGH', 25));
    for (const m of html.matchAll(/<form[^>]+action=["'](https?:\/\/[^"']+)["']/gi)) {
      try {
        if (hasPwd && registeredDomain(new URL(m[1]).hostname) !== reg) {
          out.push(sig('L-FORM', 'Login form posts to another site', new URL(m[1]).hostname, 'HIGH', 30));
          break;
        }
      } catch {
        /* ignore malformed action */
      }
    }
  }
  return out;
}

function textSignals(text: string): Signal[] {
  const t = text.toLowerCase();
  const out: Signal[] = [];
  if (OTP_THEFT.some((w) => t.includes(w))) out.push(sig('L-OTP', 'Asks you to share an OTP / PIN', 'Banks never ask for this.', 'CRITICAL', 60));
  const hits = SCAM_TEXT.filter((w) => t.includes(w));
  if (hits.length) out.push(sig('L-SCAM', 'Scam wording', hits.slice(0, 3).join(', '), 'HIGH', Math.min(50, 25 * hits.length)));
  for (const m of text.matchAll(/https?:\/\/[^\s)"']+/gi)) {
    const s = urlSignals(m[0], '').filter((x) => x.severity !== 'TRUST');
    out.push(...s);
  }
  return out;
}

export function localAnalyze(req: AnalyzeRequest): AnalyzeResponse {
  const isText = req.type === 'SOCIAL' || req.type === 'SMS' || req.type === 'EMAIL';
  const signals = isText
    ? textSignals(req.content)
    : urlSignals(req.type === 'WEBPAGE' && req.pageUrl ? req.pageUrl : req.content, req.type === 'WEBPAGE' ? req.content : '');

  const score = Math.max(0, Math.min(100, signals.reduce((a, s) => a + s.weight, 0)));
  const level: RiskLevel = score >= 75 ? 'MALICIOUS' : score >= 50 ? 'HIGH_RISK' : score >= 25 ? 'SUSPICIOUS' : 'SAFE';
  const priority = { MALICIOUS: 'P1', HIGH_RISK: 'P2', SUSPICIOUS: 'P3', SAFE: 'P4' }[level];
  const risky = signals.filter((s) => s.weight > 0);
  const explanation = risky.length
    ? risky.map((s) => `${s.name}: ${s.detail}`).join('  •  ')
    : 'No suspicious indicators found by the offline checks.';
  return {
    reportId: 'local-' + Date.now(),
    contentType: req.type,
    riskScore: score,
    riskLevel: level,
    priority,
    wording: { SAFE: 'Looks safe', SUSPICIOUS: 'Be careful', HIGH_RISK: 'Likely phishing', MALICIOUS: 'Dangerous — do not proceed' }[level],
    confidence: risky.length ? 0.7 : 0.5,
    verified: false,
    trusted: signals.some((s) => s.severity === 'TRUST'),
    initiatesPayment: false,
    categories: [],
    signals,
    explanation: explanation + '  (offline check — backend not connected)',
    recommendations: level === 'SAFE'
      ? ['Stay alert for unexpected requests for money or codes.']
      : ['Do not enter passwords, OTP or card details.', 'Verify the site by typing the official address yourself.', 'Report it if you received it by SMS or email.'],
    payment: null,
    analyzedAt: new Date().toISOString(),
  };
}
