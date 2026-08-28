# Cyber Shield — Backend (Detection API)

Intelligent phishing / scam / cyber-fraud detection engine for **HACKSPRINT 2.0 — Problem Statement #5**.
This is the shared "brain": the Chrome extension and the Android app are thin clients that
send content here and render the verdict.

Java 21 · Spring Boot 3 · SQLite (hot tier) · rotating gzipped JSONL (cold tier).

---

## What it does (maps to the problem statement)

| Requirement | Where |
|---|---|
| Analyse URLs, emails, SMS, QR codes, web pages, social-media messages | `POST /api/v1/analyze` (`type` = `URL\|EMAIL\|SMS\|QR\|WEBPAGE\|SOCIAL`) |
| Risk classification | 0–100 score → `SAFE / SUSPICIOUS / HIGH_RISK / MALICIOUS` → priority `P4..P1` |
| Suspicious-pattern detection | 25+ weighted policies in `engine/policies/**` (URL, web, text, QR, behavioural) |
| Explanation of why content is risky | `explanation` + per-signal `detail` list (transparency) |
| Safe-browsing recommendations | `recommendations[]` in every response |
| Threat reporting | `POST /api/v1/report` → admin confirm → community blocklist |
| Educational awareness modules | `GET /api/v1/education/modules` |
| QR: decode → validate → classify → extract UPI → analyse recipient → risk → explain | `qr/**` + `engine/policies/qr/**` |
| "Never claim 100% authorised" wording ladder | `RiskLevel` + `Verdict.wording()` — `verified` only set by an authoritative source |
| "Scan to receive money" warning | `ReceiveMoneyScamPolicy` + `ExplanationService` (always shown for any `upi://`) |

## Security controls (maps to the security spec)

| Principle | Implementation |
|---|---|
| Validate every input | Jakarta Bean Validation on all DTOs; strict JSON (`fail-on-unknown-properties`); enum whitelist; size caps; `UrlParts` / `UpiUri` defensive parsing |
| Sanitise server inputs | Parameterised JPA only; `PiiRedactor` strips PII + CRLF before logging/LLM; output encoded by clients |
| Limit login attempts | `LoginAttemptService` (per-username + per-IP lockout) + `RateLimitFilter` (Bucket4j) |
| Hash every password | `DelegatingPasswordEncoder` (bcrypt; Argon2-ready); hash never logged/returned |
| Hide auth details | Generic "Invalid username or password"; dummy-hash timing equalisation; generic register response; no stack traces (`server.error.include-*=never`); security headers |
| SSRF | `SafeFetchService` + `IpGuard`: scheme allowlist, resolve-then-validate every IP, pinned-IP connect (DNS-rebinding safe), manual redirect re-validation, alt-encoding normalisation, size/time caps |
| File upload | `ImageUploadValidator`: Tika magic-byte type check, allowlist, size ceiling, must decode as image, server-generated name |

## Two-tier storage

- **Hot** — SQLite (`data/cybershield.db`): last ~30 days of scans, users, reports. `HotTierPruneJob` deletes older rows nightly (they're already in the cold log).
- **Cold** — `data/archive/scans-*.jsonl.gz`: one JSON line per analysis, rotated by size+date and gzipped (`logback-spring.xml`). Immutable audit trail + ML dataset.

---

## Run it

```bash
cp .env.example .env          # then edit secrets
# export the vars (or use a tool like direnv / dotenv)
export CYBERSHIELD_JWT_SECRET=$(head -c 48 /dev/urandom | base64)
export CYBERSHIELD_HMAC_SECRET=$(head -c 48 /dev/urandom | base64)
export CYBERSHIELD_ADMIN_USER=admin
export CYBERSHIELD_ADMIN_PASSWORD='a-strong-password-min-12'

./gradlew bootRun
```

API base: `http://localhost:8080`  ·  Swagger UI: `http://localhost:8080/swagger-ui.html`

### Quick smoke test

```bash
# 1. log in
TOKEN=$(curl -s localhost:8080/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"a-strong-password-min-12"}' | jq -r .accessToken)

# 2. analyse a phishing SMS
curl -s localhost:8080/api/v1/analyze -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"type":"SMS","content":"URGENT: your SBI account is blocked. Verify KYC now: http://sbi-netbanking-update.in and share the OTP"}' | jq

# 3. analyse a UPI QR payload
curl -s localhost:8080/api/v1/analyze -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"type":"QR","content":"upi://collect?pa=random123@okhdfcbank&pn=Amazon%20Refund&am=4999&tn=refund"}' | jq
```

## Test

```bash
./gradlew test
```

Covers input validation, authentication (JWT tamper/expiry, lockout, enumeration parity, role access),
injection payloads (SQLi/XSS/path/CRLF/SSRF), SSRF IP guard, and file-upload rejection.

---

## Build / stack notes

- Dev uses Hibernate `ddl-auto=update` to own the schema. For production, switch to Flyway migrations.
- `SafeFetchService` outbound fetch is on by default; set `CYBERSHIELD_FETCH_ENABLED=false` to make the engine fully offline (URL analysis still runs on the string).
- Live threat feeds (Google Safe Browsing / PhishTank / URLhaus / OpenPhish) plug in behind `LocalIntelStore`; the seed lists in `resources/intel/` are for the demo.
- LLM explanations (Claude) can wrap `ExplanationService` later — the signal list is the stable contract.
