# Cyber Shield — Detection Dashboard

React + Vite + Tailwind admin console for the [Cyber Shield backend](../cybershield-backend).

## Pages

| Route | What |
|---|---|
| `/` Overview | totals, risk mix, per-type, volume/day + top signals & categories (from the cold JSONL archive) |
| `/queue` Priority queue | recent analyses across all users, filterable by P1–P4, score ring + signals |
| `/analyze` Analyze console | run any content through `/api/v1/analyze` and inspect the full verdict, signal waterfall, payment details |
| `/reports` Reports | moderate community threat reports — **Confirm** pushes the indicator to the live blocklist |
| `/education` Education | the awareness modules served to the app/extension |

## Run (dev)

```bash
npm install
npm run dev
```

Opens `http://localhost:5173`. Vite proxies `/api` and `/auth` to the backend at
`http://localhost:8899` (override with `VITE_BACKEND`). Log in with the backend's
`CYBERSHIELD_ADMIN_USER` / `CYBERSHIELD_ADMIN_PASSWORD`.

The backend must be running first:

```bash
cd ../cybershield-backend
.\run.ps1
```

## Build (production)

```bash
npm run build          # -> dist/
```

Serve `dist/` behind the backend or any static host. When served same-origin as
the API no proxy/CORS config is needed. The backend already permits
`GET /`, `/assets/**`, `/index.html` for this.

## Auth

JWT from `/auth/login` is kept in `sessionStorage` and sent as `Authorization: Bearer`.
Token TTL is 15 min server-side; on expiry the dashboard drops back to the login screen.
