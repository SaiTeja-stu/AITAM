# Cyber Shield — Chrome Extension

Category-A client for the [Cyber Shield backend](../cybershield-backend):
checks the current page, links, and selected text for phishing / scams.

**Manifest V3 · TypeScript · esbuild** (no framework).

## What it does

| Surface | Behaviour |
|---|---|
| **Toolbar popup** | On open, sends the current page (URL + capped HTML) to `POST /api/v1/analyze` as `WEBPAGE` and shows the verdict: risk level, score, signal list, explanation, recommendations, and payment details for UPI links. |
| **Toolbar badge** | On every page load the background worker scores the URL and colours the icon badge — green / `!` / `!!` / `✕`. |
| **Right-click → "check selected text"** | Analyses the selection as `SOCIAL`. |
| **Right-click → "check this link"** | Analyses the link URL as `URL`. |
| **Report** | One click sends the content to `POST /api/v1/report`. |
| **Options page** | Set the backend URL and sign in (JWT stored in `chrome.storage.local`). |

The page content leaves the browser only to your own backend (the URL you set),
sent with a Bearer token. Nothing is sent anywhere else.

## Build

```bash
npm install
npm run build      # -> dist/
```

`npm run watch` rebuilds on change.

## Load in Chrome

1. `npm run build`
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → pick the `dist/` folder.
3. Click the Cyber Shield icon → **Open settings to sign in** → enter your backend
   URL (default `http://localhost:8899`) and the backend admin credentials.
4. Open any site and click the icon.

The backend must be running and must allow the extension origin — its
`SecurityConfig` already permits `chrome-extension://*` in CORS.

## Files

```
src/
  api.ts         fetch wrapper, token + baseUrl in chrome.storage
  background.ts   context menus, badge colouring, notifications
  content.ts      extracts {url, html, selection, linkCount} on request
  popup.ts        popup verdict UI
  options.ts      settings + login
  types.ts        shared response/request types
public/
  manifest.json, popup.html, options.html, icons/
build.mjs         esbuild multi-entry bundle -> dist/
```
