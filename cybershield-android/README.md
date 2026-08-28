# Cyber Shield — Android app (Java)

Category-B client for the [Cyber Shield backend](../cybershield-backend): SMS,
social-media messages, QR codes, and a system-wide fraud-interception layer.

Pure Java · minSdk 26 · targetSdk 34 · Retrofit · Room · CameraX + ML Kit.

## What it does

| Feature | How |
|---|---|
| **Scan a QR code** | `ScanQrActivity` — CameraX preview + **ML Kit barcode** decode (on-device). Payload → verdict screen. |
| **Check a message / link** | Paste in `MainActivity`, or **share text into the app** from any app (`ShareReceiverActivity`, `ACTION_SEND`). |
| **Scan incoming SMS** | `SmsReceiver` runs the on-device check on arrival; posts a high-priority notification if it looks like a scam. |
| **Verdict screen** | `VerdictActivity` shows the on-device result instantly, then replaces it with the authoritative server verdict. Works offline. |
| **History** | `HistoryActivity` — last 200 checks from Room. Stores only a redacted snippet. |
| **System-wide protection** | `FraudAccessibilityService` + `OverlayService` — see below. |

## The interception layer (opt-in)

`FraudAccessibilityService` is scoped — in `res/xml/accessibility_service_config.xml`
it is bound **only** to a fixed list of UPI / bank package names. For those apps:

1. On a payment-confirmation screen it walks the accessibility node tree and
   extracts **only** the payee VPA and amount (`PaymentScreenParser`).
2. The risk decision runs **on-device** (`LocalFraudEngine` + the synced
   blocklist). Nothing from the screen is uploaded.
3. On a blocking verdict it presses **BACK** (to leave before the PIN pad) and
   shows a full-screen warning (`OverlayService`, `SYSTEM_ALERT_WINDOW`).
   In *warn-only* mode it shows the overlay without pressing BACK.

Limitations (documented for the report):
- `FLAG_SECURE` screens (bank PIN pads) can't be read or covered — the shield
  acts on the confirmation screen *before* them.
- Payment-app UI redesigns can break the parser; per-app rules should be pushed
  from the server.
- Guaranteed blocking = "scan inside Cyber Shield". The accessibility layer is a
  best-effort safety net.
- Google Play restricts AccessibilityService use — distribute as a signed APK /
  via Android Enterprise, or apply for the exception.

## Privacy posture

- On-device first: verdicts come from the local engine; the server is called
  only for confirmation, and message/QR content is PII-redacted (`Redact`) first.
- VPAs and phone numbers are stored/matched **only as HMAC hashes** (`Hashing` —
  keep the secret in sync with the backend's `cybershield.hmac-secret`).
- No analytics SDKs. The accessibility service reads nothing outside payment
  screens of the whitelisted apps.
- Every capability is toggleable (`ShieldPrefs`, system settings).

## Build & run

Requires Android Studio (Koala+) or the command-line SDK.

```bash
# point the app at your backend (emulator: 10.0.2.2 = host machine)
# edit app/build.gradle -> defaultConfig.buildConfigField API_BASE_URL

./gradlew :app:assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk

# install on a connected device / emulator
./gradlew :app:installDebug
```

`local.properties` (SDK path) is generated automatically by Android Studio;
a copy is included for this machine.

### First-run setup in the app

1. Grant camera + notification permissions (normal prompts).
2. **Settings → System-wide protection** walks through the special-access ones:
   SMS, "display over other apps", and enabling the accessibility service.
   On Android 13+ you may first need to allow *Restricted settings* from the
   app's App-info screen.

## Auth

The hackathon build logs in with the shared demo account (`ApiModule`,
`DEMO_USER`/`DEMO_PASS`) and caches the JWT. A production build would register
each device and use a device-scoped API key instead.
