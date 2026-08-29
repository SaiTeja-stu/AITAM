# 🛡️ CyberShield — Intelligent Cyber-Fraud & Phishing Defense Suite

[![Java](https://img.shields.io/badge/Java-21-orange.svg?style=flat&logo=openjdk)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.5-brightgreen.svg?style=flat&logo=springboot)](https://spring.io/projects/spring-boot)
[![Android](https://img.shields.io/badge/Android-SDK_26--34-3DDC84.svg?style=flat&logo=android)](https://developer.android.com)
[![Chrome Extension](https://img.shields.io/badge/Manifest_V3-TypeScript-blue.svg?style=flat&logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**CyberShield** is an end-to-end cyber-threat detection and defense ecosystem designed to proactively protect users against phishing URLs, malicious QR codes, fraudulent SMS/social messages, and UPI payment scams in real time.

---

## 📌 Ecosystem Overview

CyberShield operates as a unified multi-client defense architecture powered by a central intelligent analysis engine:

```
                               ┌────────────────────────────────────────┐
                               │       🛡️ CyberShield Backend           │
                               │  Spring Boot 3 • Java 21 • SQLite/Log  │
                               │   25+ Security Policies • ML Scoring   │
                               └──────────────────┬─────────────────────┘
                                                  │ (REST API / JWT)
             ┌────────────────────────────────────┼────────────────────────────────────┐
             ▼                                    ▼                                    ▼
┌───────────────────────────┐      ┌───────────────────────────┐      ┌───────────────────────────┐
│   📱 Android Mobile App   │      │ 🌐 Chrome Web Extension   │      │  📊 SOC & Web Dashboard   │
│ • CameraX & ML Kit QR     │      │ • Manifest V3 & TS        │      │ • Incident Telemetry      │
│ • SMS Phishing Classifier │      │ • Real-time URL Scanning  │      │ • Threat Verification     │
│ • UPI Interception Shield │      │ • Dynamic Risk Badges     │      │ • Community Feed Monitor  │
│ • Multilingual Modules    │      │ • Context Menu Analysis   │      │                           │
└───────────────────────────┘      └───────────────────────────┘      └───────────────────────────┘
```

---

## 🚀 Key Features

### 1. 🔍 Comprehensive Threat Analysis (`cybershield-backend`)
- **Multi-Vector Scanning**: Analyzes URLs, raw Webpages, SMS messages, Emails, QR codes, and Social Media text (`POST /api/v1/analyze`).
- **Graduated Risk Engine**: Computes risk scores (`0-100`) mapped to risk tiers: `SAFE`, `SUSPICIOUS`, `HIGH_RISK`, and `MALICIOUS` (Priorities `P4` to `P1`).
- **25+ Security Policies**: Deep inspection across typosquatting, IDN homoglyphs, brand impersonation, suspicious TLDs, urgent coercion keywords, unverified UPI VPAs, and malicious redirect chains.
- **Two-Tier Audit Storage**: Hot-tier SQLite database for active queries coupled with immutable, compressed JSONL cold-tier logs for forensic analysis and ML dataset generation.
- **Enterprise-Grade Defenses**: Built-in SSRF guards (IP allowlisting, DNS rebinding mitigation), rate limiting with Bucket4j, PII redaction, and Bcrypt/Argon2 credential protection.

### 2. 📱 Native Android Protection (`cybershield-android`)
- **Real-Time Payment Interception**: Custom `AccessibilityService` that monitors payment confirmation screens across major UPI applications, flags high-risk VPAs on-device, and displays an emergency warning overlay before PIN submission.
- **On-Device QR & SMS Scanner**: CameraX with Google ML Kit Barcode scanning and SMS broadcast receivers providing instant on-device verdicts even when offline.
- **Modern Glassmorphic UI**: Interactive custom `RiskDonutView`, biometric gate (`BiometricPrompt`), and risk breakdown screens.
- **Multilingual Cyber Safety Education**: Built-in interactive training modules available in **English**, **Hindi (हिंदी)**, and **Telugu (తెలుగు)**.

### 3. 🌐 Chrome Browser Extension (`cybershield-extension`)
- **Zero-Friction Browsing Protection**: Automatically inspects visited tabs in the background and sets visual toolbar badge indicators (`Green`, `!`, `!!`, `✕`).
- **Context Menu Inspection**: Right-click any highlighted text or link to immediately evaluate phishing risk without leaving the current tab.
- **Fast Local Execution**: Built with TypeScript and bundled with esbuild for sub-millisecond overhead.

---

## 📂 Project Structure

```
AITAM/
├── cybershield-backend/       # Core Spring Boot API & Fraud Analysis Engine
│   ├── src/main/java/         # Policies, Controllers, Services, Security
│   ├── src/main/resources/    # Configuration, ML models, Education catalogs
│   └── build.gradle           # Gradle dependencies & plugins
│
├── cybershield-android/       # Native Android Application (Java)
│   ├── app/src/main/java/     # UI, Shield Services, SMS Classifiers, Biometrics
│   ├── app/src/main/res/      # Layouts, Glassmorphic Drawables, Assets
│   └── app/build.gradle       # Android build configs (minSdk 26, targetSdk 34)
│
├── cybershield-extension/     # Chrome Extension (Manifest V3)
│   ├── src/                   # Background service workers, Popup UI, Content scripts
│   ├── public/                # Icons & Manifest definition
│   └── build.mjs              # esbuild packaging script
│
└── cybershield-dashboard/     # Web & Telemetry Dashboard
    ├── public/                # Static assets & logos
    └── src/                   # Frontend components
```

---

## ⚡ Getting Started

### Prerequisites
- **Java**: JDK 21+
- **Android**: Android Studio (Koala or newer) / Android SDK (API 26+)
- **Node.js**: v18+ & npm
- **Git**

---

### 1. Backend Setup

```bash
cd cybershield-backend

# Set necessary environment variables (or configure .env)
export CYBERSHIELD_JWT_SECRET="generate-a-secure-48-character-random-secret-key"
export CYBERSHIELD_HMAC_SECRET="generate-a-secure-48-character-random-secret-key"
export CYBERSHIELD_ADMIN_USER="admin"
export CYBERSHIELD_ADMIN_PASSWORD="YourSecureAdminPassword123"

# Run with Gradle wrapper
./gradlew bootRun
```
- **Base URL**: `http://localhost:8080`
- **Swagger Docs**: `http://localhost:8080/swagger-ui.html`

---

### 2. Android App Setup

1. Open `cybershield-android` in **Android Studio**.
2. Update the backend URL in `app/build.gradle` (or use `http://10.0.2.2:8080` for the Android Emulator).
3. Build and deploy to your connected device/emulator:
```bash
cd cybershield-android
./gradlew :app:assembleDebug
```

---

### 3. Chrome Extension Setup

```bash
cd cybershield-extension

# Install dependencies and build
npm install
npm run build
```
1. Open Chrome and navigate to `chrome://extensions`.
2. Toggle on **Developer mode** (top-right).
3. Click **Load unpacked** and select the `cybershield-extension/dist` folder.
4. Open the extension settings popup and configure your backend endpoint (`http://localhost:8080`).

---

## 📡 API Reference Overview

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/auth/login` | `POST` | Authenticate and obtain JWT Bearer Token |
| `/api/v1/analyze` | `POST` | Analyze payload (`URL`, `EMAIL`, `SMS`, `QR`, `WEBPAGE`, `SOCIAL`) |
| `/api/v1/report` | `POST` | Submit a threat/phishing incident report |
| `/api/v1/education/modules` | `GET` | Retrieve interactive cyber-safety modules |
| `/actuator/health` | `GET` | Service health status |

---

## 🔒 Privacy & Security Standards

- **Defensive PII Redaction**: Sensitive personal information (account numbers, names, plain text messages) is scrubbed locally before cloud scoring.
- **HMAC Anonymization**: Payment VPAs and phone numbers are matched against threat databases exclusively via salted HMAC hashes.
- **SSRF & DNS Rebinding Immunity**: All outbound URL lookups enforce socket pinning, internal IP range blocks, and strict schema validation.
- **Zero Third-Party Ad Trackers**: Completely free of third-party analytics, prioritizing user confidentiality.

---

## 👥 Authors & Acknowledgments

- Developed for **AITAM / HACKSPRINT 2.0**.
- Built with a focus on cyber safety, payment integrity, and accessible consumer awareness.
