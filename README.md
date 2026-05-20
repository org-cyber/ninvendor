# NIN Kiosk — Commercial

Multi-tenant NIN and BVN verification kiosk for cybercafés. BYOK (Bring Your Own Key) model.

## What It Does

- **NIN Verification** — Lookup National Identification Numbers, print digital slips
- **BVN Verification** — Lookup Bank Verification Numbers
- **Demo Mode** — Test layout without spending vendor credits
- **Multi-tenant** — Each cybercafé uses their own license key and API credentials
- **Zero PII Storage** — No personal data stored on server (names, NINs, BVNs stay in browser only)

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Node.js, Express |
| Database | Firebase Firestore (metadata only) |
| Frontend | Vanilla HTML/CSS/JS |
| Encryption | AES-256-GCM for API keys at rest |
| QR Codes | qrcodejs |

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env: add ENCRYPTION_SECRET (openssl rand -hex 32) and FIREBASE_KEY_PATH

# 3. Start server
npm start

# 4. Open http://localhost:8080


Onboarding a Cybercafé

# Generate license key
npm run tenant:create "Cafe Name" "080xxxxxxxxx" basic 6


Copy the printed license key. Send to café owner via WhatsApp.
Café owner then:

    Signs up at ninbvnportal.com.ng
    Funds wallet, copies API key
    Opens your kiosk URL, enters license key + API key
    Activates terminal

Project Structure


├── server.js              # Express backend
├── static/
│   ├── index.html         # Main kiosk UI
│   ├── history.html       # Local lookup history
│   ├── background.png     # Card background
│   └── Screenshot...png   # Reference image
├── scripts/
│   ├── create-tenant.js   # Generate license keys
│   └── rotate-keys.js     # Emergency key rotation
├── .env                   # Secrets (never commit)
├── .gitignore
└── package.json


| Collection | Purpose                           | Contains PII? |
| ---------- | --------------------------------- | ------------- |
| `tenants`  | Café accounts, encrypted API keys | No            |
| `usage`    | Lookup metadata, consent logs     | No            |

Security

    API keys encrypted with AES-256-GCM
    License keys hashed with SHA-256
    Firestore rules block all direct client access
    All PII flows directly from vendor → browser, never touches server

License
Internal use only.
