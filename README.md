# PhishCheck

A scam and phishing awareness tool. Paste a suspicious link or message and PhishCheck lists the warning signs it finds, explains why each one matters, and teaches you how to verify the message safely.

PhishCheck reports **risk indicators, not verdicts**. A low score does not prove something is safe, and a high score does not prove it is malicious.

## Features

- **URL Scanner**: lookalike brand names, embedded official domains, IP-address links, `user@host` tricks, Punycode, link shorteners, shared hosting platforms.
- **Message Analyzer**: credential and payment requests, urgency, delivery/fine fee scams, fake account-suspension threats, in English and Arabic. Links inside the message are scanned too.
- **Scan history** saved in your browser only (messages keep just a short preview).
- **PDF report** export and a **Learning Center**.
- **Optional** Google Web Risk lookup through the included backend.

## Privacy

Analysis runs in your browser. Links are never opened. If you enable the Web Risk backend, submitted URLs (not messages) are sent to your server and then to Google.

## Run locally

```bash
npm install
npm run dev
```

## Run the tests

```bash
npm test
```

## Enable Google Web Risk (optional)

1. Copy `backend/.env.example` to `backend/.env` and add your key.
2. Copy `.env.example` to `.env` (sets `VITE_API_URL`).
3. Start the backend: `cd backend && npm install && npm run dev`.
4. Start the frontend: `npm run dev`.

## Project structure

```
src/securityEngine.js   scoring rules for URLs and messages
src/webRisk.js          optional Web Risk client
src/App.jsx             interface
backend/server.js       Express API (Google Web Risk proxy, rate limited)
```
