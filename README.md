# PhishCheck

A scam and phishing awareness tool. Paste a suspicious link or message and PhishCheck lists the warning signs it finds, explains why each one matters, and teaches you how to verify the message safely.

PhishCheck reports **risk indicators, not verdicts**. A low score does not prove something is safe, and a high score does not prove it is malicious.

## How detection works

PhishCheck combines two layers.

1. **Local warning-sign checks** (always on, in your browser): lookalike brand names, official domains hidden inside fake ones, IP-address links, `user@host` tricks, Punycode, link shorteners, free-hosting pages with scam-style names, and for messages: credential and payment requests, urgency, delivery/fine fee scams, account-suspension threats (English and Arabic). Links inside messages are scanned too.
2. **Online threat lists** (optional, through the backend). Submitted links are checked against the services you configure:

| Source | Covers | Cost and terms |
| --- | --- | --- |
| Google Safe Browsing | phishing, malware, unwanted software | Free, **non-commercial use only** |
| Google Web Risk | same lists as Safe Browsing | Commercial. First 100,000 lookups per month free, billing account required |
| URLhaus (abuse.ch) | malware distribution links | Free key, fair use / non-commercial |
| OpenPhish community feed | phishing links | Free, **non-commercial only**, updated every 12 hours, partial coverage |

If you start selling anything built on PhishCheck, switch to Web Risk and turn the non-commercial sources off.

### How well does it work?

Run `npm run evaluate` to test the local checks against the current OpenPhish feed, which is replaced with new links every day. Results when this version was built (136 legitimate sites in the comparison list):

- On 300 links the rules were tuned against, local checks flagged about **48%**. On completely new links they had never seen, they flagged about **37% to 39%** (two separate days). The second number is the more honest one. Before the improvements in this version the figure was about 4%.
- **0** of the 136 legitimate sites and **0** of 23 ordinary messages were wrongly flagged.
- The links that slip through are mostly randomly named pages on free hosting and hacked websites, which look ordinary. Only the online lists can catch many of these, and only once they have been reported.
- Brand-new scam pages are often not listed anywhere yet. **No result from PhishCheck guarantees a link is safe.**

These numbers come from small samples taken on one day, so treat them as a rough guide, not a promise.

## Learning Center

- **English and Arabic.** A switch at the top of the section changes the quiz, checklist and incident guides to Arabic and flips the layout to right-to-left. The Arabic text was written by an AI assistant and should be reviewed by a native speaker before you rely on it. The Message Analyzer also understands common Arabic scam wording.
- **Can you spot the scam?** A quiz with 14 realistic scenarios (fake delivery fees, bank calls, job offers, boss-impersonation emails, QR stickers). Each round has 8 questions and always includes genuine messages, so people do not learn to distrust everything. Every answer explains the warning signs and what to do, and has a button to test the same message in the analyzer. The quiz stores nothing.
- **How to verify a message safely:** a 7-step checklist.
- **I already clicked or shared something:** step-by-step advice for five situations (clicked a link, entered a password, shared card details or a code, installed an app, sent money).

## Team training

Managers create a team, share a team code or link with staff, and see **totals only**: how many finished the quiz, the average score, and the most missed topics. There are no staff accounts. Staff choose whether to send their score after each round. Only the score, the language and the missed topics are stored. Never names, emails, phone numbers or message text. Details appear only after 3 quizzes, so nobody's own score can be worked out. A manager can delete the team and all its results at any time.

It needs a database. Setup:

1. Create a free project at supabase.com.
2. In its SQL Editor, run `backend/sql/team_training.sql`.
3. Add `SUPABASE_URL` and `SUPABASE_SECRET_KEY` (a secret key, never the public one) to the backend settings (Render, or `backend/.env`).
4. Restart the backend. `/api/health` shows `"teamTraining":true`.

The free Render backend sleeps when idle, so it cannot store data itself. That is why the data lives in Supabase.

## Privacy

- Analysis of messages and links runs in your browser. Links are never opened.
- Scan history lives only in your own browser, so each device has its own list. Use **Export history** and **Import history** on the Scan History page to move it between devices. The exported file contains the links you checked and short message previews, so keep it private. Imported files are validated and cleaned before use.
- With the backend enabled, **only URLs** (never message text) are sent to your server, with usernames, passwords and `#fragments` removed, and then to the threat-list services. Google Safe Browsing receives only a short hash prefix of the link. The server does not log submitted URLs.

## Run locally

```bash
npm install
npm run dev
```

## Enable the online threat lists (optional)

1. Backend setup:
   ```bash
   cd backend
   npm install
   copy .env.example .env     # on Mac/Linux: cp .env.example .env
   ```
   Open `backend/.env` and add the keys you have (see comments in the file).
2. Frontend: copy `.env.example` to `.env` in the project root (it sets `VITE_API_URL`).
3. Start the backend with `npm run dev` inside `backend`, and the frontend with `npm run dev` in the project root.
4. Check `http://localhost:5000/api/health` to see which sources are active.

## Put it online

The website (frontend) and the backend are deployed separately.

1. **Backend on Render** (free web service): connect this GitHub repo, set Root Directory to `backend`, Build Command `npm install`, Start Command `npm start`, Health Check Path `/api/health`. Add these environment variables in Render, never in GitHub: `FRONTEND_ORIGIN` (your Vercel address, no trailing slash, several allowed separated by commas), `TRUST_PROXY=1`, `ENABLE_OPENPHISH`, and any API keys you have.
2. **Frontend on Vercel**: add the environment variable `VITE_API_URL` set to your Render address (no trailing slash), then redeploy. It is read at build time, so changing it needs a new deployment.
3. Free Render services sleep after 15 minutes without traffic and can take up to about a minute to wake. The website wakes the backend as soon as a page opens. If the backend is still asleep, results say the online lists could not be reached and use the local checks only.

## Tests

```bash
npm test                  # local checks and result handling
cd backend && npm test    # canonicalization, providers, API route
```

## Project structure

```
src/securityEngine.js       local scoring rules for URLs and messages
src/linkCheck.js            sends links to the backend and merges the results
src/historyTransfer.js      history export and safe import
src/TeamTraining.jsx        team pages for managers and staff
src/teamApi.js              calls to the team service
src/App.jsx                 interface
src/LearningExtras.jsx      quiz and checklist components
src/learningContent.js      quiz scenarios, checklist and incident steps
scripts/evaluate.mjs        measures detection against the live OpenPhish feed
backend/server.js           Express API (rate limited)
backend/lib/checkUrl.js     runs all sources in parallel, caches, combines results
backend/lib/canonicalize.js Safe Browsing URL canonicalization and hashing
backend/lib/providers/      one file per threat-list source
backend/lib/team/           team codes, anonymous summaries, storage, routes
backend/sql/                database setup for team training
```
