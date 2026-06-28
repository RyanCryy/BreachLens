# 🔍 BreachLens — Passive Security Exposure Scanner

Enter a domain, get a beautiful, prioritized security exposure report in plain English — like a junior security analyst reviewed your public footprint, wrote up the findings, then stuck around to answer follow-up questions.

Built for **Kiro BuildFest**. Fully functional, deployable to **Netlify**, no database, no login.

![Stack](https://img.shields.io/badge/stack-Netlify_Functions_+_OpenAI-00d9ff)

---

## What it does

Given a domain, BreachLens runs **passive, no-auth checks** and turns them into a clear report:

| Check | Source |
|---|---|
| DNS records (A / MX / TXT) + **SPF / DMARC** presence | Node `dns` |
| **CAA record** (which CAs may issue certs) | Node `dns` |
| **TLS certificate** expiry, issuer, validity | Node `tls` (port 443) |
| **Subdomain enumeration** | [crt.sh](https://crt.sh) certificate transparency logs |
| **HTTP security headers** (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) | homepage fetch |
| **Cookie security flags** (Secure / HttpOnly / SameSite) | reuses the homepage fetch |
| **Mixed content** (http:// resources on an https page) | reuses the homepage fetch |
| **Tech-stack fingerprint** (informational only) | response headers + page markup |
| **robots.txt / sitemap.xml** exposure (sensitive Disallow paths) | direct fetch |
| **Exposed sensitive files** (`/.git/config`, `/.env`, …) — *status code only, body never read* | direct fetch |
| **Provider inference** (Cloudflare / Route 53 / GoDaddy …) | nameservers → tailored fix advice |

> HaveIBeenPwned domain breach data requires a paid API key, so it is intentionally reported as *unavailable* rather than faked.

### Two-pass AI analysis (the "credits well spent" part)

1. **Pass 1 — independent classification.** Each raw finding is sent to the model in its **own concurrent call** (`Promise.all`), scoring that finding *in isolation* so severities stay consistent and unanchored. Recommendations are tailored to the inferred provider when confidence is reasonable.
2. **Pass 2 — senior synthesis.** All Pass 1 results go to a single model call acting as a senior analyst: overall 0–100 risk score, risk level, a non-technical summary, findings re-ordered by severity, and the single top priority.

Both passes use OpenAI JSON mode, demand strict JSON, **retry once** with a stricter instruction on parse failure, and fall back to a **deterministic rule-based report** if the model is unavailable — so a live demo never breaks.

### Pass 3 — narrative layer

A third call (after Pass 2) generates an **"attacker's-eye view"** — a short, explicitly *hypothetical* scenario chaining only the findings that actually exist — plus an **"if left unaddressed"** risk-trajectory note. It's hard-constrained to never invent vulnerabilities, returns a positive note for clean scans, and is gracefully omitted if parsing fails. Findings also carry a copy-pasteable `fixSnippet` (e.g. the literal SPF/DMARC/CAA record), and a **certificate-history timeline** is built from the crt.sh data already fetched.

### Follow-up chat

After the report renders, ask questions about it. Each message sends the question + full report JSON + prior turns (chat history lives **only in client-side state**) to the model, which answers **strictly from the report** — no invented vulnerabilities.

---

## Project structure

```
.
├── netlify.toml                 # build + functions + /api redirects
├── public/                      # static frontend (no build step)
│   ├── index.html
│   ├── styles.css               # premium dark "cyber SaaS" UI
│   └── app.js                   # views, streaming progress, gauge, chat
├── netlify/functions/
│   ├── scan.js                  # POST /api/scan  (streams NDJSON progress)
│   ├── chat.js                  # POST /api/chat
│   └── lib/
│       ├── checks.js            # passive checks + timeouts
│       ├── findings.js          # raw → discrete findings + deterministic fallback
│       ├── llm.js               # OpenAI fetch wrapper + JSON mode + parse/retry
│       └── analysis.js          # Pass 1 + Pass 2 orchestration
└── scripts/test-checks.mjs      # quick local check of the passive scanners
```

The frontend is plain HTML/CSS/JS (no build), so `publish = "public"` serves it directly and the build command is a no-op.

---

## Configuration

BreachLens needs **one** environment variable:

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | ✅ | Your OpenAI API key. Used **server-side only** in Netlify Functions — never exposed to the browser. |
| `OPENAI_MODEL` | optional | Overrides the model (default `gpt-4o-mini`). |

> Without the key, scans still complete and render — they automatically use the **deterministic rule-based** report instead of AI analysis.

---

## Run locally

The simplest way uses a lightweight built-in dev server (no Netlify CLI needed) that
serves the frontend and routes `/api/scan` + `/api/chat` to the functions with full
streaming:

```bash
echo "OPENAI_API_KEY=sk-..." > .env
npm run dev                     # http://localhost:8888
```

> Without a key, scans still run and render using the deterministic fallback report.

Prefer the real Netlify runtime? `npm run dev:netlify` (requires `npm i -g netlify-cli`).
Note: the Netlify CLI may stall on its Edge Functions bootstrap on some machines —
`npm run dev` avoids that entirely and behaves identically for this app.

Quick-test just the passive checks (no key required):

```bash
npm run test:checks github.com
```

---

## Deploy to Netlify

1. Push this repo to GitHub.
2. In Netlify: **Add new site → Import from Git**, pick the repo.
3. Build settings are read from `netlify.toml` (publish `public`, functions `netlify/functions`) — no changes needed.
4. **Site settings → Environment variables →** add `OPENAI_API_KEY`. **Never commit the key.**
5. Deploy. `/api/scan` and `/api/chat` are wired via redirects in `netlify.toml`.

---

## Reliability notes for the demo

- **Per-check timeouts (6–8s)** so one slow source (crt.sh is often rate-limited) never hangs the scan — it proceeds with partial results.
- **Streaming progress**: the loading checklist ticks off each check the moment it actually resolves, reflecting real concurrency — not a fake timed sequence.
- **Graceful AI fallback** at both passes and per-finding.
- **Friendly error states** for domains that don't resolve.

---

_Passive checks only. BreachLens inspects publicly available information and does not perform intrusive testing._
