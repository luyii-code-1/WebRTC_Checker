# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

WebRTC IP leak checker — a privacy diagnostic tool that probes a browser's WebRTC stack for unexpected network-exit information. It runs on Cloudflare Pages as a static frontend (`index.html` + `app.js` + `style.css`) with one serverless backend function (`functions/api/ip.js`). No build step, no framework, no database.

## Running locally

```bash
npx wrangler pages dev .
```

Opens at `http://localhost:8788/`. The `/api/ip` endpoint serves from `functions/api/ip.js`. Opening `index.html` directly in a browser won't work for the HTTP-outlet detection — the Cloudflare-specific `request.cf` fields will be missing.

## Architecture

### Frontend (`app.js`)

Single global script with no imports, no modules, strict mode vanilla JS. Three main phases on "开始检测" click:

1. **HTTP outlet detection** — `getHttpInfo()` fetches `/api/ip` (with 8 s timeout, `no-store` cache, `omit` credentials). The response supplies `ip`, `country`, `asn`, `colo`, `tlsVersion`, and other Cloudflare-derived fields.

2. **WebRTC candidate collection** — `collectWebRTCCandidates()` creates an `RTCPeerConnection` configured with Google's public STUN server (`stun:stun.l.google.com:19302`), opens a transient data channel, and gathers ICE candidates with a 4.5 s timeout. Completion is triggered by either the null-candidate event or `iceGatheringState === "complete"`.

3. **Report building** — `buildReport()` parses raw candidates with `parseCandidate()`, classifies addresses (IPv4/IPv6/private/public/mDNS/Loopback) with `classifyAddress()`, and runs risk evaluation with `evaluateRisk()`.

**Risk logic** (`evaluateRisk`, lines 284–412): The key signal is whether WebRTC `srflx` public IPs match the HTTP outlet IP. If they differ → **high risk** (possible VPN/proxy leak). If no mismatch but private host candidates are exposed → **medium risk**. mDNS-only host candidates → **medium-low**. All srflx match HTTP → **low risk**.

**Key constants**: `STUN_SERVERS` (line 3), `ICE_GATHERING_TIMEOUT_MS` = 4500 (line 4), `HTTP_TIMEOUT_MS` = 8000 (line 5).

### Backend (`functions/api/ip.js`)

Cloudflare Pages Function (ES module export `onRequest`). Reads Cloudflare-specific headers (`CF-Connecting-IP`) and `request.cf` object (country, ASN, colo, city, region, timezone, HTTP protocol, TLS version). Falls back to `X-Forwarded-For` if `CF-Connecting-IP` is absent. Returns JSON with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

### CSS (`style.css`)

Single-file dark-theme design system using CSS custom properties. No preprocessor, no utility framework. Responsive breakpoint at 820px collapses the two-column grid to single column.

## Deployment

Push to `main` on GitHub → Cloudflare Pages auto-deploys. The `wrangler.toml` sets `pages_build_output_dir = "."` (static files in repo root). No build command needed — Cloudflare serves the static assets and deploys `functions/` as Pages Functions automatically.

## No tests exist

There are no test files or test infrastructure. The tool is validated manually by running it locally and observing candidate collection + risk output.
