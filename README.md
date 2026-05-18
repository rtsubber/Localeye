# Local-Eye — AI Agent Web Verification API

[![Live](https://img.shields.io/badge/Live-localeye.co-6366f1)](https://localeye.co)
[![API](https://img.shields.io/badge/API-v1-green)](https://localeye.co/v1/scrape)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

Local-Eye gives AI agents what they need to verify the real world: **residential IP browsing**, **JavaScript rendering**, and **structured data extraction** — all through a simple API.

> LinkedIn is where you find human talent. AgentSeek is where you find AI talent. **Local-Eye is how they verify it.**

## 🚀 Quick Start

```bash
# Get an API key
curl -X POST https://localeye.co/v1/keys?email=you@example.com

# Scrape any website (residential IP, full JS rendering)
curl "https://localeye.co/v1/scrape?url=https://example.com" \
  -H "X-API-Key: ley_your_key_here"

# Extract structured business data
curl "https://localeye.co/v1/verify-business?query=starbucks+near+me" \
  -H "X-API-Key: ley_your_key_here"
```

## ✨ Features

- **Residential IP access** — No Cloudflare blocks, no CAPTCHAs, no "Access Denied"
- **Full JavaScript rendering** — See what humans see, not just raw HTML
- **Structured data extraction** — Business names, hours, phone numbers, addresses
- **Screenshot capture** — Visual proof of what's on the page
- **Phone verification** — Twilio-powered business phone calls
- **HTTP 402 payment discovery** — Agents know the cost before they call
- **Skyfire integration** — Autonomous agent-to-agent payments

## 💰 Pricing

| Tier | Price | Calls/day | Features |
|------|-------|-----------|----------|
| Free | $0 | 5 | Scrape, screenshots |
| Pro | $29/mo | 500 | Business verification, phone calls, priority |
| Enterprise | $99/mo | Unlimited | Custom SLAs, dedicated support |

## 🏗️ Architecture

- **FastAPI** — Async Python with automatic OpenAPI docs
- **Playwright** — Headless browser with residential proxies
- **SQLite (WAL)** — Zero-ops database
- **Twilio** — Phone verification
- **Skyfire** — Agent-to-agent payments
- **Tailscale Funnel** — Secure public exposure

## 🔗 Part of the Agent Business Suite

- [AgentSeek](https://agentseek.co) — Discover AI agents
- **Local-Eye** — Verify real-world data
- [Agent Monitor](https://brandbooststudio.co/agent-business-suite.html#monitor) — Track uptime

Bundle all three for **$49/mo** → [agentseek.co](https://agentseek.co)

## 📄 License

MIT

---

*Built by [BrandBoost Studio](https://brandbooststudio.co) in Beeville, TX*
