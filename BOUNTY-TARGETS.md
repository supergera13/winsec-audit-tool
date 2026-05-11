# Open-Source Bounty Targets — Specific & Actionable
## Researched 2026-05-11 | Focus: Projects with recent CVEs + bounty programs

---

## Tier 1: BEST BANG FOR BUCK (open programs, recent vulns, less competition)

### 1. Open WebUI (Python) — CRITICAL HOT TARGET
- **Repo:** https://github.com/open-webui/open-webui
- **6 CVEs in ONE WEEK** (May 8-11, 2026)
- **Bounty:** HackerOne (if listed) or GitHub Security Advisories
- **Vuln types found recently:**
  - CVE-2026-44565: Arbitrary file write/delete via path traversal
  - CVE-2026-44570: Auth bypass in memories API
  - CVE-2026-44569: Insecure message access breaks authorization
  - CVE-2026-44549: Stored XSS in Excel file preview
  - CVE-2026-44554: Knowledge base destruction / RAG poisoning
  - CVE-2026-44721: Stored XSS via model description
- **Why hunt here:** 6 CVEs in a week = codebase has MORE issues. AI/ML tools have complex auth + file handling = attack surface.
- **Setup:** `docker run -d -p 3000:8080 ghcr.io/open-webui/open-webui:main`
- **Focus areas:** File upload paths, API authorization, WebSocket handlers, model import/export

### 2. Next.js (JavaScript/Node) — HIGH VALUE
- **Repo:** https://github.com/vercel/next.js
- **6 CVEs in May 2026**
- **Bounty:** Vercel runs a HackerOne program
- **Vuln types:**
  - CVE-2026-45109: Middleware/proxy bypass via segment-prefetch
  - CVE-2026-44578: SSRF via WebSocket upgrades
  - CVE-2026-44579: DoS via connection exhaustion
  - CVE-2026-44574: Middleware bypass via dynamic route params
  - CVE-2026-44573: Pages Router i18n bypass
- **Why hunt here:** Massive adoption, complex routing = surface area. Payouts are $500-5,000+
- **Focus areas:** Middleware edge cases, server actions, image optimization, route handlers

### 3. PraisonAI (Python) — AI TOOLING, LOW COMPETITION
- **Repo:** https://github.com/MervinPraison/PraisonAI
- **3 CVEs (May 2026)**
- **Vuln types:**
  - CVE-2026-44340: Symlink extraction bypass -> arbitrary file write
  - CVE-2026-44339: Unsafe tool execution of undeclared callables
  - CVE-2026-44338: API server with auth disabled by default
- **Why hunt here:** AI agent tool = hot market, fewer hunters than Next.js. Symlink + deserialization issues suggest deeper problems.
- **Focus areas:** Agent tool execution, file handling, API endpoints, model loading

### 4. LangChain (Python) — POPULAR + DESERIALIZATION
- **Repo:** https://github.com/langchain-ai/langchain
- **CVE-2026-44843: Unsafe deserialization of attacker-controlled objects**
- **Bounty:** GitHub Security Advisories / coordinated disclosure
- **Focus areas:** Chain loading, agent tool invocation, pickle/yaml deserialization, prompt injection -> code execution

### 5. GitPython (Python) — PATCH BYPASS = EASY WIN
- **Repo:** https://github.com/gitpython-developers/GitPython
- **GHSA-mv93-w799-cj2w: Newline injection in config_writer() -> RCE (patch bypass)**
- **Why hunt here:** If they patched it once and it's STILL bypassable, there are likely more
- **Focus areas:** config_writer, remote URL handling, submodule operations

---

## Tier 2: SOLID PROGRAMS WITH OPEN BOUNTY

### 6. GitLab — UP TO $12,000 PER BUG
- **URL:** https://hackerone.com/gitlab
- **Accepts:** All HackerOne users, free GitLab account for testing
- **Known vuln types:** SSRF, stored XSS, IDOR, path traversal, CI/CD abuse, repo import RCE
- **How to test:** Spin up GitLab CE locally: `docker run -d -p 80:80 gitlab/gitlab-ce:latest`
- **Focus areas:** Project import/export, CI/CD pipelines, Webhook integrations, API endpoints

### 7. Discourse — EASY TO SELF-HOST
- **URL:** https://hackerone.com/discourse
- **Min bounty:** $256
- **Known vuln types:** XSS (stored/reflected), SSRF, CSRF, RCE via theme/plugin upload
- **Setup:** `./discourse-setup` or Docker
- **Focus areas:** Onebox (SSRF), theme uploads (RCE), embed endpoints, email processing

### 8. Django (Python Framework)
- **URL:** https://hackerone.com/django
- **Known vuln types:** SQL injection, XSS, CSRF bypass, template injection, mass assignment
- **Focus areas:** ORM edge cases, file upload handling, template engine, admin interface

---

## Tier 3: INTERNET BUG BOUNTY (IBB) — HIGHEST PAYOUTS

### 9. OpenSSL / Python / Ruby / PHP / Apache / nginx / BIND
- **URL:** https://hackerone.com/ibb
- **Bounties:** $500-$15,000+
- **Difficulty:** HIGH — requires deep C/systems knowledge
- **Best for Mattia's skillset:** Python runtime bugs, nginx config issues

---

## Fresh CVEs to Investigate (last 30 days)

These projects JUST had CVEs published. The patches may be incomplete, and related bugs may exist:

| Project | CVE | Type | Ecosystem |
|---------|-----|------|-----------|
| Open WebUI | CVE-2026-44565 | Path traversal | Python |
| Open WebUI | CVE-2026-44570 | Auth bypass | Python |
| Next.js | CVE-2026-45109 | Middleware bypass | Node.js |
| Next.js | CVE-2026-44578 | SSRF | Node.js |
| MikroORM | CVE-2026-44680 | SQL injection | Node.js |
| Babel | CVE-2026-44728 | RCE | Node.js |
| Electerm | CVE-2026-43943 | RCE | Node.js |
| Velocity.js | CVE-2026-44966 | Prototype pollution | Node.js |
| urllib3 | CVE-2026-44432 | Decompression bomb | Python |
| urllib3 | CVE-2026-44431 | Header leak | Python |
| LiteLLM | CVE-2026-40217 | Sandbox escape | Python |
| LangChain | CVE-2026-44843 | Deserialization | Python |
| GitPython | GHSA-mv93 | Injection -> RCE | Python |
| free5GC | 6 vulns | DoS/Type confusion | Go |
| ZITADEL | CVE-2026-44671 | LDAP injection | Go |
| Gotenberg | CVE-2026-42595 | SSRF | Go |
| Rancher | CVE-2026-25705 | Path traversal | Go |
| Dozzle | CVE-2026-44985 | WebSocket hijack | Go |
| gix-fs | CVE-2026-44471 | Symlink escape | Rust |
| rmcp | CVE-2026-42559 | DNS rebinding | Rust |
| rustfs | GHSA-mm2q | Root takeover | Rust |

---

## Recommended Attack Plan for Mattia

**Week 1:** Open WebUI + GitPython
- Self-host Open WebUI, test file upload paths and API auth
- Review GitPython source for more injection vectors
- Both Python = Mattia can read the code

**Week 2:** Next.js + Discourse
- Set up test instances
- Focus on middleware bypass and SSRF patterns
- Discourse Onebox is a classic SSRF target

**Week 3:** GitLab + LangChain
- GitLab has the highest payouts
- LangChain deserialization is a pattern that likely has more instances

**Week 4:** Review + submit best findings
- Write reports using the template from RUNBOOK-BUG-BOUNTY.md
- Submit to HackerOne/Intigriti

---

*This document should be updated as new CVEs are published. Check GitHub Advisory Database weekly.*
