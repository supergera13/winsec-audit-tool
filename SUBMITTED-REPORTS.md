# Vulnerability Reports Submitted
## Via GitHub Security Advisory API | No platform registration required
## Date: 2026-05-11

---

## Summary: 11 reports across 4 projects, all in triage

---

### Open WebUI (3 reports)

| # | GHSA | Vulnerability | Severity | URL |
|---|------|---------------|----------|-----|
| 1 | GHSA-x7xq-74rg-m8mf | SSRF via User Webhook URL | High 7.5 | https://github.com/open-webui/open-webui/security/advisories/GHSA-x7xq-74rg-m8mf |
| 2 | GHSA-hjr5-g7q4-9fj9 | XSS via Markdown-to-HTML | Medium 5.4 | https://github.com/open-webui/open-webui/security/advisories/GHSA-hjr5-g7q4-9fj9 |
| 3 | GHSA-2m9w-qxp3-h388 | DNS Rebinding in URL Validation | High 7.7 | https://github.com/open-webui/open-webui/security/advisories/GHSA-2m9w-qxp3-h388 |

### Strapi (4 reports)

| # | GHSA | Vulnerability | Severity | URL |
|---|------|---------------|----------|-----|
| 4 | GHSA-6hwx-8w6v-r7rx | JWT Algorithm Confusion (auth bypass) | Critical 9.8 | https://github.com/strapi/strapi/security/advisories/GHSA-6hwx-8w6v-r7rx |
| 5 | GHSA-gjcc-5c3q-6vj4 | SSRF via DNS Rebind in Upload | High 7.5 | https://github.com/strapi/strapi/security/advisories/GHSA-gjcc-5c3q-6vj4 |
| 6 | GHSA-gqhx-cxhv-fj3c | SQL LIKE Injection in Folders | Medium 4.3 | https://github.com/strapi/strapi/security/advisories/GHSA-gqhx-cxhv-fj3c |
| 7 | GHSA-3p9p-jh6g-j23q | OAuth Field Injection | Medium 5.4 | https://github.com/strapi/strapi/security/advisories/GHSA-3p9p-jh6g-j23q |

### LangChain (2 reports)

| # | GHSA | Vulnerability | Severity | URL |
|---|------|---------------|----------|-----|
| 8 | GHSA-2q4q-rh6w-v8hq | Path Traversal in Chroma.encode_image() | Medium 6.5 | https://github.com/langchain-ai/langchain/security/advisories/GHSA-2q4q-rh6w-v8hq |
| 9 | GHSA-4cpx-v6wm-7p8f | Deserialization SSRF via base_url | Medium 6.5 | https://github.com/langchain-ai/langchain/security/advisories/GHSA-4cpx-v6wm-7p8f |

### Fastify (2 reports)

| # | GHSA | Vulnerability | Severity | URL |
|---|------|---------------|----------|-----|
| 10 | GHSA-ww7h-mvr8-v895 | Prototype Pollution via rfdc proto:true | Medium 5.9 | https://github.com/fastify/fastify/security/advisories/GHSA-ww7h-mvr8-v895 |
| 11 | GHSA-pfv3-px7h-x44c | Error Header Injection | Medium 4.3 | https://github.com/fastify/fastify/security/advisories/GHSA-pfv3-px7h-x44c |

---

## How Reports Were Submitted

```bash
gh api repos/{owner}/{repo}/security-advisories/reports -X POST --input report.json
```

Works with any authenticated GitHub account. No HackerOne, Bugcrowd, or Intigriti registration required.

## What Happens Next

1. Maintainers review reports (typically 1-14 days)
2. If accepted, reports get published as security advisories
3. Reporter (supergera13) gets credit on published advisories
4. If project has bounty program, payment may follow

---

*Submitted: 2026-05-11T18:20-20:00Z*
*Reporter: supergera13*
