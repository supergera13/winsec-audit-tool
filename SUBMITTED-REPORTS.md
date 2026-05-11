# Vulnerability Reports Submitted to Open WebUI
## Via GitHub Security Advisory API (no registration required)
## Date: 2026-05-11

---

## Report 1: SSRF via User Webhook URL
- **GHSA:** GHSA-x7xq-74rg-m8mf
- **Status:** triage
- **URL:** https://github.com/open-webui/open-webui/security/advisories/GHSA-x7xq-74rg-m8mf
- **Severity:** High (CVSS 7.5)
- **Reporter:** supergera13 (pending credit)
- **Description:** Any authenticated user can set a webhook URL in notification settings. The server makes unvalidated POST requests to that URL when calendar alerts fire. Enables SSRF to AWS IMDS, internal services.

## Report 2: XSS via Markdown-to-HTML Conversion
- **GHSA:** GHSA-hjr5-g7q4-9fj9
- **Status:** triage
- **URL:** https://github.com/open-webui/open-webui/security/advisories/GHSA-hjr5-g7q4-9fj9
- **Severity:** Medium (CVSS 5.4)
- **Reporter:** supergera13 (pending credit)
- **Description:** The /api/v1/utils/markdown endpoint converts markdown to HTML without sanitization. Python's markdown library passes raw HTML through unchanged. Enables JavaScript injection.

## Report 3: DNS Rebinding in URL Validation
- **GHSA:** GHSA-2m9w-qxp3-h388
- **Status:** triage
- **URL:** https://github.com/open-webui/open-webui/security/advisories/GHSA-2m9w-qxp3-h388
- **Severity:** High (CVSS 7.7)
- **Reporter:** supergera13 (pending credit)
- **Description:** The validate_url() SSRF protection resolves hostnames and checks for private IPs, but is vulnerable to DNS rebinding attacks. Developers acknowledge in code comment. Bypasses all URL validation.

---

## How Reports Were Submitted

Used GitHub's REST API for private vulnerability reporting:
```bash
gh api repos/open-webui/open-webui/security-advisories/reports -X POST --input report.json
```

This works with any authenticated GitHub account. No HackerOne, Bugcrowd, or Intigriti registration required.

## What Happens Next

1. Open WebUI maintainers review the reports (typically 1-7 days)
2. If accepted, reports get published as security advisories
3. Reporter (supergera13) gets credit on the published advisory
4. If Open WebUI has a bounty program, payment may follow

---

*Submitted: 2026-05-11T18:20:00Z*
