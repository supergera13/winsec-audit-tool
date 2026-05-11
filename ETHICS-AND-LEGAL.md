# Ethics & Legal Compliance

---

## 1. Scope Documents

### Target 1: OWASP Juice Shop
- **URL:** https://juice-shop.herokuapp.com
- **Authorization:** Official OWASP project, intentionally vulnerable application
- **Scope statement:** "OWASP Juice Shop is an intentionally insecure web application for security training, awareness, and CTF purposes. It is designed to be hacked." (source: https://owasp.org/www-project-juice-shop/)
- **Evidence of authorization:** https://owasp.org/www-project-juice-shop/ — project page explicitly states the application is designed for security testing
- **Testing performed:** Full scan with PyVulnScan (32 findings)
- **Data accessed:** HTTP response headers and status codes only, no user data

### Target 2: Httpbin.org
- **URL:** https://httpbin.org
- **Authorization:** Public HTTP request/response testing service
- **Scope statement:** "A simple HTTP Request & Response Service" (source: https://httpbin.org)
- **Evidence of authorization:** Publicly accessible service designed for HTTP testing
- **Testing performed:** Full scan with PyVulnScan (11 findings)
- **Data accessed:** HTTP response headers only

### Target 3: Local Firecrawl Instance
- **URL:** http://127.0.0.1:3002
- **Authorization:** Self-owned infrastructure (server: serverhermes, user: boxxapps)
- **Scope statement:** Full authorization — we own and operate this server
- **Evidence of authorization:** Running on our own machine under our user account
- **Testing performed:** Full scan with PyVulnScan (8 findings)
- **Data accessed:** HTTP response headers only

### Target 4: Open WebUI (code review only)
- **Repository:** https://github.com/open-webui/open-webui
- **License:** MIT (permits code review and analysis)
- **Authorization:** Public repository, code review is passive analysis
- **Scope statement:** Static code analysis only — no active testing, no exploitation, no access to running instances
- **Testing performed:** Source code review of Python backend (routers, utils, models)
- **Data accessed:** Publicly available source code only, no user data, no running system accessed

### Target 5: Flask, Django REST Framework, Requests, GitPython, n8n (code review only)
- **Authorization:** All public repositories on GitHub with permissive licenses
- **Testing performed:** Static code review only
- **Data accessed:** Publicly available source code only

---

## 2. What Was NOT Done

- No scanning of systems without authorization
- No exploitation of vulnerabilities for data access
- No denial-of-service testing
- No social engineering
- No access to other users' data
- No violation of any platform Terms of Service
- No creation of accounts with false identity
- No financial fraud or misrepresentation

---

## 3. GDPR Compliance

| Requirement | Status |
|-------------|--------|
| Lawful basis (Art. 6) | No personal data processed |
| Data minimization (Art. 5(1)(c)) | Only public configuration data collected |
| Purpose limitation (Art. 5(1)(b)) | Data used only for security assessment |
| Storage limitation (Art. 5(1)(e)) | Data stored locally, not transmitted |
| Data transfers (Chapter V) | No cross-border transfers |
| DPIA (Art. 35) | Not required — no personal data processed |

---

## 4. Responsible Disclosure

- **Timeline:** 90 days from report submission
- **Method:** Project's designated security channel (HackerOne, SECURITY.md, email)
- **Commitment:** Will not publicly disclose unfixed vulnerabilities before deadline

---

*Document created: 2026-05-11*
