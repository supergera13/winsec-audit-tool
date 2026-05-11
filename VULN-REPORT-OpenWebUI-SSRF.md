# Vulnerability Report: SSRF via User Webhook URL in Open WebUI
## READY TO SUBMIT — HackerOne (Open WebUI program)

---

**Title:** Server-Side Request Forgery (SSRF) via User-Configurable Webhook URL in Calendar Alerts

**Severity:** High (CVSS 7.5 — AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Affected Component:**
- Repository: https://github.com/open-webui/open-webui
- File: `backend/open_webui/utils/automations.py` (lines 549-580)
- File: `backend/open_webui/utils/webhook.py` (lines 13-60)

**Weakness:** CWE-918 (Server-Side Request Forgery)

---

## Summary

When the `ENABLE_USER_WEBHOOKS` configuration flag is set to `True`, any authenticated (non-admin) user can configure a webhook URL in their notification settings. This URL is used by the server to make outbound HTTP POST requests when calendar alert events fire. The webhook URL is **not validated** against any allowlist, blocklist, or SSRF protections before being fetched by the server. This allows an authenticated attacker to make the Open WebUI server send arbitrary POST requests to internal services, cloud metadata endpoints, or other protected resources.

---

## Technical Details

### Vulnerable Code Path

**1. User sets webhook URL (no validation):**

The webhook URL is stored in the user's settings as `user.settings.ui.notifications.webhook_url`. This is a user-controlled string that can be set to any URL via the settings API.

**2. Calendar alert triggers webhook (automations.py:549-580):**

```python
# automations.py lines 552-580
enable_user_webhooks = getattr(app.state.config, 'ENABLE_USER_WEBHOOKS', False)

if enable_user_webhooks:
    user = await Users.get_user_by_id(event.user_id)
    if user and user.settings:
        webhook_url = (
            user.settings.get('ui', {}).get('notifications', {}).get('webhook_url', None)
            # ... fallback logic ...
        )
        if webhook_url:
            from open_webui.utils.webhook import post_webhook
            await post_webhook(
                webui_name,
                webhook_url,  # <-- USER-CONTROLLED, NO VALIDATION
                f'{event.title} — starting {time_str}',
                {
                    'action': 'calendar_alert',
                    'title': event.title,
                    'minutes_until': minutes_until,
                    'event_id': event.id,
                },
            )
```

**3. post_webhook makes unvalidated request (webhook.py:13-60):**

```python
# webhook.py lines 48-56
else:
    # Default Payload — sends ALL event data to ANY URL
    payload = {**event_data}

async with aiohttp.ClientSession(trust_env=True) as session:
    async with session.post(url, json=payload, ssl=AIOHTTP_CLIENT_SESSION_SSL) as r:
        r_text = await r.text()
        r.raise_for_status()
```

### Key Observations

1. **No URL validation**: Unlike other URL-accepting endpoints (e.g., `validate_url()` in `retrieval/web/utils.py`), the webhook URL is passed directly to `aiohttp.ClientSession.post()` without any validation.

2. **`trust_env=True`**: The session is configured with `trust_env=True`, which means it respects environment proxy settings. This could be exploited if the server is behind a proxy.

3. **Default payload leaks data**: The "else" branch (line 49-50) sends the entire `event_data` dictionary to the webhook URL, potentially leaking event titles, user IDs, and other internal data.

4. **Auth requirement is low**: Only requires a verified (non-admin) user account. In default Open WebUI configurations, self-registration is enabled, meaning anyone can create an account.

---

## Steps to Reproduce

1. Deploy Open WebUI with `ENABLE_USER_WEBHOOKS=true` (or enable it via admin panel):
   ```bash
   docker run -d -p 3000:8080 -e ENABLE_USER_WEBHOOKS=true ghcr.io/open-webui/open-webui:main
   ```

2. Register a new user account (or log in as an existing non-admin user).

3. Start a collaborator-controlled HTTP server to receive the SSRF request:
   ```bash
   # On your VPS (e.g., your-vps.example.com)
   python3 -m http.server 8888
   ```

4. Set the webhook URL via the Open WebUI settings API:
   ```bash
   curl -X POST 'http://localhost:3000/api/v1/auths/update/profile' \
     -H 'Authorization: Bearer <USER_TOKEN>' \
     -H 'Content-Type: application/json' \
     -d '{
       "settings": {
         "ui": {
           "notifications": {
             "webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
           }
         }
       }
     }'
   ```

5. Create a calendar event that will trigger an alert (set it for 1 minute in the future).

6. When the calendar alert fires, the Open WebUI server will make a POST request to the configured webhook URL, in this case the AWS IMDS endpoint.

7. On the attacker's server, observe the incoming request. On AWS, if the server has an IAM role attached, the IMDS response will contain temporary AWS credentials.

---

## Impact

- **Cloud credential theft**: On AWS/GCP/Azure, an attacker can access the Instance Metadata Service (IMDS) to steal temporary cloud credentials.
- **Internal network scanning**: The attacker can use the server as a proxy to scan internal networks (e.g., `http://192.168.1.1/admin`, `http://10.0.0.1:8080/`).
- **Service enumeration**: Access internal APIs, databases, and admin panels that are not exposed to the internet.
- **Data exfiltration**: The default payload sends event data (titles, user IDs) to the attacker's server.

---

## Remediation

1. **Validate webhook URLs** using the existing `validate_url()` function, which checks for:
   - Valid URL format
   - HTTP/HTTPS protocol only
   - Blocklist compliance
   - Private IP blocking (when `ENABLE_RAG_LOCAL_WEB_FETCH` is disabled)

2. **Add an allowlist** for webhook URLs, restricting to known webhook services (Slack, Discord, Teams, etc.).

3. **Restrict payload data**: Don't send the full `event_data` to user-configured webhook URLs. Send only a minimal notification.

4. **Rate limit webhook requests** per user to prevent abuse.

Suggested fix for `automations.py`:
```python
from open_webui.retrieval.web.utils import validate_url

if webhook_url:
    try:
        validate_url(webhook_url)
    except ValueError:
        log.warning(f'Invalid webhook URL blocked: {webhook_url}')
        return
    # ... proceed with webhook
```

---

## References
- CWE-918: Server-Side Request Forgery
- OWASP SSRF Prevention Cheat Sheet
- AWS IMDS documentation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html

---

*Report generated 2026-05-11. Code analyzed from commit HEAD of open-webui/open-webui.*
