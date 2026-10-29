#!/usr/bin/env python3
"""
Cisco Secure Workload (CSW / Tetration) API client with HMAC digest authentication.

Compatible with: CSW SaaS clusters and on-prem Tetration appliances.

Usage:
    python3 csw_api.py GET /openapi/v1/app_scopes
    python3 csw_api.py GET /openapi/v1/sensors
    python3 csw_api.py POST /openapi/v1/inventory/search '{"filter": {...}}'
    python3 csw_api.py GET /openapi/v1/sensors --limit 100 --offset 0

Environment variables (set in .env or export before running):
    CSW_API_URL    - Cluster base URL e.g. https://your-cluster.tetrationcloud.com
    CSW_API_KEY    - API key (hex string from CSW UI → API Keys)
    CSW_API_SECRET - API secret (hex string from CSW UI → API Keys)

Optional:
    CSW_VERIFY_SSL - Set to "false" to skip TLS verification (corporate proxies)
                     Default: "true"
"""

import base64
import hashlib
import hmac
import json
import os
import random
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

# Tunable network behaviour (override via environment).
#   CSW_API_TIMEOUT     - per-request socket timeout in seconds (default 30)
#   CSW_API_MAX_RETRIES - retries on throttling / transient errors (default 3)
_TIMEOUT = float(os.environ.get("CSW_API_TIMEOUT", "30"))
_MAX_RETRIES = int(os.environ.get("CSW_API_MAX_RETRIES", "3"))
# Statuses worth retrying: 429 (throttle — see CSW "API DDoS throttling"), plus transient 5xx.
_RETRY_STATUS = {429, 502, 503, 504}


def _load_dotenv():
    """Load KEY=value pairs from .env file next to this script.
    Does not override variables already set in the environment.
    """
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            # partition splits only on the first '=', so values may contain '=' (e.g. base64).
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, val)


def _ensure_ca_bundle():
    """Point urllib at certifi's CA bundle when the system trust store is empty.

    macOS Python framework builds often ship without a populated cert store,
    which makes valid public CAs (incl. CSW SaaS clusters) fail with
    'self signed certificate in certificate chain'. We do NOT disable TLS
    verification; we just use a curated, modern CA list. No-op if SSL_CERT_FILE
    is already set or certifi is not installed (TLS still verified via defaults).

    Lives in the shared client so every script that calls make_request() gets
    reliable TLS, not just count_agents.py.
    """
    if os.environ.get("SSL_CERT_FILE"):
        return
    try:
        import certifi  # type: ignore
        os.environ["SSL_CERT_FILE"] = certifi.where()
    except Exception:
        pass


def _retry_delay(attempt, retry_after=None):
    """Seconds to wait before the next attempt.

    Honors a server-provided ``Retry-After`` (integer seconds) when present;
    otherwise exponential back-off (1, 2, 4, ... capped at 30s) with jitter.
    """
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except (TypeError, ValueError):
            pass
    return min(2 ** (attempt - 1), 30) + random.uniform(0, 0.5)


def get_config():
    """Read and validate required environment variables."""
    url    = os.environ.get("CSW_API_URL", "").rstrip("/")
    key    = os.environ.get("CSW_API_KEY", "")
    secret = os.environ.get("CSW_API_SECRET", "")

    missing = [v for v, val in [("CSW_API_URL", url), ("CSW_API_KEY", key), ("CSW_API_SECRET", secret)] if not val]
    if missing:
        print(json.dumps({
            "error": f"Missing environment variables: {', '.join(missing)}",
            "hint":  "Copy .env.example to .env and fill in your cluster credentials."
        }), file=sys.stderr)
        sys.exit(1)

    verify_ssl = os.environ.get("CSW_VERIFY_SSL", "true").lower() != "false"
    return url, key, secret, verify_ssl


def compute_signature(secret, method, path, checksum, content_type, timestamp):
    """Compute HMAC-SHA256 signature per the CSW OpenAPI authentication specification.

    Canonical message format:
        METHOD\\nPATH\\nCHECKSUM\\nCONTENT-TYPE\\nTIMESTAMP\\n
    """
    msg = "\n".join([method, path, checksum, content_type, timestamp]) + "\n"
    sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256)
    # CSW expects the raw HMAC-SHA256 digest, Base64-encoded, as the Authorization value (not a scheme prefix).
    return base64.b64encode(sig.digest()).decode("utf-8")


def make_request(method, path, body=None, params=None):
    """Execute an authenticated CSW API request and return a parsed result dict.

    Resilience: enforces a socket timeout and retries throttling (HTTP 429) and
    transient 5xx responses up to ``CSW_API_MAX_RETRIES`` times, honoring any
    ``Retry-After`` header. Timestamp + HMAC signature are recomputed on every
    attempt (the signature is time-bound), so retries stay valid.
    """
    _ensure_ca_bundle()
    base_url, api_key, api_secret, verify_ssl = get_config()

    if params:
        # The signed path must match the request URL exactly, including the query string.
        path = f"{path}?{urllib.parse.urlencode(params)}"

    url          = f"{base_url}{path}"
    content_type = "application/json"

    body_bytes = b""
    if body:
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")

    # Canonical checksum is the SHA-256 hex of the body for POST/PUT with a body; otherwise the empty string (including POST/PUT with no body).
    checksum = hashlib.sha256(body_bytes).hexdigest() if method.upper() in ("POST", "PUT") and body_bytes else ""

    if not verify_ssl:
        import ssl
        ctx = ssl.create_default_context()
        # Insecure: only for broken corporate TLS inspection; avoids hostname/Certificate mismatch with proxies.
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    else:
        ctx = None
    kwargs = {"context": ctx} if ctx else {}

    attempt = 0
    while True:
        attempt += 1
        # Recompute per attempt — the signature is bound to this timestamp.
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")
        signature = compute_signature(api_secret, method.upper(), path, checksum, content_type, timestamp)
        headers = {
            "Content-Type":  content_type,
            "Id":            api_key,
            "Authorization": signature,
            "Timestamp":     timestamp,
            "User-Agent":    "csw-tme-toolkit/1.1",
        }
        if checksum:
            headers["X-Tetration-Cksum"] = checksum

        req = urllib.request.Request(
            url,
            data=body_bytes if body_bytes else None,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT, **kwargs) as resp:
                raw = resp.read().decode("utf-8")
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = raw
                return {"status": resp.status, "data": data}
        except urllib.error.HTTPError as e:
            if e.code in _RETRY_STATUS and attempt <= _MAX_RETRIES:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                delay = _retry_delay(attempt, retry_after)
                sys.stderr.write(
                    f"  csw_api: HTTP {e.code} on {path} — retry {attempt}/{_MAX_RETRIES} in {delay:.1f}s\n"
                )
                time.sleep(delay)
                continue
            raw = e.read().decode("utf-8", errors="replace")
            try:
                err_data = json.loads(raw)
            except json.JSONDecodeError:
                err_data = raw
            return {"status": e.code, "error": str(e.reason), "data": err_data}
        except urllib.error.URLError as e:
            # Timeouts and connection resets are often transient — back off and retry.
            if attempt <= _MAX_RETRIES:
                delay = _retry_delay(attempt)
                sys.stderr.write(
                    f"  csw_api: connection error ({e.reason}) on {path} — retry {attempt}/{_MAX_RETRIES} in {delay:.1f}s\n"
                )
                time.sleep(delay)
                continue
            return {"status": 0, "error": f"Connection failed: {e.reason}", "data": None}


def main():
    """Parse CLI arguments, optional --limit/--offset and generic --key value pairs, then run one signed request."""
    _load_dotenv()
    if len(sys.argv) < 3:
        print("Usage: csw_api.py METHOD PATH [BODY_JSON] [--limit N] [--offset N]")
        print()
        print("Examples:")
        print("  csw_api.py GET /openapi/v1/app_scopes")
        print("  csw_api.py GET /openapi/v1/sensors")
        print("  csw_api.py GET /openapi/v1/applications")
        print('  csw_api.py POST /openapi/v1/inventory/search \'{"filter": {"type": "eq", "field": "os", "value": "windows"}}\'')
        print("  csw_api.py GET /openapi/v1/sensors --limit 50 --offset 0")
        sys.exit(1)

    method = sys.argv[1].upper()
    path   = sys.argv[2]
    body   = None
    params = {}
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
            params["limit"] = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == "--offset" and i + 1 < len(sys.argv):
            params["offset"] = sys.argv[i + 1]; i += 2
        elif sys.argv[i].startswith("--"):
            k = sys.argv[i].lstrip("-")
            if i + 1 < len(sys.argv):
                params[k] = sys.argv[i + 1]; i += 2
            else:
                i += 1
        elif body is None:
            try:
                body = json.loads(sys.argv[i])
            except json.JSONDecodeError:
                print(json.dumps({"error": f"Invalid JSON body: {sys.argv[i]}"}))
                sys.exit(1)
            i += 1
        else:
            i += 1

    result = make_request(method, path, body=body, params=params if params else None)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
