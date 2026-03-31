import os
import json
import base64
import ipaddress
from urllib.parse import urlparse

import jwt
import requests as http_requests
from flask import Flask, request, jsonify, make_response
from functools import wraps

app = Flask(__name__)

# JWT signing secret — used for HS256 token creation and verification
JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-signing-key-do-not-leak")
# Flag returned by the internal debug endpoint
FLAG = "aprilfools{" + os.environ.get("FLAG", "dummy_flag") + "}"

# In-memory user store; admin password is randomised each startup
USERS = {
    "guest": {"password": "guest", "role": "user"},
    "admin": {"password": os.urandom(32).hex(), "role": "admin"},
}


def _b64url_decode(s):
    """Decode a Base64-URL string with padding correction."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_token(token):
    """
    Vulnerable: reads alg from the token header and trusts it.
    If alg is 'none', signature verification is skipped entirely,
    allowing an attacker to forge arbitrary claims.
    """
    try:
        header = json.loads(_b64url_decode(token.split(".")[0]))
    except Exception:
        header = {}

    alg = header.get("alg", "HS256")

    # BUG: accepting alg=none lets anyone craft a valid token without the secret
    if alg == "none":
        return jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])

    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def require_auth(f):
    """Decorator: rejects requests without a valid JWT (cookie or Authorization header)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("token") or request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            return jsonify({"error": "Missing token"}), 401
        try:
            payload = decode_token(token)
        except Exception as e:
            return jsonify({"error": f"Invalid token: {e}"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    """Decorator: requires an authenticated user with role=admin."""
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if request.user.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper


def _resolve_and_validate(url):
    """
    SSRF mitigation: resolve the hostname once, validate the IP is public,
    and return a rewritten URL that connects directly to the resolved IP.
    This eliminates the DNS TOCTOU / rebinding gap.
    Returns (safe_url, hostname) on success or (None, None) on failure.
    """
    import socket
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname or parsed.scheme not in ("http", "https"):
            return None, None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addr = socket.getaddrinfo(hostname, port)[0][4][0]
        ip = ipaddress.ip_address(addr)
        if not ip.is_global:
            return None, None
        # Rewrite URL to use the resolved IP so requests doesn't re-resolve
        replaced = parsed._replace(netloc=f"{addr}:{port}")
        return replaced.geturl(), hostname
    except Exception:
        return None, None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/login")
def login():
    """Authenticate with username/password and receive a signed JWT."""
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode({"sub": username, "role": user["role"]}, JWT_SECRET, algorithm="HS256")
    resp = make_response(jsonify({"token": token}))
    resp.set_cookie("token", token)
    return resp


@app.get("/api/profile")
@require_auth
def profile():
    """Return the authenticated user's JWT claims."""
    return jsonify({"user": request.user})


@app.post("/api/admin/healthcheck")
@require_admin
def healthcheck():
    """
    Admin-only: fetches a URL to check service health.
    PATCHED: now validates the target URL to prevent SSRF against internal services.
    """
    data = request.get_json(force=True)
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url is required"}), 400

    # SSRF fix: resolve once, validate, and use the resolved IP directly
    safe_url, original_host = _resolve_and_validate(url)
    if not safe_url:
        return jsonify({"error": "URL targets a non-public address"}), 400

    try:
        r = http_requests.get(safe_url, timeout=5, allow_redirects=False,
                              headers={"Host": original_host})
        return jsonify({"status": r.status_code, "body": r.text[:4096]})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.get("/internal/debug/env")
def debug_env():
    """Internal debug endpoint — only accessible from localhost (returns the flag)."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"FLAG": FLAG})


@app.get("/")
def index():
    """Landing page with basic usage instructions."""
    return """<!DOCTYPE html>
<html>
<head><title>Bastion</title></head>
<body>
<h1>Bastion Auth Service</h1>
<p>POST /api/login with {"username":"guest","password":"guest"} to get started.</p>
<p>Admins can use POST /api/admin/healthcheck to verify service uptime.</p>
</body>
</html>"""


@app.get("/health")
def health():
    """Simple liveness probe."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9999")), debug=False)
