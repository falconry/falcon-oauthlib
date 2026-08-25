"""Tests for the Authorization Code grant + mandatory S256 PKCE.

Exercises:
  * S256 code_challenge  → 200 on /authorize, token on /token (with correct verifier)
  * Plain code_challenge  → rejected at /authorize (UnsupportedCodeChallengeMethod)
  * No code_challenge     → rejected at /authorize (MissingCodeChallenge)
  * Wrong code_verifier   → rejected on /token
  * Expired code          → rejected on /token
  * Redirect URI mismatch → rejected on /token

Run with::

    python -m pytest doodles/test_pkce.py
"""

import datetime
import urllib.parse
from urllib.parse import urlencode
from pathlib import Path

import falcon.testing

HERE = Path(__file__).resolve().parent
if str(HERE) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(HERE))

import server  # noqa: E402

CLIENT_ID = "01m0m43hg0dcx1d6wn5qqb4f0g"  # public-spa client
REDIRECT_URI = "http://localhost:8000/app"


def _body_str(body: dict) -> str:
    return urlencode(body)


def make_app() -> falcon.testing.TestClient:
    app = server.create_app()
    return falcon.testing.TestClient(app)


def generate_verifier() -> str:
    import base64
    import os

    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    assert 43 <= len(verifier) <= 128, "verifier length out of range"
    return verifier


def generate_challenge(verifier: str) -> tuple[str, str]:
    import hashlib
    import base64

    s256_digest = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return s256_digest, "S256"


def extract_code(location: str) -> str:
    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    return parsed["code"][0]


# ---------------------------------------------------------------------------
# Authorization (GET → POST) helpers
# ---------------------------------------------------------------------------

def do_authorize(client, query_params: dict):
    """GET /authorize to populate _last_creds on the resource, then POST with
    an empty scope set.  Returns the result of the POST step."""
    uri = f"/authorize?{urlencode(query_params)}"
    # Step 1: GET – validates and stores credentials in the resource instance.
    client.simulate_get(uri)
    # Step 2: POST – form submission.
    return client.simulate_post(
        "/authorize",
        body=_body_str(query_params),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_s256_challenge_issues_code():
    """A request with code_challenge_method=S256 should return a 302 with code."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )
    assert resp.status_code == 302
    code = extract_code(resp.headers.get("Location", ""))
    assert len(code) > 0


def test_plain_challenge_is_rejected():
    """code_challenge_method=plain must be rejected (OAuth 2.1 mandates S256)."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "plain",
        },
    )
    assert resp.status_code == 400
    assert "Transform algorithm not supported" in resp.json["description"]


def test_missing_code_challenge_is_rejected():
    """A request without code_challenge must be rejected."""
    client = make_app()
    # Test at GET level: MissingCodeChallengeError is raised during GET
    # validation, before any POST can occur.
    uri = (
        f"/authorize?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={urllib.parse.quote_plus(REDIRECT_URI)}"
    )
    resp = client.simulate_get(uri)
    assert resp.status_code == 400
    assert "Code challenge required" in resp.json["description"]


def test_token_exchanges_with_correct_verifier():
    """Full flow: /authorize with S256 → /token with correct code_verifier."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    auth_resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )
    code = extract_code(auth_resp.headers.get("Location", ""))

    token_resp = make_app().simulate_post(
        "/token",
        body=_body_str({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert token_resp.status_code == 200
    body = token_resp.json
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "admin read write"
    assert body["access_token"]
    assert body["refresh_token"]


def test_token_rejects_wrong_verifier():
    """A wrong code_verifier must be rejected on /token."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    auth_resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )
    code = extract_code(auth_resp.headers.get("Location", ""))

    token_resp = make_app().simulate_post(
        "/token",
        body=_body_str({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "wrong-verifier-does-not-match",
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert token_resp.status_code == 400
    assert token_resp.json["error"] == "invalid_grant"


def test_code_is_use_once():
    """An authorization code must be invalid after it's been exchanged."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    auth_resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )
    code = extract_code(auth_resp.headers.get("Location", ""))

    # First exchange succeeds
    token_resp1 = make_app().simulate_post(
        "/token",
        body=_body_str({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert token_resp1.status_code == 200

    # Second exchange fails (code invalidated)
    token_resp2 = make_app().simulate_post(
        "/token",
        body=_body_str({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert token_resp2.status_code == 400
    assert token_resp2.json["error"] == "invalid_grant"


def test_expired_code_is_rejected():
    """An authorization code past its expiry should be rejected."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    auth_resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )
    code = extract_code(auth_resp.headers.get("Location", ""))

    # Manually expire the code by reaching into the module-level store
    if code in server.AUTHORIZATION_CODES:
        server.AUTHORIZATION_CODES[code].expires_at = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=1)
        )

    token_resp = make_app().simulate_post(
        "/token",
        body=_body_str({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert token_resp.status_code == 400
    assert token_resp.json["error"] == "invalid_grant"


def test_redirect_uri_mismatch_at_token():
    """A redirect_uri different from /authorize must be rejected."""
    verifier = generate_verifier()
    challenge, method = generate_challenge(verifier)
    client = make_app()
    auth_resp = do_authorize(
        client,
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )
    code = extract_code(auth_resp.headers.get("Location", ""))

    token_resp = make_app().simulate_post(
        "/token",
        body=_body_str({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://evil.example/callback",
            "code_verifier": verifier,
        }),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert token_resp.status_code == 400
    assert token_resp.json["error"] == "invalid_request"
