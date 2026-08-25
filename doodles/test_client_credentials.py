"""Reference tests for RFC 7521 (private_key_jwt) and RFC 6749 §2.3.1
(client_secret_basic / client_secret_post) client-credentials auth.

These live with the ``doodles/`` reference integration (next to ``server.py``)
until the verification primitives are ported into the ``falcon_oauthlib``
paper library; at that point they move to the top-level ``tests/`` package and
import from ``falcon_oauthlib`` instead. They exercise the secure-by-default
guarantees of ``verify_client_assertion``: signature checked against the
client's PUBLIC JWK Set, required claims enforced, and HS*/``none`` signatures
or the wrong audience/client rejected. A future ``jti`` replay guard would add
on top of ``verify_client_assertion`` (see its docstring).

They are self-contained: they generate an ephemeral RSA keypair in memory
rather than relying on committed key material. Run with::

    python -m pytest doodles/test_client_credentials.py
"""

import datetime
import json
import sys
import urllib.parse
from pathlib import Path

import falcon.testing
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

# ``server.py`` sits in the same (namespace) directory; make it importable
# regardless of how pytest is invoked.
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import server  # noqa: E402

CID = 'client-credentials-01'
AUDIENCE = 'https://as.example/oauth/token'
ACCEPTED = {AUDIENCE}


def _now():
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def _rsa_keypair():
    """Return (jwks, jwk, private_pem) for a fresh RSA-2048 signing key."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    jwk = {'kty': 'RSA', 'kid': 'test-key', 'n': jwk['n'], 'e': jwk['e']}
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {'keys': [jwk]}, jwk, pem


@pytest.fixture(scope='module')
def keypair():
    return _rsa_keypair()


def make_claims(aud, extra=None, **overrides):
    claims = {
        'iss': CID,
        'sub': CID,
        'aud': aud,
        'exp': _now() + 300,
        'iat': _now(),
        'jti': 'jwt-id-1',
    }
    claims.update(extra or {})
    claims.update(overrides)
    return claims


def mint(claims, pem, alg='RS256', kid='test-key'):
    return jwt.encode(claims, pem, algorithm=alg, headers={'kid': kid})


def verify(
    assertion, jwks, client_id=CID, assertion_type=None, accepted=ACCEPTED
):
    """Call the under-test primitive with a default (secure) audience set."""
    return server.verify_client_assertion(
        assertion=assertion,
        jwks=jwks,
        client_id=client_id,
        assertion_type=assertion_type or server.CLIENT_ASSERTION_TYPE,
        accepted_audiences=accepted,
    )


def public_client():
    return server.Client(
        client_id='public-spa-client',
        grant_types=['authorization_code', 'refresh_token'],
        scopes=['read', 'write'],
        response_type='code',
        redirect_uris=['http://localhost:8000/app'],
    )


def confidential_client(jwks):
    return server.Client(
        client_id=CID,
        grant_types=['client_credentials'],
        scopes=['read'],
        jwks=jwks,
    )


def post_token(body, clients, extra_headers=None):
    """Drive the real /token endpoint with a temporary client roster."""
    original = server.CLIENTS
    server.CLIENTS = clients
    try:
        app = server.create_app()
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        headers.update(extra_headers or {})
        return falcon.testing.TestClient(app).simulate_post(
            '/token', body=body, headers=headers
        )
    finally:
        server.CLIENTS = original


# --- verify_client_assertion: the secure-by-default primitive ----------------


def test_accepts_valid_assertion(keypair):
    jwks, _, pem = keypair
    assert verify(mint(make_claims(AUDIENCE), pem), jwks) is True


def test_rejects_wrong_audience(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(aud='https://evil.example/token'), pem)
    assert verify(a, jwks) is False


def test_rejects_multiple_audience_with_wrong_entry(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(aud=[AUDIENCE, 'https://evil.example/token']), pem)
    # At least one accepted audience present -> still acceptable.
    assert verify(a, jwks) is True
    a = mint(make_claims(aud=['https://evil.example/token']), pem)
    assert verify(a, jwks) is False


def test_rejects_expired(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(AUDIENCE, exp=_now() - 100), pem)
    assert verify(a, jwks) is False


def test_rejects_missing_jti(keypair):
    jwks, _, pem = keypair
    claims = make_claims(AUDIENCE)
    del claims['jti']
    assert verify(mint(claims, pem), jwks) is False


def test_rejects_missing_exp(keypair):
    jwks, _, pem = keypair
    claims = make_claims(AUDIENCE)
    del claims['exp']
    assert verify(mint(claims, pem), jwks) is False


def test_rejects_sub_that_is_not_client_id(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(AUDIENCE, sub='someone-else'), pem)
    assert verify(a, jwks) is False


def test_rejects_issuer_that_is_not_client_id(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(AUDIENCE, iss='someone-else'), pem)
    assert verify(a, jwks) is False


def test_rejects_unregistered_client_id(keypair):
    # Valid signature/claims, but asking for a different client than iss/sub.
    jwks, _, pem = keypair
    a = mint(make_claims(AUDIENCE), pem)
    assert verify(a, jwks, client_id='unknown-client') is False


def test_rejects_when_no_jwks(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(AUDIENCE), pem)
    assert verify(a, jwks=None) is False


def test_rejects_hs256_algorithm(keypair):
    # HS* would treat the public key as a symmetric secret -> must refuse.
    jwks, _, _ = keypair
    a = mint(make_claims(AUDIENCE), b'x' * 32, alg='HS256')
    assert verify(a, jwks) is False


def test_rejects_none_algorithm(keypair):
    jwks, _, _ = keypair
    a = jwt.encode(make_claims(AUDIENCE), key=None, algorithm='none')
    assert verify(a, jwks) is False


def test_rejects_wrong_signing_key(keypair):
    # Signature made by a different private key than the registered JWK.
    jwks, _, pem = keypair
    other_pem = _rsa_keypair()[2]
    a = mint(make_claims(AUDIENCE), other_pem)
    assert verify(a, jwks) is False


def test_rejects_wrong_assertion_type(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(AUDIENCE), pem)
    assert (
        verify(
            a,
            jwks,
            assertion_type=(
                'urn:ietf:params:oauth:client-assertion-type:client-secret-jwt'
            ),
        )
        is False
    )


def test_rejects_garbage_assertion(keypair):
    jwks = keypair[0]
    assert verify('not-a-jwt', jwks) is False


# --- through the /token endpoint (oauthlib + ClientCredentialsGrant) ---------


def _token_body(client_id, assertion=None, scope=None):
    parts = ['grant_type=client_credentials', f'client_id={client_id}']
    if scope:
        parts.append(f'scope={scope}')
    parts.append(f'client_assertion_type={server.CLIENT_ASSERTION_TYPE}')
    if assertion:
        parts.append('client_assertion=' + urllib.parse.quote_plus(assertion))
    return '&'.join(parts)


def test_endpoint_issues_token_for_valid_assertion(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(server.TOKEN_ENDPOINT), pem)
    r = post_token(
        _token_body(CID, a), (public_client(), confidential_client(jwks))
    )
    assert r.status_code == 200
    body = r.json
    assert body['token_type'] == 'Bearer'
    assert body['scope'] == 'read'
    assert body['access_token']


def test_endpoint_omits_refresh_token(keypair):
    # RFC 6749 §4.4.3: client-credentials MUST NOT return a refresh_token.
    jwks, _, pem = keypair
    a = mint(make_claims(server.TOKEN_ENDPOINT, exp=_now() + 300), pem)
    r = post_token(
        _token_body(CID, a), (public_client(), confidential_client(jwks))
    )
    assert r.status_code == 200
    assert 'refresh_token' not in r.json


def test_endpoint_rejects_missing_assertion(keypair):
    jwks, _, pem = keypair
    r = post_token(
        _token_body(CID, None), (public_client(), confidential_client(jwks))
    )
    assert r.status_code == 401
    assert r.json['error'] == 'invalid_client'


def test_endpoint_rejects_wrong_audience(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(aud='https://evil.example/token'), pem)
    r = post_token(
        _token_body(CID, a), (public_client(), confidential_client(jwks))
    )
    assert r.status_code == 401


def test_endpoint_rejects_unregistered_client(keypair):
    jwks, _, pem = keypair
    a = mint(make_claims(server.TOKEN_ENDPOINT), pem)
    r = post_token(
        _token_body('not-registered', a),
        (public_client(), confidential_client(jwks)),
    )
    assert r.status_code == 401


def test_endpoint_public_client_cannot_use_grant(keypair):
    # A public client has no signing JWK: it cannot do client_credentials.
    jwks, _, pem = keypair
    a = mint(
        make_claims(
            server.TOKEN_ENDPOINT,
            iss='public-spa-client',
            sub='public-spa-client',
        ),
        pem,
    )
    r = post_token(
        _token_body('public-spa-client', a),
        (public_client(), confidential_client(jwks)),
    )
    assert r.status_code in (400, 401)


# --- client_secret authentication (RFC 6749 §2.3.1) ------------------------


def confidential_client_with_secret(jwks=None, client_secret=None):
    return server.Client(
        client_id='secret-client-01',
        grant_types=['client_credentials'],
        scopes=['read'],
        jwks=jwks,
        client_secret=client_secret,
    )


SECRET = 'a-very-long-doodle-shared-secret-0123456789'


def _basic_header(client_id, secret):
    import base64

    raw = f'{client_id}:{secret}'.encode()
    return f'Basic {base64.b64encode(raw).decode("ascii")}'


def _secret_token_body(client_id, post=False):
    parts = [
        'grant_type=client_credentials',
        f'client_id={client_id}',
        f'scope=read',
    ]
    if post:
        parts.append('client_secret=' + urllib.parse.quote_plus(SECRET))
    return '&'.join(parts)


def test_endpoint_client_secret_basic():
    r = post_token(
        _secret_token_body('secret-client-01'),
        (public_client(), confidential_client_with_secret(client_secret=SECRET)),
        extra_headers={'Authorization': _basic_header('secret-client-01', SECRET)},
    )
    assert r.status_code == 200
    body = r.json
    assert body['token_type'] == 'Bearer'
    assert body['scope'] == 'read'
    assert body['access_token']
    assert 'refresh_token' not in body


def test_endpoint_client_secret_post():
    r = post_token(
        _secret_token_body('secret-client-01', post=True),
        (public_client(), confidential_client_with_secret(client_secret=SECRET)),
    )
    assert r.status_code == 200
    assert r.json['token_type'] == 'Bearer'


def test_endpoint_client_secret_basic_wrong_secret():
    r = post_token(
        _secret_token_body('secret-client-01'),
        (public_client(), confidential_client_with_secret(client_secret=SECRET)),
        extra_headers={
            'Authorization': _basic_header('secret-client-01', 'attacker-secret')
        },
    )
    assert r.status_code == 401
    assert r.json['error'] == 'invalid_client'


def test_endpoint_client_secret_post_wrong_secret():
    body = '&'.join(
        [
            'grant_type=client_credentials',
            'client_id=secret-client-01',
            'client_secret=attacker-secret',
        ]
    )
    r = post_token(
        body,
        (public_client(), confidential_client_with_secret(client_secret=SECRET)),
    )
    assert r.status_code == 401
    assert r.json['error'] == 'invalid_client'


def test_endpoint_client_secret_basic_id_mismatch():
    # Header claims a different client_id than the body -> reject.
    r = post_token(
        _secret_token_body('secret-client-01'),
        (public_client(), confidential_client_with_secret(client_secret=SECRET)),
        extra_headers={'Authorization': _basic_header('another-client', SECRET)},
    )
    assert r.status_code == 401


def test_endpoint_client_secret_without_registered_secret():
    # No registered secret and no JWKS: the client cannot authenticate at all
    # with a secret.
    r = post_token(
        _secret_token_body('secret-client-01'),
        (public_client(), confidential_client_with_secret()),
        extra_headers={'Authorization': _basic_header('secret-client-01', SECRET)},
    )
    assert r.status_code == 401
    r = post_token(
        _secret_token_body('secret-client-01', post=True),
        (public_client(), confidential_client_with_secret()),
    )
    assert r.status_code == 401


def test_endpoint_public_client_cannot_use_client_secret():
    # The public SPA client registered NO secret: neither the Basic header nor
    # the body parameter may ever succeed for it, even with a well-formed
    # credential.
    clients = (
        public_client(),
        confidential_client_with_secret(client_secret=SECRET),
    )
    r = post_token(
        'grant_type=client_credentials&client_id=public-spa-client',
        clients,
        extra_headers={
            'Authorization': _basic_header('public-spa-client', SECRET)
        },
    )
    assert r.status_code == 401
    r = post_token(
        'grant_type=client_credentials&client_id=public-spa-client&client_secret='
        + urllib.parse.quote_plus(SECRET),
        clients,
    )
    assert r.status_code == 401


def test_endpoint_secret_client_also_accepts_private_key_jwt(keypair):
    # A client may be registered for BOTH methods; each must keep working.
    jwks, _, pem = keypair
    client = confidential_client_with_secret(
        jwks=jwks, client_secret=SECRET
    )
    client.client_id = CID  # assertion iss/sub must match the request client
    # private_key_jwt path still works...
    r = post_token(
        _token_body(CID, mint(make_claims(server.TOKEN_ENDPOINT), pem)),
        (public_client(), client),
    )
    assert r.status_code == 200
    # ...as does the secret path.
    r = post_token(
        'grant_type=client_credentials&client_id='
        + CID
        + '&client_secret=' + urllib.parse.quote_plus(SECRET),
        (public_client(), client),
    )
    assert r.status_code == 200
