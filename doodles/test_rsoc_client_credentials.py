"""Live ``client_credentials`` + ``private_key_jwt`` check for the doodle AS.

Exercises the Client Credentials grant using an RFC 7521 ``private_key_jwt``
client assertion, via ``requests_oauth2client``. The doodle stores only the
client's PUBLIC JWK Set, so the PRIVATE key lives on the client side and is in
``doodles/keys/mock-client.pem``; the registered ``client_id`` and scope are
read from ``doodles/server.py``.

Prereqs (this hits the running server, so it is a live/demo check, not part of
the library unit suite):

* the doodle AS up at ``http://localhost:8000`` (python doodles/server.py)
* ``requests_oauth2client`` installed in the same env

Run directly:

    python doodles/test_rsoc_client_credentials.py

It performs two checks:

1. a VALID assertion signed with the registered key  -> 200 + Bearer token
2. the SAME registered key, but a WRONG aud claim   -> 401 (invalid_client)
"""

from __future__ import annotations

import sys
from pathlib import Path

import requests
from jwskate import Jwk
from requests_oauth2client import OAuth2Client
from requests_oauth2client import OAuth2Error
from requests_oauth2client import PrivateKeyJwt

HERE = Path(__file__).resolve().parent

# Match the doodle's confidential (client_credentials) client and its endpoint.
TOKEN_ENDPOINT = 'http://localhost:8000/token'
CLIENT_ID = '01m0mkfnh10bjd947gp1pq3h5q'  # grant_types=['client_credentials']
SCOPE = 'read'  # registered scope for this client
KID = 'mock-client-1'  # must match mock-client.jwks.json
PEM_PATH = HERE / 'keys' / 'mock-client.pem'


def _server_up() -> bool:
    """Return True if the token endpoint answers, False if the server is down.

    Any HTTP response (even a 401) means the AS is reachable; only a
    connection-error means it is not running.
    """
    try:
        requests.post(
            TOKEN_ENDPOINT,
            data={'grant_type': 'client_credentials'},
            timeout=2,
        )
    except requests.ConnectionError:
        return False
    return True


def _client_with(pem: str, aud: str = TOKEN_ENDPOINT) -> OAuth2Client:
    """Build an OAuth2Client that authenticates with ``private_key_jwt``.

    The private key is loaded from PEM and tagged with the expected ``kid``/
    ``alg`` (which become the assertion's header), used to mint a fresh
    assertion per request. ``aud`` is the assertion's ``aud`` claim; it
    defaults to the token endpoint (satisfying the doodle's
    ``ACCEPTED_AUDIENCES``) but is overridable to craft a "registered client,
    wrong audience" case.
    """
    key = Jwk.from_pem(pem, kid=KID, alg='RS256')
    auth = PrivateKeyJwt(CLIENT_ID, key, alg='RS256', aud=aud)
    # testing=True only relaxes endpoint-URI validation (the doodle is plain
    # http, not https); it does not weaken request/TLS security.
    return OAuth2Client(TOKEN_ENDPOINT, auth=auth, testing=True)


def ok_case() -> bool:
    print('\n[1] client_credentials + VALID private_key_jwt  -> expect 200')
    try:
        token = _client_with(PEM_PATH.read_text()).client_credentials(
            scope=SCOPE
        )
    except OAuth2Error as exc:
        print(f'    FAIL: the server rejected the valid assertion: {exc}')
        return False
    print(f'    token_type    : {token.token_type!r}')
    print(f'    access_token  : {token.access_token[:40]!r}...')
    print(f'    scope         : {token.scope!r}')
    print(f'    refresh_token : {token.refresh_token!r}')
    assert token.access_token, 'expected an access token'
    assert SCOPE in str(token.scope), (
        f'expected {SCOPE!r} in scope, got {token.scope!r}'
    )
    assert not token.refresh_token, (
        'client_credentials MUST NOT return a refresh token (RFC 6749 §4.4.3)'
    )
    print('    OK: bearer token for the registered scope, no refresh token')
    return True


def rejected_case() -> bool:
    # Same *registered* client and key (public half is in the server's JWKS),
    # but an ``aud`` the doodle does not accept: a validly-signed key is not
    # enough if the assertion is malformed on a claim the AS enforces.
    wrong_aud = 'https://other-as.example/token'
    print(f'\n[2] registered client, WRONG aud ({wrong_aud}) -> expect 401')
    try:
        _client_with(PEM_PATH.read_text(), aud=wrong_aud).client_credentials(
            scope=SCOPE
        )
    except OAuth2Error as exc:
        print(f'    token endpoint returned: {exc}')
        print('    OK: registered key is valid, but the AS rejected the aud')
        return True
    print('    FAIL: server accepted an assertion with an unaccepted audience')
    return False


def main() -> int:
    if not _server_up():
        print(
            f'ERROR: doodle AS not reachable at {TOKEN_ENDPOINT}.\n'
            '       Start it first:  python doodles/server.py'
        )
        return 2

    results = [ok_case(), rejected_case()]
    if all(results):
        print(
            '\nAll client_credentials / private_key_jwt checks passed against '
            f'{TOKEN_ENDPOINT}'
        )
        return 0
    print('\nOne or more checks failed.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
