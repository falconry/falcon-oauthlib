import dataclasses
import datetime
import io
import json
import logging
import os
import wsgiref.simple_server

import falcon
import jwt
from jwt.algorithms import ECAlgorithm
from jwt.algorithms import OKPAlgorithm
from jwt.algorithms import RSAAlgorithm
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO
)


@dataclasses.dataclass
class User:
    name: str
    user_id: str
    password: str  # Just for testing purposes, ought to use secure hash


@dataclasses.dataclass
class Client:
    client_id: str
    grant_types: list[str]
    scopes: list[str]
    # Confidential (client-credentials) clients present a signed JWT
    # (RFC 7521 private_key_jwt) proving they hold the matching private key.
    # The server stores only the client's PUBLIC JWK Set. Public
    # (authorization-code + PKCE) clients leave this None.
    jwks: dict | None = None
    # Only set for authorization-code clients (e.g. "code").
    response_type: str | None = None
    redirect_uris: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class BearerToken:
    client: Client
    scopes: list[str]
    access_token: str
    refresh_token: str
    expires_at: datetime.datetime
    user: User | None = None


@dataclasses.dataclass
class AuthorizationCode:
    client: Client
    scopes: list[str]
    redirect_uri: str
    code: str
    expires_at: datetime.datetime
    challenge: str
    challenge_method: str
    user: User | None = None


# The client roster. Each client is bound to an explicit set of grant types
# it is allowed to use; confidential clients carry their PUBLIC JWK Set.
def _resolve_mock_jwks() -> dict | None:
    """Load the mock client's PUBLIC JWK Set (the client holds the private)."""
    # Server keeps only the CLIENT's public key (doodles/keys/). Never ship a
    # real client's private key. Resolved from __file__ (no ordering coupling).
    key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
    path = os.path.join(key_dir, 'mock-client.jwks.json')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning('could not load %s: %s', path, exc)
        return None


CLIENTS = (
    # Public client (browser SPA): OAuth 2.1 authorization code + PKCE.
    Client(
        client_id='01m0m43hg0dcx1d6wn5qqb4f0g',
        grant_types=['authorization_code', 'refresh_token'],
        scopes=['admin', 'read', 'write'],
        response_type='code',
        redirect_uris=['http://localhost:8000/app'],
    ),
    # Confidential client: Client Credentials grant (no end-user, no redirect).
    # RFC 7521: authenticates with a private_key_jwt client_assertion; we keep
    # only the matching PUBLIC JWK Set (client retains its private key).
    Client(
        client_id='01m0mkfnh10bjd947gp1pq3h5q',
        grant_types=['client_credentials'],
        scopes=['read'],
        jwks=_resolve_mock_jwks(),
    ),
)

# In-memory authorization code store: code -> AuthorizationCode.
# Swap for a real DB / redis (with TTL) in production.
AUTHORIZATION_CODES: dict[str, AuthorizationCode] = {}

# In-memory bearer token store (ephemeral): access_token -> BearerToken.
BEARER_TOKENS: dict[str, BearerToken] = {}

# Directory holding the static PKCE client (index.html, style.css, app.js).
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public')

# Authorization server identifiers the client_assertion's `aud` must include.
TOKEN_ENDPOINT = 'http://localhost:8000/token'
ISSUER = 'http://localhost:8000'
ACCEPTED_AUDIENCES = {TOKEN_ENDPOINT, ISSUER}

# RFC 7521 §7.2.2 - client_assertion_type for a JWT bearer assertion.
CLIENT_ASSERTION_TYPE = (
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
)

# Signature algorithms we will accept. Pinned deliberately: never HS* (which
# would misuse the public key as a symmetric secret) and never "none".
JWT_ALLOWED_ALGORITHMS = ('RS256', 'ES256')


def _scopes_to_list(scopes) -> list[str]:
    """Normalize scopes to a canonical list[str].

    oauthlib's wire format is a space-delimited *string* (RFC 6749 §3.3), but
    internally (and in our stores/validators) we want a *list*. This handles
    the case where a single-valued HTML form field hands us a string like
    'read', and where a list/set/tuple is already given. oauthlib later does
    `' '.join(request.scopes)` in the token response, so a bare string there
    would be corrupted to 'r e a d' - keep these as lists.
    """
    if not scopes:
        return []
    if isinstance(scopes, (list, tuple, set)):
        return [str(s) for s in scopes]
    return scopes.strip().split(' ')


def _req_param(request, name):
    """Safely read a body parameter from an oauthlib Request (a dict of "
    "urlencoded body params lives in Request._params)."""
    params = getattr(request, '_params', None)
    if isinstance(params, dict):
        return params.get(name)
    return getattr(request, name, None)


def _select_jwk(jwks, kid):
    """Pick the JWK to verify with: by `kid` if given, else the only key."""
    keys = (jwks or {}).get('keys', [])
    if kid:
        for key in keys:
            if key.get('kid') == kid:
                return key
    if len(keys) == 1:
        return keys[0]
    return None


def _jwt_public_key(jwk):
    """Convert a JWK into a PyJWT-verifiable public key (dispatch on `kty`)."""
    kty = jwk.get('kty')
    if kty == 'RSA':
        return RSAAlgorithm.from_jwk(jwk)
    if kty == 'EC':
        return ECAlgorithm.from_jwk(jwk)
    if kty == 'OKP':
        return OKPAlgorithm.from_jwk(jwk)
    raise ValueError(f'signing key type not supported: {kty!r}')


def verify_client_assertion(
    *,
    assertion,
    jwks,
    client_id,
    assertion_type,
    accepted_audiences=ACCEPTED_AUDIENCES,
    algorithms=JWT_ALLOWED_ALGORITHMS,
    leeway=30,
):
    """Verify an RFC 7521 §7.2 ``private_key_jwt`` client assertion.

    The client proves possession of a private key by presenting a JWT it
    signed. We never handle the private key; we validate the signature against
    the client's PUBLIC JWK Set, then enforce the required claims:
    ``iss``/``sub`` == client_id, a valid (unexpired) ``exp``, present ``iat``
    and ``jti``, and an ``aud`` within ``accepted_audiences``.

    Returns ``True`` only if every check passes. ``accepted_audiences`` and
    ``algorithms`` are deliberate, secure-by-default; callers may tighten them
    but never loosen them (no HS*, no ``none``). A future ``jti`` replay guard
    would slot in here, against a shared store.
    """
    if assertion_type != CLIENT_ASSERTION_TYPE:
        return False
    if not (assertion and jwks and client_id):
        return False
    try:
        header = jwt.get_unverified_header(assertion)
        jwk = _select_jwk(jwks, header.get('kid'))
        if jwk is None:
            return False
        payload = jwt.decode(
            assertion,
            _jwt_public_key(jwk),
            algorithms=list(algorithms),
            issuer=client_id,
            options={
                'verify_aud': False,  # aud compared against accepted_audiences
                'require': ['exp', 'iat', 'jti', 'iss', 'sub'],
            },
            leeway=leeway,
        )
    except (ValueError, jwt.PyJWTError):
        return False
    if payload.get('sub') != client_id:
        return False
    aud = payload.get('aud')
    auds = set(aud) if isinstance(aud, (list, tuple, set)) else {aud}
    return bool(auds & set(accepted_audiences))


class DoodleValidator(RequestValidator):
    # Ordered roughly in order of appearance in the authorization grant flow
    # Pre- and post-authorization.

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        logging.info(f'validate_client_id{(client_id,)}')

        for client in CLIENTS:
            if client_id == client.client_id:
                request.client = client
                return True
        return False

    def validate_redirect_uri(
        self, client_id, redirect_uri, request, *args, **kwargs
    ):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        logging.info(f'validate_redirect_uri{(client_id, redirect_uri)}')

        return redirect_uri in request.client.redirect_uris

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        logging.info(f'get_default_redirect_uri{(client_id,)}')

    def validate_scopes(
        self, client_id, scopes, client, request, *args, **kwargs
    ):
        # Is the client allowed to access the requested scopes?
        logging.info(f'validate_scopes{(client_id, scopes)}')

        if isinstance(scopes, str):
            scopes = scopes.split()

        return scopes and set(scopes).issubset(request.client.scopes)

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        logging.info(f'get_default_scopes{(client_id,)}')

        return request.client.scopes

    def validate_response_type(
        self, client_id, response_type, client, request, *args, **kwargs
    ):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        logging.info(f'validate_response_type{(client_id, response_type)}')

        return request.client.response_type == response_type

    # Post-authorization

    def is_pkce_required(self, client_id, request):
        # PKCE is REQUIRED at all times (OAuth 2.1 / RFC 9700 & 9728 mandate it
        # for every Authorization Code Grant, public and confidential clients
        # alike). A client that omits code_challenge will be rejected with
        # MissingCodeChallengeError.
        logging.info(f'is_pkce_required{(client_id,)}')
        return True

    def save_authorization_code(
        self, client_id, code, request, *args, **kwargs
    ):
        # `code` is a dict like {'code': '<actual>'}; `request.client` was
        # populated by validate_client_id.
        logging.info(f'save_authorization_code{(client_id, code["code"])}')
        AUTHORIZATION_CODES[code['code']] = AuthorizationCode(
            client=request.client,
            scopes=_scopes_to_list(request.scopes),
            redirect_uri=request.redirect_uri,
            code=code['code'],
            expires_at=datetime.datetime.now(datetime.timezone.utc),
            # PKCE: persist the challenge so /token can verify the verifier.
            challenge=request.code_challenge,
            challenge_method=request.code_challenge_method,
            user=request.user,
        )

    def get_code_challenge(self, code, request):
        # Called on the /token step. Return the stored challenge, or None to
        # tell oauthlib the code is not PKCE-protected.
        auth_code = AUTHORIZATION_CODES.get(code)
        return auth_code.challenge if auth_code else None

    def get_code_challenge_method(self, code, request):
        # Called on the /token step. Must return 'plain' or 'S256'.
        logging.info(f'get_code_challenge_method{(code,)}')
        auth_code = AUTHORIZATION_CODES.get(code)
        return auth_code.challenge_method if auth_code else None

    # Token request

    @staticmethod
    def _find_client(client_id):
        for client in CLIENTS:
            if client.client_id == client_id:
                return client
        return None

    def client_authentication_required(self, request, *args, **kwargs):
        # The client presented a client_assertion we must validate (RFC 7521).
        logging.info(f'client_authentication_required<{request}>')
        return _req_param(request, 'client_assertion') is not None

    def authenticate_client(self, request, *args, **kwargs):
        # RFC 7521 §7.2 - private_key_jwt. Thin oauthlib adapter over the
        # reusable verify_client_assertion(): resolve the client, then verify
        # the assertion. NOTE: oauthlib requires request.client on success.
        logging.info(f'authenticate_client<{request}>')

        client_id = _req_param(request, 'client_id')
        client = self._find_client(client_id) if client_id else None
        if client is None or client.jwks is None:
            return False
        if not verify_client_assertion(
            assertion=_req_param(request, 'client_assertion'),
            jwks=client.jwks,
            client_id=client_id,
            assertion_type=_req_param(request, 'client_assertion_type'),
        ):
            return False
        request.client = client
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # The client_id must match a PUBLIC (non-confidential) client - one
        # with no signing JWK. Confidential clients authenticate via
        # authenticate_client() (RFC 7521) instead. NOTE: oauthlib requires
        # request.client to be set.
        logging.info(f'authenticate_client_id{(client_id,)}')
        client = self._find_client(client_id)
        if client is not None and client.jwks is None:
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes
        # and user to request.scopes and request.user.
        logging.info(f'validate_code{(client_id, code)}')
        auth_code = AUTHORIZATION_CODES.get(code)
        if auth_code is None:
            return False
        if auth_code.client.client_id != client_id:
            return False
        request.scopes = _scopes_to_list(auth_code.scopes)
        request.user = auth_code.user
        return True

    def confirm_redirect_uri(
        self, client_id, code, redirect_uri, client, request, *args, **kwargs
    ):
        # You did save the redirect uri with the authorization code right?
        logging.info(f'confirm_redirect_uri{(client_id, code, redirect_uri)}')
        auth_code = AUTHORIZATION_CODES.get(code)
        return auth_code is not None and redirect_uri == auth_code.redirect_uri

    def validate_grant_type(
        self, client_id, grant_type, client, request, *args, **kwargs
    ):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        logging.info(f'validate_grant_type{(client_id, grant_type)}')
        return client is not None and grant_type in client.grant_types

    def save_bearer_token(self, token, request, *args, **kwargs):
        # `token` has access_token, refresh_token, expires_in, scope, ...
        # `request.client` / `request.user` / `request.scopes` were set during
        # authorization-code validation.
        logging.info(f'save_bearer_token{(token["access_token"],)}')
        expires_in = token.get('expires_in', 3600)
        bt = BearerToken(
            client=request.client,
            scopes=_scopes_to_list(request.scopes)
            or _scopes_to_list(token.get('scope')),
            access_token=token['access_token'],
            refresh_token=token.get('refresh_token'),
            expires_at=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=expires_in),
            user=request.user,
        )
        BEARER_TOKENS[bt.access_token] = bt

    def invalidate_authorization_code(
        self, client_id, code, request, *args, **kwargs
    ):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        logging.info(f'invalidate_authorization_code{(client_id, code)}')
        AUTHORIZATION_CODES.pop(code, None)

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # `token` is the raw access_token string; `scopes` is a (possibly
        # empty) list of scopes the resource requires.
        logging.info(f'validate_bearer_token{(token,)}')
        bt = BEARER_TOKENS.get(token)
        if bt is None:
            return False
        if (
            bt.expires_at is not None
            and datetime.datetime.now(datetime.timezone.utc) >= bt.expires_at
        ):
            return False
        if scopes and not set(scopes).issubset(bt.scopes):
            return False
        # Expose context to downstream handlers.
        request.client = bt.client
        request.user = bt.user
        return True

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Called for the refresh_token grant. Return the scopes of the token
        # originally issued for this refresh_token (None if unknown).
        logging.info(f'get_original_scopes{(refresh_token,)}')
        for bt in BEARER_TOKENS.values():
            if bt.refresh_token == refresh_token:
                return bt.scopes
        return None


def extract_params(req: falcon.Request) -> tuple:
    uri = req.uri
    method = req.method
    body = None
    headers = req.headers
    if method == 'POST':
        body = req.get_media()
    return uri, method, body, headers


class AuthorizationResource:
    def __init__(self, oauth2_server: WebApplicationServer) -> None:
        self._oauth2_server = oauth2_server
        self._last_creds = None

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        uri, http_method, body, headers = extract_params(req)

        try:
            scopes, credentials = (
                self._oauth2_server.validate_authorization_request(
                    uri, http_method, body, headers
                )
            )

            # Not necessarily in session but they need to be
            # accessible in the POST view after form submit.
            # request.session['oauth2_credentials'] = credentials
            self._last_creds = credentials

            # You probably want to render a template instead.
            html = io.StringIO()
            # client_id is a required query param on /authorize (see the
            # OAuth2 client that initiated the request).
            client_id = req.params['client_id']
            html.write(f'<h1> Authorize access to {client_id} </h1>')
            html.write('<form method="POST" action="/authorize">')
            for scope in scopes or []:
                html.write(
                    f'<input type="checkbox" name="scopes" value="{scope}"/> '
                    f'{scope}<br>'
                )
            html.write('<input type="submit" value="Authorize"/>')

            resp.content_type = falcon.MEDIA_HTML
            resp.text = html.getvalue()

        # Errors that should be shown to the user on the provider website
        except errors.FatalClientError as e:
            raise falcon.HTTPBadRequest(description=str(e))

        # Errors embedded in the redirect URI back to the client
        except errors.OAuth2Error as e:
            raise falcon.HTTPTemporaryRedirect(e.in_uri(e.redirect_uri))

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        uri, http_method, body, headers = extract_params(req)

        logging.info((uri, http_method, body, headers))
        # The scopes the user actually authorized, i.e. checkboxes that were
        # selected. May be absent (user approved nothing), so default to an
        # empty list rather than KeyError-ing on body['scopes'].
        scopes = _scopes_to_list(body.get('scopes') or [])

        # Extra credentials we need in the validator
        # credentials = {'user': request.user}
        credentials = {}

        # The previously stored (in authorization GET view) credentials
        credentials.update(self._last_creds or {})

        try:
            headers, body, status = (
                self._oauth2_server.create_authorization_response(
                    uri, http_method, body, headers, scopes, credentials
                )
            )
            logging.info(f'auth resp {headers=} {body=} {status=}')
            resp.set_headers(headers)
            if isinstance(body, str):
                resp.data = body.encode('utf-8')
            elif body is not None:
                resp.data = body
            resp.status = status
            return

        except errors.FatalClientError as e:
            raise falcon.HTTPBadRequest(description=str(e))


class TokenResource:
    def __init__(self, oauth2_server):
        self._oauth2_server = oauth2_server

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        uri, http_method, body, headers = extract_params(req)

        # If you wish to include request specific extra credentials for
        # use in the validator, do so here.
        credentials = {'foo': 'bar'}

        headers, body, status = self._oauth2_server.create_token_response(
            uri, http_method, body, headers, credentials
        )

        # All requests to /token will return a json response, no redirection.
        logging.info(f'token resp {headers=} {body=} {status=}')
        resp.set_headers(headers)
        if isinstance(body, str):
            resp.data = body.encode('utf-8')
        elif body is not None:
            resp.data = body
        resp.status = status
        return


def create_app() -> falcon.App:
    validator = DoodleValidator()
    server = WebApplicationServer(validator)

    # WebApplicationServer only registers authorization_code + refresh_token by
    # default. Add the client-credentials grant explicitly so the confidential
    # client can use it, without enabling password/device/implicit grants.
    server.grant_types['client_credentials'] = ClientCredentialsGrant(
        validator
    )

    app = falcon.App()
    app.add_route('/authorize', AuthorizationResource(server))
    app.add_route('/token', TokenResource(server))

    # Static PKCE client (a browser SPA). Served under the /app prefix, which
    # is also the client's registered redirect_uri, so no validator change is
    # needed. The bare prefix maps to the SPA; assets live at /app/*.
    app.add_static_route('/app', PUBLIC_DIR, fallback_filename='index.html')

    return app


if __name__ == '__main__':
    host, port = '', 8000
    with wsgiref.simple_server.make_server(host, port, create_app()) as httpd:
        logging.info(f'Serving on port {port}...')
        logging.info(
            f'Open the PKCE client in your browser: '
            f'http://localhost:{port}/app'
        )
        logging.info(
            'It will drive /authorize and /token for you (PKCE is '
            'mandatory on the server).'
        )

        # Serve until process is killed
        httpd.serve_forever()
