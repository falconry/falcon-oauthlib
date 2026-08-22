import dataclasses
import datetime
import io
import logging
import wsgiref.simple_server

import falcon
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749 import errors

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
    # user: User
    grant_type: str
    response_type: str
    scopes: list[str]
    redirect_uris: list[str]


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


CLIENTS = (
    Client(
        client_id='01m0m43hg0dcx1d6wn5qqb4f0g',
        grant_type='authorization_code',
        response_type='code',
        scopes=['admin', 'read', 'write'],
        redirect_uris=['http://localhost:8000/app'],
    ),
)


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

    def save_authorization_code(
        self, client_id, code, request, *args, **kwargs
    ):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        logging.info(f'save_authorization_code{(client_id, code)}')

    # Token request

    def client_authentication_required(self, request, *args, **kwargs):
        # Check if the client provided authentication information that needs to
        # be validated, e.g. HTTP Basic auth
        logging.info(f'client_authentication_required<{request}>')

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        logging.info(f'authenticate_client<{request}>')

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # The client_id must match an existing public (non-confidential) client
        logging.info(f'save_bearer_token{(client_id,)}')

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes
        # and user to request.scopes and request.user.
        logging.info(f'validate_code{(client_id, code)}')

    def confirm_redirect_uri(
        self, client_id, code, redirect_uri, client, request, *args, **kwargs
    ):
        # You did save the redirect uri with the authorization code right?
        logging.info(f'confirm_redirect_uri{(client_id, code, redirect_uri)}')

    def validate_grant_type(
        self, client_id, grant_type, client, request, *args, **kwargs
    ):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        logging.info(f'validate_grant_type{(client_id, grant_type)}')

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        logging.info(f'save_bearer_token{(token,)}')

    def invalidate_authorization_code(
        self, client_id, code, request, *args, **kwargs
    ):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        logging.info(f'invalidate_authorization_code{(client_id, code)}')

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        logging.info(f'validate_bearer_token{(token,)}')

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        logging.info(f'get_original_scopes{(refresh_token,)}')


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
            html.write('<h1> Authorize access to {client_id} </h1>')
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
        # The scopes the user actually authorized, i.e. checkboxes
        # that were selected.
        scopes = body['scopes']

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
        resp.data = body
        resp.status = status
        return


class AppStub:
    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.media = {
            'info': 'Not much to see... This could be your SPA.',
            'req.headers': req.headers,
            'req.params': req.params,
        }


def create_app() -> falcon.App:
    validator = DoodleValidator()
    server = WebApplicationServer(validator)

    app = falcon.App()
    app.add_route('/authorize', AuthorizationResource(server))
    app.add_route('/token', TokenResource(server))

    app.add_route('/app', AppStub())

    return app


if __name__ == '__main__':
    host, port = '', 8000
    with wsgiref.simple_server.make_server(host, port, create_app()) as httpd:
        logging.info(f'Serving on port {port}...')
        logging.info(
            f'Example OAuth2 URL: '
            f'http://localhost:{port}/authorize?'
            f'client_id=01m0m43hg0dcx1d6wn5qqb4f0g&response_type=code&'
            f'redirect_uri=http://localhost:8000/app'
        )

        # Serve until process is killed
        httpd.serve_forever()
