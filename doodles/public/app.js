/* OAuth 2.1 PKCE client -- pure browser, no build step.
 * Served at /app (also our registered redirect_uri).
 *   1. No ?code on page -> show "Authorize" button.
 *   2. Click -> generate verifier (sessionStorage), S256 challenge,
 *      navigate to /authorize?...&code_challenge=...&code_challenge_method=S256.
 *   3. Redirect back to /app?code=... -> exchange code+verifier at /token.
 */
(() => {
  const ORIGIN = window.location.origin;
  const REDIRECT_URI = `${ORIGIN}/app`;
  const AUTH_ENDPOINT = `${ORIGIN}/authorize`;
  const TOKEN_ENDPOINT = `${ORIGIN}/token`;

  const CLIENT_ID = '01m0m43hg0dcx1d6wn5qqb4f0g';
  const SCOPE = 'read write admin';
  const SS_VERIFIER = 'pkce.code_verifier';

  const statusEl = document.getElementById('status');
  const resultEl = document.getElementById('result');

  /* Base64url encode a binary string into the 43..128-char space we need. */
  const b64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

  const base64Random = (bytes) => {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return b64url(arr.buffer);
  };

  const sha256 = (text) =>
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));

  const setStatus = (msg) => {
    statusEl.textContent = msg;
  };

  const showResult = (obj) => {
    resultEl.hidden = false;
    resultEl.textContent = JSON.stringify(obj, null, 2);
  };

  /* /app?code=...  (also handles ?error=...) after the redirect back. */
  async function handleCallback(params) {
    if (params.get('error')) {
      setStatus(
        'Authorization was rejected: ' + params.get('error') +
          (params.get('error_description')
            ? ` — ${params.get('error_description')}`
            : ''),
      );
      return;
    }

    const code = params.get('code');
    if (!code) {
      return;
    }

    const verifier = sessionStorage.getItem(SS_VERIFIER);
    sessionStorage.removeItem(SS_VERIFIER);
    if (!verifier) {
      setStatus('Session expired (code_verifier not found). Reload to start over.');
      return;
    }

    setStatus('Exchanging code for tokens at /token …');
    const body = new URLSearchParams({
      client_id: CLIENT_ID,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });

    const resp = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await resp.json().catch(() => ({}));
    showResult(data);
    setStatus(
      resp.ok
        ? `HTTP ${resp.status} — got a token. 🎉`
        : `HTTP ${resp.status} — token request failed.`,
    );
  }

  /* Kick off the authorization with a fresh PKCE pair. */
  async function startAuthorization() {
    const verifier = base64Random(64); // ~86 base64url chars (within 43..128)
    sessionStorage.setItem(SS_VERIFIER, verifier);
    const challenge = b64url(await sha256(verifier));

    setStatus('Redirecting you to the authorization server…');
    const url = new URL(AUTH_ENDPOINT);
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();
    window.location.assign(url);
  }

  /* Decide whether we're coming back from the auth server or starting fresh. */
  const params = new URLSearchParams(window.location.search);
  if (params.get('code') || params.get('error')) {
    handleCallback(params);
  } else {
    const go = document.createElement('button');
    go.textContent = 'Authorize';
    go.addEventListener('click', startAuthorization);
    statusEl.appendChild(go);
  }
})();
