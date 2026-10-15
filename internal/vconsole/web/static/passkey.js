// Passkey enrollment and sign-in. Loaded from /static/ (the CSP forbids inline script). The server
// sends WebAuthn options as JSON with base64url byte fields; the browser API wants ArrayBuffers.
'use strict';

(function () {
  function b64urlToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out.buffer;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function say(text) {
    var el = document.getElementById('message');
    if (el) { el.textContent = text; }
  }

  async function post(url, body) {
    var res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? '' : JSON.stringify(body)
    });
    var data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) { throw new Error(data.error || ('request failed (' + res.status + ')')); }
    return data;
  }

  function finish(data) {
    if (data.redirect && data.redirect.charAt(0) === '/' && data.redirect.charAt(1) !== '/') {
      window.location.assign(data.redirect);
    }
  }

  async function enroll(code) {
    var opts = await post('/webauthn/register/begin', { code: code });
    var pk = opts.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    var cred = await navigator.credentials.create({ publicKey: pk });
    var r = cred.response;
    var body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        attestationObject: bufToB64url(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : []
      }
    };
    finish(await post('/webauthn/register/finish', body));
  }

  async function login() {
    var opts = await post('/webauthn/login/begin');
    var pk = opts.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    var cred = await navigator.credentials.get({ publicKey: pk, mediation: opts.mediation || undefined });
    var r = cred.response;
    var body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        authenticatorData: bufToB64url(r.authenticatorData),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : undefined
      }
    };
    finish(await post('/webauthn/login/finish', body));
  }

  function failed(err) {
    // A cancelled or timed-out browser prompt is a NotAllowedError; say so plainly.
    if (err && err.name === 'NotAllowedError') { say('The passkey prompt was cancelled or timed out.'); return; }
    say(err && err.message ? err.message : 'Something went wrong.');
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (!window.PublicKeyCredential) {
      say('This browser does not support passkeys.');
      return;
    }
    var loginButton = document.getElementById('login-button');
    if (loginButton) {
      loginButton.addEventListener('click', function () {
        say('');
        loginButton.disabled = true;
        login().catch(failed).finally(function () { loginButton.disabled = false; });
      });
    }
    var form = document.getElementById('enroll-form');
    if (form) {
      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var button = document.getElementById('enroll-button');
        var code = document.getElementById('enroll-code').value.trim();
        if (!code) { say('Enter the enrollment code.'); return; }
        say('');
        button.disabled = true;
        enroll(code).catch(failed).finally(function () { button.disabled = false; });
      });
    }
  });
})();
