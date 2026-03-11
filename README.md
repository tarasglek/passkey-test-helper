# passkey-test-helper

`passkey-test-helper` is a small Go CLI for generating WebAuthn/passkey payloads for automated tests.

It is useful when you want to:
- test passkey registration flows without driving a real browser
- test login/assertion verification without a physical authenticator
- generate realistic WebAuthn JSON fixtures for backend integration tests
- debug server-side WebAuthn handling locally

The tool reads JSON from stdin and writes JSON to stdout.

## Commands

- `register-response` — generate a registration attestation payload plus a generated credential
- `login-response` — generate a login assertion payload using a previously generated credential

## Build

```bash
go build ./cmd/passkey-test-helper
```

## Example: registration payload

Generate a WebAuthn registration response from creation options:

```bash
cat <<'EOF' | go run ./cmd/passkey-test-helper register-response
{
  "origin": "http://localhost",
  "creationOptions": {
    "challenge": "test-challenge",
    "rp": {
      "id": "localhost",
      "name": "Lineage"
    },
    "user": {
      "id": "user-123",
      "name": "alice",
      "displayName": "alice"
    },
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 }
    ]
  }
}
EOF
```

This returns JSON containing:
- `attestationResponse` — the registration payload to POST to your server
- `credential` — the generated key material and metadata to reuse in later tests

## Example: login payload

Generate a login/assertion response using a previously generated credential:

```bash
cat <<'EOF' | go run ./cmd/passkey-test-helper login-response
{
  "origin": "http://localhost",
  "requestOptions": {
    "challenge": "login-challenge",
    "rpId": "localhost"
  },
  "credential": {
    "id": "credential-123",
    "userId": "user-123",
    "rpId": "localhost",
    "algorithm": -7,
    "publicKey": "public-key-bytes",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
    "signCount": 0
  }
}
EOF
```

This returns JSON containing:
- `assertionResponse` — the login payload to POST to your server
- `credential` — the updated credential metadata, including the incremented sign counter

## Typical test flow

1. Call `register-response` with WebAuthn creation options from your app.
2. Save the returned `credential` in your test fixture.
3. Call `login-response` later with request options plus that credential.
4. Send the generated payloads to your registration/login endpoints.

This keeps backend WebAuthn tests fast, deterministic, and independent of browser automation.
