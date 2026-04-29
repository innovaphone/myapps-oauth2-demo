# Handoff: Missing OAuth2 `LoginResult.digest` Verification in `cli.js`

## Problem summary

`cli.js` currently completes OAuth2 login after deriving the ECDH shared secret and decrypting the session credentials, but it does **not** verify the PBX-provided `LoginResult.digest` for OAuth2 logins.

This is a protocol/security gap. The SDK documentation in:

```text
C:\dvl\17\apps-js\kubernetes\sdk\doc\appwebsocket\myApps.htm
```

states that successful `LoginResult` messages include a `digest` that verifies:

1. the server knows the correct shared secret, and
2. the integrity of the included `info` object.

For OAuth2, the “password” used in this digest is **not** a user password or OAuth token. It is the ECDH shared secret derived from:

```text
ECDH(secp256r1, <client-private-key>, <Login.keyShare>, <LoginResult.info.keyShare>)
```

Current `cli.js` skips this verification and instead trusts the PBX result.

---

## Affected file

```text
cli.js
```

Relevant current area: OAuth2 success path in `loginWithOauth2At()`, around the block that computes:

```js
const sharedSecretHex = computeSharedSecretHex(ecdh, msg.info.keyShare);
```

The current code then does:

```js
// For OAuth2, the PBX has already authenticated the user via the IdP.
// We trust the result and just use the username from the response.
const username = msg.info.user && msg.info.user.sip ? msg.info.user.sip : 'unknown';
console.log(`[info] OAuth2 login successful for user: ${username}`);
```

This is incorrect/incomplete for two reasons:

1. OAuth2 `LoginResult.digest` should be verified.
2. The SDK `myApps.htm` documents `Info` as a flat object with `info.sip`, not necessarily `info.user.sip`.

---

## Protocol reference from `myApps.htm`

The `LoginResult` digest is documented as:

```text
Hexstring(SHA256(
  innovaphoneAppClient:loginresult:
  <domain>:<username>:<password>:<nonce>:<challenge>:<info>
))
```

For OAuth2:

```text
<username> = SIP URI from LoginResult.info.sip
<password> = Hexstring(ECDH(secp256r1, <private-key>, <Login.keyShare>, <LoginResult.info.keyShare>))
```

The `info` value must be JSON-encoded without unnecessary whitespace. In JavaScript/Node this project already uses `JSON.stringify(infoObject)`, which matches the SDK note for JavaScript.

Existing helper already available in `cli.js`:

```js
function buildLoginResultDigest(domain, username, password, nonce, challenge, infoObject) {
  return sha256Hex(`innovaphoneAppClient:loginresult:${domain}:${username}:${password}:${nonce}:${challenge}:${JSON.stringify(infoObject)}`);
}
```

So the fix does not require a new digest algorithm.

---

## Why this matters

Without OAuth2 `LoginResult.digest` verification, the client accepts the `LoginResult.info` structure without proving that it was protected by the ECDH shared secret.

The digest protects important fields such as:

- `info.sip`
- `info.dn`
- `info.email`
- `info.session.usr`
- `info.session.pwd`
- `info.keyShare`
- redirect/alternative PBX metadata when present

A correct client should reject the login if:

- `digest` is missing,
- `info.keyShare` is missing,
- the SIP username cannot be determined, or
- the calculated digest differs from `LoginResult.digest`.

---

## Proposed fix

### 1. Add robust helpers for `Info` user fields

The SDK documentation shows flat fields:

```json
{
  "sip": "usr",
  "dn": "User One",
  "email": "usr@example.com"
}
```

Some reports/client variants may use nested fields:

```json
{
  "user": {
    "sip": "usr",
    "dn": "User One",
    "email": "usr@example.com"
  }
}
```

To avoid version/shape issues, add helpers near the other utility functions:

```js
function infoSip(info) {
  return info && (info.sip || (info.user && info.user.sip));
}

function infoDisplayName(info) {
  return info && (info.dn || (info.user && info.user.dn));
}

function infoEmail(info) {
  return info && (info.email || (info.user && info.user.email));
}
```

`infoEmail()` may not be needed immediately, but it keeps the shape handling consistent.

---

### 2. Verify OAuth2 `LoginResult.digest`

Replace the trust-only OAuth2 success logic in `loginWithOauth2At()` with explicit verification.

Current block to replace starts after:

```js
const sharedSecretHex = computeSharedSecretHex(ecdh, msg.info.keyShare);
```

Recommended replacement:

```js
const sharedSecretHex = computeSharedSecretHex(ecdh, msg.info.keyShare);
const username = infoSip(msg.info);

if (!username) {
  throw new Error('OAuth2 LoginResult did not contain info.sip.');
}

if (!msg.digest) {
  throw new Error('OAuth2 LoginResult did not contain digest.');
}

const expectedDigest = buildLoginResultDigest(
  auth.domain,
  username,
  sharedSecretHex,
  nonce,
  auth.challenge,
  msg.info
);

if (expectedDigest !== msg.digest) {
  throw new Error('OAuth2 LoginResult digest verification failed.');
}

console.log(`[info] OAuth2 login successful for user: ${username}`);
```

Then keep the existing session extraction/persistence logic:

```js
const session = this.extractSessionFromInfo(msg.info, nonce, sharedSecretHex);
if (!session) {
  throw new Error('OAuth2 login succeeded but no session credentials were present in LoginResult.info.session.');
}

this.persistSession(wsUrl, session);
return {
  wsUrl,
  session,
  userLabel: username || infoDisplayName(msg.info)
};
```

Prefer:

```js
userLabel: username || infoDisplayName(msg.info) || 'unknown'
```

although `username` should already be mandatory by this point.

---

### 3. Update session-login user label extraction

Current session login user label also assumes nested `msg.info.user.sip`:

```js
const userLabel = msg.info && msg.info.user && msg.info.user.sip 
  ? msg.info.user.sip 
  : (msg.info && msg.info.user && msg.info.user.dn 
     ? msg.info.user.dn 
     : session.username);
```

Replace with:

```js
const userLabel = infoSip(msg.info) || infoDisplayName(msg.info) || session.username;
```

This is not the main security bug, but it is part of the same incorrect `Info` shape assumption.

---

### 4. Update `getOauthUserCandidates()` to support both `Info` shapes

Current code supports the flat SDK shape only:

```js
getOauthUserCandidates(info) {
  const set = new Set();
  if (typeof info.sip === 'string' && info.sip) set.add(info.sip);
  if (typeof info.email === 'string' && info.email) set.add(info.email);
  if (typeof info.dn === 'string' && info.dn) set.add(info.dn);
  return Array.from(set);
}
```

Recommended replacement:

```js
getOauthUserCandidates(info) {
  const set = new Set();
  if (!info) return [];

  const user = info.user || info;

  if (typeof user.sip === 'string' && user.sip) set.add(user.sip);
  if (typeof user.email === 'string' && user.email) set.add(user.email);
  if (typeof user.dn === 'string' && user.dn) set.add(user.dn);

  return Array.from(set);
}
```

This mostly affects redirect digest verification for OAuth2.

---

### 5. Remove or rewrite misleading helper/comment

Current helper:

```js
findMatchingLoginResultUsername(domain, candidates, sharedSecretHex, nonce, challenge, msg) {
  // For OAuth2, we trust the PBX and just use the first candidate since we can't verify the digest
  // The PBX has already authenticated the user via OAuth2
  return candidates.length > 0 ? candidates[0] : null;
}
```

This comment is contradicted by `myApps.htm`. OAuth2 `LoginResult.digest` **is verifiable** after receiving `LoginResult.info.sip` and `LoginResult.info.keyShare`.

If the helper is unused, delete it. If it should be kept, rewrite it to verify digest candidates:

```js
findMatchingLoginResultUsername(domain, candidates, sharedSecretHex, nonce, challenge, msg) {
  if (!msg.digest) return null;
  for (const candidate of candidates) {
    const expected = buildLoginResultDigest(domain, candidate, sharedSecretHex, nonce, challenge, msg.info);
    if (expected === msg.digest) return candidate;
  }
  return null;
}
```

However, for `LoginResult`, using `infoSip(msg.info)` directly is simpler and closer to the protocol.

---

## Optional hardening related to the same area

### Require digest for successful session login too

Current session login checks digest only if present:

```js
if (msg.digest && expected !== msg.digest) {
  throw new Error('LoginResult digest verification failed during session login.');
}
```

For successful `LoginResult`, the SDK documents `digest` as present. Consider changing to:

```js
if (!msg.digest) {
  throw new Error('Session LoginResult did not contain digest.');
}
if (expected !== msg.digest) {
  throw new Error('LoginResult digest verification failed during session login.');
}
```

### Require digest for redirects

Similarly, current redirect verification is conditional:

```js
if (msg.digest && expected !== msg.digest) {
  throw new Error('Redirect digest verification failed during session login.');
}
```

Consider requiring it for all successful `Redirect` messages:

```js
if (!msg.digest) {
  throw new Error('Redirect did not contain digest.');
}
if (expected !== msg.digest) {
  throw new Error('Redirect digest verification failed.');
}
```

---

## Testing notes

After implementing the fix:

1. Run syntax check:

   ```bash
   npm run check
   ```

2. Run first-time OAuth2 login with verbose logging:

   ```bash
   node cli.js --ws-url <wss-url> --verbose
   ```

3. Confirm the CLI logs OAuth2 success only after digest verification.

4. Confirm session file is written after OAuth2 login.

5. Run again and confirm session reuse still works:

   ```bash
   node cli.js --ws-url <wss-url>
   ```

6. If digest verification fails unexpectedly, capture the raw `LoginResult` from `--verbose`. The most likely causes are:

   - wrong username field shape (`info.sip` vs `info.user.sip`),
   - JSON serialization mismatch,
   - unexpected PBX version behavior,
   - wrong ECDH shared-secret format.

The SDK documentation says JavaScript `JSON.stringify()` is acceptable for the `info` encoding, so field-shape and shared-secret issues should be checked first.

---

## Acceptance criteria

The fix is complete when:

- OAuth2 `LoginResult` with missing `digest` is rejected.
- OAuth2 `LoginResult` with mismatched `digest` is rejected.
- OAuth2 `LoginResult` with valid `digest` succeeds.
- OAuth2 digest verification uses:
  - `auth.domain`,
  - SIP username from `info.sip` or compatible helper,
  - ECDH shared secret from `info.keyShare`,
  - the client nonce from the OAuth2 `Login` message,
  - `auth.challenge`,
  - exact `msg.info` object serialized with `JSON.stringify()`.
- User label extraction works with flat SDK `Info` objects.
- Misleading comments claiming OAuth2 digest verification is impossible are removed.
