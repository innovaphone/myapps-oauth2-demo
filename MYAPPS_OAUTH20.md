# myApps OAuth2 and Session Reuse Login Flow

This document describes the complete login flow for the innovaphone myApps protocol, focusing on OAuth2-based user authentication and subsequent session reuse.

## Overview

The login process has two main paths:

1. **OAuth2 Flow** (first login): Authenticates the user via an external Identity Provider (IdP) like Keycloak/Active Directory. Creates a persistent session on the PBX.

2. **Session Reuse Flow** (subsequent logins): Reuses the session credentials from a previous successful OAuth2 login. Much faster and doesn't require browser interaction.

## Message Flow Diagrams

### OAuth2 Flow (First Login)

```
Client                          PBX                              IdP (Keycloak/AD)
  |                               |                                  |
  |--- LoginInfo ---------------->|                                  |
  |<-- LoginInfoResult ----------|                                  |
  |                               |                                  |
  |--- Login ------------------->|                                  |
  |    type=user, method=oauth2  |                                  |
  |    nonce, keyShare           |                                  |
  |                               |--- Redirect to IdP ------------->|
  |                               |<-- Authenticate (url, challenge)-|
  |<-- Authenticate (url) ---------|                                  |
  |                               |                                  |
  |  [Browser: User authenticates at IdP and approves 2FA]         |
  |                               |                                  |
  |<-- Authorize (2FA code) ------|  (if 2FA enabled)                |
  |                               |                                  |
  |<-- LoginResult ----------------|  (success + session credentials)|
  |    [info.keyShare, info.session, digest]                          |
  |                               |                                  |
  |  [Verify digest, decrypt session, save to file]                  |
  |                               |                                  |
```

### Session Reuse Flow (Subsequent Logins)

```
Client                          PBX
  |                               |
  |--- LoginInfo ---------------->|
  |<-- LoginInfoResult -----------|
  |                               |
  |  [Read saved session from file]
  |                               |
  |--- Login (type=session) ----->|
  |<-- Authenticate (challenge) ---|
  |                               |
  |--- Login (type=session, ----->|
  |      method=digest,           |
  |      username, nonce,         |
  |      response)                 |
  |                               |
  |<-- LoginResult ----------------|
  |                               |
```

---

## Step-by-Step Process

### 1. Initial Connection

Client -> PBX:
```json
{"mt": "LoginInfo"}
```

PBX -> Client:
```json
{
  "mt": "LoginInfoResult",
  "user": {
    "digest": false,
    "ntlm": false,
    "oauth2": true,
    "oauth2Name": "Windows"
  },
  "session": {
    "digest": true
  }
}
```

The `session.digest: true` indicates that session-based login (reusing credentials) is available.

---

### 2. OAuth2 Login (No saved session)

#### Step 2.1: First Login Request with ECDHE Key Share

Client -> PBX:
```json
{
  "mt": "Login",
  "type": "user",
  "method": "oauth2",
  "nonce": "16-char-hex-random-nonce",
  "keyShare": "128-char-hex-uncompressed-public-key",
  "userAgent": "myApps (Windows)"
}
```

**Generating the keyShare:**

```javascript
const crypto = require('crypto');

function generateKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const publicKey = ecdh.getPublicKey();
  
  // Remove the 0x04 prefix byte (uncompressed format)
  const keyShareHex = publicKey.subarray(1).toString('hex');
  
  return { ecdh, keyShareHex };
}

// keyShare is 64 bytes = 128 hex characters
```

#### Step 2.2: Receive Authentication Request

PBX -> Client:
```json
{
  "mt": "Authenticate",
  "type": "user",
  "method": "oauth2",
  "domain": "example.com",
  "url": "https://keycloak.example.com/realms/.../auth?client_id=innovaphone&...",
  "challenge": "opaque-challenge-string"
}
```

The `url` is the SSO login page. The client displays this URL for the user.

#### Step 2.3: User Authentication in Browser

1. User opens the SSO URL in a browser
2. User authenticates with their IdP (Windows/AD credentials)
3. If 2FA is enabled, user approves the request on another device
4. IdP redirects back to the PBX with the authentication result

#### Step 2.4: 2FA Authorization (if enabled)

PBX -> Client:
```json
{
  "mt": "Authorize",
  "code": 5774
}
```

Display this code to the user so they can verify they're approving the correct session.

#### Step 2.5: Login Result

PBX -> Client:
```json
{
  "mt": "LoginResult",
  "info": {
    "user": {
      "domain": "example.com",
      "sip": "usr",
      "guid": "9f7b5d1fef717f4eb61e06167d42179a",
      "dn": "User One",
      "num": "23",
      "email": "usrnk@example.com",
      "onboarded": true
    },
    "session": {
      "usr": "encrypted-hex-string",
      "pwd": "encrypted-hex-string"
    },
    "keyShare": "128-char-hex-public-key",
    "alt": "pbx.example.com/PBX0",
    "master": "pbx.example.com/PBX0",
    "altMaster": true
  },
  "digest": "sha256-hex-string"
}
```

#### Step 2.6: Computing the Shared Secret

```javascript
const crypto = require('crypto');

function computeSharedSecret(ecdh, peerKeyShareHex) {
  // Prepend 0x04 to indicate uncompressed point format
  const peerKey = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(peerKeyShareHex, 'hex')
  ]);
  
  return ecdh.computeSecret(peerKey).toString('hex');
}

// sharedSecret is 32 bytes = 64 hex characters
```

#### Step 2.7: Verifying the OAuth2 LoginResult Digest

After receiving `LoginResult`, the client now verifies the PBX-provided digest before trusting `info` or saving the session. For OAuth2, the digest password is the ECDHE shared secret and the digest username is the SIP URI from `info.user.sip`.

The current `cli.js` also accepts legacy/protocol-compatible flat user fields by checking `info.sip` if `info.user.sip` is not present.

```javascript
function getInfoSip(info) {
  return info && (info.sip || (info.user && info.user.sip));
}

function buildLoginResultDigest(domain, username, password, nonce, challenge, info) {
  return sha256Hex(
    `innovaphoneAppClient:loginresult:${domain}:${username}:${password}:${nonce}:${challenge}:${JSON.stringify(info)}`
  );
}

const sharedSecretHex = computeSharedSecret(ecdh, info.keyShare);
const username = getInfoSip(info);             // usually info.user.sip on current PBX versions

if (!username) throw new Error('OAuth2 LoginResult did not contain a SIP user.');
if (!loginResult.digest) throw new Error('OAuth2 LoginResult did not contain digest.');

const expectedDigest = buildLoginResultDigest(
  authenticate.domain,
  username,
  sharedSecretHex,
  oauthLoginNonce,
  authenticate.challenge,
  info
);

if (expectedDigest !== loginResult.digest) {
  throw new Error('OAuth2 LoginResult digest verification failed.');
}
```

This was verified against a real PBX with `info.user.sip` and a valid OAuth2 `LoginResult.digest`.

#### Step 2.8: Decrypting Session Credentials

The session credentials are encrypted using RC4 with a key derived from the ECDHE shared secret.

```javascript
const crypto = require('crypto');

function rc4Decrypt(keyString, cipherHex) {
  const keyBytes = Buffer.from(keyString, 'utf8');
  const cipherBytes = Buffer.from(cipherHex, 'hex');
  
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + keyBytes[i % keyBytes.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  
  const out = Buffer.alloc(cipherBytes.length);
  i = 0; j = 0;
  for (let idx = 0; idx < cipherBytes.length; idx++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    out[idx] = cipherBytes[idx] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

// RC4 key format: innovaphoneAppClient:usr:<nonce>:<sharedSecret>
const rc4KeyUser = `innovaphoneAppClient:usr:${nonce}:${sharedSecretHex}`;
const rc4KeyPwd  = `innovaphoneAppClient:pwd:${nonce}:${sharedSecretHex}`;

const sessionUsername = rc4Decrypt(rc4KeyUser, info.session.usr).toString('utf8');
const sessionPassword = rc4Decrypt(rc4KeyPwd,  info.session.pwd).toString('utf8');
```

**Important:** The `nonce` here is the one from the OAuth2 `Login` message sent with `type:user`, `method:oauth2`, `nonce` and `keyShare`.

#### Step 2.9: Saving the Session

```json
{
  "wsUrl": "wss://ap.example.com/.../websocket",
  "savedAt": "2026-04-22T17:24:42.717Z",
  "session": {
    "username": "2017862910f54b42b0dc5a8b48509487",
    "password": "CJv8T5QopMHnuEjpau9vkMM"
  }
}
```

---

### 3. Session Reuse Login (Subsequent Logins)

#### Step 3.1: Read Saved Session

```javascript
const session = JSON.parse(fs.readFileSync(sessionFilePath, 'utf8')).session;
// session.username = "2017862910f54b42b0dc5a8b48509487"
// session.password = "CJv8T5QopMHnuEjpau9vkMM"
```

#### Step 3.2: Session Login Request

Client -> PBX:
```json
{
  "mt": "Login",
  "type": "session",
  "userAgent": "myApps (Windows)"
}
```

#### Step 3.3: Receive Challenge

PBX -> Client:
```json
{
  "mt": "Authenticate",
  "type": "session",
  "method": "digest",
  "domain": "example.com",
  "challenge": "opaque-challenge-string"
}
```

#### Step 3.4: Calculate Digest Response

```javascript
const crypto = require('crypto');

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function buildDigestResponse(domain, username, password, nonce, challenge) {
  return sha256Hex(
    `innovaphoneAppClient:session:${domain}:${username}:${password}:${nonce}:${challenge}`
  );
}

// digest = SHA256("innovaphoneAppClient:session:example.com:2017862910f54b42b0dc5a8b48509487:CJv8T5QopMHnuEjpau9vkMM:742a7df3180dd0eb:18bbf2255ea04bad")
```

#### Step 3.5: Send Credentials

Client -> PBX:
```json
{
  "mt": "Login",
  "type": "session",
  "method": "digest",
  "username": "2017862910f54b42b0dc5a8b48509487",
  "nonce": "742a7df3180dd0eb",
  "response": "7dd61942eeb98364d74edf6cada7a21ac05cf1069fabf35b8a29453730c855d9",
  "userAgent": "myApps (Windows)"
}
```

#### Step 3.6: Login Result

PBX -> Client:
```json
{
  "mt": "LoginResult",
  "info": {
    "user": {
      "domain": "example.com",
      "sip": "usr",
      "guid": "...",
      "dn": "User One"
    }
  },
  "digest": "sha256-hex-string"
}
```

#### Step 3.7: Verify LoginResult Digest

The PBX includes a digest to prove the response authenticity and protect the integrity of `info`. For session login, the current CLI verifies it if the PBX provides it:

```javascript
function buildLoginResultDigest(domain, username, password, nonce, challenge, info) {
  return sha256Hex(
    `innovaphoneAppClient:loginresult:${domain}:${username}:${password}:${nonce}:${challenge}:${JSON.stringify(info)}`
  );
}

// Verify: computed digest === msg.digest
```

**Note:** `JSON.stringify(info)` must match the PBX's serialization exactly. The SDK documentation states that JavaScript `JSON.stringify()` is the expected encoding. OAuth2 digest verification is possible after receiving `LoginResult`, because the username is available as `info.user.sip` (or legacy `info.sip`) and the password is the ECDHE shared secret derived from `info.keyShare`.

---

## Digest Calculation Reference

### Response Digest (for Login message with method=digest)

```
SHA256("innovaphoneAppClient:<type>:<domain>:<username>:<password>:<nonce>:<challenge>")
```

- `<type>`: "session" for session login, "user" for user login
- `<domain>`: From Authenticate message (e.g., "example.com")
- `<username>`: Session ID for session login, SIP URI for user login
- `<password>`: Session password for session login, user password for user login
- `<nonce>`: 16-character hex string encoding 8 random bytes from the client
- `<challenge>`: opaque challenge string from the Authenticate message

### LoginResult Digest (for verifying LoginResult)

```
SHA256("innovaphoneAppClient:loginresult:<domain>:<username>:<password>:<nonce>:<challenge>:<info-json>")
```

For OAuth2:

- `<username>`: `LoginResult.info.user.sip` on current PBX versions, or `LoginResult.info.sip` for legacy flat `Info` objects
- `<password>`: ECDHE shared secret calculated from the client private key and `LoginResult.info.keyShare`
- `<nonce>`: the nonce sent in the OAuth2 `Login` message
- `<challenge>`: the challenge from the OAuth2 `Authenticate` message
- `<info-json>`: `JSON.stringify(LoginResult.info)`

### Redirect Digest (for verifying Redirect)

```
SHA256("innovaphoneAppClient:redirect:<username>:<password>:<nonce>:<challenge>:<info-json>")
```

---

## Session Expiration Handling

If a session login fails with error 5 ("Session expired"):

1. Delete the saved session file
2. Fall back to OAuth2 login
3. The user must authenticate via browser again
4. New session credentials will be saved

```javascript
if (auth.mt === 'LoginResult' && auth.error === 5) {
  // Session expired, fall back to OAuth2
  deleteSessionFile();
  return oauth2Login();
}
```

---

## Key Security Considerations

1. **Session credentials are stored in plain text** in the session file. In production, these should be encrypted or stored in a secure keychain.

2. **Shared secret never leaves the client** - The ECDHE key exchange ensures the shared secret is computed locally and never transmitted.

3. **Digest verification** proves the server knows the shared secret and that the response hasn't been tampered with. The CLI now requires OAuth2 `LoginResult.digest` to be present and valid before it saves session credentials.

4. **Nonce prevents replay attacks** - Each login uses a fresh random nonce.

5. **2FA protection** - Even if credentials are compromised, the session can't be used without approving the 2FA request on another channel.

---

## Complete Example Session

### Saved Session File

```json
{
  "wsUrl": "wss://ap.example.com/example.com/ip/PBX0/APPCLIENT/1610855/websocket",
  "savedAt": "2026-04-22T17:24:42.717Z",
  "session": {
    "username": "2017862910f54b42b0dc5a8b48509487",
    "password": "CJv8T5QopMHnuEjpau9vkMM"
  }
}
```

### Successful Session Login

Client -> PBX:
```json
{"mt": "LoginInfo"}
```

PBX -> Client:
```json
{"mt": "LoginInfoResult", "user": {"oauth2": true}, "session": {"digest": true}}
```

Client -> PBX:
```json
{"mt": "Login", "type": "session", "userAgent": "myApps CLI"}
```

PBX -> Client:
```json
{"mt": "Authenticate", "type": "session", "method": "digest", "domain": "example.com", "challenge": "0fd218502ba3f903"}
```

Client -> PBX:
```json
{
  "mt": "Login",
  "type": "session",
  "method": "digest",
  "username": "2017862910f54b42b0dc5a8b48509487",
  "nonce": "d748d16303e83301",
  "response": "7d15dc8ac48400c5...",
  "userAgent": "myApps CLI"
}
```

PBX -> Client:
```json
{
  "mt": "LoginResult",
  "info": {
    "user": {
      "sip": "usr",
      "dn": "User One"
    }
  },
  "digest": "sha256-hex-string"
}
```

---

## Flow Decision Tree

```
START
  |
  v
Read saved session file
  |
  v
Send LoginInfo
  |
  v
LoginInfoResult received
  |
  +-- session.digest == true AND saved session exists?
  |     |
  |     +-- YES: Try session login
  |     |     |
  |     |     +-- Success: Done (logged in as user)
  |     |     +-- Error 5 (expired): Go to OAuth2
  |     |     +-- Other error: Exit with error
  |     |
  |     +-- NO: Go to OAuth2
  |
  +-- session.digest == false OR no session support?
        |
        +-- OAuth2 login required
        |
        v
OAuth2 Login
  |
  v
Generate ECDHE key pair
  |
  v
Send Login (type=user, method=oauth2, nonce, keyShare)
  |
  v
Receive Authenticate (url)
  |
  v
Display SSO URL, user authenticates in browser
  |
  v
Receive Authorize (2FA code) or proceed
  |
  v
Receive LoginResult with session credentials
  |
  v
Verify LoginResult digest using info.user.sip and ECDHE shared secret
  |
  v
Decrypt session with ECDHE shared secret
  |
  v
Save session to file
  |
  v
Done (logged in as user)
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1 | Invalid parameters | Malformed request |
| 2 | Authentication failed | Wrong credentials |
| 5 | Session expired | Saved session no longer valid |

---

## Protocol Reference

This document is based on the [innovaphone myApps Protocol documentation](https://sdk.innovaphone.com/16r1/doc/appwebsocket/myApps.htm).

Key message types:

- `LoginInfo` / `LoginInfoResult` - Query available authentication methods
- `Login` - Initial login request or credentials submission
- `Authenticate` - Challenge response with method details
- `Authorize` - 2FA authorization request
- `LoginResult` - Login success or failure
- `Redirect` - Redirection to different PBX