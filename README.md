# innovaphone myApps OAuth2 CLI Demo

A Node.js CLI demo that authenticates to innovaphone myApps using OAuth2/SSO and then saves the session credentials from the PBX for reuse in subsequent `type:"session"` logins.

For a detailed technical explanation of the login flow, see [MYAPPS_OAUTH20.md](MYAPPS_OAUTH20.md).

## What This Demo Does

- Connects to the innovaphone PBX via WebSocket
- Queries available login methods via `LoginInfo`
- First attempts a saved session login (`type:"session"`, `method:"digest"`)
- Falls back to OAuth2/SSO if no session exists or is expired
- Prints the SSO URL from the PBX to the console
- Waits for `Authorize`, `LoginResult`, or `Redirect` over the same WebSocket
- Correctly decrypts session credentials using the **ECDHE shared secret**
- Saves Session-ID and Session-Password locally for the next start

## Important Note About the Browser Flow

This demo does **not** start a local HTTP server and does **not** intercept redirect URLs.

Instead, the flow is:

1. CLI initiates OAuth2 login over WebSocket
2. PBX provides `Authenticate.url` for OAuth2
3. CLI prints this URL to the console
4. You manually copy it to your browser
5. Browser runs the normal innovaphone/IdP flow against the PBX-configured redirect URI
6. After successful SSO, the PBX sends the result back **over the existing WebSocket** to the CLI

This matches the innovaphone documentation closely and is much more practical for a CLI than browser integration.

## Prerequisites

- Node.js 18+
- Access to the innovaphone WebSocket URL
- Correctly configured OAuth2/OpenID integration on the PBX
- HTTPS/WSS connectivity to the PBX

## Installation

```bash
npm install
```

## Usage

### Option 1: Specify WebSocket URL directly

```bash
node cli.js --ws-url wss://pbx.example.com/PBX0/WEBSOCKET/websocket
```

### Option 2: Build URL from host + module

```bash
node cli.js --host pbx.example.com --module PBX0 --ws-path /WEBSOCKET/websocket
```

### For self-signed certificates

```bash
node cli.js --ws-url wss://pbx.example.com/PBX0/WEBSOCKET/websocket --insecure
```

### Explicit session file location

```bash
node cli.js --ws-url wss://pbx.example.com/PBX0/WEBSOCKET/websocket --session-file ./.innovaphone-session.json
```

### Delete saved session

```bash
node cli.js --clear-session --session-file ./.innovaphone-session.json
```

## Options

- `--ws-url <url>`: Complete WebSocket URL
- `--host <hostname>`: PBX hostname
- `--module <PBX0>`: PBX module, default `PBX0`
- `--ws-path <path>`: WebSocket path, default `/WEBSOCKET/websocket`
- `--session-file <path>`: JSON file for session storage
- `--user-agent <text>`: User-Agent for login messages
- `--insecure`: Skip TLS certificate verification
- `--verbose`: Log raw messages
- `--clear-session`: Delete session file and exit
- `--no-session-reuse`: Skip saved session login attempt
- `--login-timeout <seconds>`: Timeout for login phases, default `300`

## Typical Flow

### First Start

```text
$ node cli.js --ws-url wss://pbx.example.com/PBX0/WEBSOCKET/websocket --verbose
[info] No saved session found.
[send] {"mt":"LoginInfo"}
[recv] {"mt":"LoginInfo", ...}
[send] {"mt":"Login","type":"user","userAgent":"innovaphone SSO CLI Demo"}
[recv] {"mt":"Authenticate","type":"user","method":"oauth2","url":"https://idp.example/...","challenge":"..."}

Open this SSO URL in your browser:
https://idp.example/...

Waiting for PBX to complete the OAuth2 flow...
```

After successful browser login, the demo saves the session credentials locally.

### Second Start

```text
$ node cli.js --ws-url wss://pbx.example.com/PBX0/WEBSOCKET/websocket
[info] Found saved session. Trying session login first...
[info] Session login successful.
```

## Technical Details

This demo implements the key points from the innovaphone documentation:

- Subsequent logins with a valid session go through `type:"session"` with `method:"digest"` — no OAuth2 flow needed
- For the first OAuth2 login, an **ECDHE key share** is generated
- The **shared secret** is not the `keyShare` itself, but the result of ECDH over the private key, your own `Login.keyShare`, and the PBX's `info.keyShare`
- `info.session.usr` and `info.session.pwd` are decrypted with RC4 using the **shared secret**
- For session login, the saved **Session-ID** is used as `username` and the saved **Session-Password** for the digest
- A **new nonce** is generated for each login attempt

## Limitations

- Demo code, not a complete production client
- No NTLM support
- No local browser callback server
- Redirect cases are handled in a simple, traceable form only
- JSON serialization for digest verification uses `JSON.stringify()` and should match the PBX structure; for a highly defensive production implementation, you would preserve the exact original `info` serialization from the received JSON

## Session File Contents

The session file intentionally contains the **decrypted** session credentials so that re-login can be demonstrated. This is practical for a demo but security-sensitive.

For production use, these should be encrypted or stored in the OS Keychain / Credential Store.

## Protocol Reference

For the complete myApps protocol documentation, see:  
https://sdk.innovaphone.com/16r1/doc/appwebsocket/myApps.htm
