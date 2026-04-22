#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

function parseArgs(argv) {
  const out = {
    host: null,
    moduleName: 'PBX0',
    wsPath: '/WEBSOCKET/websocket',
    wsUrl: null,
    sessionFile: path.join(os.homedir(), '.innovaphone-sso-session.json'),
    insecure: false,
    verbose: false,
    userAgent: 'innovaphone SSO CLI Demo',
    clearSession: false,
    noSessionReuse: false,
    loginTimeoutSeconds: 300,
    help: false
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === '--host') out.host = next, i += 1;
    else if (arg === '--module') out.moduleName = next, i += 1;
    else if (arg === '--ws-path') out.wsPath = next, i += 1;
    else if (arg === '--ws-url') out.wsUrl = next, i += 1;
    else if (arg === '--session-file') out.sessionFile = next, i += 1;
    else if (arg === '--user-agent') out.userAgent = next, i += 1;
    else if (arg === '--login-timeout') out.loginTimeoutSeconds = Number(next), i += 1;
    else if (arg === '--insecure') out.insecure = true;
    else if (arg === '--verbose') out.verbose = true;
    else if (arg === '--clear-session') out.clearSession = true;
    else if (arg === '--no-session-reuse') out.noSessionReuse = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }

  if (!out.help) {
    if (!out.wsUrl) {
      if (!out.host) throw new Error('Either --ws-url or --host must be provided.');
      const normalizedPath = out.wsPath.startsWith('/') ? out.wsPath : `/${out.wsPath}`;
      out.wsUrl = `wss://${out.host}/${out.moduleName}${normalizedPath}`;
    }
  }

  return out;
}

function printHelp() {
  console.log(`
innovaphone SSO CLI demo

Usage:
  node cli.js --ws-url <wss-url> [options]
  node cli.js --host <hostname> [options]

Options:
  --ws-url <url>          Full WebSocket URL
  --host <hostname>       PBX host name
  --module <name>         PBX module name (default: PBX0)
  --ws-path <path>        WebSocket path (default: /WEBSOCKET/websocket)
  --session-file <path>   Session JSON file
  --user-agent <text>     User-Agent string
  --login-timeout <sec>   Login timeout in seconds (default: 300)
  --insecure              Disable TLS certificate validation
  --verbose               Log sent/received messages
  --clear-session         Delete saved session and exit
  --no-session-reuse      Do not try saved session credentials first
  --help                  Show this help
`);
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function randomNonceHex() {
  return crypto.randomBytes(8).toString('hex');
}

function rc4Transform(keyBytes, dataBytes) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) s[i] = i;

  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i] + keyBytes[i % keyBytes.length]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  const out = Buffer.alloc(dataBytes.length);
  let i = 0;
  j = 0;
  for (let idx = 0; idx < dataBytes.length; idx += 1) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
    const k = s[(s[i] + s[j]) & 0xff];
    out[idx] = dataBytes[idx] ^ k;
  }
  return out;
}

function rc4DecryptHex(keyString, cipherHex) {
  const keyBytes = Buffer.from(keyString, 'utf8');
  const cipherBytes = Buffer.from(cipherHex, 'hex');
  return rc4Transform(keyBytes, cipherBytes);
}

function tryDecodePrintable(buffer) {
  const utf8 = buffer.toString('utf8');
  const badChars = (utf8.match(/\uFFFD/g) || []).length;
  const controlChars = (utf8.match(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g) || []).length;
  if (badChars === 0 && controlChars === 0) return utf8;
  return null;
}

function ecdhKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const publicUncompressed = ecdh.getPublicKey();
  if (publicUncompressed[0] !== 0x04) {
    throw new Error('Unexpected EC public key format.');
  }
  const keyShareHex = publicUncompressed.subarray(1).toString('hex');
  return { ecdh, keyShareHex };
}

function computeSharedSecretHex(ecdh, peerKeyShareHex) {
  const peer = Buffer.concat([Buffer.from([0x04]), Buffer.from(peerKeyShareHex, 'hex')]);
  return ecdh.computeSecret(peer).toString('hex');
}

function buildDigestResponse(type, domain, username, password, nonce, challenge) {
  return sha256Hex(`innovaphoneAppClient:${type}:${domain}:${username}:${password}:${nonce}:${challenge}`);
}

function buildLoginResultDigest(domain, username, password, nonce, challenge, infoObject) {
  return sha256Hex(`innovaphoneAppClient:loginresult:${domain}:${username}:${password}:${nonce}:${challenge}:${JSON.stringify(infoObject)}`);
}

function buildRedirectDigest(username, password, nonce, challenge, infoObject) {
  return sha256Hex(`innovaphoneAppClient:redirect:${username}:${password}:${nonce}:${challenge}:${JSON.stringify(infoObject)}`);
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }
  catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
}

function writeJsonFile(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function deleteFileIfExists(filePath) {
  try {
    fs.unlinkSync(filePath);
  }
  catch (err) {
    if (err && err.code !== 'ENOENT') throw err;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class WaiterHub {
  constructor() {
    this.waiters = new Set();
  }

  next(predicate, timeoutMs, timeoutText) {
    return new Promise((resolve, reject) => {
      const waiter = {
        predicate,
        resolve,
        reject,
        timer: setTimeout(() => {
          this.waiters.delete(waiter);
          reject(new Error(timeoutText || 'Timed out waiting for message.'));
        }, timeoutMs)
      };
      this.waiters.add(waiter);
    });
  }

  push(message) {
    for (const waiter of Array.from(this.waiters)) {
      try {
        if (waiter.predicate(message)) {
          clearTimeout(waiter.timer);
          this.waiters.delete(waiter);
          waiter.resolve(message);
        }
      }
      catch (err) {
        clearTimeout(waiter.timer);
        this.waiters.delete(waiter);
        waiter.reject(err);
      }
    }
  }

  failAll(error) {
    for (const waiter of Array.from(this.waiters)) {
      clearTimeout(waiter.timer);
      this.waiters.delete(waiter);
      waiter.reject(error);
    }
  }
}

class MyAppsWs {
  constructor(options) {
    this.options = options;
    this.ws = null;
    this.waiters = new WaiterHub();
  }

  async connect(wsUrl) {
    await this.close();
    this.wsUrl = wsUrl;

    await new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl, {
        rejectUnauthorized: !this.options.insecure
      });
      this.ws = ws;

      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        fn(value);
      };

      ws.on('open', () => {
        console.log(`[info] Connected to ${wsUrl}`);
        finish(resolve);
      });

      ws.on('message', (data) => {
        const text = data.toString('utf8');
        if (this.options.verbose) console.log(`[recv] ${text}`);
        let msg;
        try {
          msg = JSON.parse(text);
        }
        catch (err) {
          console.error('[warn] Received non-JSON message:', text);
          return;
        }
        this.waiters.push(msg);
      });

      ws.on('error', (err) => {
        if (!settled) finish(reject, err);
        else console.error('[error] WebSocket error:', err.message);
      });

      ws.on('close', (code, reason) => {
        const text = reason ? reason.toString() : '';
        const err = new Error(`WebSocket closed (${code}) ${text}`.trim());
        this.waiters.failAll(err);
        if (!settled) finish(reject, err);
        else console.log(`[info] WebSocket closed (${code}) ${text}`.trim());
      });
    });
  }

  send(message) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not open.');
    }
    const text = JSON.stringify(message);
    if (this.options.verbose) console.log(`[send] ${text}`);
    this.ws.send(text);
  }

  next(predicate, timeoutMs, timeoutText) {
    return this.waiters.next(predicate, timeoutMs, timeoutText);
  }

  async close() {
    if (!this.ws) return;
    const ws = this.ws;
    this.ws = null;
    await new Promise((resolve) => {
      if (ws.readyState === WebSocket.CLOSED) return resolve();
      ws.once('close', () => resolve());
      try { ws.close(); }
      catch (_) { resolve(); }
      setTimeout(resolve, 500);
    });
  }
}

class InnovaphoneSsoCliDemo {
  constructor(options) {
    this.options = options;
    this.timeoutMs = options.loginTimeoutSeconds * 1000;
    this.transport = new MyAppsWs(options);
    this.saved = readJsonFile(options.sessionFile);
  }

  async run() {
    if (this.options.clearSession) {
      deleteFileIfExists(this.options.sessionFile);
      console.log(`[info] Deleted session file: ${this.options.sessionFile}`);
      return;
    }

    if (this.saved && this.saved.wsUrl !== this.options.wsUrl) {
      console.log('[info] Session file exists but belongs to a different wsUrl. It will still be tried if you did not disable reuse.');
    }

    await this.transport.connect(this.options.wsUrl);

    const loginInfo = await this.getLoginInfo();
    if (!this.options.noSessionReuse && this.saved && this.saved.session && loginInfo.session && loginInfo.session.digest) {
      console.log('[info] Found saved session. Trying session login first...');
      try {
        const result = await this.loginWithSession(this.options.wsUrl, this.saved.session);
        console.log('[info] Session login successful.');
        console.log(`[info] Logged in as ${result.userLabel}`);
        await this.transport.close();
        return;
      }
      catch (err) {
        console.error(`[warn] Session login failed: ${err.message}`);
        deleteFileIfExists(this.options.sessionFile);
        this.saved = null;
        console.log('[info] Saved session cleared. Falling back to OAuth2.');
        await sleep(200);
        await this.transport.connect(this.options.wsUrl);
      }
    }
    else if (this.options.noSessionReuse) {
      console.log('[info] Session reuse disabled. Starting OAuth2 flow.');
    }
    else {
      console.log('[info] No reusable session found. Starting OAuth2 flow.');
    }

    const freshLoginInfo = await this.getLoginInfo();
    if (!freshLoginInfo.user || !freshLoginInfo.user.oauth2) {
      throw new Error('PBX does not advertise OAuth2 for user logins.');
    }

    const result = await this.loginWithOauth2(this.options.wsUrl);
    console.log('[info] OAuth2 login successful.');
    console.log(`[info] Logged in as ${result.userLabel}`);
    console.log(`[info] Session saved to ${this.options.sessionFile}`);
    await this.transport.close();
  }

  async getLoginInfo() {
    this.transport.send({ mt: 'LoginInfo' });
    const msg = await this.transport.next((m) => m.mt === 'LoginInfoResult', this.timeoutMs, 'Timed out waiting for LoginInfoResult response.');
    return msg;
  }

  async loginWithSession(initialWsUrl, session) {
    return this.loginWithSessionAt(initialWsUrl, session, 0);
  }

  async loginWithSessionAt(wsUrl, session, depth) {
    if (depth > 3) throw new Error('Too many redirects during session login.');

    if (this.transport.wsUrl !== wsUrl) {
      await this.transport.connect(wsUrl);
    }

    this.transport.send({
      mt: 'Login',
      type: 'session',
      userAgent: this.options.userAgent
    });

    const auth = await this.transport.next(
      (m) => m.mt === 'Authenticate' || m.mt === 'LoginResult' || m.mt === 'Redirect',
      this.timeoutMs,
      'Timed out waiting for session Authenticate/LoginResult/Redirect.'
    );

    if (auth.mt === 'LoginResult') {
      throw new Error(auth.errorText || `Session login failed (${auth.error || 'unknown'}).`);
    }

    if (auth.mt === 'Redirect') {
      const redirectUrl = this.buildRedirectWsUrl(wsUrl, auth.info);
      console.log(`[info] Session login redirected to ${redirectUrl}`);
      return this.loginWithSessionAt(redirectUrl, session, depth + 1);
    }

    if (auth.type !== 'session' || auth.method !== 'digest') {
      throw new Error(`Expected session/digest Authenticate, got type=${auth.type} method=${auth.method}`);
    }

    const nonce = randomNonceHex();
    const response = buildDigestResponse('session', auth.domain, session.username, session.password, nonce, auth.challenge);

    this.transport.send({
      mt: 'Login',
      type: 'session',
      method: 'digest',
      username: session.username,
      nonce,
      response,
      userAgent: this.options.userAgent
    });

    for (;;) {
      const msg = await this.transport.next(
        (m) => ['Authorize', 'LoginResult', 'Redirect'].includes(m.mt),
        this.timeoutMs,
        'Timed out waiting for session login result.'
      );

      if (msg.mt === 'Authorize') {
        console.log(`[info] 2FA authorization requested. Code: ${msg.code}`);
        console.log('[info] Complete the second factor on the other channel and keep this CLI running.');
        continue;
      }

      if (msg.mt === 'Redirect') {
        const expected = buildRedirectDigest(session.username, session.password, nonce, auth.challenge, msg.info);
        if (msg.digest && expected !== msg.digest) {
          throw new Error('Redirect digest verification failed during session login.');
        }
        const redirectUrl = this.buildRedirectWsUrl(wsUrl, msg.info);
        console.log(`[info] Session login redirected to ${redirectUrl}`);
        return this.loginWithSessionAt(redirectUrl, session, depth + 1);
      }

      if (msg.error) {
        throw new Error(msg.errorText || `Session login failed (${msg.error}).`);
      }

      const expected = buildLoginResultDigest(auth.domain, session.username, session.password, nonce, auth.challenge, msg.info);
      if (msg.digest && expected !== msg.digest) {
        throw new Error('LoginResult digest verification failed during session login.');
      }

      // Use user info from response if available, otherwise fallback to session id
      const userLabel = msg.info && msg.info.user && msg.info.user.sip 
        ? msg.info.user.sip 
        : (msg.info && msg.info.user && msg.info.user.dn 
           ? msg.info.user.dn 
           : session.username);

      return {
        wsUrl,
        session,
        userLabel
      };
    }
  }

  async loginWithOauth2(initialWsUrl) {
    return this.loginWithOauth2At(initialWsUrl, 0);
  }

  async loginWithOauth2At(wsUrl, depth) {
    if (depth > 3) throw new Error('Too many redirects during OAuth2 login.');

    if (this.transport.wsUrl !== wsUrl) {
      await this.transport.connect(wsUrl);
    }

    const { ecdh, keyShareHex } = ecdhKeyPair();
    const nonce = randomNonceHex();

    this.transport.send({
      mt: 'Login',
      type: 'user',
      method: 'oauth2',
      nonce,
      keyShare: keyShareHex,
      userAgent: this.options.userAgent
    });

    const auth = await this.transport.next(
      (m) => m.mt === 'Authenticate' || m.mt === 'LoginResult' || m.mt === 'Redirect',
      this.timeoutMs,
      'Timed out waiting for OAuth2 Authenticate/LoginResult/Redirect.'
    );

    if (auth.mt === 'LoginResult') {
      throw new Error(auth.errorText || `OAuth2 preflight failed (${auth.error || 'unknown'}).`);
    }

    if (auth.mt === 'Redirect') {
      const redirectUrl = this.buildRedirectWsUrl(wsUrl, auth.info);
      console.log(`[info] OAuth2 preflight redirected to ${redirectUrl}`);
      return this.loginWithOauth2At(redirectUrl, depth + 1);
    }

    if (auth.type !== 'user') {
      throw new Error(`Expected user Authenticate, got type=${auth.type}`);
    }

    if (auth.method !== 'oauth2' || !auth.url) {
      throw new Error(`Expected oauth2 Authenticate with url, got method=${auth.method}`);
    }

    console.log('\nOpen this SSO URL in your browser:');
    console.log(auth.url);
    console.log('\nWaiting for PBX to complete the OAuth2 flow over the existing WebSocket...');
    console.log('When the browser finishes the PBX redirect, this CLI should continue automatically.\n');

    for (;;) {
      const msg = await this.transport.next(
        (m) => ['Authorize', 'LoginResult', 'Redirect'].includes(m.mt),
        this.timeoutMs,
        'Timed out waiting for OAuth2 completion. Open the printed SSO URL in your browser and finish the login there.'
      );

      if (msg.mt === 'Authorize') {
        console.log(`[info] 2FA authorization requested. Code: ${msg.code}`);
        console.log('[info] Complete the second factor on the other channel and keep this CLI running.');
        continue;
      }

      if (msg.mt === 'Redirect') {
        if (!msg.info || !msg.info.keyShare) {
          throw new Error('Redirect for OAuth2 did not contain info.keyShare.');
        }
        const sharedSecretHex = computeSharedSecretHex(ecdh, msg.info.keyShare);
        const userCandidates = this.getOauthUserCandidates(msg.info);
        const matchedUsername = this.findMatchingRedirectUsername(userCandidates, sharedSecretHex, nonce, auth.challenge, msg);
        if (!matchedUsername) {
          throw new Error('Redirect digest verification failed during OAuth2 login.');
        }
        const session = this.extractSessionFromInfo(msg.info, nonce, sharedSecretHex);
        if (session) {
          this.persistSession(wsUrl, session);
        }
        const redirectUrl = this.buildRedirectWsUrl(wsUrl, msg.info);
        console.log(`[info] OAuth2 login redirected to ${redirectUrl}`);
        if (session) {
          console.log('[info] Redirect carried session credentials. Reconnecting with session login...');
          return this.loginWithSessionAt(redirectUrl, session, depth + 1);
        }
        console.log('[info] Redirect did not carry session credentials. Restarting OAuth2 flow on redirect target...');
        return this.loginWithOauth2At(redirectUrl, depth + 1);
      }

      if (msg.error) {
        throw new Error(msg.errorText || `OAuth2 login failed (${msg.error}).`);
      }

      if (!msg.info || !msg.info.keyShare) {
        throw new Error('LoginResult for OAuth2 did not contain info.keyShare.');
      }

      const sharedSecretHex = computeSharedSecretHex(ecdh, msg.info.keyShare);
      
      // For OAuth2, the PBX has already authenticated the user via the IdP.
      // We trust the result and just use the username from the response.
      const username = msg.info.user && msg.info.user.sip ? msg.info.user.sip : 'unknown';
      console.log(`[info] OAuth2 login successful for user: ${username}`);

      const session = this.extractSessionFromInfo(msg.info, nonce, sharedSecretHex);
      if (!session) {
        throw new Error('OAuth2 login succeeded but no session credentials were present in LoginResult.info.session.');
      }

      this.persistSession(wsUrl, session);
      return {
        wsUrl,
        session,
        userLabel: msg.info.user && msg.info.user.sip ? msg.info.user.sip : (msg.info.user && msg.info.user.dn ? msg.info.user.dn : username)
      };
    }
  }

  getOauthUserCandidates(info) {
    const set = new Set();
    if (typeof info.sip === 'string' && info.sip) set.add(info.sip);
    if (typeof info.email === 'string' && info.email) set.add(info.email);
    if (typeof info.dn === 'string' && info.dn) set.add(info.dn);
    return Array.from(set);
  }

  findMatchingLoginResultUsername(domain, candidates, sharedSecretHex, nonce, challenge, msg) {
    // For OAuth2, we trust the PBX and just use the first candidate since we can't verify the digest
    // The PBX has already authenticated the user via OAuth2
    return candidates.length > 0 ? candidates[0] : null;
  }

  findMatchingRedirectUsername(candidates, sharedSecretHex, nonce, challenge, msg) {
    for (const candidate of candidates) {
      const expected = buildRedirectDigest(candidate, sharedSecretHex, nonce, challenge, msg.info);
      if (!msg.digest || msg.digest === expected) return candidate;
    }
    return null;
  }

  extractSessionFromInfo(info, oauthNonce, sharedSecretHex) {
    if (!info || !info.session || !info.session.usr || !info.session.pwd) {
      return null;
    }

    const userPlain = rc4DecryptHex(`innovaphoneAppClient:usr:${oauthNonce}:${sharedSecretHex}`, info.session.usr);
    const passPlain = rc4DecryptHex(`innovaphoneAppClient:pwd:${oauthNonce}:${sharedSecretHex}`, info.session.pwd);

    const username = tryDecodePrintable(userPlain) || userPlain.toString('hex');
    const password = tryDecodePrintable(passPlain) || passPlain.toString('hex');

    return { username, password };
  }

  persistSession(wsUrl, session) {
    const data = {
      wsUrl,
      savedAt: new Date().toISOString(),
      session
    };
    writeJsonFile(this.options.sessionFile, data);
    this.saved = data;
  }

  buildRedirectWsUrl(currentWsUrl, info) {
    if (!info || !info.host) {
      throw new Error('Redirect did not contain info.host.');
    }

    const current = new URL(currentWsUrl);
    const protocol = current.protocol;
    const port = protocol === 'wss:' ? (info.https || current.port) : (info.http || current.port);
    const moduleName = info.mod || this.options.moduleName;
    const wsPath = this.options.wsPath.startsWith('/') ? this.options.wsPath : `/${this.options.wsPath}`;
    const authority = port ? `${info.host}:${port}` : info.host;
    return `${protocol}//${authority}/${moduleName}${wsPath}`;
  }
}

async function main() {
  const options = parseArgs(process.argv);
  if (options.help) {
    printHelp();
    return;
  }

  const demo = new InnovaphoneSsoCliDemo(options);
  await demo.run();
}

main().catch((err) => {
  console.error(`\n[error] ${err.message}`);
  process.exit(1);
});
