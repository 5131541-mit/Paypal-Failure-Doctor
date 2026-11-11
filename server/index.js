import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { anthropic } from '@ai-sdk/anthropic';
import { generateText } from 'ai';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { databaseConfigured, pool } from './db.js';
import pg from 'pg';
import { hashPassword, verifyPassword } from './passwords.js';
import {
  createOtpAuthUrl, createRecoveryCodes, createTotpSecret, decryptTotpSecret, encryptTotpSecret,
  findRecoveryCodeIndex, hashRecoveryCode, mfaEncryptionConfigured, verifyTotp,
} from './mfa.js';
import { summarizeWebhookEvent, verifyPayPalWebhook } from './paypal-webhooks.js';

const app = express();
const port = Number(process.env.PORT || 8787);
const packageInfo = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const claudeModel = process.env.CLAUDE_MODEL || 'claude-sonnet-5-5';
const claudeConfigured = Boolean(process.env.ANTHROPIC_API_KEY);
let claudeStatus = {
  state: claudeConfigured ? 'configured' : 'local-only',
  checkedAt: null,
  message: claudeConfigured ? 'Configured; run a connection check or diagnosis to confirm access.' : 'No API key configured; the local advisor is available.',
};
const getClaudeStatus = () => ({ ...claudeStatus, configured: claudeConfigured, model: claudeModel });
function setClaudeStatus(state, message) {
  claudeStatus = { state, checkedAt: new Date().toISOString(), message };
  return getClaudeStatus();
}
function inspectClaudeError(error) {
  const chain = [];
  const pending = [error];
  const visited = new Set();
  while (pending.length && chain.length < 8) {
    const current = pending.shift();
    if (!current || (typeof current !== 'object' && typeof current !== 'function') || visited.has(current)) continue;
    visited.add(current);
    chain.push(current);
    if (current.lastError) pending.push(current.lastError);
    if (current.cause) pending.push(current.cause);
    if (Array.isArray(current.errors)) pending.push(...current.errors.slice(-2));
  }
  const statusSource = chain.find((item) => Number(item.statusCode || item.status || item.response?.status || 0) > 0);
  const status = Number(statusSource?.statusCode || statusSource?.status || statusSource?.response?.status || 0);
  let providerMessage = '';
  for (const item of chain) {
    try {
      const rawBody = item.responseBody ?? item.response?.body;
      const body = typeof rawBody === 'string' ? JSON.parse(rawBody) : rawBody;
      const message = body?.error?.message || body?.message;
      if (message) providerMessage += ` ${String(message).slice(0, 1000)}`;
    } catch { /* Keep provider response details out of the dashboard and logs. */ }
  }
  return {
    chain,
    status,
    providerMessage: providerMessage.toLowerCase(),
    transportText: chain.map((item) => `${item.name || ''} ${item.message || ''}`).join(' '),
    providerErrorName: chain.find((item) => item !== error && item.name)?.name || error?.name || 'Error',
  };
}

function getClaudeFailureMessage(error) {
  const { chain, status, providerMessage, transportText } = inspectClaudeError(error);
  const insufficientCredits = /credit balance|credits? (are )?too low|purchase credits/.test(providerMessage);
  const spendLimitReached = /usage limit|spend limit/.test(providerMessage);
  const transportError = /timeout|abort|fetch failed|network|econn|enotfound|unable to connect/i.test(transportText);
  if (insufficientCredits || status === 402) return 'The Anthropic API account has insufficient credits. Check API billing.';
  if (spendLimitReached) return 'The Anthropic API usage limit has been reached. Check the organization or workspace limit.';
  if (status === 401) return 'Anthropic rejected the API key. Check the server-side ANTHROPIC_API_KEY.';
  if (status === 403) return 'This Anthropic key or account cannot use the configured model.';
  if (status === 404) return `Anthropic could not find model “${claudeModel}”. Check CLAUDE_MODEL.`;
  if (status === 429) return 'Anthropic rate or usage limits were reached.';
  if (status >= 500) return 'Anthropic is temporarily unavailable.';
  if (status === 400 && /model/.test(providerMessage)) return `Anthropic rejected model “${claudeModel}”. Check CLAUDE_MODEL and model access.`;
  if (transportError) return 'The Claude request timed out or could not reach Anthropic. Check the API server network and retry.';
  if (status === 400) return 'Anthropic rejected the request. Check its model and request settings.';
  if (chain.some((item) => item?.name === 'AI_RetryError')) return 'Claude failed after a retry, but Anthropic returned no HTTP status. Check outbound access from the API server and the Anthropic API logs.';
  return 'Claude could not complete the request. Check the API key, model, and network.';
}
const paypalEnvironment = process.env.PAYPAL_ENVIRONMENT || 'sandbox';
if (!['sandbox', 'live'].includes(paypalEnvironment)) throw new Error('PAYPAL_ENVIRONMENT must be sandbox or live.');
if (paypalEnvironment === 'live' && process.env.NODE_ENV !== 'production') throw new Error('Live PayPal is only allowed when NODE_ENV=production.');
const livePaymentsRequested = process.env.PAYPAL_LIVE_PAYMENTS_ENABLED === 'true';
if (livePaymentsRequested && paypalEnvironment !== 'live') throw new Error('Set PAYPAL_ENVIRONMENT=live before enabling live PayPal payments.');
const paypalApiBase = paypalEnvironment === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const paypalSdkUrl = paypalEnvironment === 'live' ? 'https://www.paypal.com/web-sdk/v6/core' : 'https://www.sandbox.paypal.com/web-sdk/v6/core';
const paypalClientId = paypalEnvironment === 'live' ? process.env.PAYPAL_LIVE_CLIENT_ID : (process.env.PAYPAL_SANDBOX_CLIENT_ID || process.env.PAYPAL_CLIENT_ID);
const paypalClientSecret = paypalEnvironment === 'live' ? process.env.PAYPAL_LIVE_CLIENT_SECRET : (process.env.PAYPAL_SANDBOX_CLIENT_SECRET || process.env.PAYPAL_CLIENT_SECRET);
const paypalWebhookId = paypalEnvironment === 'live' ? process.env.PAYPAL_LIVE_WEBHOOK_ID : (process.env.PAYPAL_SANDBOX_WEBHOOK_ID || process.env.PAYPAL_WEBHOOK_ID);
const paypalCurrency = (paypalEnvironment === 'live' ? process.env.PAYPAL_LIVE_CURRENCY : process.env.PAYPAL_CURRENCY || 'USD')?.toUpperCase();
const paypalLiveAmount = process.env.PAYPAL_LIVE_AMOUNT || '';
const paypalLiveDescription = (process.env.PAYPAL_LIVE_DESCRIPTION || '').trim();
const paypalLiveDetailsReady = /^\d{1,7}(?:\.\d{1,2})?$/.test(paypalLiveAmount) && Number(paypalLiveAmount) > 0
  && /^[A-Z]{3}$/.test(paypalCurrency || '') && paypalLiveDescription.length >= 3 && paypalLiveDescription.length <= 127;
const localAuthEnabled = !databaseConfigured && process.env.NODE_ENV !== 'production' && process.env.LOCAL_AUTH_ENABLED !== 'false';
const authEnabled = databaseConfigured || localAuthEnabled;
if (process.env.NODE_ENV === 'production' && !databaseConfigured) throw new Error('DATABASE_URL is required in production; local file authentication is development-only.');
const paypalLiveCheckoutReady = paypalEnvironment === 'live' && process.env.NODE_ENV === 'production' && databaseConfigured && livePaymentsRequested
  && Boolean(paypalClientId && paypalClientSecret && paypalWebhookId && paypalLiveDetailsReady);
const paypalCheckoutReady = paypalEnvironment === 'sandbox'
  ? Boolean(paypalClientId && paypalClientSecret)
  : paypalLiveCheckoutReady;
const paypalWebhookReady = Boolean(paypalClientId && paypalClientSecret && paypalWebhookId && (paypalEnvironment === 'sandbox' || paypalLiveCheckoutReady));
const paypalOrderAmount = paypalEnvironment === 'live' ? paypalLiveAmount : '2.00';
const paypalOrderDescription = paypalEnvironment === 'live' ? paypalLiveDescription : 'Failure Doctor Sandbox checkout';
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || process.env.APP_ORIGIN || '').split(',').map((item) => item.trim()).filter(Boolean));
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], baseUri: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"],
    scriptSrc: ["'self'", 'https://www.sandbox.paypal.com', 'https://www.paypal.com'],
    connectSrc: ["'self'", 'https://api-m.sandbox.paypal.com', 'https://api-m.paypal.com', 'https://www.sandbox.paypal.com', 'https://www.paypal.com'],
    frameSrc: ["'self'", 'https://www.sandbox.paypal.com', 'https://www.paypal.com', 'https://*.paypal.com'],
    imgSrc: ["'self'", 'data:', 'https:'], styleSrc: ["'self'", "'unsafe-inline'", 'https:'], fontSrc: ["'self'", 'data:', 'https:'],
  } },
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({ origin(origin, callback) {
  if (!origin) return callback(null, false);
  if (allowedOrigins.has(origin) || (allowedOrigins.size === 0 && process.env.NODE_ENV !== 'production')) return callback(null, true);
  return callback(null, false);
}, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use('/api', (req, res, next) => {
  // Workspace activity and payment responses are private, short-lived data.
  res.set('Cache-Control', 'no-store');
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  if (req.method === 'POST' && req.path === '/paypal/webhooks') return next();
  const origin = req.headers.origin;
  if (process.env.NODE_ENV === 'production' && databaseConfigured && !origin) return res.status(403).json({ error: 'A browser Origin header is required.' });
  const sameOrigin = origin && origin === `${req.protocol}://${req.get('host')}`;
  if (origin && !sameOrigin && (allowedOrigins.size === 0 && process.env.NODE_ENV === 'production' || allowedOrigins.size > 0 && !allowedOrigins.has(origin))) return res.status(403).json({ error: 'Origin is not allowed.' });
  next();
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many sign-in attempts. Try again in 15 minutes.' } });
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false }));
const cookieName = process.env.NODE_ENV === 'production' ? '__Host-fd_session' : 'fd_session';
const cookieSettings = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 };
const hashToken = (token) => createHash('sha256').update(token).digest('hex');
const appDataDirectory = join(dirname(fileURLToPath(import.meta.url)), 'data');
const localAuthStorePath = process.env.LOCAL_AUTH_STORE_PATH || join(appDataDirectory, 'auth.json');
let localAuthStore = { users: [], workspaces: [], sessions: [] };
if (localAuthEnabled) {
  try {
    const saved = JSON.parse(readFileSync(localAuthStorePath, 'utf8'));
    if (!Array.isArray(saved.users) || !Array.isArray(saved.workspaces) || !Array.isArray(saved.sessions)) throw new Error('Invalid local auth store format.');
    if (!Array.isArray(saved.mfaChallenges)) saved.mfaChallenges = [];
    localAuthStore = saved;
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error(`Could not safely read the local authentication store: ${error.message}`);
  }
}
function saveLocalAuthStore() {
  mkdirSync(dirname(localAuthStorePath), { recursive: true });
  const tempPath = `${localAuthStorePath}.${process.pid}.tmp`;
  writeFileSync(tempPath, JSON.stringify(localAuthStore, null, 2), { mode: 0o600 });
  renameSync(tempPath, localAuthStorePath);
}
function readCookie(req, name) {
  const found = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : null;
}
async function passwordMatchesAndUpgrade(password, user) {
  const result = await verifyPassword(password, user.password_hash);
  if (!result.valid) return false;
  if (result.needsRehash) {
    const upgradedHash = await hashPassword(password);
    if (databaseConfigured) {
      await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2 AND password_hash=$3', [upgradedHash, user.id, user.password_hash]);
    } else {
      user.password_hash = upgradedHash;
      saveLocalAuthStore();
    }
  }
  return true;
}
async function createSession(res, userId, workspaceId) {
  const token = randomBytes(32).toString('base64url');
  if (databaseConfigured) {
    await pool.query('INSERT INTO sessions (token_hash, user_id, workspace_id, expires_at) VALUES ($1,$2,$3,now()+interval \'7 days\')', [hashToken(token), userId, workspaceId]);
  } else {
    localAuthStore.sessions = localAuthStore.sessions.filter((session) => session.expiresAt > Date.now());
    localAuthStore.sessions.push({ tokenHash: hashToken(token), userId, workspaceId, expiresAt: Date.now() + cookieSettings.maxAge });
    saveLocalAuthStore();
  }
  res.cookie(cookieName, token, cookieSettings);
}
async function findAuthenticatedUser(token) {
  if (!token) return null;
  if (databaseConfigured) {
    const result = await pool.query('SELECT u.id AS user_id,u.email,w.id AS workspace_id,w.name AS workspace_name,m.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN workspaces w ON w.id=s.workspace_id JOIN memberships m ON m.workspace_id=w.id AND m.user_id=u.id WHERE s.token_hash=$1 AND s.expires_at>now()', [hashToken(token)]);
    return result.rows[0] || null;
  }
  const tokenHash = hashToken(token);
  const session = localAuthStore.sessions.find((item) => item.tokenHash === tokenHash && item.expiresAt > Date.now());
  if (!session) return null;
  const user = localAuthStore.users.find((item) => item.id === session.userId);
  const workspace = localAuthStore.workspaces.find((item) => item.id === session.workspaceId);
  if (!user || !workspace) return null;
  return { user_id: user.id, email: user.email, workspace_id: workspace.id, workspace_name: workspace.name, role: 'owner' };
}

app.post('/api/auth/register', authLimiter, async (req, res) => {
  if (!authEnabled) return res.status(503).json({ error: 'Authentication is unavailable. Configure PostgreSQL before starting the production server.' });
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const workspaceName = String(req.body?.workspaceName || 'My workspace').trim().slice(0, 100) || 'My workspace';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 12 || password.length > 256) return res.status(400).json({ error: 'Use a password between 12 and 256 characters.' });
  if (!databaseConfigured) {
    if (localAuthStore.users.some((user) => user.email === email)) return res.status(409).json({ error: 'An account with that email already exists.' });
    const user = { id: randomUUID(), email, password_hash: await hashPassword(password) };
    if (localAuthStore.users.some((item) => item.email === email)) return res.status(409).json({ error: 'An account with that email already exists.' });
    const workspace = { id: randomUUID(), name: workspaceName, owner_user_id: user.id };
    localAuthStore.users.push(user);
    localAuthStore.workspaces.push(workspace);
    try {
      saveLocalAuthStore();
      await createSession(res, user.id, workspace.id);
    return res.status(201).json({ user: { id: user.id, email: user.email, role: 'owner' }, workspace: { id: workspace.id, name: workspace.name } });
    } catch (error) {
      localAuthStore.users = localAuthStore.users.filter((item) => item.id !== user.id);
      localAuthStore.workspaces = localAuthStore.workspaces.filter((item) => item.id !== workspace.id);
      console.error('Local registration failed:', error.message);
      return res.status(500).json({ error: 'Could not create the local account.' });
    }
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email', [email, await hashPassword(password)]);
    const workspace = await client.query('INSERT INTO workspaces(name) VALUES($1) RETURNING id,name', [workspaceName]);
    await client.query('INSERT INTO memberships(workspace_id,user_id,role) VALUES($1,$2,\'owner\')', [workspace.rows[0].id, user.rows[0].id]);
    await client.query('COMMIT');
    await createSession(res, user.rows[0].id, workspace.rows[0].id);
    res.status(201).json({ user: { ...user.rows[0], role: 'owner' }, workspace: workspace.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
    console.error('Registration failed:', error.message);
    res.status(500).json({ error: 'Could not create the account.' });
  } finally { client.release(); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  if (!authEnabled) return res.status(503).json({ error: 'Authentication is unavailable. Configure PostgreSQL before starting the production server.' });
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  let user;
  let workspace;
  let mfaEnabled = false;
  if (databaseConfigured) {
    const result = await pool.query('SELECT u.id,u.email,u.password_hash,u.mfa_enabled,m.workspace_id,m.role,w.name AS workspace_name FROM users u JOIN memberships m ON m.user_id=u.id JOIN workspaces w ON w.id=m.workspace_id WHERE u.email=$1 ORDER BY m.created_at LIMIT 1', [email]);
    if (!result.rowCount || !await passwordMatchesAndUpgrade(password, result.rows[0])) return res.status(401).json({ error: 'Email or password is incorrect.' });
    user = { id: result.rows[0].id, email: result.rows[0].email, role: result.rows[0].role };
    workspace = { id: result.rows[0].workspace_id, name: result.rows[0].workspace_name };
    mfaEnabled = result.rows[0].mfa_enabled;
    await pool.query('DELETE FROM sessions WHERE user_id=$1 AND expires_at < now()', [user.id]);
  } else {
    const localUser = localAuthStore.users.find((item) => item.email === email);
    if (!localUser || !await passwordMatchesAndUpgrade(password, localUser)) return res.status(401).json({ error: 'Email or password is incorrect.' });
    const localWorkspace = localAuthStore.workspaces.find((item) => item.owner_user_id === localUser.id);
    if (!localWorkspace) return res.status(401).json({ error: 'Email or password is incorrect.' });
    user = { id: localUser.id, email: localUser.email, role: 'owner' };
    workspace = { id: localWorkspace.id, name: localWorkspace.name };
    mfaEnabled = Boolean(localUser.mfa_enabled);
  }
  if (mfaEnabled) {
    const challengeToken = randomBytes(32).toString('base64url');
    const challengeHash = hashToken(challengeToken);
    if (databaseConfigured) {
      await pool.query('DELETE FROM mfa_login_challenges WHERE expires_at < now() OR attempts >= 5');
      await pool.query("INSERT INTO mfa_login_challenges(challenge_hash,user_id,workspace_id,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')", [challengeHash, user.id, workspace.id]);
    } else {
      localAuthStore.mfaChallenges = (localAuthStore.mfaChallenges || []).filter((item) => item.expiresAt > Date.now() && item.attempts < 5);
      localAuthStore.mfaChallenges.push({ challengeHash, userId: user.id, workspaceId: workspace.id, attempts: 0, expiresAt: Date.now() + 5 * 60 * 1000 });
      saveLocalAuthStore();
    }
    return res.json({ mfaRequired: true, challengeToken, email: user.email });
  }
  await createSession(res, user.id, workspace.id);
  res.json({ user, workspace });
});

app.post('/api/auth/mfa/verify', authLimiter, async (req, res) => {
  const challengeToken = String(req.body?.challengeToken || '');
  const submittedCode = String(req.body?.code || '').trim();
  if (!/^[A-Za-z0-9 -]{6,24}$/.test(submittedCode) || challengeToken.length < 32 || challengeToken.length > 128) {
    return res.status(400).json({ error: 'Enter the six-digit authenticator code or one unused recovery code.' });
  }
  const challengeHash = hashToken(challengeToken);
  let userId;
  let workspaceId;
  let user;
  let authenticated = false;
  try {
    if (databaseConfigured) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await client.query(
          `SELECT c.user_id,c.workspace_id,c.attempts,u.mfa_enabled,u.mfa_secret_encrypted,u.mfa_recovery_code_hashes,u.mfa_last_counter
           FROM mfa_login_challenges c JOIN users u ON u.id=c.user_id
           WHERE c.challenge_hash=$1 AND c.expires_at>now() AND c.attempts<5
           FOR UPDATE OF c,u`,
          [challengeHash],
        );
        const row = result.rows[0];
        if (!row?.mfa_enabled || !row.mfa_secret_encrypted) {
          await client.query('ROLLBACK');
          return res.status(401).json({ error: 'The sign-in challenge expired or is invalid. Start again.' });
        }
        userId = row.user_id;
        workspaceId = row.workspace_id;
        const secret = decryptTotpSecret(row.mfa_secret_encrypted);
        const counter = verifyTotp(secret, submittedCode, row.mfa_last_counter);
        let recoveryIndex = -1;
        if (counter === null) recoveryIndex = findRecoveryCodeIndex(submittedCode, row.mfa_recovery_code_hashes || []);
        authenticated = counter !== null || recoveryIndex >= 0;
        if (authenticated && counter !== null) {
          const updated = await client.query('UPDATE users SET mfa_last_counter=$1 WHERE id=$2 AND mfa_last_counter<$1', [counter, userId]);
          authenticated = updated.rowCount === 1;
        } else if (authenticated) {
          const remaining = [...(row.mfa_recovery_code_hashes || [])];
          remaining.splice(recoveryIndex, 1);
          await client.query('UPDATE users SET mfa_recovery_code_hashes=$1 WHERE id=$2', [remaining, userId]);
        }
        if (authenticated) {
          await client.query('DELETE FROM mfa_login_challenges WHERE challenge_hash=$1', [challengeHash]);
          await client.query('COMMIT');
        } else {
          const attempts = Number(row.attempts) + 1;
          if (attempts >= 5) await client.query('DELETE FROM mfa_login_challenges WHERE challenge_hash=$1', [challengeHash]);
          else await client.query('UPDATE mfa_login_challenges SET attempts=$1 WHERE challenge_hash=$2', [attempts, challengeHash]);
          await client.query('COMMIT');
          return res.status(401).json({ error: attempts >= 5 ? 'Too many incorrect codes. Start sign-in again.' : 'That code is incorrect or expired.' });
        }
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally { client.release(); }
      user = (await pool.query('SELECT u.id,u.email,m.role FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.workspace_id=$2', [userId, workspaceId])).rows[0];
    } else {
      const challenge = (localAuthStore.mfaChallenges || []).find((item) => item.challengeHash === challengeHash && item.expiresAt > Date.now() && item.attempts < 5);
      const localUser = challenge && localAuthStore.users.find((item) => item.id === challenge.userId);
      if (!challenge || !localUser?.mfa_enabled || !localUser.mfa_secret_encrypted) return res.status(401).json({ error: 'The sign-in challenge expired or is invalid. Start again.' });
      const secret = decryptTotpSecret(localUser.mfa_secret_encrypted);
      const counter = verifyTotp(secret, submittedCode, localUser.mfa_last_counter);
      let recoveryIndex = -1;
      if (counter === null) recoveryIndex = findRecoveryCodeIndex(submittedCode, localUser.mfa_recovery_code_hashes || []);
      authenticated = counter !== null || recoveryIndex >= 0;
      if (authenticated && counter !== null) localUser.mfa_last_counter = counter;
      else if (authenticated) localUser.mfa_recovery_code_hashes.splice(recoveryIndex, 1);
      if (!authenticated) {
        challenge.attempts += 1;
        if (challenge.attempts >= 5) localAuthStore.mfaChallenges = localAuthStore.mfaChallenges.filter((item) => item !== challenge);
        saveLocalAuthStore();
        return res.status(401).json({ error: challenge.attempts >= 5 ? 'Too many incorrect codes. Start sign-in again.' : 'That code is incorrect or expired.' });
      }
      userId = localUser.id;
      workspaceId = challenge.workspaceId;
      user = localUser;
      localAuthStore.mfaChallenges = localAuthStore.mfaChallenges.filter((item) => item !== challenge);
      saveLocalAuthStore();
    }
    if (!user) return res.status(401).json({ error: 'Could not finish signing in. Start again.' });
    await createSession(res, userId, workspaceId);
    const workspace = databaseConfigured
      ? (await pool.query('SELECT id,name FROM workspaces WHERE id=$1', [workspaceId])).rows[0]
      : localAuthStore.workspaces.find((item) => item.id === workspaceId);
    return res.json({ user: { id: userId, email: user.email, role: user.role || 'owner' }, workspace: { id: workspaceId, name: workspace?.name || 'My workspace' } });
  } catch (error) {
    console.error('Second-factor verification failed:', error.message);
    return res.status(mfaEncryptionConfigured ? 500 : 503).json({ error: 'Could not verify the second factor. Check server MFA configuration and try again.' });
  }
});

app.get('/api/auth/me', async (req, res) => {
  if (!authEnabled) return res.json({ authRequired: false, user: null, workspace: null });
  const token = readCookie(req, cookieName);
  if (!token) return res.json({ authRequired: true, user: null, workspace: null });
  const row = await findAuthenticatedUser(token);
  res.json({ authRequired: true, user: row ? { id: row.id || row.user_id, email: row.email, role: row.role } : null, workspace: row ? { id: row.workspace_id, name: row.workspace_name } : null });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = readCookie(req, cookieName);
  if (databaseConfigured && token) await pool.query('DELETE FROM sessions WHERE token_hash=$1', [hashToken(token)]);
  if (localAuthEnabled && token) {
    const tokenHash = hashToken(token);
    localAuthStore.sessions = localAuthStore.sessions.filter((session) => session.tokenHash !== tokenHash);
    saveLocalAuthStore();
  }
  res.clearCookie(cookieName, { ...cookieSettings, maxAge: undefined });
  res.json({ ok: true });
});

app.use('/api', async (req, res, next) => {
  const publicAuthPath = ['/auth/me', '/auth/login', '/auth/register', '/auth/logout', '/auth/mfa/verify'].includes(req.path);
  if (!authEnabled || req.path === '/health' || req.path === '/scenarios' || req.path === '/paypal/config' || (req.method === 'POST' && req.path === '/paypal/webhooks') || publicAuthPath) return next();
  const token = readCookie(req, cookieName);
  if (!token) return res.status(401).json({ error: 'Please sign in to access this workspace.' });
  try {
    const user = await findAuthenticatedUser(token);
    if (!user) return res.status(401).json({ error: 'Your session expired. Please sign in again.' });
    req.user = user;
    next();
  } catch (error) { next(error); }
});

app.patch('/api/workspace', async (req, res) => {
  if (req.user.role !== 'owner' && req.user.role !== 'admin') return res.status(403).json({ error: 'Only a workspace owner or admin can rename this workspace.' });
  const name = String(req.body?.name || '').trim();
  if (!name || name.length > 100) return res.status(400).json({ error: 'Workspace name must be between 1 and 100 characters.' });
  try {
    if (databaseConfigured) {
      const result = await pool.query('UPDATE workspaces SET name=$1 WHERE id=$2 RETURNING id,name', [name, req.user.workspace_id]);
      if (!result.rowCount) return res.status(404).json({ error: 'Workspace not found.' });
    } else {
      const workspace = localAuthStore.workspaces.find((item) => item.id === req.user.workspace_id);
      if (!workspace) return res.status(404).json({ error: 'Workspace not found.' });
      workspace.name = name;
      saveLocalAuthStore();
    }
    res.json({ workspace: { id: req.user.workspace_id, name } });
  } catch (error) {
    console.error('Could not update workspace settings:', error.message);
    res.status(500).json({ error: 'Could not save workspace settings.' });
  }
});

app.get('/api/auth/mfa/status', (req, res) => {
  const user = databaseConfigured
    ? null
    : localAuthStore.users.find((item) => item.id === req.user.user_id);
  if (databaseConfigured) {
    return pool.query('SELECT mfa_enabled,cardinality(mfa_recovery_code_hashes) AS recovery_count FROM users WHERE id=$1', [req.user.user_id])
      .then((result) => result.rows[0]
        ? res.json({ enabled: result.rows[0].mfa_enabled, recoveryCodesRemaining: result.rows[0].recovery_count, available: mfaEncryptionConfigured })
        : res.status(404).json({ error: 'Account not found.' }))
      .catch((error) => { console.error('Could not read MFA status:', error.message); res.status(500).json({ error: 'Could not read MFA status.' }); });
  }
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ enabled: Boolean(user.mfa_enabled), recoveryCodesRemaining: (user.mfa_recovery_code_hashes || []).length, available: mfaEncryptionConfigured });
});

app.post('/api/auth/mfa/setup', authLimiter, async (req, res) => {
  if (!mfaEncryptionConfigured) return res.status(503).json({ error: 'Set MFA_ENCRYPTION_KEY in the API server environment before enrolling an authenticator.' });
  const password = String(req.body?.password || '');
  try {
    const user = databaseConfigured
      ? (await pool.query('SELECT id,email,password_hash,mfa_enabled FROM users WHERE id=$1', [req.user.user_id])).rows[0]
      : localAuthStore.users.find((item) => item.id === req.user.user_id);
    if (!user || !await passwordMatchesAndUpgrade(password, user)) return res.status(401).json({ error: 'Current password is incorrect.' });
    if (user.mfa_enabled) return res.status(409).json({ error: 'Two-step verification is already enabled. Disable it before replacing the authenticator.' });
    const secret = createTotpSecret();
    const encrypted = encryptTotpSecret(secret);
    if (databaseConfigured) await pool.query("UPDATE users SET mfa_pending_secret_encrypted=$1,mfa_pending_expires_at=now()+interval '10 minutes' WHERE id=$2", [encrypted, req.user.user_id]);
    else {
      user.mfa_pending_secret_encrypted = encrypted;
      user.mfa_pending_expires_at = Date.now() + 10 * 60 * 1000;
      saveLocalAuthStore();
    }
    res.json({ secret, otpauthUrl: createOtpAuthUrl(secret, user.email), expiresInSeconds: 600 });
  } catch (error) {
    console.error('Could not begin authenticator setup:', error.message);
    res.status(500).json({ error: 'Could not begin authenticator setup.' });
  }
});

app.post('/api/auth/mfa/confirm', authLimiter, async (req, res) => {
  const code = String(req.body?.code || '').trim();
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the current six-digit code from your authenticator app.' });
  try {
    let user;
    if (databaseConfigured) user = (await pool.query('SELECT id,mfa_pending_secret_encrypted,mfa_pending_expires_at,mfa_last_counter FROM users WHERE id=$1', [req.user.user_id])).rows[0];
    else user = localAuthStore.users.find((item) => item.id === req.user.user_id);
    const expiresAt = databaseConfigured ? new Date(user?.mfa_pending_expires_at || 0).getTime() : Number(user?.mfa_pending_expires_at || 0);
    if (!user?.mfa_pending_secret_encrypted || expiresAt <= Date.now()) return res.status(400).json({ error: 'Authenticator setup expired. Start setup again.' });
    const secret = decryptTotpSecret(user.mfa_pending_secret_encrypted);
    const counter = verifyTotp(secret, code, user.mfa_last_counter ?? -1);
    if (counter === null) return res.status(401).json({ error: 'That code is invalid or expired. Check your device clock and try again.' });
    const recoveryCodes = createRecoveryCodes();
    const recoveryHashes = recoveryCodes.map(hashRecoveryCode);
    if (databaseConfigured) {
      const result = await pool.query(
        `UPDATE users SET mfa_enabled=true,mfa_secret_encrypted=mfa_pending_secret_encrypted,
         mfa_pending_secret_encrypted=NULL,mfa_pending_expires_at=NULL,mfa_recovery_code_hashes=$1,mfa_last_counter=$2
         WHERE id=$3 AND mfa_enabled=false AND mfa_pending_expires_at>now()`,
        [recoveryHashes, counter, req.user.user_id],
      );
      if (!result.rowCount) return res.status(409).json({ error: 'Authenticator setup expired or changed. Start setup again.' });
    } else {
      user.mfa_enabled = true;
      user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted;
      user.mfa_pending_secret_encrypted = null;
      user.mfa_pending_expires_at = null;
      user.mfa_recovery_code_hashes = recoveryHashes;
      user.mfa_last_counter = counter;
      saveLocalAuthStore();
    }
    res.json({ enabled: true, recoveryCodes });
  } catch (error) {
    console.error('Could not confirm authenticator setup:', error.message);
    res.status(500).json({ error: 'Could not confirm authenticator setup.' });
  }
});

app.post('/api/auth/mfa/disable', authLimiter, async (req, res) => {
  const password = String(req.body?.password || '');
  const proof = String(req.body?.code || '').trim();
  try {
    let user;
    if (databaseConfigured) user = (await pool.query('SELECT id,password_hash,mfa_enabled,mfa_secret_encrypted,mfa_recovery_code_hashes,mfa_last_counter FROM users WHERE id=$1', [req.user.user_id])).rows[0];
    else user = localAuthStore.users.find((item) => item.id === req.user.user_id);
    if (!user || !await passwordMatchesAndUpgrade(password, user)) return res.status(401).json({ error: 'Current password is incorrect.' });
    if (!user.mfa_enabled || !user.mfa_secret_encrypted) return res.status(409).json({ error: 'Two-step verification is not enabled.' });
    const secret = decryptTotpSecret(user.mfa_secret_encrypted);
    const counter = verifyTotp(secret, proof, user.mfa_last_counter ?? -1);
    let recoveryIndex = -1;
    if (counter === null) recoveryIndex = findRecoveryCodeIndex(proof, user.mfa_recovery_code_hashes || []);
    if (counter === null && recoveryIndex < 0) return res.status(401).json({ error: 'Authenticator or recovery code is incorrect.' });
    if (databaseConfigured) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('UPDATE users SET mfa_enabled=false,mfa_secret_encrypted=NULL,mfa_pending_secret_encrypted=NULL,mfa_pending_expires_at=NULL,mfa_recovery_code_hashes=ARRAY[]::text[],mfa_last_counter=-1 WHERE id=$1', [req.user.user_id]);
        await client.query('DELETE FROM sessions WHERE user_id=$1', [req.user.user_id]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally { client.release(); }
    } else {
      user.mfa_enabled = false;
      user.mfa_secret_encrypted = null;
      user.mfa_pending_secret_encrypted = null;
      user.mfa_pending_expires_at = null;
      user.mfa_recovery_code_hashes = [];
      user.mfa_last_counter = -1;
      localAuthStore.sessions = localAuthStore.sessions.filter((session) => session.userId !== req.user.user_id);
      saveLocalAuthStore();
    }
    res.clearCookie(cookieName, { ...cookieSettings, maxAge: undefined });
    res.json({ ok: true, sessionsRevoked: true });
  } catch (error) {
    console.error('Could not disable two-step verification:', error.message);
    res.status(500).json({ error: 'Could not disable two-step verification.' });
  }
});

app.post('/api/auth/password', authLimiter, async (req, res) => {
  if (!authEnabled) return res.status(503).json({ error: 'Account password updates are unavailable until authentication is configured.' });
  const currentPassword = String(req.body?.currentPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if (!currentPassword || currentPassword.length > 256) return res.status(400).json({ error: 'Enter your current password.' });
  if (newPassword.length < 12 || newPassword.length > 256) return res.status(400).json({ error: 'Use a new password between 12 and 256 characters.' });
  try {
    const user = databaseConfigured
      ? (await pool.query('SELECT id,password_hash FROM users WHERE id=$1', [req.user.user_id])).rows[0]
      : localAuthStore.users.find((item) => item.id === req.user.user_id);
    if (!user || !await passwordMatchesAndUpgrade(currentPassword, user)) return res.status(401).json({ error: 'Current password is incorrect.' });

    const passwordHash = await hashPassword(newPassword);
    const token = readCookie(req, cookieName);
    const currentTokenHash = token ? hashToken(token) : '';
    if (databaseConfigured) {
      await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [passwordHash, req.user.user_id]);
      await pool.query('DELETE FROM sessions WHERE user_id=$1 AND token_hash<>$2', [req.user.user_id, currentTokenHash]);
    } else {
      user.password_hash = passwordHash;
      localAuthStore.sessions = localAuthStore.sessions.filter((session) => session.userId !== req.user.user_id || session.tokenHash === currentTokenHash);
      saveLocalAuthStore();
    }
    res.json({ ok: true, sessionsRevoked: true });
  } catch (error) {
    console.error('Could not update account password:', error.message);
    res.status(500).json({ error: 'Could not update the password.' });
  }
});

// Small durable event store for a single-node hackathon deployment. Each record
// is a redacted operational summary; secrets and buyer details are never saved.
const historyPath = process.env.LOCAL_RUNS_STORE_PATH || join(appDataDirectory, 'runs.json');
const webhookEventsPath = process.env.LOCAL_WEBHOOK_EVENTS_PATH || join(appDataDirectory, 'paypal-webhooks.json');
mkdirSync(dirname(historyPath), { recursive: true });
mkdirSync(dirname(webhookEventsPath), { recursive: true });
let history = [];
try { history = JSON.parse(readFileSync(historyPath, 'utf8')); } catch { history = []; }
let localWebhookEvents = [];
try {
  localWebhookEvents = JSON.parse(readFileSync(webhookEventsPath, 'utf8'));
  if (!Array.isArray(localWebhookEvents)) throw new Error('Expected a JSON array.');
} catch (error) {
  if (error.code !== 'ENOENT') throw new Error(`Could not safely read the local PayPal webhook store: ${error.message}`);
}
function saveLocalWebhookEvents() {
  const tempPath = `${webhookEventsPath}.${process.pid}.tmp`;
  writeFileSync(tempPath, JSON.stringify(localWebhookEvents, null, 2), { mode: 0o600 });
  renameSync(tempPath, webhookEventsPath);
}
const eventClients = new Set();
function broadcastEvent(event, workspaceId) {
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of eventClients) if (client.workspaceId === workspaceId) client.res.write(payload);
}
function broadcastWebhookDelivery(event, workspaceId) {
  if (!workspaceId) return;
  broadcastEvent({
    runId: `PP-WH-${event.id}`,
    webhookEventId: event.id,
    outcome: `WEBHOOK ${event.type}`,
    source: `PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'}`,
    createdAt: event.lastReceivedAt,
    orderId: event.orderId || undefined,
    deliveries: event.deliveries,
    trace: `Verified PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'} webhook · ${event.status || event.resourceId || 'event received'}`,
  }, workspaceId);
}
function connectActivityListener() {
  if (!databaseConfigured) return;
  const listener = new pg.Client({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : undefined });
  let reconnectScheduled = false;
  const reconnect = () => {
    if (reconnectScheduled) return;
    reconnectScheduled = true;
    setTimeout(connectActivityListener, 5000).unref();
  };
  listener.on('notification', (message) => {
    try {
      const { event, workspaceId } = JSON.parse(message.payload);
      broadcastEvent(event, workspaceId);
    } catch { console.error('Ignored invalid activity notification.'); }
  });
  listener.on('error', (error) => { console.error('PostgreSQL activity listener disconnected:', error.message); reconnect(); });
  listener.connect().then(() => listener.query('LISTEN payment_activity')).catch((error) => { console.error('Could not start PostgreSQL activity listener:', error.message); reconnect(); });
}
connectActivityListener();
async function persistEvent(event, req) {
  if (databaseConfigured) {
    const saved = await pool.query(
      `INSERT INTO runs(run_id,workspace_id,created_by,scenario,trace,outcome,source,repaired,checks,details,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,COALESCE($11::timestamptz,now()))
       ON CONFLICT(run_id) DO UPDATE SET
         trace=EXCLUDED.trace,
         outcome=EXCLUDED.outcome,
         source=EXCLUDED.source,
         repaired=EXCLUDED.repaired,
         checks=EXCLUDED.checks,
         details=EXCLUDED.details,
         created_at=EXCLUDED.created_at
       WHERE runs.workspace_id=EXCLUDED.workspace_id
       RETURNING run_id`,
      [event.runId, req.user.workspace_id, req.user.user_id || null, event.scenario, event.trace || '', event.outcome, event.source, Boolean(event.repaired), JSON.stringify(event.checks || []), JSON.stringify({ orderId: event.orderId || null, webhookEventId: event.webhookEventId || null }), event.createdAt || null],
    );
    if (!saved.rowCount) throw new Error('Activity ID is already owned by another workspace.');
    try { await pool.query("SELECT pg_notify('payment_activity',$1)", [JSON.stringify({ workspaceId: req.user.workspace_id, event })]); }
    catch (error) { console.error('Activity notification failed:', error.message); broadcastEvent(event, req.user.workspace_id); }
  } else {
    const storedEvent = authEnabled ? { ...event, workspaceId: req.user?.workspace_id || null } : event;
    history = [storedEvent, ...history].slice(0, 200);
    writeFileSync(historyPath, JSON.stringify(history, null, 2));
    broadcastEvent(event, req.user?.workspace_id || null);
  }
  return event;
}

const scenarios = {
  INSTRUMENT_DECLINED: {
    label: 'Funding source declined',
    summary: 'The buyer’s funding source was declined during capture.',
    issue: 'INSTRUMENT_DECLINED',
    expected: 'Keep the order unfulfilled and offer the buyer a safe way to choose another funding source.',
    code: 'const capture = await paypal.captureOrder(orderId);\nreturn { success: true, message: "Payment complete" };',
  },
  DUPLICATE_INVOICE_ID: {
    label: 'Duplicate invoice ID',
    summary: 'The order reused an invoice ID that PayPal requires to be unique.',
    issue: 'DUPLICATE_INVOICE_ID',
    expected: 'Do not retry with the same invoice ID. Create a unique request identity and make retries idempotent.',
    code: 'const invoiceId = "INV-1042";\nconst order = await createOrder({ invoiceId });\nawait captureOrder(order.id);',
  },
  INTERNAL_SERVER_ERROR: {
    label: 'Transient PayPal error',
    summary: 'PayPal returned a temporary server error during capture.',
    issue: 'INTERNAL_SERVER_ERROR',
    expected: 'Report an unknown payment state, check the order before retrying, and avoid duplicate captures.',
    code: 'try {\n  await captureOrder(orderId);\n} catch (error) {\n  await captureOrder(orderId); // unsafe blind retry\n}',
  },
};

const localAdvice = (scenario, trace) => {
  const table = {
    INSTRUMENT_DECLINED: {
      diagnosis: 'The checkout treats a declined funding source like a successful payment. That can mark an unpaid order as fulfilled.',
      patch: 'Branch on INSTRUMENT_DECLINED, return a recoverable response to the browser, and let the buyer restart checkout with another funding source.',
      verification: 'A decline must leave fulfillment disabled. The UI should offer a retry path and must never show “Payment complete.”',
    },
    DUPLICATE_INVOICE_ID: {
      diagnosis: 'The same invoice identifier is being reused. PayPal can reject the request, and a blind retry may repeat the same failure.',
      patch: 'Generate a stable unique invoice ID per logical purchase and use a PayPal-Request-Id idempotency key for safe retries.',
      verification: 'A repeated request should resolve to the same logical order or a clear duplicate response, never a second fulfillment.',
    },
    INTERNAL_SERVER_ERROR: {
      diagnosis: 'The capture result is uncertain after a transient server failure. Immediately capturing again can create an unsafe retry path.',
      patch: 'Fetch the order status before retrying. Retry only when the payment is known not to have completed, using a stable request ID.',
      verification: 'The app must not fulfill on an unknown response. A retry should first reconcile order status and should not create duplicate fulfillment.',
    },
  };
  return { ...table[scenario], evidence: trace, model: 'Local recovery advisor' };
};

app.get('/api/health', async (_req, res) => {
  let databaseReady = false;
  if (pool) {
    try { databaseReady = (await pool.query("SELECT to_regclass('public.runs') IS NOT NULL AND to_regclass('public.paypal_webhook_events') IS NOT NULL AND to_regclass('public.paypal_environment_lock') IS NOT NULL AND to_regclass('public.mfa_login_challenges') IS NOT NULL AS schema_ready")).rows[0].schema_ready; } catch { databaseReady = false; }
  }
  res.status(databaseConfigured && !databaseReady ? 503 : 200).json({
    ok: databaseConfigured ? databaseReady : true,
    application: { name: packageInfo.name, version: packageInfo.version, nodeVersion: process.version, environment: process.env.NODE_ENV || 'development', uptimeSeconds: Math.floor(process.uptime()), startedAt: new Date(Date.now() - process.uptime() * 1000).toISOString(), serverTime: new Date().toISOString() },
    databaseConfigured,
    databaseReady,
    aiReady: claudeConfigured,
    aiModel: claudeModel,
    aiStatus: getClaudeStatus(),
    paypalReady: paypalCheckoutReady,
    paypalWebhookReady,
    paypalEnvironment,
    livePaymentsEnabled: paypalLiveCheckoutReady,
    paypalConfiguration: {
      checkoutEnabled: paypalCheckoutReady,
      credentialsConfigured: Boolean(paypalClientId && paypalClientSecret),
      webhookConfigured: Boolean(paypalWebhookId),
      livePaymentsRequested,
      productionRuntime: process.env.NODE_ENV === 'production',
      databaseReady: databaseConfigured && databaseReady,
      liveProductConfigured: paypalEnvironment !== 'live' || paypalLiveDetailsReady,
    },
    currency: paypalCurrency || 'USD',
    authentication: {
      enabled: authEnabled && (!databaseConfigured || databaseReady),
      configured: databaseConfigured,
      schemaReady: databaseReady,
      mfaEncryptionConfigured,
      mode: databaseConfigured ? 'PostgreSQL' : localAuthEnabled ? 'Local single-server file' : 'Unavailable',
      passwordHashing: 'scrypt-v2 (32 MiB, p=3)',
      sessionTokenStorage: 'SHA-256 hash',
      secureCookies: cookieSettings.secure,
      cookieHttpOnly: cookieSettings.httpOnly,
      sessionLifetimeDays: 7,
    },
  });
});

app.post('/api/ai/check', rateLimit({ windowMs: 10 * 60 * 1000, limit: 3, standardHeaders: 'draft-8', legacyHeaders: false }), async (_req, res) => {
  if (!claudeConfigured) {
    const aiStatus = setClaudeStatus('local-only', 'No API key configured; use the local advisor or configure ANTHROPIC_API_KEY on the API server.');
    return res.json({ ok: false, aiStatus });
  }
  try {
    await generateText({
      model: anthropic(claudeModel),
      prompt: 'Reply with READY only.',
      maxOutputTokens: 24,
      maxRetries: 0,
      timeout: { totalMs: 15_000 },
    });
    return res.json({ ok: true, aiStatus: setClaudeStatus('connected', 'Claude responded successfully.') });
  } catch (error) {
    const message = getClaudeFailureMessage(error);
    const details = inspectClaudeError(error);
    console.error('Claude connection check failed:', { status: details.status || 'unknown', name: details.providerErrorName, retryWrapper: error?.name === 'AI_RetryError' });
    return res.json({ ok: false, aiStatus: setClaudeStatus('unavailable', message) });
  }
});

app.get('/api/scenarios', (_req, res) => {
  res.json(Object.entries(scenarios).map(([id, item]) => ({ id, ...item })));
});

app.get('/api/runs', async (req, res) => {
  if (!databaseConfigured) return res.json(authEnabled ? history.filter((event) => event.workspaceId === req.user.workspace_id) : history);
  try {
    const result = await pool.query('SELECT run_id AS "runId",scenario,trace,outcome,source,repaired,checks,details,created_at AS "createdAt" FROM runs WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 30', [req.user.workspace_id]);
    res.json(result.rows.map((row) => ({ ...row, orderId: row.details?.orderId || undefined })));
  } catch (error) { res.status(500).json({ error: 'Could not load payment activity.' }); }
});

app.get('/api/metrics', async (req, res) => {
  if (!databaseConfigured) {
    const runs = history
      .filter((event) => event.scenario && (!authEnabled || event.workspaceId === req.user.workspace_id))
      .sort((left, right) => new Date(right.createdAt || 0) - new Date(left.createdAt || 0));
    const checks = runs.flatMap((event) => Array.isArray(event.checks) ? event.checks : []);
    const latest = runs[0];
    return res.json({
      totalRuns: runs.length,
      scenariosTested: new Set(runs.map((event) => event.scenario)).size,
      checksPassed: checks.filter((item) => item.status === 'pass').length,
      checksTotal: checks.length,
      lastRunId: latest?.runId || null,
      lastRunScenario: latest?.scenario || null,
      lastRunOutcome: latest?.outcome || null,
      lastRunAt: latest?.createdAt || null,
    });
  }

  try {
    const result = await pool.query(`
      WITH scenario_runs AS (
        SELECT run_id, scenario, outcome, checks, created_at
        FROM runs
        WHERE workspace_id = $1 AND scenario IS NOT NULL
      ),
      check_totals AS (
        SELECT
          (COUNT(*) FILTER (WHERE check_items.check_item->>'status' = 'pass'))::int AS passed,
          (COUNT(check_items.check_item))::int AS total
        FROM scenario_runs
        CROSS JOIN LATERAL jsonb_array_elements(
          CASE WHEN jsonb_typeof(scenario_runs.checks) = 'array' THEN scenario_runs.checks ELSE '[]'::jsonb END
        ) AS check_items(check_item)
      ),
      latest AS (
        SELECT run_id, scenario, outcome, created_at
        FROM scenario_runs
        ORDER BY created_at DESC
        LIMIT 1
      )
      SELECT
        (SELECT COUNT(*)::int FROM scenario_runs) AS "totalRuns",
        (SELECT COUNT(DISTINCT scenario)::int FROM scenario_runs) AS "scenariosTested",
        check_totals.passed AS "checksPassed",
        check_totals.total AS "checksTotal",
        (SELECT run_id FROM latest) AS "lastRunId",
        (SELECT scenario FROM latest) AS "lastRunScenario",
        (SELECT outcome FROM latest) AS "lastRunOutcome",
        (SELECT created_at FROM latest) AS "lastRunAt"
      FROM check_totals
    `, [req.user.workspace_id]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Could not calculate workspace reliability metrics:', error.message);
    res.status(500).json({ error: 'Could not load workspace reliability metrics.' });
  }
});

app.get('/api/events', (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write(`data: ${JSON.stringify({ type: 'connected', at: new Date().toISOString() })}\n\n`);
  const client = { res, workspaceId: req.user?.workspace_id || null };
  eventClients.add(client);
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 25000);
  req.on('close', () => { clearInterval(heartbeat); eventClients.delete(client); });
});

app.post('/api/analyze', async (req, res) => {
  const { scenario: scenarioId, trace = '', code = '', provider = 'auto' } = req.body || {};
  const scenario = scenarios[scenarioId];
  if (!scenario) return res.status(400).json({ error: 'Choose a supported failure scenario.' });

  if (provider === 'local' || !claudeConfigured) {
    const reason = provider === 'local' ? null : 'Claude is not configured; the local recovery advisor was used.';
    return res.json({ ...localAdvice(scenarioId, trace), source: 'local', warning: reason, aiStatus: getClaudeStatus() });
  }

  try {
    const { text } = await generateText({
      model: anthropic(claudeModel),
      system: 'You are PayPal Failure Doctor, a careful payment integration reliability engineer. Analyze only the supplied scenario and trace. Never claim money moved unless the trace proves it. Keep the diagnosis and fix specific. Return exactly three labeled sections: DIAGNOSIS, PATCH, VERIFY. PATCH may be pseudocode or a small code change, never a full rewrite.',
      prompt: `Scenario: ${scenario.label} (${scenario.issue})\nExpected safe behavior: ${scenario.expected}\nObserved trace:\n${String(trace).slice(0, 6000)}\nRelevant code:\n${String(code).slice(0, 6000)}`,
      maxOutputTokens: 700,
      maxRetries: 1,
      timeout: { totalMs: 20_000 },
    });
    const sections = text.split(/\n(?=PATCH:|VERIFY:)/);
    const diagnosis = sections[0]?.replace(/^DIAGNOSIS:\s*/i, '').trim() || text;
    const patch = sections.find((part) => /^PATCH:/i.test(part))?.replace(/^PATCH:\s*/i, '').trim() || 'Review the complete response below.';
    const verification = sections.find((part) => /^VERIFY:/i.test(part))?.replace(/^VERIFY:\s*/i, '').trim() || scenario.expected;
    res.json({ diagnosis, patch, verification, evidence: trace, model: claudeModel, source: 'claude', warning: null, aiStatus: setClaudeStatus('connected', 'Claude analysis completed successfully.') });
  } catch (error) {
    const details = inspectClaudeError(error);
    const status = details.status;
    const diagnostic = getClaudeFailureMessage(error);
    console.error('Claude diagnosis failed:', { status: status || 'unknown', name: details.providerErrorName, retryWrapper: error?.name === 'AI_RetryError' });
    res.json({
      ...localAdvice(scenarioId, trace),
      source: 'local',
      warning: `${diagnostic} Showing the local recovery advisor instead.`,
      providerError: status || null,
      aiStatus: setClaudeStatus('unavailable', diagnostic),
    });
  }
});

app.post('/api/simulate', async (req, res) => {
  const { scenario: scenarioId, repaired = false } = req.body || {};
  const scenario = scenarios[scenarioId];
  if (!scenario) return res.status(400).json({ error: 'Choose a supported failure scenario.' });

  const runId = `RUN-${randomUUID().toUpperCase()}`;
  const rows = {
    INSTRUMENT_DECLINED: repaired
      ? [
          ['POST /v2/checkout/orders/{id}/capture', '422', 'INSTRUMENT_DECLINED'],
          ['Fulfillment gate', 'BLOCKED', 'No capture confirmation received'],
          ['Buyer recovery', 'READY', 'Offer another funding source'],
        ]
      : [
          ['POST /v2/checkout/orders/{id}/capture', '422', 'INSTRUMENT_DECLINED'],
          ['Fulfillment gate', 'FAILED', 'Bug: app reports success despite capture failure'],
          ['Buyer recovery', 'MISSING', 'No restart path configured'],
        ],
    DUPLICATE_INVOICE_ID: repaired
      ? [
          ['POST /v2/checkout/orders', '422', 'DUPLICATE_INVOICE_ID'],
          ['Request identity', 'UNIQUE', 'New logical purchase gets a new invoice ID'],
          ['Retry behavior', 'SAFE', 'Stable idempotency key retained for this purchase'],
        ]
      : [
          ['POST /v2/checkout/orders', '422', 'DUPLICATE_INVOICE_ID'],
          ['Request identity', 'FAILED', 'Hard-coded invoice ID reused'],
          ['Retry behavior', 'LOOP', 'Same rejected request sent again'],
        ],
    INTERNAL_SERVER_ERROR: repaired
      ? [
          ['POST /v2/checkout/orders/{id}/capture', '500', 'INTERNAL_SERVER_ERROR'],
          ['GET /v2/checkout/orders/{id}', '200', 'Order status reconciled before retry'],
          ['Fulfillment gate', 'BLOCKED', 'Unknown state is not treated as success'],
        ]
      : [
          ['POST /v2/checkout/orders/{id}/capture', '500', 'INTERNAL_SERVER_ERROR'],
          ['Retry capture', 'DUPLICATE RISK', 'Blind retry without checking order status'],
          ['Fulfillment gate', 'UNCERTAIN', 'No reconciliation step'],
        ],
  }[scenarioId];

  const trace = rows.map(([step, status, detail]) => `${step}  |  ${status}  |  ${detail}`).join('\n');
  const checks = repaired
    ? [
        { label: 'Failure is surfaced', status: 'pass' },
        { label: 'No false fulfillment', status: 'pass' },
        { label: 'Recovery path is safe', status: 'pass' },
      ]
    : [
        { label: 'Failure is surfaced', status: 'pass' },
        { label: 'No false fulfillment', status: scenarioId === 'INSTRUMENT_DECLINED' ? 'fail' : 'pass' },
        { label: 'Recovery path is safe', status: 'fail' },
      ];
  const result = { runId, scenario: scenarioId, repaired, trace, checks, outcome: repaired ? 'RECOVERED' : 'ISSUES FOUND', source: 'local simulator', createdAt: new Date().toISOString() };
  try { await persistEvent(result, req); }
  catch (error) { console.error('Could not persist payment run:', error.message); return res.status(500).json({ error: 'The run completed but could not be saved.' }); }
  res.json(result);
});

async function paypalAccessToken() {
  if (!paypalClientId || !paypalClientSecret) throw new Error(`PayPal ${paypalEnvironment} credentials are not configured.`);
  const response = await fetch(`${paypalApiBase}/v1/oauth2/token`, {
    method: 'POST',
    headers: { Authorization: `Basic ${Buffer.from(`${paypalClientId}:${paypalClientSecret}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
    signal: AbortSignal.timeout(8_000),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error_description || `Could not authenticate with PayPal ${paypalEnvironment}.`);
  return data.access_token;
}

app.post('/api/paypal/webhooks', rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false }), async (req, res) => {
  if (!paypalWebhookReady) return res.status(503).json({ error: `PayPal ${paypalEnvironment} webhook verification is not configured.` });
  const event = req.body;
  const safeEvent = summarizeWebhookEvent(event);
  if (!safeEvent) return res.status(400).json({ error: 'Webhook event is missing its event ID or type.' });
  try {
    const accessToken = await paypalAccessToken();
    const verified = await verifyPayPalWebhook(event, req.headers, { webhookId: paypalWebhookId, accessToken, apiBase: paypalApiBase });
    if (!verified) return res.status(401).json({ error: 'PayPal webhook signature could not be verified.' });

    let workspaceId = null;
    if (safeEvent.orderId && databaseConfigured) {
      const match = await pool.query("SELECT workspace_id FROM runs WHERE details->>'orderId'=$1 ORDER BY created_at DESC LIMIT 1", [safeEvent.orderId]);
      workspaceId = match.rows[0]?.workspace_id || null;
    } else if (safeEvent.orderId) {
      workspaceId = history.find((item) => item.orderId === safeEvent.orderId)?.workspaceId || null;
    }

    let duplicate = false;
    if (databaseConfigured) {
      const result = await pool.query(
        `INSERT INTO paypal_webhook_events(event_id,workspace_id,event_type,order_id,resource_id,resource_status)
         VALUES($1,$2,$3,$4,$5,$6)
         ON CONFLICT(event_id) DO UPDATE SET
           deliveries=paypal_webhook_events.deliveries+1,
           workspace_id=COALESCE(paypal_webhook_events.workspace_id,EXCLUDED.workspace_id),
           order_id=COALESCE(paypal_webhook_events.order_id,EXCLUDED.order_id),
           last_received_at=now()
         RETURNING (xmax=0) AS inserted, deliveries, first_received_at, last_received_at`,
        [safeEvent.id, workspaceId, safeEvent.type, safeEvent.orderId, safeEvent.resourceId, safeEvent.status],
      );
      duplicate = !result.rows[0].inserted;
      safeEvent.deliveries = result.rows[0].deliveries;
      safeEvent.firstReceivedAt = result.rows[0].first_received_at;
      safeEvent.lastReceivedAt = result.rows[0].last_received_at;
      if (duplicate) broadcastWebhookDelivery(safeEvent, workspaceId);
      if (!duplicate && workspaceId) {
        const activity = { runId: `PP-WH-${safeEvent.id}`, webhookEventId: safeEvent.id, deliveries: safeEvent.deliveries, scenario: null, outcome: `WEBHOOK ${safeEvent.type}`, source: `PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'}`, createdAt: new Date().toISOString(), orderId: safeEvent.orderId || undefined, trace: `Verified PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'} webhook · ${safeEvent.status || safeEvent.resourceId || 'event received'}` };
        try { await persistEvent(activity, { user: { workspace_id: workspaceId, user_id: null } }); }
        catch (error) { console.error('Could not publish verified PayPal webhook activity:', error.message); }
      }
    } else {
      const existing = localWebhookEvents.find((item) => item.id === safeEvent.id);
      if (existing) {
        existing.deliveries += 1;
        existing.lastReceivedAt = new Date().toISOString();
        existing.workspaceId ||= workspaceId;
        existing.orderId ||= safeEvent.orderId;
        duplicate = true;
        Object.assign(safeEvent, existing);
        saveLocalWebhookEvents();
        broadcastWebhookDelivery(safeEvent, workspaceId);
      } else {
        Object.assign(safeEvent, { workspaceId, deliveries: 1, firstReceivedAt: new Date().toISOString(), lastReceivedAt: new Date().toISOString() });
        localWebhookEvents = [safeEvent, ...localWebhookEvents].slice(0, 500);
        saveLocalWebhookEvents();
        if (workspaceId) {
          const activity = { runId: `PP-WH-${safeEvent.id}`, webhookEventId: safeEvent.id, deliveries: safeEvent.deliveries, scenario: null, outcome: `WEBHOOK ${safeEvent.type}`, source: `PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'}`, createdAt: safeEvent.firstReceivedAt, orderId: safeEvent.orderId || undefined, trace: `Verified PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'} webhook · ${safeEvent.status || safeEvent.resourceId || 'event received'}` };
          try { await persistEvent(activity, { user: { workspace_id: workspaceId } }); }
          catch (error) { console.error('Could not publish verified PayPal webhook activity:', error.message); }
        }
      }
    }
    res.status(200).json({ received: true, duplicate, eventId: safeEvent.id });
  } catch (error) {
    console.error('PayPal webhook handling failed:', error.message);
    res.status(502).json({ error: 'Could not verify or record the PayPal webhook.' });
  }
});

app.get('/api/paypal/webhook-events', async (req, res) => {
  if (databaseConfigured) {
    const result = await pool.query('SELECT event_id AS id,event_type AS type,order_id AS "orderId",resource_id AS "resourceId",resource_status AS status,deliveries,first_received_at AS "firstReceivedAt",last_received_at AS "lastReceivedAt" FROM paypal_webhook_events WHERE workspace_id=$1 ORDER BY last_received_at DESC LIMIT 100', [req.user.workspace_id]);
    return res.json(result.rows);
  }
  return res.json(authEnabled ? localWebhookEvents.filter((item) => item.workspaceId === req.user.workspace_id) : localWebhookEvents);
});

app.get('/api/paypal/config', (_req, res) => {
  res.json({ clientId: paypalCheckoutReady ? paypalClientId : null, currency: paypalCurrency || 'USD', environment: paypalEnvironment, checkoutEnabled: paypalCheckoutReady, livePaymentsEnabled: paypalLiveCheckoutReady, amount: paypalCheckoutReady ? paypalOrderAmount : null, description: paypalCheckoutReady ? paypalOrderDescription : null });
});

app.post('/api/paypal/orders', async (req, res) => {
  if (!paypalCheckoutReady) return res.status(503).json({ error: paypalEnvironment === 'live' ? 'Live checkout is locked. Configure production, PostgreSQL, live credentials, a live webhook, and a server-side product amount/description.' : 'PayPal Sandbox checkout is not configured.' });
  try {
    const token = await paypalAccessToken();
    const response = await fetch(`${paypalApiBase}/v2/checkout/orders`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'PayPal-Request-Id': randomUUID() },
      body: JSON.stringify({ intent: 'CAPTURE', purchase_units: [{ description: paypalOrderDescription, amount: { currency_code: paypalCurrency, value: paypalOrderAmount }, invoice_id: `FD-${randomUUID().slice(0, 12)}` }] }),
    });
    const data = await response.json();
    if (response.ok) await persistEvent({ runId: `PP-${data.id}-ORDER`, scenario: null, outcome: 'ORDER CREATED', source: `PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'}`, createdAt: new Date().toISOString(), orderId: data.id, trace: `${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'} order created: ${data.status || 'CREATED'}` }, req);
    res.status(response.status).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/paypal/orders/:orderId/capture', async (req, res) => {
  const scenarioId = req.body?.scenario;
  if (!paypalCheckoutReady) return res.status(503).json({ error: `PayPal ${paypalEnvironment} checkout is not enabled.` });
  if (paypalEnvironment === 'live' && scenarioId) return res.status(400).json({ error: 'Failure injection is only available in PayPal Sandbox. Live capture is never modified with mock-failure headers.' });
  if (scenarioId && !scenarios[scenarioId]) return res.status(400).json({ error: 'Unsupported failure scenario.' });
  try {
    if (databaseConfigured) {
      const ownership = await pool.query("SELECT 1 FROM runs WHERE workspace_id=$1 AND details->>'orderId'=$2 LIMIT 1", [req.user.workspace_id, req.params.orderId]);
      if (!ownership.rowCount) return res.status(404).json({ error: 'PayPal order was not created in this workspace.' });
    } else if (authEnabled) {
      const ownsOrder = history.some((event) => event.workspaceId === req.user.workspace_id && event.orderId === req.params.orderId);
      if (!ownsOrder) return res.status(404).json({ error: 'PayPal order was not created in this workspace.' });
    }
    const token = await paypalAccessToken();
    const captureRequestId = createHash('sha256').update(`${paypalEnvironment}:capture:${req.params.orderId}`).digest('hex').slice(0, 32);
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'PayPal-Request-Id': captureRequestId };
    if (scenarioId) headers['PayPal-Mock-Response'] = JSON.stringify({ mock_application_codes: scenarioId });
    const response = await fetch(`${paypalApiBase}/v2/checkout/orders/${encodeURIComponent(req.params.orderId)}/capture`, { method: 'POST', headers });
    const data = await response.json();
    const details = Array.isArray(data.details) ? data.details.map((item) => `${item.issue || item.field || 'PayPal'}: ${item.issue || 'response detail'}`).join('\n') : '';
    const safeDetails = Array.isArray(data.details) ? data.details.map((item) => ({ issue: item.issue || null, field: item.field || null })) : [];
    const mockedFailure = Boolean(scenarioId && (safeDetails.some((item) => item.issue === scenarioId) || (scenarioId === 'INSTRUMENT_DECLINED' && data.status === 'DECLINED')));
    const outcome = paypalEnvironment === 'live'
      ? (data.status === 'COMPLETED' ? 'PAYMENT CAPTURED' : 'LIVE CAPTURE NOT COMPLETED')
      : (mockedFailure ? 'EXPECTED FAILURE REPRODUCED' : data.status === 'COMPLETED' ? 'UNEXPECTED CAPTURE' : 'FAILURE NOT CONFIRMED');
    const providerName = `PayPal ${paypalEnvironment === 'live' ? 'Live' : 'Sandbox'}`;
    const event = { runId: `PP-${req.params.orderId}-CAPTURE`, scenario: scenarioId || null, outcome, source: providerName, createdAt: new Date().toISOString(), orderId: req.params.orderId, trace: `HTTP ${response.status} · ${data.status || data.name || 'CAPTURE RESPONSE'}${details ? `\n${details}` : ''}` };
    await persistEvent(event, req);
    const safeData = { status: data.status || null, name: data.name || null, details: safeDetails, mockedFailure };
    res.status(response.status).json(safeData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use(express.static(fileURLToPath(new URL('../dist', import.meta.url))));
app.use((error, _req, res, _next) => {
  console.error('Unhandled request error:', error.message);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error.' });
});

async function startServer() {
  if (databaseConfigured) {
    try {
      await pool.query(
        `INSERT INTO paypal_environment_lock(id,paypal_environment) VALUES(1,$1)
         ON CONFLICT(id) DO NOTHING`,
        [paypalEnvironment],
      );
      const lockResult = await pool.query('SELECT paypal_environment FROM paypal_environment_lock WHERE id=1');
      const lockedEnvironment = lockResult.rows[0]?.paypal_environment;
      if (lockedEnvironment !== paypalEnvironment) throw new Error(`This database is locked to PayPal ${lockedEnvironment}; this server is configured for ${paypalEnvironment}. Use separate databases for Sandbox and Live.`);
    } catch (error) {
      console.error(`Cannot safely start PayPal ${paypalEnvironment}: ${error.message}. Run npm run db:migrate and use the matching isolated database.`);
      process.exitCode = 1;
      await pool.end();
      return;
    }
  }
  app.listen(port, '0.0.0.0', () => console.log(`PayPal Failure Doctor API (${paypalEnvironment}) listening on port ${port}`));
}

await startServer();
