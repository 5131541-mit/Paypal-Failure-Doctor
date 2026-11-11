import { useEffect, useMemo, useRef, useState } from 'react';
import { getLocalAdvice } from './local-advisor.js';
import MfaPanel from './MfaPanel.jsx';

const apiBase = import.meta.env.VITE_API_BASE_URL || '';
const apiFetch = (path, options = {}) => fetch(`${apiBase}${path}`, { credentials: 'include', ...options });
const icons = { overview: '◫', runs: '↗', docs: '⌘', auth: '♙', encryption: '⬡', settings: '⚙', network: '⌁', profile: '◎' };

const encryptionIterations = 310_000;
const encodeBase64 = (bytes) => {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.length)));
  }
  return btoa(binary);
};
const decodeBase64 = (value) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0));

async function deriveEncryptionKey(passphrase, salt) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: encryptionIterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function EncryptionPage({ run, advice, appVersion }) {
  const [plainText, setPlainText] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [cipherText, setCipherText] = useState('');
  const [decryptPassphrase, setDecryptPassphrase] = useState('');
  const [decryptedText, setDecryptedText] = useState('');
  const [cryptoMessage, setCryptoMessage] = useState('');
  const [cryptoBusy, setCryptoBusy] = useState(false);

  async function encryptSample() {
    setCryptoMessage('');
    setDecryptedText('');
    if (!window.isSecureContext || !window.crypto?.subtle) return setCryptoMessage('Web Crypto is unavailable. Open this app on localhost or HTTPS.');
    if (!plainText.trim()) return setCryptoMessage('Enter text to encrypt.');
    if (plainText.length > 10_000) return setCryptoMessage('Keep the sample under 10,000 characters.');
    if (passphrase.length < 12) return setCryptoMessage('Use a passphrase with at least 12 characters.');

    setCryptoBusy(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveEncryptionKey(passphrase, salt);
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plainText));
      const envelope = {
        version: 1,
        algorithm: 'AES-256-GCM',
        kdf: 'PBKDF2-SHA256',
        iterations: encryptionIterations,
        salt: encodeBase64(salt),
        iv: encodeBase64(iv),
        ciphertext: encodeBase64(new Uint8Array(encrypted)),
      };
      const output = JSON.stringify(envelope, null, 2);
      setCipherText(output);
      setDecryptPassphrase(passphrase);
      setCryptoMessage('Encrypted in this browser. The text and passphrase were not sent to the server.');
    } catch {
      setCryptoMessage('Encryption failed in this browser.');
    } finally {
      setCryptoBusy(false);
    }
  }

  async function exportIncidentBundle() {
    setCryptoMessage('');
    if (!run) return setCryptoMessage('Run a simulator scenario first so there is an incident to export.');
    if (!window.isSecureContext || !window.crypto?.subtle) return setCryptoMessage('Web Crypto is unavailable. Open this app on localhost or HTTPS.');
    if (passphrase.length < 12) return setCryptoMessage('Use a passphrase with at least 12 characters.');

    setCryptoBusy(true);
    try {
      const redact = (value) => String(value || '')
        .replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, '[REDACTED_EMAIL]')
        .replace(/\b(?:\d[ -]?){12,19}\b/g, '[REDACTED_NUMBER]')
        .replace(/\b[A-Z0-9]{17,}\b/g, '[REDACTED_REFERENCE]');
      const bundle = {
        kind: 'paypal-failure-doctor-incident',
        formatVersion: 1,
        appVersion,
        exportedAt: new Date().toISOString(),
        incident: {
          runId: redact(run.runId), scenario: run.scenario, outcome: redact(run.outcome), source: run.source,
          repaired: Boolean(run.repaired), trace: redact(run.trace),
          checks: (Array.isArray(run.checks) ? run.checks : []).map(({ label, status }) => ({ label: redact(label), status })),
        },
        advisor: advice ? { model: advice.model, source: advice.source, diagnosis: redact(advice.diagnosis), patch: redact(advice.patch), verification: redact(advice.verification) } : null,
      };
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveEncryptionKey(passphrase, salt);
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(bundle)));
      const envelope = JSON.stringify({ version: 1, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iterations: encryptionIterations, salt: encodeBase64(salt), iv: encodeBase64(iv), ciphertext: encodeBase64(new Uint8Array(encrypted)) }, null, 2);
      setCipherText(envelope);
      const url = URL.createObjectURL(new Blob([envelope], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `failure-doctor-incident-${new Date().toISOString().slice(0, 10)}.fdx`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setCryptoMessage('Encrypted incident bundle downloaded. It contains a redacted run and advisor summary; neither the report nor passphrase was uploaded. Keep the passphrase separately.');
    } catch {
      setCryptoMessage('Could not encrypt the incident bundle in this browser.');
    } finally {
      setCryptoBusy(false);
    }
  }

  async function decryptSample() {
    setCryptoMessage('');
    setDecryptedText('');
    if (!window.isSecureContext || !window.crypto?.subtle) return setCryptoMessage('Web Crypto is unavailable. Open this app on localhost or HTTPS.');
    if (!decryptPassphrase) return setCryptoMessage('Enter the passphrase used to encrypt this text.');
    if (cipherText.length > 100_000) return setCryptoMessage('The encrypted sample is too large.');

    setCryptoBusy(true);
    try {
      const envelope = JSON.parse(cipherText);
      if (envelope.version !== 1 || envelope.algorithm !== 'AES-256-GCM' || envelope.kdf !== 'PBKDF2-SHA256' || envelope.iterations !== encryptionIterations) {
        throw new Error('Unsupported encrypted format.');
      }
      const salt = decodeBase64(envelope.salt);
      const iv = decodeBase64(envelope.iv);
      const encrypted = decodeBase64(envelope.ciphertext);
      if (salt.length !== 16 || iv.length !== 12 || !encrypted.length) throw new Error('Invalid encrypted format.');
      const key = await deriveEncryptionKey(decryptPassphrase, salt);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
      setDecryptedText(new TextDecoder().decode(decrypted));
      setCryptoMessage('Decrypted successfully.');
    } catch {
      setCryptoMessage('Could not decrypt. Check the passphrase and encrypted text; edits are detected.');
    } finally {
      setCryptoBusy(false);
    }
  }

  return <div className="module-stack">
    <section className="panel security-intro">
      <div className="panel-head"><div><h3>Encrypted incident bundle</h3><p>Package the current run and advisor summary for secure offline sharing.</p></div><StatusPill tone={run ? 'success' : 'neutral'}>{run ? 'RUN READY' : 'NO RUN SELECTED'}</StatusPill></div>
      <div className="security-callout">A redacted incident summary is encrypted in your browser with AES-256-GCM and a passphrase-derived key. The passphrase is never sent to the server. Anyone with the .fdx file still needs the passphrase to open it.</div>
      <label className="module-field">Bundle passphrase<input type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="At least 12 characters" /></label>
      <button className="primary-btn module-action" type="button" onClick={exportIncidentBundle} disabled={cryptoBusy || !run}>{cryptoBusy ? 'Encrypting…' : 'Encrypt and download latest incident'}</button>
    </section>
    <section className="panel security-intro">
      <div className="panel-head"><div><h3>Browser encryption tool</h3><p>Encrypt and decrypt a sample directly in this browser.</p></div><StatusPill tone="success">AES-256-GCM</StatusPill></div>
      <div className="security-callout">This browser tool encrypts samples and downloadable incident bundles only. Server account passwords are scrypt-hashed; this feature does not encrypt stored run history or PayPal transactions.</div>
    </section>
    <section className="module-grid encryption-grid">
      <div className="panel module-panel">
        <div className="panel-head"><div><h3>Encrypt sample</h3><p>A random salt and nonce are created for each encryption.</p></div></div>
        <label className="module-field">Text to encrypt<textarea rows="5" maxLength={10_000} value={plainText} onChange={(event) => setPlainText(event.target.value)} placeholder="Type a non-sensitive sample" /></label>
        <label className="module-field">Passphrase<input type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="At least 12 characters" /></label>
        <button className="primary-btn module-action" type="button" onClick={encryptSample} disabled={cryptoBusy}>{cryptoBusy ? 'Working…' : 'Encrypt in browser'}</button>
      </div>
      <div className="panel module-panel">
        <div className="panel-head"><div><h3>Decrypt sample</h3><p>Paste a Failure Doctor encryption envelope.</p></div></div>
        <label className="module-field">Open an .fdx file<input type="file" accept=".fdx,.json,application/json" onChange={async (event) => { const file = event.target.files?.[0]; if (file && file.size <= 100_000) setCipherText(await file.text()); else if (file) setCryptoMessage('Encrypted bundle files must be smaller than 100 KB.'); }} /></label>
        <label className="module-field">Encrypted envelope<textarea rows="7" value={cipherText} onChange={(event) => setCipherText(event.target.value)} placeholder="Encrypted JSON appears here" /></label>
        <label className="module-field">Passphrase<input type="password" autoComplete="current-password" value={decryptPassphrase} onChange={(event) => setDecryptPassphrase(event.target.value)} /></label>
        <button className="secondary-btn module-action" type="button" onClick={decryptSample} disabled={cryptoBusy}>Decrypt in browser</button>
        {decryptedText && <div className="decrypted-output"><b>Decrypted text</b><p>{decryptedText}</p></div>}
      </div>
    </section>
    {cryptoMessage && <div className="notice" role="status"><span>ⓘ</span>{cryptoMessage}</div>}
    <section className="panel security-intro"><h3>Application data protection</h3><p className="module-copy">New account passwords use versioned, salted scrypt hashes; older hashes upgrade at the next successful login. Session tokens are stored as SHA-256 hashes. Production uses secure session cookies and HTTPS at the hosting layer. App event records are redacted; this browser tool does not change how they are stored.</p></section>
  </div>;
}

function NetworkingPage({ health }) {
  const [diagnostic, setDiagnostic] = useState({ running: false, online: typeof navigator === 'undefined' ? false : navigator.onLine, api: 'pending', events: 'pending', latency: null, checkedAt: null, error: '' });
  const apiOrigin = typeof window === 'undefined' ? '' : new URL(apiBase || window.location.origin, window.location.href).origin;
  const secure = typeof window !== 'undefined' && (window.isSecureContext || window.location.hostname === 'localhost');

  async function checkNetwork() {
    setDiagnostic((current) => ({ ...current, running: true, online: navigator.onLine, api: 'checking', events: 'checking', error: '' }));
    let api = 'offline';
    let latency = null;
    let error = '';
    if (navigator.onLine) {
      const started = performance.now();
      try {
        const response = await apiFetch('/api/health', { cache: 'no-store' });
        const body = await response.json();
        latency = Math.round(performance.now() - started);
        api = response.ok && body.ok ? 'connected' : 'degraded';
        if (api === 'degraded') error = `Health endpoint returned HTTP ${response.status}.`;
      } catch (cause) { api = 'unavailable'; error = cause.message || 'Could not reach the application API.'; }
    }
    let events = 'unavailable';
    if (navigator.onLine && api !== 'unavailable' && typeof EventSource !== 'undefined') {
      events = await new Promise((resolve) => {
        let settled = false;
        const source = new EventSource(`${apiBase}/api/events`, { withCredentials: true });
        const finish = (value) => { if (settled) return; settled = true; clearTimeout(timer); source.close(); resolve(value); };
        const timer = setTimeout(() => finish('timeout'), 3500);
        source.onmessage = (message) => { try { if (JSON.parse(message.data).type === 'connected') finish('connected'); } catch { /* Ignore unrelated frames. */ } };
        source.onerror = () => finish('blocked');
      });
    }
    setDiagnostic({ running: false, online: navigator.onLine, api, events, latency, checkedAt: new Date().toISOString(), error });
  }

  useEffect(() => { checkNetwork(); }, []);
  const tone = (value) => value === 'connected' ? 'success' : value === 'checking' || value === 'pending' ? 'neutral' : 'warning';
  const label = (value) => ({ connected: 'CONNECTED', checking: 'CHECKING', pending: 'NOT CHECKED', offline: 'OFFLINE', unavailable: 'UNAVAILABLE', degraded: 'DEGRADED', blocked: 'BLOCKED', timeout: 'TIMED OUT' }[value] || String(value).toUpperCase());
  return <div className="module-stack">
    <section className="status-grid network-status-grid">
      <div className="panel status-module"><span>DEVICE NETWORK</span><StatusPill tone={diagnostic.online ? 'success' : 'warning'}>{diagnostic.online ? 'ONLINE' : 'OFFLINE'}</StatusPill><p>Browser connectivity signal from this device.</p></div>
      <div className="panel status-module"><span>APPLICATION API</span><StatusPill tone={tone(diagnostic.api)}>{label(diagnostic.api)}</StatusPill><p>{diagnostic.latency == null ? 'Round-trip time unavailable.' : `${diagnostic.latency} ms to the health endpoint.`}</p></div>
      <div className="panel status-module"><span>LIVE EVENT STREAM</span><StatusPill tone={tone(diagnostic.events)}>{label(diagnostic.events)}</StatusPill><p>Server-Sent Events connection check for live activity updates.</p></div>
    </section>
    <section className="module-grid">
      <div className="panel module-panel"><div className="panel-head"><div><h3>Connection details</h3><p>Live checks from this browser and API server.</p></div></div><div className="security-facts"><div><span>API origin</span><b>{apiOrigin}</b></div><div><span>Browser context</span><b>{secure ? 'HTTPS / secure localhost' : 'HTTP (not a secure context)'}</b></div><div><span>API version</span><b>{health.application?.version || 'Unavailable'}</b></div><div><span>API runtime</span><b>{health.application?.nodeVersion || 'Unavailable'} · {health.application?.environment || 'unknown'}</b></div><div><span>Last checked</span><b>{diagnostic.checkedAt ? new Date(diagnostic.checkedAt).toLocaleString() : 'Checking…'}</b></div></div>{diagnostic.error && <div className="security-callout network-error">{diagnostic.error}</div>}<button className="primary-btn module-action" onClick={checkNetwork} disabled={diagnostic.running}>{diagnostic.running ? 'Checking connections…' : 'Check connections again'}</button></div>
    </section>
  </div>;
}

function StatusPill({ children, tone = 'neutral' }) {
  return <span className={`pill ${tone}`}><i />{children}</span>;
}

function relativeTime(value) {
  if (!value) return '—';
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return '—';
  const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60_000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

function App() {
  const [health, setHealth] = useState({ aiReady: false, aiModel: 'openrouter/free', aiStatus: { state: 'local-only' }, paypalReady: false, currency: 'USD', databaseConfigured: false, authentication: {} });
  const [metrics, setMetrics] = useState({ totalRuns: 0, scenariosTested: 0, checksPassed: 0, checksTotal: 0, lastRunId: null, lastRunScenario: null, lastRunOutcome: null, lastRunAt: null });
  const [scenarios, setScenarios] = useState([]);
  const [scenario, setScenario] = useState('INSTRUMENT_DECLINED');
  const [run, setRun] = useState(null);
  const [advice, setAdvice] = useState(null);
  const [busy, setBusy] = useState(false);
  const [aiBusy, setAiBusy] = useState(false);
  const [aiCheckBusy, setAiCheckBusy] = useState(false);
  const analysisRevision = useRef(0);
  const [notice, setNotice] = useState('');
  const [activeNav, setActiveNav] = useState('Overview');
  const [paypalConfig, setPaypalConfig] = useState(null);
  const [activity, setActivity] = useState([]);
  const [webhookEvents, setWebhookEvents] = useState([]);
  const [suiteResults, setSuiteResults] = useState([]);
  const [suiteProgress, setSuiteProgress] = useState(null);
  const [auth, setAuth] = useState({ checking: true, required: false, user: null, workspace: null });
  const [authMode, setAuthMode] = useState('login');
  const [authForm, setAuthForm] = useState({ email: '', password: '', workspaceName: '' });
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState('');
  const [mfaChallenge, setMfaChallenge] = useState('');
  const [mfaLoginCode, setMfaLoginCode] = useState('');
  const [workspaceName, setWorkspaceName] = useState('');
  const [workspaceBusy, setWorkspaceBusy] = useState(false);
  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '' });
  const [passwordBusy, setPasswordBusy] = useState(false);

  const selected = useMemo(() => scenarios.find((item) => item.id === scenario), [scenarios, scenario]);

  useEffect(() => { if (auth.workspace?.name) setWorkspaceName(auth.workspace.name); }, [auth.workspace?.name]);

  async function refreshWebhookEvents() {
    try {
      const response = await apiFetch('/api/paypal/webhook-events');
      if (response.ok) setWebhookEvents(await response.json());
    } catch { /* Webhook history is optional; other workspace modules stay available. */ }
  }

  async function refreshMetrics() {
    try {
      const response = await apiFetch('/api/metrics');
      if (response.ok) setMetrics(await response.json());
    } catch { /* Reliability metrics are supplemental; the simulator remains available. */ }
  }

  useEffect(() => {
    const requests = ['/api/health', '/api/scenarios', '/api/paypal/config', '/api/auth/me'].map((path) => apiFetch(path).then((response) => response.json()));
    Promise.allSettled(requests).then(([statusResult, scenariosResult, paypalResult, authResult]) => {
      if (statusResult.status === 'fulfilled') setHealth(statusResult.value);
      else setNotice('Could not load service health. Other dashboard modules remain available.');
      if (scenariosResult.status === 'fulfilled') setScenarios(scenariosResult.value);
      else setNotice('Could not load scenarios. Check the API service.');
      if (paypalResult.status === 'fulfilled') setPaypalConfig(paypalResult.value);
      if (authResult.status === 'fulfilled') {
        const session = authResult.value;
        setAuth({ checking: false, required: session.authRequired, user: session.user, workspace: session.workspace });
      } else {
        setAuth({ checking: false, required: true, user: null, workspace: null });
        setAuthError('Could not check your sign-in session. Refresh or check the API service.');
      }
    });
  }, []);

  useEffect(() => {
    if (auth.checking || (auth.required && !auth.user)) return undefined;
    let live = true;
    apiFetch('/api/runs').then((r) => r.ok ? r.json() : []).then((items) => { if (live) setActivity(items); }).catch(() => {});
    refreshMetrics();
    refreshWebhookEvents();
    const stream = new EventSource(`${apiBase}/api/events`, { withCredentials: true });
    stream.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);
        if (event.type !== 'connected') {
          setActivity((current) => [event, ...current.filter((item) => item.runId !== event.runId)].slice(0, 30));
          if (event.scenario) refreshMetrics();
          if (event.webhookEventId) setWebhookEvents((current) => [{ id: event.webhookEventId, type: event.outcome.replace('WEBHOOK ', ''), orderId: event.orderId || null, status: event.trace?.split(' · ').at(-1) || null, deliveries: event.deliveries || 1, firstReceivedAt: event.createdAt, lastReceivedAt: event.createdAt }, ...current.filter((item) => item.id !== event.webhookEventId)].slice(0, 100));
        }
      } catch { /* Ignore malformed event frames; the next event will resync. */ }
    };
    return () => { live = false; stream.close(); };
  }, [auth.checking, auth.required, auth.user]);

  async function submitAuth(event) {
    event.preventDefault(); setAuthBusy(true); setAuthError('');
    try {
      const response = await apiFetch(`/api/auth/${authMode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(authForm) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not sign in.');
      if (data.mfaRequired) {
        setMfaChallenge(data.challengeToken);
        setAuthError('');
        return;
      }
      setMfaChallenge('');
      setAuth({ checking: false, required: true, user: data.user, workspace: data.workspace });
    } catch (error) { setAuthError(error.message); }
    finally { setAuthBusy(false); }
  }

  async function verifyMfaLogin(event) {
    event.preventDefault(); setAuthBusy(true); setAuthError('');
    try {
      const response = await apiFetch('/api/auth/mfa/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: mfaChallenge, code: mfaLoginCode }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Second-factor verification failed.');
      setMfaChallenge(''); setMfaLoginCode('');
      setAuth({ checking: false, required: true, user: data.user, workspace: data.workspace });
    } catch (error) { setAuthError(error.message); }
    finally { setAuthBusy(false); }
  }

  async function signOut() {
    await apiFetch('/api/auth/logout', { method: 'POST' });
    setAuth((current) => ({ ...current, user: null, workspace: null }));
  }

  async function checkOpenRouterConnection() {
    setAiCheckBusy(true);
    setNotice('');
    try {
      const response = await apiFetch('/api/ai/check', { method: 'POST' });
      const data = await response.json();
      if (data.aiStatus) setHealth((current) => ({ ...current, aiStatus: data.aiStatus }));
      if (!response.ok) {
        setNotice(data.error || data.message || 'OpenRouter connection check is temporarily unavailable. Try again later.');
        return;
      }
      setNotice(data.ok ? 'OpenRouter connection confirmed. The next AI diagnosis will use OpenRouter.' : data.aiStatus?.message || 'OpenRouter is unavailable; use the local advisor.');
    } catch {
      setNotice('Could not reach the API server for the OpenRouter connection check. The local advisor is still available.');
    } finally {
      setAiCheckBusy(false);
    }
  }

  async function saveWorkspaceSettings(event) {
    event.preventDefault();
    setWorkspaceBusy(true);
    try {
      const response = await apiFetch('/api/workspace', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: workspaceName }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not save workspace settings.');
      setAuth((current) => ({ ...current, workspace: data.workspace }));
      setNotice('Workspace name saved.');
    } catch (error) { setNotice(error.message); }
    finally { setWorkspaceBusy(false); }
  }

  async function updatePassword(event) {
    event.preventDefault();
    setPasswordBusy(true);
    try {
      const response = await apiFetch('/api/auth/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(passwordForm) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not update the password.');
      setPasswordForm({ currentPassword: '', newPassword: '' });
      setNotice('Password updated. Other active sessions were revoked; this session remains signed in.');
    } catch (error) { setNotice(error.message); }
    finally { setPasswordBusy(false); }
  }

  async function runCheck(repaired = false) {
    if (!selected) return;
    const revision = ++analysisRevision.current;
    setBusy(true); setNotice(''); setAdvice(null);
    try {
      const response = await apiFetch('/api/simulate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario, repaired }) });
      const data = await response.json();
      if (revision !== analysisRevision.current) return;
      if (!response.ok) throw new Error(data.error || 'Simulation failed');
      setRun(data);
      const localAdvice = getLocalAdvice(scenario, data.trace);
      if (revision === analysisRevision.current && localAdvice) setAdvice(localAdvice);
    } catch (error) { if (revision === analysisRevision.current) setNotice(error.message); }
    finally { setBusy(false); }
  }

  async function runFullSuite() {
    if (!scenarios.length) return;
    const total = scenarios.length * 2;
    const results = [];
    const revision = ++analysisRevision.current;
    setBusy(true);
    setNotice('');
    setAdvice(null);
    setSuiteResults([]);
    setSuiteProgress({ completed: 0, total, running: true });

    try {
      for (const item of scenarios) {
        for (const repaired of [false, true]) {
          const caseNumber = results.length + 1;
          setSuiteProgress({ completed: results.length, total, running: true, current: `${item.label} · ${repaired ? 'repaired' : 'unsafe baseline'}` });
          const response = await apiFetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: item.id, repaired }),
          });
          const data = await response.json();
          if (revision !== analysisRevision.current) return;
          if (!response.ok) throw new Error(data.error || `Suite stopped at case ${caseNumber} of ${total}.`);
          results.push({ ...data, scenarioLabel: item.label });
          setSuiteResults([...results]);
          setSuiteProgress({ completed: results.length, total, running: true, current: `${item.label} · ${repaired ? 'repaired' : 'unsafe baseline'}` });
        }
      }

      const recoveryCount = scenarios.filter((item) => {
        const recovered = results.find((result) => result.scenario === item.id && result.repaired);
        return recovered?.checks?.length && recovered.checks.every((check) => check.status === 'pass');
      }).length;
      const baselineCount = scenarios.filter((item) => {
        const baseline = results.find((result) => result.scenario === item.id && !result.repaired);
        return baseline?.checks?.some((check) => check.status === 'fail');
      }).length;
      setSuiteProgress({ completed: results.length, total, running: false });
      setRun(results.at(-1));
      setNotice(`Reliability suite complete: ${baselineCount}/${scenarios.length} unsafe baselines surfaced an issue; ${recoveryCount}/${scenarios.length} repaired paths passed every check.`);
    } catch (error) {
      if (revision !== analysisRevision.current) return;
      setSuiteProgress({ completed: results.length, total, running: false, failed: true });
      setNotice(`Suite stopped after ${results.length}/${total} cases. ${error.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function analyzeCurrentRun() {
    if (!run) return;
    const runToAnalyze = run;
    const revision = analysisRevision.current;
    const runScenario = scenarios.find((item) => item.id === runToAnalyze.scenario) || selected;
    if (!runScenario) return;
    setAiBusy(true); setNotice('');
    try {
      const response = await apiFetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: runScenario.id, trace: runToAnalyze.trace, code: runScenario.code }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Diagnosis failed.');
      if (data.aiStatus) setHealth((current) => ({ ...current, aiStatus: data.aiStatus }));
      if (revision === analysisRevision.current) {
        setAdvice(data);
        if (data.warning) setNotice(data.warning);
      }
    } catch (error) {
      if (revision === analysisRevision.current) setNotice(error.message);
    }
    finally { setAiBusy(false); }
  }

  function useLocalAdvisor(trace = run?.trace || 'No captured trace. Explain the selected payment failure and its safe recovery.') {
    const data = getLocalAdvice(scenario, trace);
    if (!data) {
      setNotice('Choose a supported failure scenario to use the local advisor.');
      return;
    }
    setAdvice(data);
    setNotice('This advisor runs in your browser without an OpenRouter API key or network request.');
    setActiveNav('Overview');
  }

  async function loadPayPal() {
    if (!health.paypalReady || !paypalConfig?.clientId || !paypalConfig?.checkoutEnabled) {
      setNotice(paypalConfig?.environment === 'live'
        ? 'Live checkout is locked. Configure the production server, PostgreSQL, separate live credentials, a live webhook, and a server-side product price and description.'
        : 'Add Sandbox client credentials on the API server, then restart it to enable PayPal Sandbox checkout.');
      return;
    }
    setNotice(paypalConfig.environment === 'live'
      ? `Production checkout is LIVE: buyer approval captures ${paypalConfig.amount} ${paypalConfig.currency} for “${paypalConfig.description}”. This uses real PayPal funds.`
      : 'Connecting to PayPal Sandbox v6. The $2 order uses fictional Sandbox funds; no real money moves. You can use Run selected scenario for a zero-payment simulation.');
    if (window.paypal?.createInstance) { await renderPayPalButton(); return; }
    const script = document.createElement('script');
    script.src = paypalConfig.environment === 'live' ? 'https://www.paypal.com/web-sdk/v6/core' : 'https://www.sandbox.paypal.com/web-sdk/v6/core';
    script.async = true;
    script.onload = renderPayPalButton;
    script.onerror = () => setNotice(`Could not load PayPal ${paypalConfig.environment === 'live' ? 'Live' : 'Sandbox'} Checkout. Check the matching client ID and network connection.`);
    document.body.appendChild(script);
  }

  if (auth.checking) return <div className="auth-page"><div className="auth-card"><div className="brand-mark">P<span>+</span></div><p>Connecting to your workspace…</p></div></div>;
  if (auth.required && !auth.user && mfaChallenge) return <div className="auth-page"><form className="auth-card" onSubmit={verifyMfaLogin}><div className="brand"><div className="brand-mark">P<span>+</span></div><div><b>PayPal</b><small>FAILURE DOCTOR</small></div></div><span className="eyebrow">SECOND STEP</span><h1>Verify it’s you</h1><p>Enter the six-digit code from your authenticator app, or use one unused recovery code.</p>{authError && <div className="auth-error" role="alert">{authError}</div>}<label>Authenticator or recovery code<input required autoFocus autoComplete="one-time-code" inputMode="numeric" value={mfaLoginCode} onChange={(event) => setMfaLoginCode(event.target.value)} /></label><button className="primary-btn auth-submit" disabled={authBusy || !mfaLoginCode.trim()}>{authBusy ? 'Verifying…' : 'Verify and sign in'}</button><button type="button" className="auth-switch" onClick={() => { setMfaChallenge(''); setMfaLoginCode(''); setAuthForm({ ...authForm, password: '' }); setAuthError(''); }}>Cancel and return to sign in</button></form></div>;
  if (auth.required && !auth.user) return <div className="auth-page"><form className="auth-card" onSubmit={submitAuth}><div className="brand"><div className="brand-mark">P<span>+</span></div><div><b>PayPal</b><small>FAILURE DOCTOR</small></div></div><span className="eyebrow">SECURE WORKSPACE</span><h1>{authMode === 'login' ? 'Welcome back' : 'Create your workspace'}</h1><p>Payment activity is private to your workspace.</p>{authError && <div className="auth-error">{authError}</div>}{authMode === 'register' && <label>Workspace name<input required maxLength="100" value={authForm.workspaceName} onChange={(e) => setAuthForm({ ...authForm, workspaceName: e.target.value })} placeholder="My team" /></label>}<label>Email<input required type="email" autoComplete="email" value={authForm.email} onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })} /></label><label>Password<input required type="password" minLength="12" maxLength="256" autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} value={authForm.password} onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })} />{authMode === 'register' && <small>Use at least 12 characters.</small>}</label><button className="primary-btn auth-submit" disabled={authBusy}>{authBusy ? 'Please wait…' : authMode === 'login' ? 'Sign in' : 'Create account'}</button><button type="button" className="auth-switch" onClick={() => { setAuthMode(authMode === 'login' ? 'register' : 'login'); setAuthError(''); }}>{authMode === 'login' ? 'Create a new workspace' : 'I already have an account'}</button></form></div>;

  async function renderPayPalButton() {
    const target = document.getElementById('paypal-buttons');
    if (!target || !window.paypal?.createInstance) return;
    target.innerHTML = '';
    try {
      const sdk = await window.paypal.createInstance({ clientId: paypalConfig.clientId, components: ['paypal-payments'], pageType: 'checkout' });
      const eligibility = await sdk.findEligibleMethods({ currencyCode: paypalConfig.currency || 'USD' });
      if (!eligibility.isEligible('paypal')) { setNotice(`PayPal ${paypalConfig.environment === 'live' ? 'Live' : 'Sandbox'} checkout is not eligible for this buyer or currency.`); return; }

      const session = sdk.createPayPalOneTimePaymentSession({
        onApprove: async (data) => {
          const orderId = data.orderId || data.orderID;
          const response = await apiFetch(`/api/paypal/orders/${encodeURIComponent(orderId)}/capture`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(paypalConfig.environment === 'live' ? {} : { scenario }) });
          const capture = await response.json();
          const provider = paypalConfig.environment === 'live' ? 'PayPal Live' : 'PayPal Sandbox';
          const trace = `${provider} capture response\nHTTP ${response.status} · ${capture.status || capture.name || 'CAPTURE RESPONSE'}${capture.details?.length ? `\n${capture.details.map((item) => `${item.issue || 'PayPal'}${item.field ? ` (${item.field})` : ''}`).join('\n')}` : ''}`;
          if (paypalConfig.environment === 'live') {
            ++analysisRevision.current;
            const captured = response.ok && capture.status === 'COMPLETED';
            setRun({ runId: `PP-${orderId.slice(-8)}`, scenario: null, repaired: false, trace, checks: [{ label: 'PayPal response received', status: capture.status || capture.name ? 'pass' : 'fail' }, { label: 'Live capture completed', status: captured ? 'pass' : 'fail' }], outcome: captured ? 'PAYMENT CAPTURED' : 'LIVE CAPTURE NOT COMPLETED', source: provider });
            setAdvice(null);
            setNotice(captured ? `Live payment captured: ${paypalConfig.amount} ${paypalConfig.currency}. Verify it in your PayPal Business account and reconcile the matching webhook.` : 'PayPal did not confirm a completed live capture. Check the payment status in PayPal before attempting any retry.');
            return;
          }
          const expectedFailureReturned = Boolean(capture.mockedFailure || capture.details?.some((item) => item.issue === scenario) || (scenario === 'INSTRUMENT_DECLINED' && capture.status === 'DECLINED'));
          const captureCompleted = capture.status === 'COMPLETED';
          const outcome = expectedFailureReturned ? 'EXPECTED FAILURE REPRODUCED' : captureCompleted ? 'UNEXPECTED CAPTURE' : 'FAILURE NOT CONFIRMED';
          ++analysisRevision.current;
          setRun({ runId: `PP-${orderId.slice(-8)}`, scenario, repaired: false, trace, checks: [{ label: 'Sandbox response received', status: capture.status || capture.name ? 'pass' : 'fail' }, { label: 'Selected mock failure returned', status: expectedFailureReturned ? 'pass' : 'fail' }, { label: 'No payment capture completed', status: captureCompleted ? 'fail' : 'pass' }], outcome, source: 'PayPal Sandbox' });
          setNotice(expectedFailureReturned ? `Sandbox confirmed the selected ${scenario} failure. No real money moves in Sandbox.` : captureCompleted ? 'The selected failure was not returned and this Sandbox order captured. Sandbox funds are fictional; use the local simulator for a no-checkout run.' : 'PayPal did not confirm the selected mock failure. Inspect the response trace or use the local simulator.');
          setAdvice(getLocalAdvice(scenario, trace));
        },
        onCancel: () => setNotice(`${paypalConfig.environment === 'live' ? 'Live' : 'Sandbox'} checkout was cancelled. No capture was requested.`),
        onError: (error) => setNotice(error?.message || `PayPal ${paypalConfig.environment === 'live' ? 'Live' : 'Sandbox'} checkout failed.`),
      });

      const button = document.createElement('paypal-button');
      button.setAttribute('type', 'pay');
      button.addEventListener('click', async () => {
        setNotice(`Waiting for ${paypalConfig.environment === 'live' ? 'Live' : 'Sandbox'} buyer approval…`);
        try {
          await session.start({ presentationMode: 'auto' }, createOrder());
        } catch (error) { setNotice(error?.message || 'Could not start PayPal Sandbox checkout.'); }
      });
      target.appendChild(button);
      button.removeAttribute('hidden');
      setNotice(paypalConfig.environment === 'live'
        ? `PayPal Live v6 is ready. Approving charges ${paypalConfig.amount} ${paypalConfig.currency} for “${paypalConfig.description}”. Failure injection is disabled in Live mode.`
        : `PayPal Sandbox v6 is ready. The $2 order uses fictional Sandbox funds; no real money moves. Approve it to inject “${selected?.label || scenario}” at capture. The run passes only when PayPal returns the expected failure.`);
    } catch (error) {
      setNotice(error?.message || `Could not initialize PayPal ${paypalConfig.environment === 'live' ? 'Live' : 'Sandbox'} v6.`);
    }

    async function createOrder() {
      const response = await apiFetch('/api/paypal/orders', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.message || 'Order creation failed');
      return { orderId: data.id };
    }
  }

  const pageInfo = {
    Overview: ['PAYMENT RELIABILITY', 'Failure Doctor', 'Exercise payment failures. Find the bug. Verify the recovery.'],
    'Test runs': ['DIAGNOSTICS', 'Test runs', 'Run each failure scenario and review its own trace and recovery checks.'],
    'Developer Docs': ['DEVELOPER TOOLS', 'Developer Docs', 'Application API reference and PayPal integration resources.'],
    Networking: ['OPERATIONS', 'Networking', 'Check API reachability, live activity transport, browser security context, and runtime.'],
    Authentication: ['SECURITY', 'Authentication', 'Review workspace sign-in and session protections.'],
    Encryption: ['SECURITY', 'Encryption', 'Encrypt sample text and redacted incident exports locally; this does not encrypt server data.'],
    Profile: ['ACCOUNT', 'Profile', 'Manage your workspace identity and account security.'],
    Settings: ['WORKSPACE', 'Settings', 'Review integrations, application version, runtime, and deployment settings.'],
  }[activeNav] || ['WORKSPACE', activeNav, 'PayPal Failure Doctor workspace'];

  const navButton = (item, icon, badge = false) => <button key={item} title={item} aria-current={activeNav === item ? 'page' : undefined} onClick={() => setActiveNav(item)} className={`nav-item ${activeNav === item ? 'selected' : ''}`}><span>{icon}</span>{item}{badge && run && <em>1</em>}</button>;

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">P<span>+</span></div><div><b>PayPal</b><small>FAILURE DOCTOR</small></div></div>
      <div className="workspace-label">WORKSPACE</div>
      <div className="project-select"><span className="project-dot">S</span><span>{auth.workspace?.name || 'Sandbox Store'}<small>{health.application?.environment === 'production' ? 'Production app' : 'Development app'}</small></span><span className="chevron">⌄</span></div>
      <div className="nav-label">BUILD</div>
      {navButton('Overview', icons.overview)}
      {navButton('Test runs', icons.runs, true)}
      {navButton('Developer Docs', icons.docs)}
      {navButton('Networking', icons.network)}
      <div className="nav-label">SECURITY</div>
      {navButton('Authentication', icons.auth)}
      {navButton('Encryption', icons.encryption)}
      <div className="nav-label settings-label">PREFERENCES</div>
      {navButton('Profile', icons.profile)}
      {navButton('Settings', icons.settings)}
      <div className="sidebar-bottom"><div className="avatar">{(auth.user?.email || 'JD').slice(0, 2).toUpperCase()}</div><span><b>{auth.user?.email || 'Jordan Developer'}</b><small>{auth.user ? `${auth.user.role || 'member'} · account` : 'Local demo'}</small></span>{auth.user && <button className="more" onClick={signOut} title="Sign out">↗</button>}</div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div className="breadcrumbs">{auth.workspace?.name || 'Sandbox Store'} <span>/</span> <b>{activeNav}</b></div><div className="top-actions"><span className={`env-badge ${health.paypalEnvironment === 'live' ? 'env-badge-live' : ''}`} title={`App: ${health.application?.environment || 'loading'} · PayPal: ${health.paypalEnvironment || 'sandbox'}`}><i />{health.paypalEnvironment === 'live' ? (health.livePaymentsEnabled ? 'LIVE PAYMENTS' : 'LIVE MODE · LOCKED') : health.application?.environment === 'production' ? 'PRODUCTION · SANDBOX' : 'SANDBOX ENVIRONMENT'}</span><div className="tiny-avatar">{(auth.user?.email || 'JD').slice(0, 2).toUpperCase()}</div></div></header>
      <div className="page-wrap">
        {activeNav !== 'Overview' && <section className="page-heading module-heading"><div><div className="eyebrow">{pageInfo[0]} <span>•</span> WORKSPACE</div><h1>{pageInfo[1]}</h1><p>{pageInfo[2]}</p></div><div className="heading-actions">{activeNav === 'Test runs' && <button className="primary-btn" onClick={() => runCheck(false)} disabled={busy}>{busy ? 'Running…' : '▶ Run selected scenario'}</button>}{activeNav === 'Authentication' && auth.user && <button className="secondary-btn" onClick={signOut}>Sign out</button>}{activeNav === 'Settings' && <button className="secondary-btn" onClick={() => useLocalAdvisor()}>Use local advisor</button>}</div></section>}
        {notice && <div className="notice" role="status"><span>ⓘ</span>{notice}<button onClick={() => setNotice('')} aria-label="Dismiss notice">×</button></div>}

        {activeNav === 'Overview' && <>
          <section className="page-heading"><div><div className="eyebrow">PAYMENT RELIABILITY <span>•</span> WORKSPACE</div><h1>Failure Doctor</h1><p>Exercise payment failures. Find the bug. Verify the recovery.</p></div><div className="heading-actions"><button className="secondary-btn" onClick={() => { ++analysisRevision.current; setRun(null); setAdvice(null); setNotice(''); setSuiteResults([]); setSuiteProgress(null); }}>↻ <span>Reset workspace</span></button><button className="secondary-btn suite-launch-btn" onClick={runFullSuite} disabled={busy}>{busy ? 'Running…' : 'Run full suite'}</button><button className="primary-btn" onClick={() => runCheck(false)} disabled={busy}>{busy ? <span className="spinner" /> : <span>▶</span>} Run diagnostic</button></div></section>
          <section className="metrics-row">
            <div className="metric-card"><div className="metric-top"><span>LAST TEST RUN</span><span className="metric-icon">◷</span></div><strong>{relativeTime(metrics.lastRunAt)}</strong><small>{metrics.lastRunId ? `${metrics.lastRunId} · ${metrics.lastRunOutcome}` : 'No diagnostics yet'}</small></div>
            <div className="metric-card"><div className="metric-top"><span>SCENARIOS COVERED</span><span className="metric-icon purple">⌁</span></div><strong>{scenarios.length ? `${Math.min(metrics.scenariosTested || 0, scenarios.length)} / ${scenarios.length}` : '—'}</strong><small>Across recorded run history</small></div>
            <div className="metric-card"><div className="metric-top"><span>CHECKS PASSED</span><span className="metric-icon green">✓</span></div><strong>{metrics.checksTotal ? `${metrics.checksPassed} / ${metrics.checksTotal}` : '—'}</strong><small>{metrics.checksTotal ? 'Across recorded simulator checks' : 'No simulator checks yet'}</small></div>
            <div className="metric-card integration-card"><div className="metric-top"><span>INTEGRATIONS</span><span className="metric-icon blue">⌘</span></div><div className="integration-status"><span className="paypal-mini">P</span><div><b>PayPal {health.paypalEnvironment === 'live' ? 'Live' : 'Sandbox'}</b><small>{health.paypalReady ? 'Checkout enabled' : health.paypalEnvironment === 'live' ? 'Live gate locked' : 'Demo mode'}</small></div><StatusPill tone={health.paypalReady ? 'success' : 'neutral'}>{health.paypalReady ? 'READY' : 'LOCAL'}</StatusPill></div></div>
          </section>
          {suiteProgress && <section className="panel suite-panel"><div className="panel-head"><div><h3>Reliability suite</h3><p>Six independent simulator cases: unsafe baseline and repaired flow for every supported failure.</p></div><StatusPill tone={suiteProgress.failed ? 'warning' : suiteProgress.running ? 'neutral' : 'success'}>{suiteProgress.running ? `RUNNING ${suiteProgress.completed}/${suiteProgress.total}` : suiteProgress.failed ? `STOPPED ${suiteProgress.completed}/${suiteProgress.total}` : `${suiteProgress.completed}/${suiteProgress.total} COMPLETE`}</StatusPill></div>{suiteProgress.running && <div className="suite-progress"><div className="suite-progress-track"><span style={{ width: `${Math.round((suiteProgress.completed / suiteProgress.total) * 100)}%` }} /></div><small>Now running: {suiteProgress.current || 'Preparing suite'}</small></div>}<div className="suite-table-wrap"><table className="suite-table"><thead><tr><th>Failure scenario</th><th>Unsafe baseline</th><th>Repaired flow</th></tr></thead><tbody>{scenarios.map((item) => { const baseline = suiteResults.find((result) => result.scenario === item.id && !result.repaired); const repaired = suiteResults.find((result) => result.scenario === item.id && result.repaired); const baselineDetected = baseline?.checks?.some((check) => check.status === 'fail'); const recoveryVerified = repaired?.checks?.length && repaired.checks.every((check) => check.status === 'pass'); return <tr key={item.id}><th scope="row"><b>{item.label}</b><small>{item.id}</small></th><td>{baseline ? <span className={`suite-state ${baselineDetected ? 'pass' : 'fail'}`}>{baselineDetected ? 'ISSUE REPRODUCED' : 'NOT DETECTED'}</span> : <span className="suite-pending">Waiting</span>}</td><td>{repaired ? <span className={`suite-state ${recoveryVerified ? 'pass' : 'fail'}`}>{recoveryVerified ? 'ALL CHECKS PASS' : 'CHECKS FAILED'}</span> : <span className="suite-pending">Waiting</span>}</td></tr>; })}</tbody></table></div><div className="suite-footnote">Runs in the local simulator only. No PayPal checkout or OpenRouter request is made. Each case is also saved to activity history.</div></section>}
          <section className="panel activity-panel"><div className="activity-heading"><div><h3>Payment activity</h3><p>Simulator and configured PayPal environment events stream separately by source.</p></div><StatusPill tone="success">LIVE STREAM</StatusPill></div>{activity.length ? <div className="activity-list">{activity.slice(0, 5).map((item) => <div className="activity-item" key={`${item.runId}-${item.createdAt}`}><span className={`activity-source ${item.source?.startsWith('PayPal') ? 'real' : ''}`}>{item.source?.startsWith('PayPal') ? 'P' : 'D'}</span><div className="activity-summary"><b>{item.outcome}</b><small>{item.source} · {item.scenario || 'Checkout'} · {new Date(item.createdAt).toLocaleString()}</small></div><code>{item.runId}</code></div>)}</div> : <div className="activity-empty">No attempts recorded yet. Run the simulator or approve a configured PayPal checkout to create activity.</div>}</section>
          <div className="section-title"><div><h2>Test a failure path</h2><p>Failure injection runs only in the simulator or PayPal Sandbox; Live checkout is separate.</p></div><a className="docs-link" href="https://developer.paypal.com/docs/api/orders/v2/" target="_blank" rel="noreferrer">PayPal docs ↗</a></div>
          <section className="work-grid">
            <div className="panel scenario-panel"><div className="panel-head"><div><h3>Failure scenarios</h3><p>Pick a case to run against the sample checkout.</p></div><span className="count-badge">03</span></div>
              <div className="scenario-list">{scenarios.map((item, index) => <button key={item.id} disabled={busy} onClick={() => { ++analysisRevision.current; setScenario(item.id); setRun(null); setAdvice(null); }} className={`scenario-item ${scenario === item.id ? 'active' : ''}`}><span className={`scenario-symbol s${index}`}>{['↘', '⧉', 'ϟ'][index]}</span><span className="scenario-copy"><b>{item.label}</b><small>{item.issue}</small></span><span className="radio">{scenario === item.id && <i />}</span></button>)}</div>
              <div className="scenario-summary"><div className="summary-icon">✳</div><div><b>Expected safe behavior</b><p>{selected?.expected || 'Select a scenario to see the expected behavior.'}</p></div></div>
              <div className="panel-actions"><button className="run-btn" onClick={() => runCheck(false)} disabled={busy}>{busy ? 'Running…' : '▶ Run in demo simulator'}</button>{health.paypalEnvironment !== 'live' && <><button className="paypal-btn" onClick={loadPayPal}><span className="paypal-mini">P</span>Test in PayPal Sandbox</button><div id="paypal-buttons" /></>}</div>
              {health.paypalEnvironment === 'live' && <div className="live-checkout-box"><div className="live-checkout-heading"><b>Separate production checkout</b><StatusPill tone="warning">REAL FUNDS</StatusPill></div><p>{paypalConfig?.checkoutEnabled ? `${paypalConfig.amount} ${paypalConfig.currency} · ${paypalConfig.description}` : 'Live checkout remains locked until production credentials, webhook, and product settings are complete.'}</p><button className="paypal-btn" type="button" onClick={loadPayPal}>{paypalConfig?.checkoutEnabled ? 'Continue to PayPal Live approval' : 'Review Live checkout readiness'}</button><div id="paypal-buttons" /><small>The selected failure scenario applies only to the demo simulator. Live checkout never injects failures and captures only after buyer approval.</small></div>}
            </div>
            <div className="panel trace-panel"><div className="panel-head trace-head"><div><h3>Execution trace</h3><p>Request flow and recovery checks</p></div><StatusPill tone={run?.repaired ? 'success' : run ? 'warning' : 'neutral'}>{run ? run.outcome : 'AWAITING RUN'}</StatusPill></div>
              {!run ? <div className="empty-state"><div className="empty-graphic"><span>↗</span><i /><i /><i /></div><b>Nothing to inspect yet</b><p>Run a scenario to see the request trace,<br />failure signal, and recovery checks.</p></div> : <><div className="run-meta"><span><small>RUN ID</small><b>{run.runId}</b></span><span><small>MODE</small><b>{run.source || 'Local simulation'}</b></span><span><small>RESULT</small><b className={run.repaired ? 'text-green' : 'text-amber'}>{run.outcome}</b></span></div><div className="trace-rows">{run.trace.split('\n').map((line, index) => <div className="trace-row" key={index}><span className={`trace-dot ${run.repaired ? 'ok' : index === 1 ? 'bad' : 'warn'}`}>{run.repaired ? '✓' : index === 1 ? '×' : '!'}</span><code>{line}</code></div>)}</div><div className="check-list">{run.checks.map((item) => <div className="check-row" key={item.label}><span className={item.status === 'pass' ? 'check-ok' : 'check-fail'}>{item.status === 'pass' ? '✓' : '×'}</span>{item.label}<span className={`check-state ${item.status}`}>{item.status === 'pass' ? 'PASS' : 'ISSUE'}</span></div>)}</div></>}
              <div className="trace-footer"><span><i className="live-dot" /> {run ? 'Trace captured' : 'Waiting for first run'}</span><button disabled={!run} onClick={() => navigator.clipboard?.writeText(run?.trace || '')}>Copy trace</button></div>
            </div>
          </section>
          <section className="panel diagnosis-panel"><div className="diagnosis-head"><div className="doctor-icon">✳</div><div><h3>Diagnosis</h3><p>{advice ? `Analysis by ${advice.model}` : 'Local diagnosis runs automatically with each simulator run'}</p></div><div className="ai-label"><span />{advice ? (advice.source === 'openrouter' ? `OPENROUTER · ${advice.model}` : 'LOCAL ADVISOR') : health.aiStatus?.state === 'connected' ? 'OPENROUTER CONNECTED' : health.aiStatus?.state === 'unavailable' ? 'OPENROUTER FAILED · LOCAL' : health.aiReady ? 'OPENROUTER UNCHECKED' : 'LOCAL ADVISOR'}</div></div>
            {!advice ? <div className="diagnosis-empty">{busy ? <><span className="spinner dark" /> Running the simulator…</> : <>Run a diagnostic to simulate a failure and get the local explanation. OpenRouter analysis is optional.{run && <button className="secondary-btn" onClick={analyzeCurrentRun} disabled={aiBusy || run.source === 'PayPal Live'}>{aiBusy ? 'Asking OpenRouter…' : 'Ask OpenRouter about latest run'}</button>}</>}</div> : <div className="diagnosis-content"><div className="diagnosis-block"><div className="block-label"><span className="block-number">01</span> ROOT CAUSE</div><p>{advice.diagnosis}</p></div><div className="diagnosis-block patch-block"><div className="block-label"><span className="block-number">02</span> SUGGESTED FIX</div><p>{advice.patch}</p></div><div className="diagnosis-block"><div className="block-label"><span className="block-number">03</span> VERIFY</div><p>{advice.verification}</p></div><div className="diagnosis-actions"><button className="verify-btn" onClick={() => runCheck(true)} disabled={busy}>✓ Simulate recovery and re-run</button><button className="secondary-btn" onClick={() => useLocalAdvisor(run?.trace)} disabled={busy}>Use local advisor</button><button className="secondary-btn" onClick={analyzeCurrentRun} disabled={!run || aiBusy || run.source === 'PayPal Live'}>{aiBusy ? 'Asking OpenRouter…' : 'Ask OpenRouter'}</button></div></div>}
          </section>
        </>}

        {activeNav === 'Test runs' && <div className="module-stack"><section className="module-grid"><div className="panel module-panel"><div className="panel-head"><div><h3>Run a failure independently</h3><p>This simulator does not require OpenRouter or PayPal credentials.</p></div></div><label className="module-field">Scenario<select value={scenario} disabled={busy} onChange={(event) => { ++analysisRevision.current; setScenario(event.target.value); setAdvice(null); }}>{scenarios.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label><div className="scenario-summary"><div className="summary-icon">✳</div><div><b>Expected safe behavior</b><p>{selected?.expected}</p></div></div><button className="primary-btn module-action" onClick={() => runCheck(false)} disabled={busy}>{busy ? 'Running…' : 'Run unrepaired scenario'}</button><button className="secondary-btn module-action" onClick={() => runCheck(true)} disabled={busy}>{busy ? 'Running…' : 'Run repaired scenario'}</button>{run && run.source !== 'PayPal Live' && <button className="secondary-btn module-action" onClick={analyzeCurrentRun} disabled={aiBusy}>{aiBusy ? 'Asking OpenRouter…' : 'Ask OpenRouter to analyze latest run'}</button>}</div><div className="panel module-panel"><div className="panel-head"><div><h3>Latest result</h3><p>{run ? run.runId : 'No run selected yet.'}</p></div></div>{run ? <><StatusPill tone={run.repaired ? 'success' : 'warning'}>{run.outcome}</StatusPill><pre className="module-trace">{run.trace}</pre><div className="check-list">{run.checks.map((check) => <div className="check-row" key={check.label}><span className={check.status === 'pass' ? 'check-ok' : 'check-fail'}>{check.status === 'pass' ? '✓' : '×'}</span>{check.label}<span className={`check-state ${check.status}`}>{check.status === 'pass' ? 'PASS' : 'ISSUE'}</span></div>)}</div>{advice && <div className="security-callout"><b>{advice.model}</b><p>{advice.diagnosis}</p><p>{advice.patch}</p></div>}</> : <p className="module-copy">Run either simulator button. It makes no OpenRouter or PayPal request. Use “Ask OpenRouter to analyze latest run” only when you want a separate explanation.</p>}</div></section><section className="panel module-panel"><div className="panel-head"><div><h3>Activity history</h3><p>{activity.length} recent event{activity.length === 1 ? '' : 's'}</p></div></div>{activity.length ? <div className="activity-list">{activity.map((item) => <div className="activity-item" key={`${item.runId}-${item.createdAt}`}><span className={`activity-source ${item.source?.startsWith('PayPal') ? 'real' : ''}`}>{item.source?.startsWith('PayPal') ? 'P' : 'D'}</span><div className="activity-summary"><b>{item.outcome}</b><small>{item.source} · {item.scenario || 'Checkout'} · {new Date(item.createdAt).toLocaleString()}</small></div><code>{item.runId}</code></div>)}</div> : <div className="activity-empty">No activity yet. Runs are kept locally for this session or persisted to the configured database.</div>}</section></div>}

        {activeNav === 'Test runs' && <section className="panel module-panel webhook-panel"><div className="panel-head"><div><h3>PayPal webhook reconciliation</h3><p>Verified {health.paypalEnvironment === 'live' ? 'Live' : 'Sandbox'} deliveries, linked orders, and duplicate counts.</p></div><div className="webhook-heading-actions"><StatusPill tone={health.paypalWebhookReady ? 'success' : 'warning'}>{health.paypalWebhookReady ? 'VERIFICATION READY' : 'NOT CONFIGURED'}</StatusPill><button className="secondary-btn" onClick={refreshWebhookEvents}>Refresh</button></div></div>{!health.paypalWebhookReady && <div className="security-callout webhook-callout">Configure <code>{health.paypalEnvironment === 'live' ? 'PAYPAL_LIVE_WEBHOOK_ID' : 'PAYPAL_SANDBOX_WEBHOOK_ID'}</code> with the matching PayPal app credentials, then register <code>https://your-public-host/api/paypal/webhooks</code> in PayPal Developer Dashboard. Localhost is not reachable by PayPal; use a deployed HTTPS URL or a secure tunnel. Sandbox checkout and simulator runs do not depend on this webhook setup.</div>}{webhookEvents.length ? <div className="webhook-list">{webhookEvents.map((event) => <div className="webhook-row" key={event.id}><span className="webhook-status">✓</span><div className="webhook-summary"><b>{event.type}</b><small>{event.orderId ? `Order ${event.orderId}` : `Resource ${event.resourceId || 'not linked to a checkout'}`} · {event.status || 'Received'} · {new Date(event.lastReceivedAt || event.firstReceivedAt).toLocaleString()}</small></div><span className="webhook-deliveries">{event.deliveries} delivery{event.deliveries === 1 ? '' : 'ies'}</span></div>)}</div> : <div className="activity-empty">No verified webhook deliveries yet. This remains independent from simulator runs and checkout testing.</div>}</section>}

        {activeNav === 'Developer Docs' && <div className="panel module-panel api-reference"><div className="panel-head"><div><h3>Application API endpoints</h3><p>Reference for the API used by this workspace. Routes use the current app origin and return JSON, except the live event stream.</p></div></div>{[
          ['GET', '/api/health', 'Independent status for API, database, AI connectivity state, and security settings.'],
          ['POST', '/api/ai/check', 'Send a small authenticated request to confirm the configured OpenRouter key and model work.'],
          ['PATCH', '/api/workspace', 'Rename the signed-in workspace (owner or admin).'],
          ['POST', '/api/auth/password', 'Change the signed-in account password and revoke other sessions.'],
          ['GET', '/api/scenarios', 'Read the supported payment failure scenarios.'],
          ['GET', '/api/runs', 'Read recent payment activity for the current session or workspace.'],
          ['GET', '/api/metrics', 'Read workspace-scoped run counts, scenario coverage, check totals, and latest run.'],
          ['GET', '/api/events', 'Subscribe to the live Server-Sent Events activity stream.'],
          ['POST', '/api/simulate', 'Run a failure scenario without calling PayPal or OpenRouter.'],
          ['POST', '/api/analyze', 'Get OpenRouter analysis, local fallback, or set provider to local.'],
          ['POST', '/api/auth/register', 'Create a workspace account in local MVP mode or PostgreSQL production mode.'],
          ['POST', '/api/auth/login', 'Create a secure session for an existing account.'],
          ['POST', '/api/auth/mfa/verify', 'Complete a password login with a TOTP or one-time recovery code.'],
          ['GET', '/api/auth/mfa/status', 'Read two-step verification status for the signed-in account.'],
          ['POST', '/api/auth/mfa/setup', 'Begin authenticator enrollment after password confirmation.'],
          ['POST', '/api/auth/mfa/confirm', 'Enable authenticator verification and issue one-time recovery codes.'],
          ['POST', '/api/auth/mfa/disable', 'Disable MFA after password and authenticator or recovery verification.'],
          ['POST', '/api/paypal/orders', 'Create an order in the server-selected environment; Live requires the production safety gate.'],
          ['POST', '/api/paypal/orders/:orderId/capture', 'Capture an owned order; failure injection is rejected in Live mode.'],
          ['POST', '/api/paypal/webhooks', 'Verify webhook signatures with the selected PayPal environment and record deduplicated summaries.'],
          ['GET', '/api/paypal/webhook-events', 'Read verified webhook summaries for the current workspace.'],
        ].map(([method, route, summary]) => <div className="endpoint-row" key={`${method}-${route}`}><code className={`http-method ${method.toLowerCase()}`}>{method}</code><code className="endpoint-path">{route}</code><span>{summary}</span></div>)}</div>}

        {activeNav === 'Authentication' && <div className="module-stack"><section className="module-grid"><div className="panel module-panel"><div className="panel-head"><div><h3>Account authentication</h3><p>Authentication is independent from OpenRouter and PayPal.</p></div><StatusPill tone={health.authentication?.enabled ? 'success' : 'warning'}>{health.authentication?.enabled ? 'ENABLED' : health.authentication?.mode === 'Unavailable' ? 'UNAVAILABLE' : 'DATABASE SETUP REQUIRED'}</StatusPill></div><div className="security-facts"><div><span>Mode</span><b>{health.authentication?.mode || (health.authentication?.enabled ? 'Database-backed accounts' : 'Sign-in unavailable')}</b></div><div><span>Current user</span><b>{auth.user?.email || 'No signed-in account'}</b></div><div><span>Workspace</span><b>{auth.workspace?.name || 'Sandbox Store'}</b></div><div><span>Password storage</span><b>{health.authentication?.passwordHashing || 'scrypt'} salted hash</b></div><div><span>Session lifetime</span><b>{health.authentication?.sessionLifetimeDays || 7} days</b></div></div>{health.authentication?.mode === 'Local single-server file' && <div className="security-callout">Local MVP accounts work across browsers on this app server. Passwords are scrypt-hashed and session tokens are hashed; account state stays in a server-local file. Use PostgreSQL for hosted or multi-instance deployments.</div>}{!health.authentication?.enabled && <div className="security-callout">PostgreSQL must be configured and migrated with <code>npm run db:migrate</code> before production account authentication can start.</div>}{auth.user && <button className="secondary-btn module-action" onClick={signOut}>Sign out of this workspace</button>}</div><div className="panel module-panel"><div className="panel-head"><div><h3>Session protections</h3><p>Session tokens are random and server validated.</p></div></div><div className="security-facts"><div><span>Browser cookie</span><b>{health.authentication?.cookieHttpOnly ? 'HttpOnly' : 'Not HttpOnly'}</b></div><div><span>Cross-site policy</span><b>SameSite=Lax</b></div><div><span>Production-only flag</span><b>{health.authentication?.secureCookies ? 'Secure cookie enabled' : 'Secure cookie activates in production'}</b></div><div><span>Stored session value</span><b>{health.authentication?.sessionTokenStorage || 'SHA-256 hash'}</b></div></div><p className="module-copy">The sign-in screen appears automatically whenever account authentication is enabled. Production requires PostgreSQL; local MVP mode uses one app server.</p></div></section></div>}

        {activeNav === 'Authentication' && auth.user && <MfaPanel user={auth.user} onDisabled={signOut} />}

        {activeNav === 'Networking' && <NetworkingPage health={health} />}

        {activeNav === 'Profile' && <div className="module-stack"><section className="module-grid"><form className="panel module-panel" onSubmit={saveWorkspaceSettings}><div className="panel-head"><div><h3>Profile and workspace</h3><p>Your email identifies this account. Workspace name controls how this private project is labeled.</p></div><StatusPill tone={auth.user ? 'success' : 'neutral'}>{auth.user ? 'SIGNED IN' : 'LOCAL DEMO'}</StatusPill></div><label className="module-field">Account email<input type="email" value={auth.user?.email || 'Local demo account'} readOnly /></label><label className="module-field">Workspace name<input required maxLength="100" value={workspaceName || auth.workspace?.name || ''} onChange={(event) => setWorkspaceName(event.target.value)} placeholder="My workspace" /></label><div className="security-facts"><div><span>Workspace role</span><b>{auth.user?.role || (auth.user ? 'member' : 'Demo visitor')}</b></div><div><span>Workspace ID</span><b>{auth.workspace?.id || 'Local demo'}</b></div></div><button className="primary-btn module-action" type="submit" disabled={!auth.user || workspaceBusy}>{workspaceBusy ? 'Saving…' : 'Save workspace profile'}</button>{!auth.user && <p className="module-copy">Create an account or sign in to persist profile changes.</p>}</form><section className="panel module-panel"><div className="panel-head"><div><h3>Account security</h3><p>Change your password without logging out of this device.</p></div><StatusPill tone={health.authentication?.enabled ? 'success' : 'warning'}>{health.authentication?.enabled ? 'AUTH ACTIVE' : 'DEMO MODE'}</StatusPill></div>{auth.user ? <form onSubmit={updatePassword}><label className="module-field">Current password<input required type="password" autoComplete="current-password" value={passwordForm.currentPassword} onChange={(event) => setPasswordForm({ ...passwordForm, currentPassword: event.target.value })} /></label><label className="module-field">New password<input required type="password" minLength="12" maxLength="256" autoComplete="new-password" value={passwordForm.newPassword} onChange={(event) => setPasswordForm({ ...passwordForm, newPassword: event.target.value })} /><small className="field-hint">Use 12–256 characters. Other active sessions are revoked after the change.</small></label><button className="secondary-btn module-action" type="submit" disabled={passwordBusy}>{passwordBusy ? 'Updating…' : 'Update password'}</button></form> : <div className="security-callout">Sign in to update your password. The demo workspace has no account credential.</div>}<button className="secondary-btn module-action" type="button" onClick={() => setActiveNav('Authentication')}>Review authentication controls</button></section></section></div>}

        {activeNav === 'Encryption' && <EncryptionPage run={run} advice={advice} appVersion={health.application?.version || 'unknown'} />}


        {activeNav === 'Settings' && <div className="module-stack"><section className="panel security-intro live-gate-panel"><div className="panel-head"><div><h3>Payment environment and live gate</h3><p>Mode is controlled only by API-server environment settings, never by a browser toggle.</p></div><StatusPill tone={health.livePaymentsEnabled ? 'warning' : health.paypalEnvironment === 'sandbox' ? 'success' : 'neutral'}>{health.livePaymentsEnabled ? 'LIVE CAPTURE ENABLED' : health.paypalEnvironment === 'live' ? 'LIVE GATE LOCKED' : 'SANDBOX MODE'}</StatusPill></div><div className="security-facts"><div><span>PayPal environment</span><b>{(health.paypalEnvironment || 'sandbox').toUpperCase()}</b></div><div><span>Checkout status</span><b>{health.paypalReady ? 'Enabled' : 'Unavailable / locked'}</b></div><div><span>Production server</span><b>{health.paypalConfiguration?.productionRuntime ? 'Confirmed' : 'Not production'}</b></div><div><span>PostgreSQL</span><b>{health.paypalConfiguration?.databaseReady ? 'Ready' : 'Required for Live'}</b></div><div><span>Live credentials</span><b>{health.paypalConfiguration?.credentialsConfigured && health.paypalEnvironment === 'live' ? 'Configured' : health.paypalEnvironment === 'live' ? 'Missing' : 'Isolated from Sandbox'}</b></div><div><span>Live webhook</span><b>{health.paypalEnvironment === 'live' && health.paypalConfiguration?.webhookConfigured ? 'Configured' : health.paypalEnvironment === 'live' ? 'Required' : 'Separate live ID required'}</b></div><div><span>Live product/price</span><b>{health.paypalEnvironment === 'live' && health.paypalConfiguration?.liveProductConfigured ? 'Configured' : health.paypalEnvironment === 'live' ? 'Required' : 'Not used in Sandbox'}</b></div></div><div className="security-callout live-gate-callout">Live capture requires <code>NODE_ENV=production</code>, <code>PAYPAL_ENVIRONMENT=live</code>, PostgreSQL, live-only client credentials, a live webhook ID, <code>PAYPAL_LIVE_PAYMENTS_ENABLED=true</code>, and a server-set amount/currency/description. Until every check passes, the order endpoint returns 503. Failure injection and AI analysis are never run on Live captures.</div></section><section className="panel runtime-panel"><div className="panel-head"><div><h3>Application runtime</h3><p>Version and service details read from the running API.</p></div><StatusPill tone={health.ok ? 'success' : 'warning'}>{health.ok ? 'HEALTHY' : 'DEGRADED'}</StatusPill></div><div className="security-facts"><div><span>Application version</span><b>{health.application?.version || 'Loading…'}</b></div><div><span>Environment</span><b>{health.application?.environment || 'Unknown'}</b></div><div><span>Node.js</span><b>{health.application?.nodeVersion || 'Unknown'}</b></div><div><span>Server uptime</span><b>{health.application?.uptimeSeconds == null ? 'Unknown' : `${Math.floor(health.application.uptimeSeconds / 3600)}h ${Math.floor((health.application.uptimeSeconds % 3600) / 60)}m`}</b></div><div><span>Server time</span><b>{health.application?.serverTime ? new Date(health.application.serverTime).toLocaleString() : 'Unknown'}</b></div></div><button className="secondary-btn module-action" onClick={() => setActiveNav('Networking')}>Open networking diagnostics</button></section><section className="status-grid"><div className="panel status-module"><span>PAYPAL {health.paypalEnvironment === 'live' ? 'LIVE' : 'SANDBOX'}</span><StatusPill tone={health.paypalReady ? 'success' : 'warning'}>{health.paypalReady ? 'CHECKOUT READY' : health.paypalEnvironment === 'live' ? 'GATE LOCKED' : 'DEMO MODE'}</StatusPill><p>{health.paypalEnvironment === 'live' ? 'Approved captures use real funds and configured product pricing.' : 'Sandbox checkout uses fictional test funds and stays separate from simulator runs.'}</p></div><div className="panel status-module"><span>OPENROUTER</span><StatusPill tone={health.aiStatus?.state === 'connected' ? 'success' : health.aiStatus?.state === 'unavailable' ? 'warning' : 'neutral'}>{health.aiStatus?.state === 'connected' ? 'CONNECTED' : health.aiStatus?.state === 'unavailable' ? 'USING LOCAL' : health.aiReady ? 'CONFIGURED · NOT CHECKED' : 'LOCAL ONLY'}</StatusPill><p>Model: {health.aiModel || 'openrouter/free'}. {health.aiStatus?.message || 'The deterministic local advisor remains available.'}</p>{health.aiStatus?.checkedAt && <small className="field-hint">Last checked: {new Date(health.aiStatus.checkedAt).toLocaleString()}</small>}<button className="secondary-btn module-action" type="button" onClick={checkOpenRouterConnection} disabled={!health.aiReady || aiCheckBusy}>{aiCheckBusy ? 'Checking OpenRouter…' : health.aiReady ? 'Check OpenRouter connection' : 'Configure OpenRouter API key on the server'}</button>{health.aiReady && <small className="field-hint">Connection check sends one small API request and may use a small amount of API credit.</small>}</div><div className="panel status-module"><span>POSTGRESQL</span><StatusPill tone={health.databaseReady ? 'success' : 'warning'}>{health.databaseReady ? 'READY' : 'LOCAL MODE'}</StatusPill><p>{health.databaseReady ? 'Accounts and shared activity are available.' : 'Local accounts and activity use this server; PostgreSQL enables shared durable storage for hosted deployments.'}</p></div></section><section className="module-grid"><div className="panel module-panel"><div className="panel-head"><div><h3>Independent recovery options</h3><p>Use each service only when you need it.</p></div></div><ul className="module-list"><li>Demo simulator runs without PayPal or OpenRouter.</li><li>PayPal Sandbox checkout runs without OpenRouter.</li><li>The browser-local advisor works without an OpenRouter API key or network request after the app has loaded.</li><li>Browser encryption works without the API or database.</li><li>Local accounts use the server file; PostgreSQL supports hosted multi-instance workspaces.</li></ul><button className="primary-btn module-action" onClick={() => useLocalAdvisor()} disabled={busy}>{busy ? 'Working…' : 'Try local advisor'}</button></div><div className="panel module-panel"><div className="panel-head"><div><h3>Server configuration</h3><p>Set these in the API server environment or Render dashboard. Never paste secret values into the browser.</p></div></div><div className="security-facts"><div><span>OpenRouter key</span><b>OPENROUTER_API_KEY (API server only)</b></div><div><span>OpenRouter model</span><b>OPENROUTER_MODEL=openrouter/free</b></div><div><span>Database</span><b>DATABASE_URL</b></div><div><span>Sandbox PayPal</span><b>PAYPAL_SANDBOX_CLIENT_ID + PAYPAL_SANDBOX_CLIENT_SECRET</b></div><div><span>Live PayPal</span><b>PAYPAL_LIVE_CLIENT_ID + PAYPAL_LIVE_CLIENT_SECRET</b></div><div><span>Live product</span><b>PAYPAL_LIVE_AMOUNT, PAYPAL_LIVE_CURRENCY, PAYPAL_LIVE_DESCRIPTION</b></div></div><button className="secondary-btn module-action" onClick={() => setActiveNav('Profile')}>Open profile settings</button><button className="secondary-btn module-action" onClick={() => setActiveNav('Authentication')}>Open Authentication module</button><button className="secondary-btn module-action" onClick={() => setActiveNav('Encryption')}>Open Encryption module</button></div></section></div>}

        <footer className="page-footer"><span>Failure Doctor v{health.application?.version || '…'} <span className="footer-dot">•</span> PayPal payment reliability toolkit</span><span>{health.livePaymentsEnabled ? 'Live capture enabled' : health.paypalEnvironment === 'live' ? 'Live capture locked' : 'Sandbox active · Live locked'}</span></footer>
      </div>
    </main>
  </div>;
}

export default App;
