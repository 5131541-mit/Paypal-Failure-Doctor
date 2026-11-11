import { useEffect, useState } from 'react';

const apiBase = import.meta.env.VITE_API_BASE_URL || '';
const apiFetch = (path, options = {}) => fetch(`${apiBase}${path}`, { credentials: 'include', ...options });

export default function MfaPanel({ user, onDisabled }) {
  const [status, setStatus] = useState(null);
  const [password, setPassword] = useState('');
  const [proof, setProof] = useState('');
  const [setup, setSetup] = useState(null);
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function refreshStatus() {
    try {
      const response = await apiFetch('/api/auth/mfa/status');
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not read verification status.');
      setStatus(data);
    } catch (failure) { setError(failure.message); }
  }

  useEffect(() => {
    if (user?.id) refreshStatus();
  }, [user?.id]);

  async function beginSetup(event) {
    event.preventDefault(); setBusy(true); setError(''); setMessage('');
    try {
      const response = await apiFetch('/api/auth/mfa/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not start setup.');
      setSetup(data); setPassword(''); setProof('');
      setMessage('Add this account in your authenticator app, then confirm with its current six-digit code.');
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }

  async function confirmSetup(event) {
    event.preventDefault(); setBusy(true); setError(''); setMessage('');
    try {
      const response = await apiFetch('/api/auth/mfa/confirm', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: proof }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not enable two-step verification.');
      setSetup(null); setProof(''); setRecoveryCodes(data.recoveryCodes || []);
      setMessage('Two-step verification is enabled. Save these recovery codes now; they are shown only once.');
      await refreshStatus();
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }

  async function disableMfa(event) {
    event.preventDefault(); setBusy(true); setError(''); setMessage('');
    try {
      const response = await apiFetch('/api/auth/mfa/disable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password, code: proof }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not disable two-step verification.');
      setPassword(''); setProof(''); setStatus({ enabled: false, recoveryCodesRemaining: 0, available: status?.available });
      setMessage('Two-step verification was disabled and all sessions were signed out.');
      onDisabled?.();
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }

  async function copyRecoveryCodes() {
    try {
      await navigator.clipboard.writeText(recoveryCodes.join('\n'));
      setMessage('Recovery codes copied. Store them in a password manager, then clear this screen.');
    } catch { setError('Clipboard access failed. Select and copy the codes manually.'); }
  }

  return <section className="panel module-panel mfa-panel">
    <div className="panel-head"><div><h3>Two-step verification</h3><p>Use an authenticator app for sign-in codes, with single-use recovery codes if you lose the device.</p></div><span className={`mfa-state ${status?.enabled ? 'is-enabled' : ''}`}>{status?.enabled ? 'ENABLED' : status ? 'NOT ENABLED' : 'LOADING'}</span></div>
    <div className="security-callout">Authenticator secrets are encrypted by the API server. Keep the MFA encryption key backed up securely; losing it can prevent authenticator verification.</div>
    {!status?.available && <div className="security-callout">Configure <code>MFA_ENCRYPTION_KEY</code> on the API server and restart it before enrolling an authenticator.</div>}
    {error && <div className="auth-error" role="alert">{error}</div>}
    {message && <div className="mfa-message" role="status">{message}</div>}

    {!status?.enabled && !setup && !recoveryCodes.length && <form onSubmit={beginSetup}>
      <label className="module-field">Confirm your password<input required type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button className="primary-btn module-action" disabled={busy || !status?.available}>{busy ? 'Starting…' : 'Set up authenticator app'}</button>
    </form>}

    {setup && <div className="mfa-setup">
      <p>In your authenticator app, add an account manually using these settings:</p>
      <div className="security-facts"><div><span>Account</span><b>{user.email}</b></div><div><span>Type</span><b>Time-based (TOTP)</b></div><div><span>Digits / period</span><b>6 digits / 30 seconds</b></div></div>
      <label className="module-field">Setup key <input readOnly value={setup.secret} onFocus={(event) => event.target.select()} autoComplete="off" /></label>
      <small className="field-hint">This key can enroll an authenticator. Do not share it; setup expires after 10 minutes.</small>
      <form onSubmit={confirmSetup}><label className="module-field">Current authenticator code<input required inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength="6" value={proof} onChange={(event) => setProof(event.target.value.replace(/\D/g, '').slice(0, 6))} /></label><button className="primary-btn module-action" disabled={busy || proof.length !== 6}>{busy ? 'Confirming…' : 'Confirm and enable'}</button></form>
      <button className="auth-switch" type="button" onClick={() => { setSetup(null); setProof(''); setError(''); }}>Cancel setup</button>
    </div>}

    {recoveryCodes.length > 0 && <div className="mfa-recovery"><p>Each recovery code works once. Save them somewhere private and separate from your authenticator device.</p><pre>{recoveryCodes.join('\n')}</pre><div className="panel-actions"><button className="secondary-btn" type="button" onClick={copyRecoveryCodes}>Copy recovery codes</button><button className="primary-btn" type="button" onClick={() => { setRecoveryCodes([]); setMessage('Recovery codes cleared from this screen.'); }}>I saved them</button></div></div>}

    {status?.enabled && recoveryCodes.length === 0 && <>
      <div className="security-facts"><div><span>Recovery codes remaining</span><b>{status.recoveryCodesRemaining}</b></div><div><span>Sign-in security</span><b>Password + authenticator code</b></div></div>
      <form onSubmit={disableMfa}><label className="module-field">Confirm your password<input required type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label><label className="module-field">Authenticator or recovery code<input required autoComplete="one-time-code" value={proof} onChange={(event) => setProof(event.target.value)} /></label><button className="secondary-btn module-action" disabled={busy}>{busy ? 'Disabling…' : 'Disable two-step verification'}</button></form>
    </>}
  </section>;
}
