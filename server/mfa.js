import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const issuer = 'PayPal Failure Doctor';
const stepSeconds = 30;
const keyText = process.env.MFA_ENCRYPTION_KEY || '';
const encryptionKey = keyText ? Buffer.from(keyText, 'base64') : null;
if (keyText && encryptionKey.length !== 32) throw new Error('MFA_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
export const mfaEncryptionConfigured = Boolean(encryptionKey);

function requireEncryptionKey() {
  if (!encryptionKey) throw new Error('MFA_ENCRYPTION_KEY is not configured.');
  return encryptionKey;
}

export function encodeBase32(bytes) {
  let buffer = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += base32Alphabet[(buffer << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value) {
  const normalized = String(value || '').replace(/[=\s-]/g, '').toUpperCase();
  let buffer = 0;
  let bits = 0;
  const output = [];
  for (const character of normalized) {
    const index = base32Alphabet.indexOf(character);
    if (index < 0) throw new Error('Invalid authenticator secret.');
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

export function createTotpSecret() {
  return encodeBase32(randomBytes(20));
}

export function createOtpAuthUrl(secret, accountName) {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const query = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: String(stepSeconds) });
  return `otpauth://totp/${label}?${query}`;
}

export function encryptTotpSecret(secret) {
  const key = requireEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('.');
}

export function decryptTotpSecret(envelope) {
  const key = requireEncryptionKey();
  const [version, ivText, tagText, ciphertextText] = String(envelope || '').split('.');
  if (version !== 'v1' || !ivText || !tagText || !ciphertextText) throw new Error('Invalid encrypted authenticator secret.');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
}

function hotp(secret, counter) {
  const movingFactor = Buffer.alloc(8);
  movingFactor.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decodeBase32(secret)).update(movingFactor).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

function constantTimeTextEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function verifyTotp(secret, submittedCode, lastAcceptedCounter = -1, now = Date.now()) {
  const code = String(submittedCode || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return null;
  const currentCounter = Math.floor(now / 1000 / stepSeconds);
  let matchedCounter = null;
  for (const counter of [currentCounter - 1, currentCounter, currentCounter + 1]) {
    if (counter >= 0 && constantTimeTextEqual(hotp(secret, counter), code) && counter > Number(lastAcceptedCounter || -1)) {
      matchedCounter = counter;
    }
  }
  return matchedCounter;
}

export function createRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => randomBytes(8).toString('hex').toUpperCase().match(/.{4}/g).join('-'));
}

export function hashRecoveryCode(code) {
  const normalized = String(code || '').replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-F0-9]{16}$/.test(normalized)) return '';
  return createHmac('sha256', requireEncryptionKey()).update(normalized).digest('hex');
}

export function findRecoveryCodeIndex(code, hashes) {
  const submittedHash = hashRecoveryCode(code);
  let found = -1;
  for (let index = 0; index < hashes.length; index += 1) {
    const stored = Buffer.from(String(hashes[index] || ''), 'hex');
    const candidate = Buffer.from(submittedHash || '0'.repeat(64), 'hex');
    if (stored.length === candidate.length && timingSafeEqual(stored, candidate)) found = index;
  }
  return found;
}
