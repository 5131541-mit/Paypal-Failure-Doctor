import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

process.env.MFA_ENCRYPTION_KEY = Buffer.alloc(32, 0x5a).toString('base64');
const {
  createOtpAuthUrl,
  createRecoveryCodes,
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  findRecoveryCodeIndex,
  hashRecoveryCode,
  mfaEncryptionConfigured,
  verifyTotp,
} = await import('./mfa.js?test=mfa-suite');

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(value) {
  let buffer = 0;
  let bits = 0;
  const bytes = [];
  for (const character of value) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 255);
    }
  }
  return Buffer.from(bytes);
}

function createCode(secret, counter) {
  const movingFactor = Buffer.alloc(8);
  movingFactor.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decodeBase32(secret)).update(movingFactor).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

test('authenticator secrets encrypt and decrypt; tampering fails closed', () => {
  assert.equal(mfaEncryptionConfigured, true);
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret);
  assert.equal(decryptTotpSecret(encrypted), secret);
  const parts = encrypted.split('.');
  parts[3] = Buffer.from('tampered').toString('base64url');
  assert.throws(() => decryptTotpSecret(parts.join('.')));
});

test('TOTP enrollment URI is valid and accepted codes cannot be replayed', () => {
  const secret = createTotpSecret();
  const now = Date.now();
  const counter = Math.floor(now / 30_000);
  const code = createCode(secret, counter);
  const url = new URL(createOtpAuthUrl(secret, 'user@example.test'));

  assert.equal(url.protocol, 'otpauth:');
  assert.equal(url.searchParams.get('secret'), secret);
  assert.equal(url.searchParams.get('digits'), '6');
  assert.equal(verifyTotp(secret, code, -1, now), counter);
  assert.equal(verifyTotp(secret, code, counter, now), null);
  assert.equal(verifyTotp(secret, 'invalid', -1, now), null);
});

test('recovery codes are hashed and a consumed code no longer matches', () => {
  const codes = createRecoveryCodes();
  const hashes = codes.map(hashRecoveryCode);

  assert.equal(codes.length, 10);
  assert.match(codes[0], /^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/);
  assert.notEqual(hashes[0], codes[0]);
  assert.equal(findRecoveryCodeIndex(codes[0], hashes), 0);
  hashes.splice(0, 1);
  assert.equal(findRecoveryCodeIndex(codes[0], hashes), -1);
  assert.equal(findRecoveryCodeIndex('not-a-recovery-code', hashes), -1);
});
