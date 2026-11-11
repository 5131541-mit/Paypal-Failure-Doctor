import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
import { hashPassword, verifyPassword } from './passwords.js';

const scrypt = promisify(scryptCallback);

test('new password hashes use the versioned stronger scrypt profile', async () => {
  const hash = await hashPassword('correct horse battery staple');
  assert.match(hash, /^scrypt-v2:[a-f0-9]{32}:[a-f0-9]{128}$/);
  assert.deepEqual(await verifyPassword('correct horse battery staple', hash), { valid: true, needsRehash: false });
  assert.deepEqual(await verifyPassword('wrong password', hash), { valid: false, needsRehash: false });
});

test('legacy scrypt hashes verify and request a one-time upgrade', async () => {
  const salt = randomBytes(16);
  const key = await scrypt('legacy password', salt, 64);
  const legacyHash = `scrypt:${salt.toString('hex')}:${Buffer.from(key).toString('hex')}`;
  assert.deepEqual(await verifyPassword('legacy password', legacyHash), { valid: true, needsRehash: true });
});

test('malformed or unknown hash formats fail closed', async () => {
  assert.deepEqual(await verifyPassword('anything', 'scrypt:bad:bad'), { valid: false, needsRehash: false });
  assert.deepEqual(await verifyPassword('anything', 'argon2:bad:bad'), { valid: false, needsRehash: false });
});
