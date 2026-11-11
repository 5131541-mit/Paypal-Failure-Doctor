import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
// OWASP's 2^15 / r=8 / p=3 scrypt profile; allow overhead above the 32 MiB core.
export const scryptOptions = Object.freeze({ N: 2 ** 15, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
const maxConcurrentDerivations = 2;
let activeDerivations = 0;
const derivationQueue = [];
const keyLength = 64;
const saltLength = 16;
const keyHexLength = keyLength * 2;

async function deriveKey(password, salt, options) {
  if (activeDerivations >= maxConcurrentDerivations) await new Promise((resolve) => derivationQueue.push(resolve));
  activeDerivations += 1;
  try { return await scrypt(password, salt, keyLength, options); }
  finally {
    activeDerivations -= 1;
    derivationQueue.shift()?.();
  }
}

export async function hashPassword(password) {
  const salt = randomBytes(saltLength);
  const key = await deriveKey(password, salt, scryptOptions);
  return `scrypt-v2:${salt.toString('hex')}:${Buffer.from(key).toString('hex')}`;
}

export async function verifyPassword(password, storedHash) {
  const [version, saltHex, keyHex, extra] = String(storedHash || '').split(':');
  if (extra !== undefined || !['scrypt', 'scrypt-v2'].includes(version)) return { valid: false, needsRehash: false };
  if (!new RegExp(`^[a-f0-9]{${saltLength * 2}}$`, 'i').test(saltHex || '') || !new RegExp(`^[a-f0-9]{${keyHexLength}}$`, 'i').test(keyHex || '')) {
    return { valid: false, needsRehash: false };
  }
  const options = version === 'scrypt-v2' ? scryptOptions : undefined;
  const actual = Buffer.from(await deriveKey(password, Buffer.from(saltHex, 'hex'), options));
  const expected = Buffer.from(keyHex, 'hex');
  const valid = actual.length === expected.length && timingSafeEqual(actual, expected);
  return { valid, needsRehash: valid && version !== 'scrypt-v2' };
}
