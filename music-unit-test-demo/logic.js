const { randomBytes, scryptSync, timingSafeEqual } = require('node:crypto');

const MAX_MP3_BYTES = 10 * 1024 * 1024;

// Store a salted password hash instead of the plaintext password.
function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  return `${salt}:${scryptSync(password, salt, 32).toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || typeof storedHash !== 'string') return false;
  const [salt, hexHash, extra] = storedHash.split(':');
  if (extra || !/^[a-f0-9]{32}$/.test(salt || '') || !/^[a-f0-9]{64}$/.test(hexHash || '')) {
    return false;
  }
  const expected = Buffer.from(hexHash, 'hex');
  const supplied = scryptSync(password, salt, 32);
  return timingSafeEqual(supplied, expected);
}

function authenticate(username, password, account) {
  return username === account.username && verifyPassword(password, account.passwordHash);
}

// Keep only the filename, not folder names like ../../private/.
function safeMp3Name(originalName) {
  if (typeof originalName !== 'string') return null;
  const baseName = originalName.replace(/\\/g, '/').split('/').pop();
  if (!/\.mp3$/i.test(baseName || '')) return null;
  const stem = baseName.slice(0, -4)
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/^\.+/, '')
    .slice(0, 72);
  return stem ? `${stem}.mp3` : null;
}

// A basic file-signature check (not a complete MP3 decoder or malware scanner).
function hasMp3Signature(data) {
  if (!Buffer.isBuffer(data) || data.length < 3) return false;
  if (data.subarray(0, 3).toString('ascii') === 'ID3') return true;
  return data.length >= 4
    && data[0] === 0xff
    && (data[1] & 0xe0) === 0xe0
    && (data[1] & 0x18) !== 0x08
    && (data[1] & 0x06) !== 0
    && (data[2] & 0xf0) !== 0xf0;
}

function validateUpload(originalName, data) {
  const fileName = safeMp3Name(originalName);
  if (!fileName) return { ok: false, error: 'Only .mp3 filenames are allowed.' };
  if (!Buffer.isBuffer(data) || data.length === 0) {
    return { ok: false, error: 'The file is empty.' };
  }
  if (data.length > MAX_MP3_BYTES) {
    return { ok: false, error: 'MP3s must be 10 MB or smaller.' };
  }
  if (!hasMp3Signature(data)) {
    return { ok: false, error: 'This file does not look like an MP3.' };
  }
  return { ok: true, fileName };
}

module.exports = {
  MAX_MP3_BYTES, hashPassword, verifyPassword, authenticate,
  safeMp3Name, hasMp3Signature, validateUpload
};
