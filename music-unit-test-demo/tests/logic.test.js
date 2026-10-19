const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  MAX_MP3_BYTES, hashPassword, verifyPassword, authenticate,
  safeMp3Name, hasMp3Signature, validateUpload
} = require('../logic');

const sampleMp3 = Buffer.from('ID3\x04\x00\x00SAMPLE MP3 DATA', 'latin1');

test('Password hashing: correct password passes verification', () => {
  const storedHash = hashPassword('MyPassword123!');
  assert.equal(verifyPassword('MyPassword123!', storedHash), true);
  assert.equal(storedHash.includes('MyPassword123!'), false);
});

test('SECURITY: incorrect passwords and malformed hashes are rejected', () => {
  const hash = hashPassword('MyPassword123!');
  assert.equal(verifyPassword('wrong', hash), false);
  assert.equal(verifyPassword('anything', 'invalid-hash'), false);
});

test('Login accepts valid details, rejects invalid details', () => {
  const account = { username: 'demo', passwordHash: hashPassword('DemoPass123!') };
  assert.equal(authenticate('demo', 'DemoPass123!', account), true);
  assert.equal(authenticate('demo', 'wrong', account), false);
  assert.equal(authenticate('another-user', 'DemoPass123!', account), false);
});

test('SECURITY: directory traversal is removed from MP3 filenames', () => {
  assert.equal(safeMp3Name('../../secrets.mp3'), 'secrets.mp3');
  assert.equal(safeMp3Name('C:\\folder\\music.mp3'), 'music.mp3');
  assert.equal(safeMp3Name('hello<script>.mp3'), 'hello_script_.mp3');
});

test('Only .mp3 file names are accepted', () => {
  assert.equal(safeMp3Name('notes.txt'), null);
  assert.equal(safeMp3Name('song.mp3'), 'song.mp3');
});

test('SECURITY: a fake MP3 is rejected even if the extension is .mp3', () => {
  assert.equal(hasMp3Signature(Buffer.from('this is just text')), false);
  assert.equal(validateUpload('fake.mp3', Buffer.from('not an mp3')).ok, false);
  assert.equal(validateUpload('real.mp3', sampleMp3).ok, true);
});

test('SECURITY: oversized MP3 uploads are rejected', () => {
  const bigFile = Buffer.alloc(MAX_MP3_BYTES + 1);
  bigFile.write('ID3');
  assert.equal(validateUpload('large.mp3', bigFile).ok, false);
});


test('MP3 uploads up to exactly 10 MB are accepted', () => {
  assert.equal(MAX_MP3_BYTES, 10 * 1024 * 1024);
  const maxSizeFile = Buffer.alloc(MAX_MP3_BYTES);
  maxSizeFile.write('ID3');
  assert.equal(validateUpload('limit.mp3', maxSizeFile).ok, true);
});
