
/*
 * UNIT TESTS FOR LOGIC.JS
 *
 * Tests individual JavaScript functions without starting a server.
 * Covers password security, login authentication,
 * filename validation and MP3 upload restrictions.
 */

// 1. IMPORT REQUIRED MODULES
// Import Node.js testing tools and functions from logic.js.
// These allow us to execute tests and compare actual results
// against expected results.
const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  MAX_MP3_BYTES, hashPassword, verifyPassword, authenticate,
  safeMp3Name, hasMp3Signature, validateUpload
} = require('../logic');


// 2. CREATE SAMPLE MP3 DATA
// Create a small fake MP3 file with an ID3 header.
// Used to test whether the upload validation accepts
// files with a recognised MP3 signature.
const sampleMp3 = Buffer.from(
  'ID3\x04\x00\x00SAMPLE MP3 DATA',
  'latin1'
);


// 3. TEST: PASSWORD HASHING
// Check that a correct password can be verified.
// Also ensure the stored hash does not contain
// the original password in plaintext.
test('Password hashing: correct password passes verification', () => {
  const storedHash = hashPassword('MyPassword123!');

  assert.equal(verifyPassword('MyPassword123!', storedHash), true);
  assert.equal(storedHash.includes('MyPassword123!'), false);
});


// 4. SECURITY TEST: INCORRECT PASSWORDS
// Check that an incorrect password is rejected.
// Also verify that invalid or corrupted password hashes
// cannot successfully authenticate a user.
test('SECURITY: incorrect passwords and malformed hashes are rejected', () => {
  const hash = hashPassword('MyPassword123!');

  assert.equal(verifyPassword('wrong', hash), false);
  assert.equal(verifyPassword('anything', 'invalid-hash'), false);
});


// 5. TEST: LOGIN AUTHENTICATION
// Create a sample user account with a hashed password.
// Check that valid login details are accepted,
// while incorrect usernames or passwords are rejected.
test('Login accepts valid details, rejects invalid details', () => {
  const account = {
    username: 'demo',
    passwordHash: hashPassword('DemoPass123!')
  };

  assert.equal(authenticate('demo', 'DemoPass123!', account), true);
  assert.equal(authenticate('demo', 'wrong', account), false);
  assert.equal(authenticate('another-user', 'DemoPass123!', account), false);
});


// 6. SECURITY TEST: DIRECTORY TRAVERSAL
// Check that unsafe folder paths are removed from filenames.
// This prevents users from using filenames to access or
// save files outside the intended upload directory.
// Potentially unsafe characters are also replaced.
test('SECURITY: directory traversal is removed from MP3 filenames', () => {
  assert.equal(safeMp3Name('../../secrets.mp3'), 'secrets.mp3');
  assert.equal(safeMp3Name('C:\\folder\\music.mp3'), 'music.mp3');
  assert.equal(safeMp3Name('hello<script>.mp3'), 'hello_script_.mp3');
});


// 7. TEST: FILE EXTENSION VALIDATION
// Check that the application accepts MP3 filenames
// and rejects filenames with other extensions,
// such as .txt files.
test('Only .mp3 file names are accepted', () => {
  assert.equal(safeMp3Name('notes.txt'), null);
  assert.equal(safeMp3Name('song.mp3'), 'song.mp3');
});


// 8. SECURITY TEST: FAKE MP3 FILES
// Check that renaming a text file to .mp3 is not enough
// for it to pass the application's upload validation.
// Also check that sample data with an ID3 header passes.
test('SECURITY: a fake MP3 is rejected even if the extension is .mp3', () => {
  assert.equal(hasMp3Signature(Buffer.from('this is just text')), false);
  assert.equal(validateUpload('fake.mp3', Buffer.from('not an mp3')).ok, false);
  assert.equal(validateUpload('real.mp3', sampleMp3).ok, true);
});


// 9. SECURITY TEST: OVERSIZED UPLOADS
// Create a file that is one byte larger than the 10 MB limit.
// Add an ID3 header so the test focuses on file size.
// Check that the upload is rejected.
test('SECURITY: oversized MP3 uploads are rejected', () => {
  const bigFile = Buffer.alloc(MAX_MP3_BYTES + 1);

  bigFile.write('ID3');

  assert.equal(validateUpload('large.mp3', bigFile).ok, false);
});


// 10. TEST: MAXIMUM ALLOWED FILE SIZE
// Check that the upload limit is exactly 10 MB.
// Create a file that is exactly the maximum allowed size.
// Confirm that it is accepted rather than rejected.
test('MP3 uploads up to exactly 10 MB are accepted', () => {
  assert.equal(MAX_MP3_BYTES, 10 * 1024 * 1024);

  const maxSizeFile = Buffer.alloc(MAX_MP3_BYTES);

  maxSizeFile.write('ID3');

  assert.equal(validateUpload('limit.mp3', maxSizeFile).ok, true);
});
