
/*
 * SERVER INTEGRATION TEST
 *
 * Tests the login system, MP3 uploading, file storage
 * and security restrictions using a temporary server.
 */

// Import Node.js testing tools and required modules.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { createApp } = require('../app');


// TEST: Check authentication, uploading and MP3 playback.
test('SECURITY: uploads require login, then a valid MP3 can be saved and played', async () => {

  // 1. SET UP THE TEST ENVIRONMENT
  // Create a temporary folder so testing does not affect
  // real MP3 files. Start a separate server for this test.
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'music-demo-test-'));
  const app = createApp({ uploadDir: directory });

  try {
    await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));

    // Get the server's address and randomly assigned port.
    const origin = `http://127.0.0.1:${app.address().port}`;


    // 2. CREATE A SAMPLE MP3 FILE
    // Generate fake MP3 data with an ID3 header.
    // This is sufficient for the application's basic validation.
    const mp3 = Buffer.from('ID3\x04\x00\x00sample', 'latin1');

    // Set up the HTTP request used to upload the file.
    const fileOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'audio/mpeg',
        'X-Filename': encodeURIComponent('../song.mp3')
      },
      body: mp3
    };


    // 3. SECURITY TEST: UPLOAD WITHOUT LOGIN
    // Attempt to upload an MP3 without being authenticated.
    // Expected result: HTTP 401 (Unauthorized).
    const unauthorized = await fetch(`${origin}/api/upload`, fileOptions);
    assert.equal(unauthorized.status, 401);


    // 4. SECURITY TEST: INCORRECT PASSWORD
    // Attempt to log in using the correct username
    // but an incorrect password.
    // Expected result: HTTP 401 (Unauthorized).
    const badLogin = await fetch(`${origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'demo',
        password: 'wrong'
      })
    });

    assert.equal(badLogin.status, 401);


    // 5. TEST: SUCCESSFUL LOGIN
    // Log in using valid credentials.
    // Expected result: HTTP 200 (OK).
    const login = await fetch(`${origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'demo',
        password: 'DemoPass123!'
      })
    });

    assert.equal(login.status, 200);

    // Extract the session cookie received after login.
    // Check that the HttpOnly security attribute is present.
    // HttpOnly prevents browser JavaScript from reading the cookie.
    const cookie = login.headers.get('set-cookie').split(';')[0];
    assert.match(login.headers.get('set-cookie'), /HttpOnly/);


    // 6. TEST: AUTHENTICATED MP3 UPLOAD
    // Retry the upload with a valid login session cookie.
    // Expected result: HTTP 201 (Created).
    const upload = await fetch(`${origin}/api/upload`, {
      ...fileOptions,
      headers: {
        ...fileOptions.headers,
        Cookie: cookie
      }
    });

    assert.equal(upload.status, 201);


    // 7. TEST: VERIFY MP3 STORAGE
    // Request the list of uploaded MP3 files.
    // Check that exactly one file exists and its name
    // has been cleaned from '../song.mp3' to 'song.mp3'.
    const listing = await fetch(`${origin}/api/files`, {
      headers: { Cookie: cookie }
    });

    const { files } = await listing.json();

    assert.equal(files.length, 1);
    assert.equal(files[0].name, 'song.mp3');


    // 8. TEST: RETRIEVE THE UPLOADED MP3
    // Request the uploaded audio file using its unique ID.
    // Check that the request succeeds and that the returned
    // file data matches the original uploaded data.
    const audio = await fetch(
      `${origin}/api/audio/${encodeURIComponent(files[0].id)}`,
      { headers: { Cookie: cookie } }
    );

    assert.equal(audio.status, 200);
    assert.equal(
      Buffer.compare(Buffer.from(await audio.arrayBuffer()), mp3),
      0
    );


    // 9. SECURITY TEST: BLOCK UNAUTHORISED AUDIO ACCESS
    // Attempt to retrieve the MP3 without a session cookie.
    // Expected result: HTTP 401 (Unauthorized).
    const blockedWithoutCookie = await fetch(
      `${origin}/api/audio/${encodeURIComponent(files[0].id)}`
    );

    assert.equal(blockedWithoutCookie.status, 401);

  } finally {

    // 10. CLEAN UP AFTER TESTING
    // Always stop the temporary server and delete the
    // temporary folder, even if one of the tests fails.
    await new Promise(resolve => app.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });

  }
});
