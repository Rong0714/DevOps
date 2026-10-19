const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { createApp } = require('../app');

// This is an additional HTTP integration test, alongside the unit tests.
test('SECURITY: uploads require login, then a valid MP3 can be saved and played', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'music-demo-test-'));
  const app = createApp({ uploadDir: directory });
  try {
    await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${app.address().port}`;
    const mp3 = Buffer.from('ID3\x04\x00\x00sample', 'latin1');
    const fileOptions = {
      method: 'POST',
      headers: { 'Content-Type': 'audio/mpeg', 'X-Filename': encodeURIComponent('../song.mp3') },
      body: mp3
    };

    const unauthorized = await fetch(`${origin}/api/upload`, fileOptions);
    assert.equal(unauthorized.status, 401);

    const badLogin = await fetch(`${origin}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'demo', password: 'wrong' })
    });
    assert.equal(badLogin.status, 401);

    const login = await fetch(`${origin}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'demo', password: 'DemoPass123!' })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    assert.match(login.headers.get('set-cookie'), /HttpOnly/);

    const upload = await fetch(`${origin}/api/upload`, {
      ...fileOptions, headers: { ...fileOptions.headers, Cookie: cookie }
    });
    assert.equal(upload.status, 201);

    const listing = await fetch(`${origin}/api/files`, { headers: { Cookie: cookie } });
    const { files } = await listing.json();
    assert.equal(files.length, 1);
    assert.equal(files[0].name, 'song.mp3');

    const audio = await fetch(`${origin}/api/audio/${encodeURIComponent(files[0].id)}`, { headers: { Cookie: cookie } });
    assert.equal(audio.status, 200);
    assert.equal(Buffer.compare(Buffer.from(await audio.arrayBuffer()), mp3), 0);

    const blockedWithoutCookie = await fetch(`${origin}/api/audio/${encodeURIComponent(files[0].id)}`);
    assert.equal(blockedWithoutCookie.status, 401);
  } finally {
    await new Promise(resolve => app.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  }
});
