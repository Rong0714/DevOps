# Mini MP3 Library – JavaScript Unit Testing Demo

This is a small, functioning website with a login screen, local MP3 storage, and unit/security tests. **No npm dependencies are needed.** Requires **Node.js 20 or newer**.

## Run the website

Open CMD or PowerShell in this folder and run:

```cmd
npm run dev
```

Open **http://localhost:3000**.

Demo login: **demo** / **DemoPass123!**.

Choose an `.mp3` file (up to 10 MB) and click **Upload MP3**. Your uploaded MP3s stay in the local `uploads/` folder and can be played in the browser. Log out to verify the library requires a login. `uploads/` is generated automatically and is not part of the ZIP.

## Run the tests

Open another terminal in the same folder, or stop the server with Ctrl+C, and run:

```cmd
npm test
```

The tests exercise JavaScript functions in `logic.js` and one HTTP integration test. Security tests include wrong-password rejection, protection against filename directory traversal, rejecting fake or oversized MP3s, and blocking uploads/playback without authentication.

## Files

- `logic.js`: Small, testable functions (password hashing, login, filename cleaning, MP3 checks).
- `app.js`: Node HTTP server and API (login, logout, upload, listing, playback).
- `public/`: HTML, CSS and browser JavaScript for the login and MP3 library.
- `tests/logic.test.js`: Unit tests, including security-related tests.
- `tests/server.test.js`: API integration/security test.

## Important security note

**Educational demo only.** This uses a deliberately public demo account, in-memory sessions (lost when the server restarts), local storage, and basic MP3 signature checks. It is **not** ready for public deployment or untrusted users. A real application also needs account registration/management, persistent user records, HTTPS, login rate limiting, stronger media validation and security hardening. The password is hashed with scrypt for demonstration and compared securely. You can set a different demo password through `DEMO_PASSWORD` in your environment; if you do, the sample password text in the HTML page will no longer match.
