const loginSection = document.getElementById('loginSection');
const musicSection = document.getElementById('musicSection');
const message = document.getElementById('message');
const fileList = document.getElementById('fileList');

async function request(url, options) {
  const response = await fetch(url, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Something went wrong.');
  return result;
}

async function refreshFiles() {
  const { files } = await request('/api/files');
  fileList.replaceChildren();
  if (files.length === 0) {
    const item = document.createElement('li');
    item.textContent = 'No MP3s uploaded yet.';
    fileList.append(item);
  }
  for (const file of files) {
    const item = document.createElement('li');
    const title = document.createElement('span');
    title.textContent = file.name; // Safe: never insert a filename as HTML.
    const audio = document.createElement('audio');
    audio.controls = true;
    audio.preload = 'none';
    audio.src = `/api/audio/${encodeURIComponent(file.id)}`;
    item.append(title, audio);
    fileList.append(item);
  }
}

async function showCurrentPage() {
  const { loggedIn } = await request('/api/session');
  loginSection.hidden = loggedIn;
  musicSection.hidden = !loggedIn;
  if (loggedIn) await refreshFiles();
}

document.getElementById('loginForm').addEventListener('submit', async event => {
  event.preventDefault();
  message.textContent = '';
  try {
    await request('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      })
    });
    await showCurrentPage();
    message.textContent = 'Logged in successfully.';
  } catch (error) { message.textContent = error.message; }
});

document.getElementById('uploadForm').addEventListener('submit', async event => {
  event.preventDefault();
  message.textContent = '';
  const file = document.getElementById('mp3File').files[0];
  if (!file) return;
  try {
    await request('/api/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'audio/mpeg',
        'X-Filename': encodeURIComponent(file.name)
      },
      body: file
    });
    document.getElementById('uploadForm').reset();
    await refreshFiles();
    message.textContent = 'MP3 uploaded successfully.';
  } catch (error) { message.textContent = error.message; }
});

document.getElementById('logoutButton').addEventListener('click', async () => {
  try {
    await request('/api/logout', { method: 'POST' });
    await showCurrentPage();
    message.textContent = 'Logged out.';
  } catch (error) { message.textContent = error.message; }
});

showCurrentPage().catch(error => { message.textContent = error.message; });
