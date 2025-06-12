import crypto from 'crypto';
import { writeFile, readFile } from 'fs/promises';
import dotenv from 'dotenv';
dotenv.config();

const COOKIE_STORE = '.cookie';

function formatCookieHeader(raw: string): string {
  return raw
    .split(',')
    .map(entry => entry.split(';')[0].trim())
    .join('; ');
}

async function login(): Promise<string> {
  try {
    const existing = (await readFile(COOKIE_STORE, 'utf-8')).trim();
    console.log('Reusing saved auth cookie');
    return existing;
  } catch {}

  console.log('Fetching login page…');
  const pageResponse = await fetch('https://challenge.sunvoy.com/login');
  const rawCsrfCookie = pageResponse.headers.get('set-cookie');
  console.log('Received CSRF cookie:', rawCsrfCookie);

  const html = await pageResponse.text();
  const match = html.match(/name="nonce" value="([^"]+)"/);

  if (!match) throw new Error('Login nonce not found');

  const nonce = match[1];
  console.log('Extracted nonce:', nonce);

  const form = new URLSearchParams({
    nonce,
    username: process.env.USER_EMAIL!,
    password: process.env.USER_PASSWORD!,
  });;

  console.log('Signing in');
  const postResponse = await fetch('https://challenge.sunvoy.com/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': rawCsrfCookie || '',
    },
    body: form.toString(),
    redirect: 'manual',
  });
  console.log('Login POST status:', postResponse.status);

  const authCookie = postResponse.headers.get('set-cookie');
  console.log('Received auth cookie:', authCookie);
  if (!authCookie || postResponse.status === 401) {
    throw new Error(`Login failed (status ${postResponse.status})`);
  }

  const formattedAuthCookie = formatCookieHeader(authCookie)

  await writeFile(COOKIE_STORE, formattedAuthCookie);
  console.log('Auth cookie saved to', COOKIE_STORE);
  return formattedAuthCookie;
}

async function fetchUsers(cookie: string): Promise<any[]> {
  console.log('Fetching all users');
  const response = await fetch('https://challenge.sunvoy.com/api/users', {
    method: 'POST',
    headers: { 
      Cookie: cookie, 
      Accept: 'application/json',
    },
  });
  if (!response.ok) throw new Error(`Users fetch failed (${response.status})`);
  const users = await response.json();
  console.log(`Retrieved ${users.length} users`);
  return users;
}

async function fetchTokenData(cookie: string) {
  console.log('Fetching token data');
  const response = await fetch('https://challenge.sunvoy.com/settings/tokens', {
    headers: { Cookie: cookie, Accept: 'text/html' },
  });
  if (!response.ok) throw new Error(`Token page failed (${response.status})`);

  const html = await response.text();
  const pick = (id: string) => {
    const m = html.match(new RegExp(`id="${id}"\\s+value="([^"]+)"`));
    if (!m) throw new Error(`Token "${id}" missing`);
    return m[1];
  };

  const tokenData = {
    access_token: pick('access_token'),
    apiuser:      pick('apiuser'),
    language:     pick('language'),
    openId:       pick('openId'),
    operateId:    pick('operateId'),
    userId:       pick('userId'),
  };

  console.log('Parsed token data:', tokenData);
  return tokenData;
}

function createSignedPayload(t: Record<string, string>) {
  // To pass the Unix Epoch time in seconds
  const timestamp = Math.floor(Date.now() / 1e3);

  const data: Record<string, string> = { ...t, timestamp: timestamp.toString() };

  const payload = Object.keys(data)
    .sort()
    .map((k: string) => `${k}=${encodeURIComponent(data[k])}`)
    .join('&');
  
  const hmac = crypto.createHmac('sha1', 'mys3cr3t');

  hmac.update(payload);

  const checkcode = hmac.digest('hex').toUpperCase();
  const signedPayload = `${payload}&checkcode=${checkcode}`

  console.log( 'Created signedPayload:', signedPayload);

  return { signedPayload };
}

async function fetchCurrentUser(cookie: string) {
  const tokenData = await fetchTokenData(cookie);
  const { signedPayload } = createSignedPayload(tokenData);

  const response = await fetch('https://api.challenge.sunvoy.com/api/settings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: cookie,
      Accept: 'application/json',
    },
    body: signedPayload,
  });

  console.log('/api/settings POST status:', response.status);

  if (!response.ok) throw new Error(`Profile fetch failed (${response.status})`);

  const currentUser = await response.json();

  console.log('Retrieved current user:', currentUser);
  return currentUser;
}

async function main() {
  const cookie = await login();
  const users = await fetchUsers(cookie);
  const currentUserProfile = await fetchCurrentUser(cookie);
  users.push({ currentUser: currentUserProfile });
  await writeFile('users.json', JSON.stringify(users, null, 2));
  console.log(`Retrieved ${users.length} users, written in users.json.`);
}

main().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
