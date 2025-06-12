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

async function main() {
  const cookie = await login();
  const users = await fetchUsers(cookie);
}

main().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
