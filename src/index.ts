import { writeFile, readFile } from 'fs/promises';
import dotenv from 'dotenv';
dotenv.config();

const COOKIE_STORE = '.cookie';


async function login(): Promise<string> {
  try {
    const existing = (await readFile(COOKIE_STORE, 'utf-8')).trim();
    console.log('Reusing saved auth cookie');
    return existing;
  } catch {}

  console.log('Fetching login page…');
  const pageResponse = await fetch('https://challenge.sunvoy.com/login');
  const csrfCookie = pageResponse.headers.get('set-cookie');
  console.log('Received CSRF cookie:', csrfCookie);

  const html = await pageResponse.text();
  const match = html.match(/name="nonce" value="([^"]+)"/);

  if (!match) throw new Error('Login nonce not found');

  const nonce = match[1];
  console.log('Extracted nonce:', nonce);

  const form = new URLSearchParams();
  form.append('nonce', nonce);
  form.append('username', process.env.USER_EMAIL!);
  form.append('password', process.env.USER_PASSWORD!);

  console.log('Signing in');
  const postResponse = await fetch('https://challenge.sunvoy.com/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': csrfCookie || '',
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

  await writeFile(COOKIE_STORE, authCookie);
  console.log('Auth cookie saved to', COOKIE_STORE);
  return authCookie;
}

async function main() {
  const cookie = await login();
}

main().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
