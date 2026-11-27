// shared helpers for the Gmail connect functions (not a route: file name starts with _)
export const enc = new TextEncoder();
export const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
export const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
export const REDIRECT = (url) => new URL('/gcb', url).toString().replace('http://', 'https://');

export async function hmac(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
export async function sign(secret, obj) {
  const p = b64u(enc.encode(JSON.stringify(obj)));
  return p + '.' + (await hmac(secret, p));
}
export async function unsign(secret, tok) {
  const [p, s] = String(tok || '').split('.');
  if (!p || !s || (await hmac(secret, p)) !== s) return null;
  try { return JSON.parse(new TextDecoder().decode(fromB64u(p))); } catch (e) { return null; }
}
export const sbh = (env) => ({ apikey: env.SUPABASE_SERVICE_KEY, Authorization: 'Bearer ' + env.SUPABASE_SERVICE_KEY, 'content-type': 'application/json' });

// the signed-in customer behind a Supabase access token
export async function userOf(env, token) {
  if (!token) return null;
  const r = await fetch(env.SUPABASE_URL + '/auth/v1/user', { headers: { apikey: env.SUPABASE_SERVICE_KEY, Authorization: 'Bearer ' + token } });
  if (!r.ok) return null;
  const u = await r.json();
  return u && u.id ? u : null;
}
