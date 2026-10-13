// Accès protégé par mot de passe. Le mot de passe n'est jamais dans le dépôt :
// il est lu dans la variable d'environnement Vercel EKO_ACCESS_CODE.
export const config = { matcher: '/((?!favicon\\.ico).*)' };

const COOKIE = 'eko_access';

async function token(code) {
  const data = new TextEncoder().encode('eko-gui-13-10:' + code);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function readCookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function loginPage(error) {
  const msg = error
    ? '<p class="err"><span class="fr">Code incorrect. Réessayez.</span><span class="en">Wrong code. Please try again.</span></p>'
    : '';
  return new Response(`<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>EKO · Accès</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;600&family=Barlow+Semi+Condensed:wght@700&display=swap">
<style>
:root{--bg:#f2f4f7;--surface:#fff;--ink:#15202c;--muted:#5b6979;--line:#dde3ea;--eko:#1e64c8;--err:#cc2f27}
@media (prefers-color-scheme:dark){:root{--bg:#0f151c;--surface:#17202a;--ink:#e7ecf1;--muted:#9aa8b6;--line:#263241;--eko:#5c9bf0;--err:#ff6c5f;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font-family:Barlow,system-ui,sans-serif;padding:16px}
form{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:28px;width:min(100%,360px);display:flex;flex-direction:column;gap:14px}
h1{font-family:"Barlow Semi Condensed",Barlow,sans-serif;margin:0;font-size:1.6rem}h1 b{color:var(--eko)}
p{margin:0;color:var(--muted);font-size:.95rem}.err{color:var(--err)}
input{font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:5px;background:var(--bg);color:var(--ink)}
input:focus{outline:2px solid var(--eko);outline-offset:1px}
button{font:600 1rem Barlow,sans-serif;padding:10px;border:0;border-radius:5px;background:var(--eko);color:#fff;cursor:pointer}
.en{display:none}html[lang=en] .en{display:inline}html[lang=en] .fr{display:none}
</style></head><body>
<form method="POST">
<h1><b>EKO</b> · <span class="fr">Accès réservé</span><span class="en">Restricted access</span></h1>
<p><span class="fr">Document confidentiel. Saisissez le code d'accès.</span><span class="en">Confidential document. Enter the access code.</span></p>
${msg}
<label for="code" style="position:absolute;left:-9999px">Code</label>
<input id="code" name="code" type="password" autocomplete="current-password" autofocus required>
<button type="submit"><span class="fr">Entrer</span><span class="en">Enter</span></button>
</form>
<script>if((navigator.language||'').slice(0,2)!=='fr')document.documentElement.lang='en';</script>
</body></html>`, {
    status: error ? 401 : 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex' },
  });
}

export default async function middleware(req) {
  const code = process.env.EKO_ACCESS_CODE;
  if (!code) return new Response('Access code not configured.', { status: 503 });
  const expected = await token(code);

  if (req.method === 'POST') {
    const form = await req.formData().catch(() => null);
    const given = form ? String(form.get('code') || '') : '';
    if (given && (await token(given)) === expected) {
      const url = new URL(req.url);
      return new Response(null, {
        status: 303,
        headers: {
          location: url.pathname + url.search,
          'set-cookie': `${COOKIE}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
        },
      });
    }
    return loginPage(true);
  }

  if (readCookie(req, COOKIE) === expected) return; // accès accordé : la page statique est servie
  return loginPage(false);
}
