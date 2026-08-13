import { createClientFromRequest } from 'npm:@base44/sdk@0.8.40';
import { authenticate } from '../../shared/apiKeyAuth.ts';
import { readFile, writeFile } from '../../shared/githubCorpus.ts';

export default async function(req: Request): Promise<Response> {
  try {
    const base44 = createClientFromRequest(req);
    const auth = await authenticate(req, base44);
    if (auth.mode === 'apikey' && !(auth.rec.scopes || []).includes('password')) {
      return Response.json({ error: 'Missing scope: password' }, { status: 403 });
    }

    const body = await req.json().catch(() => ({}));
    const prefix = typeof body?.prefix === 'string' ? body.prefix.toUpperCase() : '';
    if (!/^[A-F0-9]{5}$/.test(prefix)) return Response.json({ error: 'Invalid prefix' }, { status: 400 });

    const path = "ranges/" + prefix.slice(0, 2) + "/" + prefix + ".json";
    const existing = await readFile(base44, path);
    if (existing) {
      return Response.json({ prefix, suffixes: existing.content.suffixes || [], source: 'omega-github' });
    }

    let suffixes = [];
    try {
      const r = await fetch('https://api.pwnedpasswords.com/range/' + prefix, {
        headers: { 'User-Agent': 'Omega-Breach-API' }
      });
      if (r.ok) {
        const text = await r.text();
        suffixes = text.split('\n').map(line => line.split(':')[0].toUpperCase()).filter(Boolean);
        if (suffixes.length) {
          await writeFile(base44, path, { prefix, suffixes, count: suffixes.length, source: 'hibp-seed' }, "seed range " + prefix);
        }
      }
    } catch (e) { /* seeding is best-effort */ }

    return Response.json({ prefix, suffixes, source: suffixes.length ? 'omega-seeded' : 'empty' });
  } catch (error) {
    const status = /Unauthorized|Invalid API key|revoked|Rate limit|Missing scope|GitHub/.test(error.message) ? 401 : 500;
    return Response.json({ error: error.message }, { status });
  }
}
