import { createClientFromRequest } from 'npm:@base44/sdk@0.8.40';
import { authenticate } from '../../shared/apiKeyAuth.ts';
import { readFile } from '../../shared/githubCorpus.ts';

export default async function(req: Request): Promise<Response> {
  try {
    const base44 = createClientFromRequest(req);
    const auth = await authenticate(req, base44);
    if (auth.mode === 'apikey' && !(auth.rec.scopes || []).includes('breaches')) {
      return Response.json({ error: 'Missing scope: breaches' }, { status: 403 });
    }

    const body = await req.json().catch(() => ({}));
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
    const domain = typeof body?.domain === 'string' ? body.domain.trim().toLowerCase() : '';
    let target = domain;
    if (email) { const m = email.split('@')[1]; if (m) target = m; }
    if (!target) return Response.json({ error: 'email or domain required' }, { status: 400 });

    const idx = await readFile(base44, 'breaches/index.json');
    const all = idx ? (idx.content || []) : [];
    const breaches = all.filter((b) => (b.domain || '').toLowerCase() === target);
    return Response.json({ domain: target, breaches, source: 'omega-github' });
  } catch (error) {
    const status = /Unauthorized|Invalid API key|revoked|Rate limit|Missing scope|GitHub/.test(error.message) ? 401 : 500;
    return Response.json({ error: error.message }, { status });
  }
}
