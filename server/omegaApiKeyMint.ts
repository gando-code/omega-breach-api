import { createClientFromRequest } from 'npm:@base44/sdk@0.8.40';
import { sha256Hex } from '../../shared/apiKeyAuth.ts';

export default async function(req: Request): Promise<Response> {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

    const body = await req.json().catch(() => ({}));
    const name = typeof body?.name === 'string' ? body.name.trim() : '';
    if (!name) return Response.json({ error: 'name required' }, { status: 400 });
    const scopes = Array.isArray(body?.scopes) ? body.scopes : ['password', 'breaches'];
    const rate_limit = Number(body?.rate_limit) > 0 ? Number(body.rate_limit) : 1000;

    const rand = crypto.getRandomValues(new Uint8Array(24));
    const hex = [...rand].map((b) => b.toString(16).padStart(2, '0')).join('');
    const key = 'omv_live_' + hex;
    const hash = await sha256Hex(key);

    const rec = await base44.entities.ApiKey.create({
      name, key_hash: hash, key_prefix: key.slice(-6),
      scopes, rate_limit, requests_today: 0,
      reset_date: new Date().toISOString().slice(0, 10),
      active: true, last_used: new Date().toISOString()
    });
    return Response.json({ key, id: rec.id, name, scopes, rate_limit });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
