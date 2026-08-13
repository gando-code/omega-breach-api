// Shared API-key + session authentication for the Omega Breach API public endpoints.

export async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Returns { mode: "apikey" | "user", rec } — throws on any auth failure.
export async function authenticate(req, base44) {
  const auth = req.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) {
    const key = m[1].trim();
    const hash = await sha256Hex(key);
    const keys = await base44.asServiceRole.entities.ApiKey.filter({ key_hash: hash });
    if (!keys || keys.length === 0) throw new Error("Invalid API key");
    const rec = keys[0];
    if (!rec.active) throw new Error("API key revoked");
    const today = new Date().toISOString().slice(0, 10);
    if (rec.reset_date !== today) {
      await base44.asServiceRole.entities.ApiKey.update(rec.id, {
        requests_today: 1, reset_date: today, last_used: new Date().toISOString()
      });
      return { mode: "apikey", rec: { ...rec, requests_today: 1 } };
    }
    if ((rec.requests_today || 0) >= rec.rate_limit) throw new Error("Rate limit exceeded");
    await base44.asServiceRole.entities.ApiKey.update(rec.id, {
      requests_today: (rec.requests_today || 0) + 1, last_used: new Date().toISOString()
    });
    return { mode: "apikey", rec };
  }
  const user = await base44.auth.me();
  if (!user) throw new Error("Unauthorized");
  return { mode: "user", rec: null };
}
