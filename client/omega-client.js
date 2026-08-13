// Omega Breach API — browser/Node client SDK. No dependencies.
// Usage:
//   const api = new OmegaClient({ baseUrl: "https://YOUR_FUNCTIONS_BASE", apiKey: "omv_live_..." });
//   const { compromised } = await api.checkPassword("correct horse battery staple");
//   const { breaches } = await api.breachLookup({ email: "user@example.com" });

const sha1Hex = async (text) => {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
};

export class OmegaClient {
  constructor({ baseUrl, apiKey }) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  async _call(fn, body) {
    const res = await fetch(this.baseUrl + "/" + fn, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.apiKey
      },
      body: JSON.stringify(body || {})
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  // k-anonymity password range. Returns { suffixes, source }.
  async passwordRange(sha1Prefix) {
    const prefix = String(sha1Prefix).toUpperCase();
    return this._call("omegaBreachPasswordRange", { prefix });
  }

  // Convenience: check a full password. Returns { compromised, suffix }.
  async checkPassword(password) {
    const hash = (await sha1Hex(password)).toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const { suffixes } = await this.passwordRange(prefix);
    const compromised = suffixes.includes(suffix);
    return { compromised, suffix };
  }

  async breachLookup({ email, domain } = {}) {
    return this._call("omegaBreachLookup", { email, domain });
  }
}
