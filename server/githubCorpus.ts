// GitHub-backed corpus for the Omega Breach API.
// The breach index and k-anonymity hash ranges live as versioned JSON files in
// a public GitHub repo, making the corpus community-growable and independent.

const REPO_NAME = "omega-breach-corpus";
const API = "https://api.github.com";

function headers(token) {
  return {
    Authorization: "Bearer " + token,
    Accept: "application/vnd.github+json",
    "User-Agent": "Omega-Breach-API"
  };
}

export async function getGitHub(base44) {
  const { accessToken } = await base44.asServiceRole.connectors.getConnection("github");
  const r = await fetch(API + "/user", { headers: headers(accessToken) });
  const u = await r.json();
  if (!u.login) throw new Error("GitHub connection unavailable");
  const owner = u.login;
  await ensureRepo(accessToken, owner);
  return { token: accessToken, owner };
}

async function ensureRepo(token, owner) {
  const r = await fetch(API + "/repos/" + owner + "/" + REPO_NAME, { headers: headers(token) });
  if (r.status === 200) return;
  if (r.status === 404) {
    await fetch(API + "/user/repos", {
      method: "POST",
      headers: { ...headers(token), "Content-Type": "application/json" },
      body: JSON.stringify({
        name: REPO_NAME,
        description: "Omega Breach API — community-growable breach intelligence corpus",
        private: false,
        auto_init: true
      })
    });
    return;
  }
  throw new Error("GitHub repo check failed: " + r.status);
}

export async function readFile(base44, path) {
  const { token, owner } = await getGitHub(base44);
  const r = await fetch(API + "/repos/" + owner + "/" + REPO_NAME + "/contents/" + path, { headers: headers(token) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("GitHub read failed: " + r.status);
  const data = await r.json();
  const content = atob(data.content.replace(/\n/g, ""));
  return { content: JSON.parse(content), sha: data.sha };
}

export async function writeFile(base44, path, obj, message) {
  const { token, owner } = await getGitHub(base44);
  const existing = await fetch(API + "/repos/" + owner + "/" + REPO_NAME + "/contents/" + path, { headers: headers(token) });
  let sha;
  if (existing.status === 200) { const e = await existing.json(); sha = e.sha; }
  const b64 = btoa(JSON.stringify(obj, null, 2));
  const r = await fetch(API + "/repos/" + owner + "/" + REPO_NAME + "/contents/" + path, {
    method: "PUT",
    headers: { ...headers(token), "Content-Type": "application/json" },
    body: JSON.stringify({ message, content: b64, ...(sha ? { sha } : {}) })
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error("GitHub write failed: " + (err.message || r.status));
  }
  return true;
}

export function repoUrl(owner) {
  return "https://github.com/" + owner + "/" + REPO_NAME;
}
