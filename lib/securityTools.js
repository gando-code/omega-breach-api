// Pure security utilities: password/passphrase generation, TOTP, password-health analysis.

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS = /[Il1O0o]/g;

const WORDLIST = [
  "anchor","blossom","canyon","dolphin","ember","falcon","granite","harbor",
  "ivy","jungle","kestrel","lantern","meadow","nebula","ocean","pebble",
  "quartz","raven","summit","tundra","umber","violet","willow","xenon",
  "yonder","zephyr","amber","boulder","cedar","drift","echo","frost",
  "glacier","horizon","indigo","juniper","kettle","lagoon","marble","nimbus",
  "orchid","plume","quiver","ridge","spruce","tide","umber","vortex",
  "wren","yarrow","badge","cipher","delta","fjord","gulf","haven",
  "isle","knoll","linden","marsh","nook","outcrop","pinnacle","quay",
  "ravine","slope","thicket","upland","vale","wharf","breeze","cliff",
  "dune","field","grove","hill","isle","jetty","knoll","lake",
  "mesa","narrows","oasis","peak","quartz","ridge","stone","trail"
];

function secureRandomInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

export function generatePassword(length = 20, opts = {}) {
  const { lower = true, upper = true, numbers = true, symbols = true, avoidAmbiguous = false } = opts;
  let sets = [];
  if (lower) sets.push(LOWER);
  if (upper) sets.push(UPPER);
  if (numbers) sets.push(NUMBERS);
  if (symbols) sets.push(SYMBOLS);
  if (sets.length === 0) sets = [LOWER];
  let all = sets.join("");
  if (avoidAmbiguous) all = all.replace(AMBIGUOUS, "");
  let out = "";
  for (let i = 0; i < length; i++) {
    out += all[secureRandomInt(all.length)];
  }
  return out;
}

export function generatePassphrase(words = 4, separator = "-") {
  const parts = [];
  for (let i = 0; i < words; i++) {
    parts.push(WORDLIST[secureRandomInt(WORDLIST.length)]);
  }
  return parts.join(separator);
}

export function estimateEntropy(password) {
  if (!password) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += SYMBOLS.length;
  const bits = password.length * Math.log2(Math.max(pool, 2));
  return Math.round(bits);
}

export function strengthLabel(entropy) {
  if (entropy >= 100) return { label: "Exceptional", tone: "emerald" };
  if (entropy >= 70) return { label: "Strong", tone: "green" };
  if (entropy >= 50) return { label: "Fair", tone: "amber" };
  if (entropy >= 30) return { label: "Weak", tone: "orange" };
  return { label: "Critical", tone: "red" };
}

const COMMON = ["password","123456","123456789","qwerty","abc123","111111","letmein","admin","welcome","monkey","dragon","sunshine","password1","iloveyou"];

export function analyzePassword(pw) {
  if (!pw) return { score: 0, issues: ["Empty"] };
  const issues = [];
  if (pw.length < 8) issues.push("Too short (< 8)");
  else if (pw.length < 12) issues.push("Short (< 12)");
  if (!/[A-Z]/.test(pw)) issues.push("No uppercase");
  if (!/[a-z]/.test(pw)) issues.push("No lowercase");
  if (!/[0-9]/.test(pw)) issues.push("No numbers");
  if (!/[^a-zA-Z0-9]/.test(pw)) issues.push("No symbols");
  if (COMMON.includes(pw.toLowerCase())) issues.push("Common password");
  const entropy = estimateEntropy(pw);
  let score = 0;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw) && /[^a-zA-Z0-9]/.test(pw)) score++;
  if (entropy >= 70) score++;
  if (COMMON.includes(pw.toLowerCase())) score = 0;
  return { score: Math.min(score, 5), entropy, issues };
}

const SECRET_KEYS = ["password", "pin", "secret", "code"];

function collectPasswords(items) {
  const list = [];
  for (const item of items) {
    const fields = item.fields || {};
    for (const [key, value] of Object.entries(fields)) {
      if (SECRET_KEYS.some((s) => key.toLowerCase().includes(s)) && value) {
        list.push({ itemId: item.id, title: item.title, key, value });
      }
    }
  }
  return list;
}

export function buildHealthReport(items) {
  const passwords = collectPasswords(items);
  const seen = {};
  passwords.forEach((p) => { (seen[p.value] = seen[p.value] || []).push(p); });
  const reused = Object.values(seen).filter((g) => g.length > 1).flat();
  const weak = passwords.filter((p) => analyzePassword(p.value).score < 3);
  const old = items.filter((i) => {
    if (!i.updated_date) return false;
    const age = Date.now() - new Date(i.updated_date).getTime();
    return age > 1000 * 60 * 60 * 24 * 180;
  });
  const totalScore = passwords.length
    ? Math.round((passwords.reduce((a, p) => a + analyzePassword(p.value).score, 0) / (passwords.length * 5)) * 100)
    : 100;
  return {
    totalPasswords: passwords.length,
    weak: weak.length,
    reused: reused.length,
    oldItems: old.length,
    totalItems: items.length,
    score: totalScore,
    weakItems: weak,
    reusedGroups: Object.values(seen).filter((g) => g.length > 1)
  };
}

// --- TOTP (RFC 6238) using Web Crypto ---

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input) {
  const cleaned = input.replace(/=+$/, "").replace(/\\s/g, "").toUpperCase();
  let bits = "";
  for (const ch of cleaned) {
    const val = B32.indexOf(ch);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return new Uint8Array(bytes);
}

export async function generateTotp(secret, period = 30, digits = 6) {
  const key = base32Decode(secret);
  if (key.length === 0) return { code: "", remaining: 0 };
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / period);
  const remaining = period - (epoch % period);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, buffer));
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = (binary % Math.pow(10, digits)).toString().padStart(digits, "0");
  return { code, remaining };
}
