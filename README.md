# Omega Breach API

A self-growing, privacy-preserving breach intelligence API with an API-key system you can build on — an open alternative to HIBP / XposedOrNot.

## Why
- k-anonymity password checks (only the first 5 chars of a SHA-1 hash leave the device).
- A community-growable corpus: breach records and exposed-hash ranges live as versioned JSON in a public GitHub repo. Every password scan self-seeds a new range, so the corpus grows independent of any third party over time.
- API keys with scopes and per-key daily rate limits.
- No HIBP API key required.

## Live endpoints
Replace BASE with your deployed function base URL (Dashboard -> Code -> Functions).

### Password range (k-anonymity)
    POST BASE/omegaBreachPasswordRange
    Authorization: Bearer YOUR_KEY
    { "prefix": "5BAA6" }
Returns { "prefix", "suffixes": [...], "source": "omega-github" }

### Breach lookup
    POST BASE/omegaBreachLookup
    Authorization: Bearer YOUR_KEY
    { "email": "user@example.com" }
Returns { "domain", "breaches": [...] }

### Mint a key (authenticated app user)
    POST BASE/omegaApiKeyMint
    { "name": "My app", "scopes": ["password","breaches"], "rate_limit": 1000 }
Returns the plaintext key once (omv_live_...).

### Publish breach index to GitHub
    POST BASE/omegaBreachSeed
Publishes BreachCorpus records to the corpus repo as breaches/index.json.

## Auth
Authorization: Bearer omv_live_...
Scopes: password, breaches. Daily rate limit per key (default 1000, mintable up to 10000).

## Client SDK
See client/omega-client.js. Zero dependencies, browser + Node.

## Corpus repo
Breach index and hash ranges are versioned in a public repo (omega-breach-corpus). Each password-range miss is fetched once from HIBP and committed, so the corpus becomes self-sufficient.

## Integration modules in this repo
- server/apiKeyAuth.ts — API-key + session authentication, rate limiting, scope checks
- server/githubCorpus.ts — GitHub-backed versioned corpus read/write
- server/omegaBreachPasswordRange.ts — k-anonymity password range (self-seeding)
- server/omegaBreachLookup.ts — email/domain breach lookup
- server/omegaApiKeyMint.ts — API key minting (server-side hashing)
- server/omegaBreachSeed.ts — publish breach index to GitHub
- lib/securityTools.js — password/passphrase generation, TOTP (RFC 6238), password-health analysis
- lib/vaultCrypto.js — AES-256-GCM + PBKDF2 client-side E2E encryption

## License
MIT
