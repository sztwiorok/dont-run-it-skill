---
name: security-review
description: >-
  Perform a static security review of the current codebase or pending diff WITHOUT
  executing the code. Looks for OWASP top 10 issues, leaked secrets, injection
  sinks, weak auth, insecure deserialization, SSRF, and unsafe dependencies.
  Triggers on: security review, audit, vulnerability scan, check for secrets,
  OWASP, find injection, review for security.
---

# Security Review

Static-only security audit. **Never run the code under review** — no `npm start`, no `python app.py`, no installing untrusted dependencies, no executing user-supplied scripts. Read, grep, reason. If a check would require execution, report it as "needs dynamic testing" instead of running it.

## Scope

By default, review the **pending diff** on the current branch (`git diff main...HEAD` and unstaged changes). If the user asks for a full audit, expand to the whole repository.

Ask the user (AskUserQuestion) only when ambiguous:
- Diff vs. full-repo review
- Production-facing code only, or include tests/scripts/fixtures
- Specific threat model (e.g., multi-tenant SaaS, public API, internal tool)

## What to look for

### 1. Secrets and credentials
- API keys, tokens, passwords, private keys committed to source
- `.env` files tracked by git
- Hardcoded connection strings, JWT secrets, signing keys
- Grep patterns: `(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]`, `-----BEGIN`, `AKIA[0-9A-Z]{16}`, `ghp_`, `sk-`

### 2. Injection
- **SQL** — string concatenation/interpolation into queries; missing parameterization
- **Command** — `exec`, `spawn`, `system`, `shell=True`, backticks with user input
- **XSS** — `innerHTML`, `dangerouslySetInnerHTML`, unescaped templating, `v-html`
- **Path traversal** — user input concatenated into file paths without normalization
- **SSRF** — user-controlled URLs passed to `fetch`/`requests`/`http.get` without allowlist
- **LDAP/NoSQL/XPath/template** injection in the relevant stacks

### 3. AuthN / AuthZ
- Missing auth middleware on sensitive routes
- IDOR — endpoints that take an ID but don't verify ownership
- Privilege checks done in the UI only
- JWT: `alg: none`, weak secrets, missing `exp`, signature not verified
- Session: predictable IDs, missing `HttpOnly`/`Secure`/`SameSite`, no rotation on login

### 4. Cryptography
- MD5/SHA1 for passwords or signatures (use bcrypt/argon2/scrypt for passwords; HMAC-SHA256+ for signatures)
- Hardcoded IVs, ECB mode, missing authentication (use AEAD: AES-GCM, ChaCha20-Poly1305)
- `Math.random()` / `random.random()` for security-sensitive values (use `crypto.randomBytes` / `secrets`)
- Custom crypto — flag every time

### 5. Deserialization & parsing
- `pickle.loads`, `yaml.load` (without `SafeLoader`), `eval`, `Function(...)`, `unserialize`
- XML: external entities (XXE) — disable DTDs and external entity resolution
- ZIP/tar extraction without path validation (zip-slip)

### 6. Dependencies
- `package.json` / `requirements.txt` / `go.mod` / `Gemfile.lock` for known-vulnerable versions
- Suspicious typo-squat-looking package names
- Unpinned versions on security-sensitive libs
- Postinstall scripts in npm dependencies

### 7. Transport & headers
- HTTP instead of HTTPS for sensitive endpoints
- Missing `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`
- Permissive CORS (`Access-Control-Allow-Origin: *` with credentials)
- Cookies without `Secure` / `HttpOnly` / `SameSite`

### 8. Logging & info disclosure
- Logging secrets, tokens, full request bodies, PII
- Stack traces returned to the client in production
- Verbose error messages revealing schema/internals

### 9. Business-logic & misuse
- Race conditions on balance/inventory/quota mutations
- Missing rate limits on auth, password reset, OTP
- Mass assignment (`User.update(req.body)` without allowlist)
- Open redirect (`?next=` taken as-is)

## Workflow

1. **Scope** — `git diff` to see what's actually changed; or `find . -type f` filtered to source for a full audit. Skip `node_modules`, `vendor`, `.git`, build outputs.
2. **Run the bundled pre-scan** — invoke the static scanner that ships with this skill:
   ```bash
   bash "${CLAUDE_PLUGIN_ROOT}/skills/security-review/scripts/scan.sh" <path>
   ```
   It outputs `[SEVERITY] CATEGORY: file:line: snippet` lines. Treat this as a **candidate list, not a final report** — every line still needs confirmation by reading the source.
3. **Read suspicious files in full** — the scanner gives candidates; confirm by reading surrounding context. Don't report from a single grep line.
4. **Trace data flow** — for each candidate sink, follow inputs back to the boundary (HTTP handler, CLI arg, file read). If the input is attacker-controlled and reaches the sink unsanitized, it's a real finding. If the input is a constant or already sanitized, drop it from the report.
5. **Add categories the scanner doesn't cover** — IDOR / missing authz, race conditions, mass assignment, open redirect, business logic. The scanner is pattern-based; these need code reading.
6. **Report** — group by severity (Critical / High / Medium / Low / Info). For each: file:line, what it is, why it matters, suggested fix. No fluff.

## Output format

```
## Security Review — <scope, e.g., branch `feature/login` vs main>

### Critical
- `src/auth/login.ts:42` — SQL injection: user-supplied `email` interpolated into raw query.
  Fix: parameterize via `db.query('... WHERE email = $1', [email])`.

### High
- ...

### Medium
- ...

### Notes / needs dynamic testing
- Rate limiting on `/auth/reset` — config-driven, can't verify statically. Recommend load test.
```

If nothing is found in a category, **omit the category** — don't pad the report.

## Rules

- **Do not execute** the reviewed code, its tests, its install scripts, or its dependencies. Running `scripts/scan.sh` is fine — it's pure grep over text and never invokes the reviewed code. If the user explicitly asks "run the tests," confirm before doing so and treat the test run as a separate step outside the review.
- **Do not modify** the code as part of the review. Suggest fixes in the report; let the user (or a follow-up `/simplify` / edit pass) apply them.
- **Cite file:line** for every finding so the user can jump straight to the source.
- **No false-positive theater** — if you're not sure something is exploitable, mark it `Info` or "needs dynamic testing", not `High`.
- **Prefer the diff** over the whole repo unless asked otherwise. Reviewing 50k lines when only 200 changed wastes the user's time.
