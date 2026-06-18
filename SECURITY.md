# Security notes — red team / blue team

This file records the red-team/blue-team exercise from PLAN 7. Both "teams" had
full source access. Each round: attack a real behavior, then fix the vector.
All testing was done against an isolated sandbox copy, not live data.

## Round 1 — Log injection via the upload filename  ✅ fixed

**Attack.** The upload's original filename flowed from the multipart body into
`uploads.log` via `fprintf("…%s…")` with no sanitization. A crafted filename
containing tab bytes injected extra TSV columns (e.g. a forged source IP), and
embedded ANSI escape sequences (`\x1b[…m`) would execute in an admin's terminal
when viewing the log (spoofing/hiding lines, screen control). Raw newline
injection was blocked by Mongoose's header parser, but column/escape injection
succeeded. Demonstrated: one upload turned a 6-field log line into 12 fields.

**Fix.** `log_sanitize()` replaces every byte outside printable ASCII
(and the tab delimiter) with `_` before logging the IP and filename. Server-
generated fields (timestamp, md5, size, stored path) are trusted as-is. The
crafted line now stays 6 fields with all control bytes neutralized.

## Round 2 — X-Forwarded-For spoofing → rate-limit bypass + forged identity  ✅ fixed

**Attack.** `X-Forwarded-For` was trusted whenever proxy mode was on
(`CHAN_TRUST_PROXY=1`), from *any* peer. A direct client could therefore:
rotate XFF to get a fresh rate-limit key on every request (bypassing the
1-post-per-window limit entirely), and write an attacker-chosen IP into the
upload log (false attribution). Demonstrated: 5 spoofed posts all accepted.

**Fix.** Replaced the boolean with `CHAN_TRUSTED_PROXY=<ip>`. XFF is honored
only when the TCP peer address equals the configured proxy; otherwise the peer
address is used. Now a direct attacker's XFF is ignored (rate-limited by real
peer), while a genuine proxy still gets correct per-client limiting.

## Round 3 — Missing security headers (sniffing / clickjacking / polyglots)  ✅ fixed

**Attack.** Uploads were served with their content-type but no
`X-Content-Type-Options: nosniff`, and HTML pages had no CSP / `X-Frame-Options`.
A GIF/HTML polyglot (valid `GIF89a` magic + `<script>`) is accepted by the
magic-byte check and served from the same origin — a MIME-confusion / stored-XSS
risk, and pages could be framed for clickjacking.

**Fix.** All HTML responses now send `nosniff`, `X-Frame-Options: DENY`, and a
Content-Security-Policy. Static assets send `nosniff`. User uploads are served
from a dedicated route with `nosniff` **and** `Content-Security-Policy: sandbox;
default-src 'none'`, so even a polyglot opened directly cannot execute script.

## Probed and found already-safe

- **SQL injection** — all queries use prepared statements with bound parameters;
  thread IDs are parsed as integers.
- **Stored XSS** via name/subject/comment — all output is HTML-escaped; quote
  links and backlinks are built from integers only. No SVG/HTML upload types.
- **Path traversal** — Mongoose's `mg_http_serve_dir` rejects `../` and encoded
  traversal (`/../src/main.c`, `/uploads/%2e%2e/chan.db` → 404/400, no leak).
- **Memory safety** — exercised under AddressSanitizer/UBSan (normal posts,
  control-char filenames, polyglots, 5 KB greentext, traversal): no findings.
  (On WSL2, ASan needs `setarch -R` to avoid an ASLR-entropy startup crash.)

## PLAN 8 — exfiltration round (target: `../JUICY_PAYLOAD_FOR_RED_TEAM.txt`)

Objective: red team tries to read a secret file one level *above* the project
dir (i.e. above the static root `web/`) **through the running server** — no
direct `cat` (no cheating). A real target file was placed there and the server
was run from a sibling dir so `../` resolved to the genuine file. Leak detection
compared response-body MD5 against the file's MD5, so the exploit stayed purely
over HTTP (the file's contents were never read out-of-band).

### Round 4 — Directory listing information disclosure  ✅ fixed
**Attack.** `GET /uploads/` returned a Mongoose auto-generated index listing
**every uploaded file** (names + sizes) — anyone could enumerate and bulk-scrape
all uploads, including any not currently linked from a visible thread. (Pruned
threads *do* have their files deleted — verified — so this is about mass
enumeration. Did not reach the secret, which lives outside `web/`.)
**Fix.** Built with `-DMG_ENABLE_DIRLIST=0`; directory requests now return 403.
Verified: `/uploads/` → 403, while individual files (`/uploads/1.gif`,
`/style.css`, `/htmx.min.js`) still serve 200.

### Round 5 — Focused secret exfiltration  ❌ red team could NOT breach
A multi-vector campaign was run against the file-read surface:
- Path traversal via both the `/uploads/#` and the catch-all static routes:
  literal `../` (sent with `curl --path-as-is` to defeat client-side
  normalization), `%2e%2e`, `..%2f`, double-encoding (`%252f`), `....//`,
  backslashes, `..%00` null-byte truncation, `..;/`, mixed/again-encoded — **all
  returned 400/404; zero bytes of the target leaked.** Mongoose's
  `mg_path_is_sane` rejects any `/..` segment after a single URL-decode.
- SQL injection (subject/comment/thread-id) — parameterized everywhere; payload
  stored as inert text, schema intact. No `readfile()` (extension loading is
  compiled out) even if injection existed.
- Upload-path injection — stored names are server-generated (`<rowid>.<ext>` with
  `ext` from a fixed magic-byte allowlist); attacker controls neither path nor
  extension. No symlink creation primitive.

**Result: the secret was not exfiltrable through the server.** The PLAN 7
hardening plus Mongoose's path sanitization, fully parameterized SQL, and
generated upload paths leave no attacker-controlled file-read path. This is the
honest outcome — no breach was achieved or fabricated.

**Defense-in-depth already in place / recommended:** directory listing disabled
(Round 4); to further contain a *hypothetical* future traversal regression, run
the server as an unprivileged user in its own directory (or chroot/container) so
files outside `web/` are unreadable by the process at the OS level.

## PLAN 10 — final exfiltration round (target moved into the cwd)

Objective: same as PLAN 8, but the secret file now sits in the server's **current
working directory** — i.e. one level above the `web/` static root (`web/../SECRET`)
instead of two. Tested in a faithful sandbox (secret in cwd, `web/` as root, same
production binary); leak detection by response-body MD5, so the exploit stayed
over HTTP.

### Round 6 — Secret exfiltration (cwd file)  ❌ red team could NOT breach
Attempts, all repelled (400/404, zero secret bytes returned):
- Traversal up one level: `/../`, `%2e%2e`, `..%2f`, `..%5c`, `..%00`, `.%2e`,
  `//../`, `/...%2f`, `/web/../`, via both the `/uploads/#` and catch-all routes
  (literal `..` sent with `--path-as-is`).
- Malformed request-line targets (raw sockets): no-leading-slash
  (`GET web/../SECRET`, `GET SECRET`), absolute-form (`GET http://x/../SECRET`),
  absolute filesystem paths (`/proc/self/cwd/SECRET`, `/<abs>/SECRET`).
- No-leading-slash relative serving — verified it does **not** resolve to cwd
  (even `GET web/style.css` with no slash 404s), so cwd files aren't served.
- Full endpoint sweep (`/`, `/thread/N`, `/uploads/`, static) — no route ever
  returns the file; none reads an arbitrary path off disk.

**Result: not exfiltrable.** Moving the secret closer (cwd vs parent) changes
nothing: Mongoose's `mg_path_is_sane` rejects any `/..` segment regardless of
depth, and no application route opens an attacker-named file. Reported honestly —
defenses held; no breach achieved or fabricated. The only thing that would defend
a *hypothetical* future traversal regression is OS-level containment (run as an
unprivileged user in its own dir / container, ideally read-only FS).

## Known residual risks / future work

- CSP uses `'unsafe-inline'` because the UI relies on inline `<script>`/`onclick`/
  `hx-on` handlers; output escaping remains the primary XSS defense.
- `CHAN_TRUSTED_PROXY` accepts a single proxy IP (no CIDR / multi-hop list).
- No CSRF tokens on the post/reply forms (anonymous board, no accounts/sessions).
