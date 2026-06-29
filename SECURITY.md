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

## PLAN 11 — fix the O(n²) thread-render DoS  ✅ fixed

`render_thread_contents` computed reply backlinks in O(n²) (it rescanned every
comment for every post), and `GET /thread/N` is unauthenticated and not rate
limited — an attacker could repeatedly fetch a large thread to burn CPU on the
single-threaded event loop (a complexity-DoS amplifier). Replaced with an O(n)
prepass: each comment is scanned once for `>>N` quote links, and backlinks are
appended onto the referenced target via a binary-search id→index lookup
(`posts[]` is id-sorted), with a small `seen[]` array to dedup repeats. Backlink
output is byte-identical (verified across multi-quote, duplicate-quote,
dangling-ref, and self-quote cases). A/B benchmark: the quadratic backlink term
(old−new render time) grew ~4× per post-count doubling (26 ms → 99 ms from
n=300→600) and is now eliminated; new render time is linear in thread size.

## PLAN 12 — bound per-request memory (static limits + scratch arena)  ✅ done

Two related hardening goals: make the memory a single request can consume
*provably finite*, and remove per-request heap churn from the render path.

- **Static field-size limits.** Name / subject / body are capped at 32 / 256 /
  4096 bytes at parse time (`copy_mgstr` truncates into fixed buffers). This
  bounds each post's contribution to a rendered page.
- **Reply-blocking bump limit.** The bump limit is now a *hard cap*: once a
  thread holds `BUMP_LIMIT` posts it returns `403` to further replies (it still
  records `bumplimit_at` so pruning proceeds). Previously the limit only stopped
  bumping, so a thread could grow without bound between hitting the limit and
  being pruned — an unbounded input to the O(n) render.
- **Thread limit.** At most `THREAD_LIMIT` threads live at once; creating a new
  OP prunes the least-recently-bumped threads (and their uploads). This bounds
  the catalog/index page.
- **Per-request scratch arena.** A single buffer is allocated once at startup;
  the HTML builder (`sbuf`), the loaded `posts[]`, and the per-post backlink
  buffers all bump-allocate from it (`scratch_save` / `scratch_alloc` /
  `scratch_realloc` / `scratch_restore`) and are freed in O(1) when the request
  frame unwinds in `ev_handler`. This replaces all per-request
  malloc/realloc/calloc/strdup in the render path. The long-lived rate-limit
  hash table is deliberately **excluded** — it must persist across requests, so
  it stays on the heap.

With the field/bump/thread limits in place the worst-case page size is finite,
so `SCRATCH_BYTES` (64 MiB default) is a hard ceiling on per-request memory. If
a page ever exceeds the arena, allocations return `NULL` and the builder
degrades to **truncated output** (logged) rather than overflowing or crashing —
verified under ASan/UBSan with a deliberately tiny 64 KiB arena (forced
exhaustion produced no memory errors), and the full-size happy path renders
complete threads with no truncation and no sanitizer findings.

## Known residual risks / future work

- CSP uses `'unsafe-inline'` because the UI relies on inline `<script>`/`onclick`/
  `hx-on` handlers; output escaping remains the primary XSS defense.
- `CHAN_TRUSTED_PROXY` accepts a single proxy IP (no CIDR / multi-hop list). It
  trusts the left-most `X-Forwarded-For` entry, which a client can forge through
  some CDNs (notably Cloudflare). Build with `-DCLOUDFLARED` to key off
  `CF-Connecting-IP` (set by Cloudflare's edge, not client-forgeable) instead.
- No CSRF tokens on the post/reply forms (anonymous board, no accounts/sessions).
- Admin delete (`?del`, PLAN 18) authenticates with HTTP Basic over whatever
  transport the server runs on — run it behind TLS (the intended reverse-proxy
  deployment) so the `admin` password isn't sent in the clear. It mutates on
  `GET` and has no CSRF token by design; the password is the only gate.
- `GET` endpoints aren't rate limited. Thread render is O(n) and response size is
  now bounded by the bump/thread/field limits (PLAN 12), but a worst-case thread
  can still render a multi-MB page on each fetch — consider caching rendered
  threads if read-amplification DoS becomes a concern.
