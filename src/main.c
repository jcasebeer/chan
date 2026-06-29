// chan - a minimal single-board imageboard (4chan-style clone).
//
// Stack: mongoose (HTTP server) + sqlite (storage) + htmx (frontend).
// Single textboard "board"; no per-board routing.
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "md5.h"
#include "mongoose.h"
#include "sqlite3.h"

#define BOARD_TITLE "CHAN"
#define BOARD_SUB "a tiny imageboard written in C"
#define WEB_ROOT "web"
#define UPLOAD_DIR WEB_ROOT "/uploads"
#define DB_PATH "chan.db"
// Static per-field size limits (bytes, excluding the NUL). These bound how much
// any single post can contribute to a rendered page, which in turn lets the
// render path run entirely off a fixed-size scratch arena (see below).
#define MAX_NAME 32
#define MAX_SUBJECT 256
#define MAX_COMMENT 4096
#define MAX_UPLOAD (8 * 1024 * 1024)  // 8 MiB
// Largest request body we accept: an 8 MiB upload plus a small multipart/field
// envelope. A request whose Content-Length exceeds this is rejected at the header
// stage (before the body is read), so an oversized upload can't fill the recv
// buffer up to MG_MAX_RECV_SIZE and trigger mongoose's mid-stream connection abort.
#define MAX_REQUEST_BYTES (MAX_UPLOAD + 65536)
#ifndef BUMP_LIMIT
#define BUMP_LIMIT 300                // posts (OP + replies); the limit BLOCKS further replies
#endif
#ifndef THREAD_LIMIT
#define THREAD_LIMIT 100              // max live threads; oldest are pruned to bound the catalog
#endif
#ifndef DELETE_AFTER
#define DELETE_AFTER (8 * 3600)       // seconds after hitting the bump limit before deletion
#endif
#ifndef RATE_WINDOW
#define RATE_WINDOW 5                // min seconds between posts from one IP
#endif
#ifndef MAX_DISK_BYTES
#define MAX_DISK_BYTES (8LL * 1024 * 1024 * 1024)  // upload dir quota: 8 GiB
#endif
#define UPLOAD_LOG "uploads.log"

// Which header carries the real client IP when sitting behind a trusted proxy
// (see client_ip / $CHAN_TRUSTED_PROXY). Default is X-Forwarded-For. Build with
// -DCLOUDFLARED to use CF-Connecting-IP instead: behind a Cloudflare Tunnel the
// left-most X-Forwarded-For entry can be spoofed by the client, whereas
// CF-Connecting-IP is set by Cloudflare's own edge and isn't client-forgeable.
#ifdef CLOUDFLARED
#define CLIENT_IP_HEADER "CF-Connecting-IP"
#else
#define CLIENT_IP_HEADER "X-Forwarded-For"
#endif

// Security headers for HTML responses: block content sniffing, framing
// (clickjacking), and external resource loads. 'unsafe-inline' is required
// because the UI uses inline <script> blocks and onclick handlers; server output
// is HTML-escaped, so CSP here is defense-in-depth. ('unsafe-eval' is NOT granted,
// so we avoid htmx's hx-on, which evaluates via new Function -- see page_head.)
#define HTML_HDRS                                                             \
  "Content-Type: text/html; charset=utf-8\r\n"                               \
  "Cache-Control: no-cache\r\n"                                              \
  "X-Content-Type-Options: nosniff\r\n"                                      \
  "X-Frame-Options: DENY\r\n"                                                \
  "Content-Security-Policy: default-src 'self'; img-src 'self'; "            \
  "media-src 'self'; style-src 'self' 'unsafe-inline'; "                     \
  "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; "  \
  "frame-ancestors 'none'\r\n"

// Plain-text error responses (rate limit, validation) still get nosniff.
#define TEXT_HDRS "Content-Type: text/plain\r\nX-Content-Type-Options: nosniff\r\n"

static sqlite3 *g_db;

// ---------------------------------------------------------------------------
// Per-request scratch arena.
//
// One large buffer is allocated once at startup; every per-request render
// allocation (the HTML sbuf, the loaded posts[], the per-post backlink buffers)
// bump-allocates from it and the whole frame is freed in O(1) by restoring the
// offset at the end of the request. This replaces malloc/realloc/calloc/strdup
// in the hot render path and hard-bounds the memory one request can consume: the
// static field-size limits, the reply-blocking bump limit, and the thread limit
// together make the worst-case page size finite.
//
// API (stack discipline):
//   size_t save = scratch_save();
//   char *p = scratch_alloc(n);   // or scratch_calloc / scratch_realloc / scratch_strdup
//   scratch_restore(save);        // frees everything allocated since `save`
//
// NOTE: the long-lived rate-limit hash table is deliberately NOT part of this
// arena -- it must persist across requests, so it stays on the heap.
//
// Worst case is dominated by backlinks: each of up to BUMP_LIMIT posts can quote
// every other post, so total backlink text is O(BUMP_LIMIT^2). That text is held
// once in the bl[] buffers and again in the response, each grown by doubling
// (~2x slack), plus the escaped bodies. 64 MiB covers the adversarial worst case
// for the default limits; on exhaustion allocations return NULL and callers
// degrade to truncated output rather than crashing.
#ifndef SCRATCH_BYTES
#define SCRATCH_BYTES (64u * 1024 * 1024)
#endif

static char *g_scratch;
static size_t g_scratch_cap;
static size_t g_scratch_off;
static int g_scratch_oom;  // latched if any alloc overflowed the current frame

static size_t scratch_save(void) { return g_scratch_off; }

static void scratch_restore(size_t save) {
  g_scratch_off = save;
  if (save == 0) g_scratch_oom = 0;  // clear the OOM latch at the outermost frame
}

// Bump-allocate `n` bytes, 16-byte aligned. Returns NULL (latching the OOM flag)
// if the arena is exhausted.
static void *scratch_alloc(size_t n) {
  size_t off = (g_scratch_off + 15u) & ~(size_t) 15u;
  if (off > g_scratch_cap || n > g_scratch_cap - off) {
    g_scratch_oom = 1;
    return NULL;
  }
  g_scratch_off = off + n;
  return g_scratch + off;
}

static void *scratch_calloc(size_t count, size_t size) {
  size_t n = count * size;  // counts here are bounded by the post/thread limits
  void *p = scratch_alloc(n);
  if (p != NULL) memset(p, 0, n);
  return p;
}

// Grow a prior scratch allocation. If `old` is the most-recent (top) allocation
// it is extended in place -- the common, stack-shaped case. Otherwise a fresh
// block is allocated and the contents copied; the old bytes are abandoned until
// the frame is restored (correct for interleaved growth, just not space-optimal).
static void *scratch_realloc(void *old, size_t oldn, size_t newn) {
  if (old != NULL) {
    char *p = (char *) old;
    if (p + oldn == g_scratch + g_scratch_off) {  // `old` is the arena top
      size_t base = (size_t) (p - g_scratch);
      if (newn <= g_scratch_cap - base) {
        g_scratch_off = base + newn;
        return old;
      }
      g_scratch_oom = 1;
      return NULL;
    }
  }
  void *fresh = scratch_alloc(newn);
  if (fresh != NULL && old != NULL && oldn > 0) memcpy(fresh, old, oldn);
  return fresh;
}

static char *scratch_strdup(const char *s) {
  if (s == NULL) return NULL;
  size_t n = strlen(s) + 1;
  char *p = (char *) scratch_alloc(n);
  if (p != NULL) memcpy(p, s, n);
  return p;
}

// ---------------------------------------------------------------------------
// Dynamic string buffer used to build HTML responses.
// ---------------------------------------------------------------------------
struct sbuf {
  char *buf;
  size_t len;
  size_t cap;
};

static void sb_grow(struct sbuf *s, size_t need) {
  if (s->len + need + 1 <= s->cap) return;
  size_t cap = s->cap ? s->cap : 1024;
  while (s->len + need + 1 > cap) cap *= 2;
  char *nb = (char *) scratch_realloc(s->buf, s->cap, cap);
  if (nb == NULL) return;  // arena exhausted: keep the old buffer, drop the growth
  s->buf = nb;
  s->cap = cap;
}

static void sb_append(struct sbuf *s, const char *data, size_t n) {
  sb_grow(s, n);
  if (s->len + n + 1 > s->cap) return;  // grow failed (arena exhausted): truncate
  memcpy(s->buf + s->len, data, n);
  s->len += n;
  s->buf[s->len] = '\0';
}

static void sb_puts(struct sbuf *s, const char *str) {
  sb_append(s, str, strlen(str));
}

static void sb_printf(struct sbuf *s, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0) return;
  sb_grow(s, (size_t) n);
  if (s->len + (size_t) n + 1 > s->cap) return;  // grow failed: truncate
  va_start(ap, fmt);
  vsnprintf(s->buf + s->len, (size_t) n + 1, fmt, ap);
  va_end(ap);
  s->len += (size_t) n;
}

// sbuf storage lives in the scratch arena, so there is nothing to free here;
// the whole frame is reclaimed by scratch_restore() at the end of the request.
// This just resets the handle so it can't be reused after the frame is gone.
static void sb_free(struct sbuf *s) {
  s->buf = NULL;
  s->len = s->cap = 0;
}

// Append a single character HTML-escaped.
static void sb_putc_esc(struct sbuf *s, char c) {
  switch (c) {
    case '&': sb_puts(s, "&amp;"); break;
    case '<': sb_puts(s, "&lt;"); break;
    case '>': sb_puts(s, "&gt;"); break;
    case '"': sb_puts(s, "&quot;"); break;
    case '\'': sb_puts(s, "&#39;"); break;
    default: sb_append(s, &c, 1); break;
  }
}

// Append a NUL-terminated string HTML-escaped.
static void sb_esc(struct sbuf *s, const char *str) {
  if (str == NULL) return;
  for (const char *p = str; *p; p++) sb_putc_esc(s, *p);
}

// ---------------------------------------------------------------------------
// Comment formatting: greentext (>foo) and quote links (>>123).
// Operates on raw text, emitting HTML-escaped output.
// ---------------------------------------------------------------------------
static void format_comment(struct sbuf *s, const char *text) {
  if (text == NULL) return;
  const char *p = text;
  while (*p) {
    // Find end of this line.
    const char *eol = strchr(p, '\n');
    const char *end = eol ? eol : p + strlen(p);

    // Greentext: line begins with '>' but not '>>'.
    int green = (p < end && p[0] == '>' && !(p + 1 < end && p[1] == '>'));
    if (green) sb_puts(s, "<span class=\"quote\">");

    const char *q = p;
    while (q < end) {
      // Quote link: >>digits
      if (q[0] == '>' && q + 1 < end && q[1] == '>' &&
          q + 2 < end && q[2] >= '0' && q[2] <= '9') {
        const char *d = q + 2;
        while (d < end && *d >= '0' && *d <= '9') d++;
        int id = atoi(q + 2);
        sb_printf(s, "<a class=\"quotelink\" href=\"#p%d\">", id);
        sb_append(s, q, (size_t) (d - q));  // ">>123" has no special chars
        sb_puts(s, "</a>");
        q = d;
        continue;
      }
      sb_putc_esc(s, *q);
      q++;
    }

    if (green) sb_puts(s, "</span>");
    if (eol) {
      sb_puts(s, "<br>");
      p = eol + 1;
    } else {
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Time formatting.
// ---------------------------------------------------------------------------
static void fmt_time(char *out, size_t n, sqlite3_int64 t) {
  time_t tt = (time_t) t;
  struct tm tm;
  gmtime_r(&tt, &tm);
  strftime(out, n, "%m/%d/%y(%a)%H:%M:%S", &tm);
}

// ---------------------------------------------------------------------------
// HTML page chrome.
// ---------------------------------------------------------------------------
static void page_head(struct sbuf *s, const char *title) {
  sb_puts(s, "<!doctype html><html><head><meta charset=\"utf-8\">");
  sb_puts(s, "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
  sb_puts(s, "<title>");
  sb_esc(s, title);
  sb_puts(s, "</title>");
  sb_puts(s, "<link rel=\"stylesheet\" href=\"/style.css\">");
  sb_puts(s, "<script src=\"/htmx.min.js\"></script>");
  // Clicking a post number calls quote(): if a reply box exists on the page it
  // inserts ">>id" and focuses it (returning false to cancel navigation);
  // otherwise it returns true so the link navigates to the thread.
  sb_puts(s,
      "<script>function quote(id){"
      "var t=document.querySelector('#postform textarea[name=comment]');"
      "if(!t)return true;"
      "t.value+=(t.value&&!t.value.endsWith('\\n')?'\\n':'')+'>>'+id+'\\n';"
      "t.focus();"
      "document.getElementById('postform').scrollIntoView({block:'nearest'});"
      "return false;}</script>");
  // Surface server error responses (rate limit, validation) in #notice. htmx
  // does not swap non-2xx responses, so read the body from the error event.
  sb_puts(s,
      "<script>addEventListener('htmx:responseError',function(e){"
      "var n=document.getElementById('notice');"
      "if(n)n.textContent=e.detail.xhr.responseText||('Error '+e.detail.xhr.status);});"
      "addEventListener('htmx:afterRequest',function(e){"
      "if(!e.detail.successful)return;"
      "var n=document.getElementById('notice');if(n)n.textContent='';"
      // Clear the post form after a successful submit. (Done here in a real
      // inline <script> rather than via hx-on, because hx-on evaluates its body
      // with new Function(), which our CSP blocks for lack of 'unsafe-eval'.)
      "var f=e.target;if(f&&f.id==='postform'&&f.reset)f.reset();});</script>");
  // Client-side guard: reject an over-size file before uploading it, so the user
  // gets an instant "Too large!" instead of a multi-MB upload that the server
  // rejects mid-stream. The server still enforces the limit; this is purely UX.
  sb_printf(s,
      "<script>addEventListener('htmx:beforeRequest',function(e){"
      "var f=e.target.querySelector&&e.target.querySelector('input[type=file]');"
      "if(f&&f.files&&f.files[0]&&f.files[0].size>%d){"
      "e.preventDefault();"
      "var n=document.getElementById('notice');"
      "if(n)n.textContent='Too large!';}});</script>",
      MAX_UPLOAD);
  sb_puts(s, "</head><body>");
  sb_puts(s, "<div class=\"banner\"><h1>" BOARD_TITLE "</h1>");
  sb_puts(s, "<div class=\"sub\">" BOARD_SUB "</div></div><hr>");
}

static void page_foot(struct sbuf *s) {
  sb_puts(s, "<hr><div class=\"nav\">chan &mdash; please be kind</div>");
  sb_puts(s, "</body></html>");
}

// Render the new-thread / reply post form.
// When thread_id == 0 it posts a new thread, otherwise it replies.
static void render_form(struct sbuf *s, long thread_id) {
  // Error messages (rate limit, validation) are written here by the page JS.
  sb_puts(s, "<div id=\"notice\" class=\"notice\"></div>");
  // enctype=multipart so htmx submits the file input as FormData.
  if (thread_id == 0) {
    sb_puts(s, "<form id=\"postform\" class=\"postform\" "
               "enctype=\"multipart/form-data\" hx-post=\"/post\" "
               "hx-target=\"#catalog\" hx-swap=\"afterbegin\">");
  } else {
    // Swap the whole thread so reply backlinks on quoted posts update too.
    sb_printf(s,
              "<form id=\"postform\" class=\"postform\" "
              "enctype=\"multipart/form-data\" hx-post=\"/reply/%ld\" "
              "hx-target=\"#thread-%ld\" hx-swap=\"innerHTML\">",
              thread_id, thread_id);
  }
  sb_puts(s, "<table><tr><td class=\"lbl\">Name</td>"
             "<td><input type=\"text\" name=\"name\" placeholder=\"Anonymous\"></td></tr>");
  if (thread_id == 0) {
    sb_puts(s, "<tr><td class=\"lbl\">Subject</td>"
               "<td><input type=\"text\" name=\"subject\">"
               "<input type=\"submit\" value=\"Post\" style=\"float:right\"></td></tr>");
  }
  sb_puts(s, "<tr><td class=\"lbl\">Comment</td>"
             "<td><textarea name=\"comment\" required></textarea></td></tr>");
  sb_puts(s, "<tr><td class=\"lbl\">File</td>"
             "<td><input type=\"file\" name=\"file\" "
             "accept=\".png,.jpg,.jpeg,.gif,.webm,image/png,image/jpeg,image/gif,video/webm\">"
             "<div class=\"hint\">png / jpg / gif / webm, max 8 MiB</div></td></tr>");
  if (thread_id != 0) {
    sb_puts(s, "<tr><td></td><td><input type=\"submit\" value=\"Reply\"></td></tr>");
  }
  sb_puts(s, "</table></form>");
}

// ---------------------------------------------------------------------------
// Post rendering. is_op marks the opening post of a thread.
// ---------------------------------------------------------------------------
static int is_webm(const char *path);  // defined with the upload helpers below

// Render the file/thumbnail block for a post (floated left of the comment).
static void render_media(struct sbuf *s, const char *image) {
  if (image == NULL || image[0] == '\0') return;
  sb_puts(s, "<div class=\"file\">");
  if (is_webm(image)) {
    sb_printf(s, "<video class=\"thumb\" controls preload=\"metadata\" "
                 "src=\"/%s\"></video>", image);
  } else {
    sb_printf(s, "<a href=\"/%s\" target=\"_blank\">"
                 "<img class=\"thumb\" src=\"/%s\" loading=\"lazy\"></a>",
              image, image);
  }
  sb_puts(s, "</div>");
}

static void render_post(struct sbuf *s, int is_op, sqlite3_int64 id,
                        const char *name, const char *subject,
                        const char *comment, sqlite3_int64 created,
                        long thread_id, const char *image,
                        const char *backlinks) {
  char tbuf[64];
  fmt_time(tbuf, sizeof(tbuf), created);

  int has_image = (image != NULL && image[0] != '\0');
  sb_printf(s, "<div class=\"post %s%s\" id=\"p%lld\">", is_op ? "op" : "reply",
            has_image ? " has-image" : "", (long long) id);
  sb_puts(s, "<div class=\"postinfo\">");
  if (subject && subject[0]) {
    sb_puts(s, "<span class=\"subject\">");
    sb_esc(s, subject);
    sb_puts(s, "</span> ");
  }
  sb_puts(s, "<span class=\"name\">");
  sb_esc(s, (name && name[0]) ? name : "Anonymous");
  sb_puts(s, "</span> ");
  sb_printf(s, "<span class=\"date\">%s</span> ", tbuf);
  // Clicking the number quotes the post into the reply box (see quote() in JS);
  // if no reply box is present the link falls back to navigating to the post.
  sb_printf(s, "<span class=\"postnum\">No.<a href=\"/thread/%lld#p%lld\" "
               "onclick=\"return quote(%lld)\">%lld</a></span>",
            (long long) (is_op ? id : thread_id), (long long) id,
            (long long) id, (long long) id);
  // Backlinks: clickable references to the posts that reply to this one.
  if (backlinks && backlinks[0]) {
    sb_printf(s, "<span class=\"backlinks\">%s</span>", backlinks);
  }
  sb_puts(s, "</div>");

  render_media(s, image);
  sb_puts(s, "<blockquote class=\"comment\">");
  format_comment(s, comment);
  sb_puts(s, "</blockquote>");
  sb_puts(s, "</div>");
}

// Count replies for a thread.
static int reply_count(sqlite3_int64 tid) {
  sqlite3_stmt *st;
  int n = 0;
  if (sqlite3_prepare_v2(g_db,
          "SELECT COUNT(*) FROM posts WHERE thread_id=?", -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, tid);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
  }
  sqlite3_finalize(st);
  return n;
}

// One post loaded into memory so we can compute reply backlinks across a thread.
struct tpost {
  sqlite3_int64 id;
  char *name, *subject, *comment, *image;
  sqlite3_int64 created;
  int is_op;
};

// Binary search for the post with `id` in the id-sorted posts[] array (loaded
// ORDER BY id ASC). Returns its index, or -1 if not in this thread.
static int tpost_index(const struct tpost *posts, int n, sqlite3_int64 id) {
  int lo = 0, hi = n - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    if (posts[mid].id == id) return mid;
    if (posts[mid].id < id) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

// Render a thread's inner content: OP, then a .replies container with each
// reply. Each post is annotated with backlinks to the posts that reply to it.
// Used both by the full thread page and the htmx reply response.
static void render_thread_contents(struct sbuf *s, sqlite3_int64 tid) {
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(g_db,
          "SELECT id,name,subject,comment,created_at,image,(thread_id IS NULL) "
          "FROM posts WHERE id=? OR thread_id=? ORDER BY id ASC",
          -1, &st, NULL) != SQLITE_OK)
    return;
  sqlite3_bind_int64(st, 1, tid);
  sqlite3_bind_int64(st, 2, tid);

  // posts[] is bump-allocated; the reply-blocking bump limit caps a thread at
  // BUMP_LIMIT posts, so a fresh thread never grows past it. Legacy threads that
  // predate the limit may have more rows -- scratch_realloc handles any n, and on
  // arena exhaustion we simply stop loading (the page renders what fit).
  struct tpost *posts = NULL;
  int n = 0, cap = 0;
  while (sqlite3_step(st) == SQLITE_ROW) {
    if (n == cap) {
      int newcap = cap ? cap * 2 : 16;
      struct tpost *np =
          (struct tpost *) scratch_realloc(posts, (size_t) cap * sizeof(*posts),
                                           (size_t) newcap * sizeof(*posts));
      if (np == NULL) break;  // arena exhausted: render what we have
      posts = np;
      cap = newcap;
    }
    struct tpost *p = &posts[n++];
    const char *nm = (const char *) sqlite3_column_text(st, 1);
    const char *sj = (const char *) sqlite3_column_text(st, 2);
    const char *cm = (const char *) sqlite3_column_text(st, 3);
    const char *im = (const char *) sqlite3_column_text(st, 5);
    p->id = sqlite3_column_int64(st, 0);
    p->name = scratch_strdup(nm);
    p->subject = scratch_strdup(sj);
    p->comment = cm ? scratch_strdup(cm) : scratch_strdup("");
    p->created = sqlite3_column_int64(st, 4);
    p->image = scratch_strdup(im);
    p->is_op = sqlite3_column_int(st, 6);
  }
  sqlite3_finalize(st);

  // Prepass: build every post's backlinks in O(total comment text) rather than
  // the old O(n^2) (which rescanned every comment for every post — an unbounded,
  // unauthenticated CPU sink on GET /thread for large threads). For each post we
  // scan its comment once for ">>N" quote links and append a backlink onto the
  // referenced target. `bl[i]` accumulates the backlinks shown on post i; `seen`
  // dedups so quoting the same post twice in one comment yields one backlink.
  // Both arrays are sized to the actual post count n (a thread is kept small by
  // the bump limit), so there is no fixed-cap overflow even if replies arrive
  // after the limit but before pruning.
  struct sbuf *bl = (struct sbuf *) scratch_calloc((size_t) (n > 0 ? n : 1), sizeof(*bl));
  int *seen = (int *) scratch_alloc((size_t) (n > 0 ? n : 1) * sizeof(*seen));
  if (bl == NULL || seen == NULL) return;  // arena exhausted before the prepass
  for (int i = 0; i < n; i++) seen[i] = -1;
  for (int j = 0; j < n; j++) {
    for (const char *p = posts[j].comment; (p = strstr(p, ">>")) != NULL;) {
      p += 2;
      if (*p < '0' || *p > '9') continue;
      char *endp;
      long ref = strtol(p, &endp, 10);
      p = endp;
      int ti = tpost_index(posts, n, (sqlite3_int64) ref);
      if (ti >= 0 && ti != j && seen[ti] != j) {
        seen[ti] = j;
        // A backlink jumps to the replying post (its href anchor); unlike the
        // post-number link, it must NOT quote into the reply box.
        sb_printf(&bl[ti],
                  "<a class=\"quotelink backlink\" href=\"#p%lld\">&gt;&gt;%lld</a> ",
                  (long long) posts[j].id, (long long) posts[j].id);
      }
    }
  }

  // posts[0] is the OP (lowest id). Render OP, open .replies, then the replies.
  for (int i = 0; i < n; i++) {
    render_post(s, posts[i].is_op, posts[i].id, posts[i].name, posts[i].subject,
                posts[i].comment, posts[i].created, (long) tid, posts[i].image,
                bl[i].buf);
    if (i == 0) sb_puts(s, "<div class=\"replies\">");
  }
  if (n > 0) sb_puts(s, "</div>");  // close .replies
  // No frees: posts[], bl[], seen[], the strdup'd fields, and every bl[i].buf all
  // live in the scratch arena and are reclaimed wholesale by scratch_restore()
  // when the request frame unwinds (see ev_handler).
}

// Append `comment` truncated to ~140 chars, HTML-escaped, for catalog excerpts.
static void sb_esc_excerpt(struct sbuf *s, const char *text, size_t limit) {
  if (text == NULL) return;
  size_t i = 0;
  for (const char *p = text; *p && i < limit; p++, i++) {
    sb_putc_esc(s, *p == '\n' ? ' ' : *p);
  }
  if (text[i] != '\0') sb_puts(s, "&hellip;");
}

// Render a single catalog cell: thumbnail + stats + subject + excerpt.
// at_limit marks a thread that has hit the bump limit (shown in red).
static void render_catalog_cell(struct sbuf *s, sqlite3_int64 id,
                                const char *subject, const char *comment,
                                const char *image, int at_limit) {
  int replies = reply_count(id);
  sb_printf(s, "<div class=\"cat-cell%s\" id=\"thread-%lld\">",
            at_limit ? " bumplimit" : "", (long long) id);
  sb_printf(s, "<a class=\"cat-link\" href=\"/thread/%lld\">", (long long) id);
  if (image && image[0]) {
    if (is_webm(image)) {
      sb_printf(s, "<video class=\"cat-thumb\" muted src=\"/%s\"></video>", image);
    } else {
      sb_printf(s, "<img class=\"cat-thumb\" src=\"/%s\" loading=\"lazy\">", image);
    }
  } else {
    sb_puts(s, "<div class=\"cat-thumb cat-noimg\">[no image]</div>");
  }
  sb_puts(s, "</a>");
  sb_printf(s, "<div class=\"cat-stats\">R: %d%s</div>", replies,
            at_limit ? " &mdash; BUMP LIMIT" : "");
  if (subject && subject[0]) {
    sb_puts(s, "<div class=\"cat-subject\">");
    sb_esc(s, subject);
    sb_puts(s, "</div>");
  }
  sb_puts(s, "<div class=\"cat-excerpt\">");
  sb_esc_excerpt(s, comment, 140);
  sb_puts(s, "</div></div>");
}

// Render the whole catalog (index body). Reused by htmx after posting.
static void render_catalog(struct sbuf *s) {
  sqlite3_stmt *st;
  int any = 0;
  if (sqlite3_prepare_v2(g_db,
          "SELECT id,subject,comment,image,(bumplimit_at IS NOT NULL) FROM posts "
          "WHERE thread_id IS NULL ORDER BY bumped_at DESC", -1, &st, NULL) == SQLITE_OK) {
    while (sqlite3_step(st) == SQLITE_ROW) {
      any = 1;
      render_catalog_cell(s, sqlite3_column_int64(st, 0),
                          (const char *) sqlite3_column_text(st, 1),
                          (const char *) sqlite3_column_text(st, 2),
                          (const char *) sqlite3_column_text(st, 3),
                          sqlite3_column_int(st, 4));
    }
  }
  sqlite3_finalize(st);
  if (!any) sb_puts(s, "<div class=\"empty\">No threads yet. Start one!</div>");
}

// ---------------------------------------------------------------------------
// Request helpers.
// ---------------------------------------------------------------------------
// Trim leading/trailing ASCII whitespace in place.
static char *trim(char *s) {
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
  char *e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
    *--e = '\0';
  return s;
}

// ---------------------------------------------------------------------------
// File uploads (multipart/form-data).
// ---------------------------------------------------------------------------
// Parsed fields of a post submission.
struct post_input {
  char name[MAX_NAME + 1];
  char subject[MAX_SUBJECT + 1];
  char comment[MAX_COMMENT + 1];
  char filename[256];  // original upload filename (for logging)
  struct mg_str file;  // raw bytes, points into the request buffer
  int has_file;
};

// Copy an mg_str into a fixed buffer, NUL-terminated and length-limited.
static void copy_mgstr(char *dst, size_t cap, struct mg_str s) {
  size_t n = s.len < cap - 1 ? s.len : cap - 1;
  memcpy(dst, s.buf, n);
  dst[n] = '\0';
}

// Parse all multipart parts into a post_input.
static void parse_multipart(struct mg_http_message *hm, struct post_input *in) {
  memset(in, 0, sizeof(*in));
  size_t ofs = 0;
  struct mg_http_part part;
  while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
    if (mg_strcmp(part.name, mg_str("name")) == 0) {
      copy_mgstr(in->name, sizeof(in->name), part.body);
    } else if (mg_strcmp(part.name, mg_str("subject")) == 0) {
      copy_mgstr(in->subject, sizeof(in->subject), part.body);
    } else if (mg_strcmp(part.name, mg_str("comment")) == 0) {
      copy_mgstr(in->comment, sizeof(in->comment), part.body);
    } else if (mg_strcmp(part.name, mg_str("file")) == 0 && part.filename.len > 0) {
      in->file = part.body;
      copy_mgstr(in->filename, sizeof(in->filename), part.filename);
      in->has_file = 1;
    }
  }
}

// Detect file type from magic bytes. Returns an extension or NULL if unsupported.
static const char *sniff_ext(struct mg_str f) {
  const unsigned char *b = (const unsigned char *) f.buf;
  size_t n = f.len;
  if (n >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') return "png";
  if (n >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "jpg";
  if (n >= 6 && memcmp(b, "GIF8", 4) == 0) return "gif";
  if (n >= 4 && b[0] == 0x1A && b[1] == 0x45 && b[2] == 0xDF && b[3] == 0xA3) return "webm";
  return NULL;
}

// Validate an upload (size + type) and compute its stored relative path
// "uploads/<id>.<ext>" into `stored`. Does NOT touch disk. The extension is
// derived from the in-memory magic bytes, so the name is known before any write.
// Returns 0 if there is no file; 1 if valid; -1 if rejected (too big / bad type).
static int upload_validate(struct mg_str file, sqlite3_int64 id, char *stored,
                           size_t storedn) {
  if (file.len == 0) return 0;
  if (file.len > MAX_UPLOAD) return -1;
  const char *ext = sniff_ext(file);
  if (ext == NULL) return -1;
  snprintf(stored, storedn, "uploads/%lld.%s", (long long) id, ext);
  return 1;
}

// Write the upload bytes to disk at WEB_ROOT/<stored>. Returns 1 on success.
// IMPORTANT: callers write the DB `image` reference BEFORE calling this, so the
// on-disk file is always referenced by a row. A failure or crash here leaves at
// most a dangling reference (a broken thumbnail that is cleaned up when the
// thread is pruned) -- never an orphan file with no owning row.
static int upload_write(struct mg_str file, const char *stored) {
  char path[256];
  snprintf(path, sizeof(path), "%s/%s", WEB_ROOT, stored);
  FILE *f = fopen(path, "wb");
  if (f == NULL) return 0;
  size_t wrote = fwrite(file.buf, 1, file.len, f);
  fclose(f);
  if (wrote != file.len) {
    remove(path);  // drop a partial/corrupt write; the row's ref self-heals on prune
    return 0;
  }
  return 1;
}

// True if a stored upload path is a webm (rendered as <video> not <img>).
static int is_webm(const char *path) {
  size_t n = path ? strlen(path) : 0;
  return n >= 5 && strcmp(path + n - 5, ".webm") == 0;
}

static void delete_thread_files(sqlite3_int64 tid);  // defined with pruning below

// ---------------------------------------------------------------------------
// Client IP (used for rate limiting and the upload log).
// ---------------------------------------------------------------------------
// Configured at startup from $CHAN_TRUSTED_PROXY (the reverse proxy's IP
// address). We honor the forwarded-client-IP header (CLIENT_IP_HEADER:
// X-Forwarded-For, or CF-Connecting-IP under -DCLOUDFLARED) ONLY when the request
// actually arrives from that proxy; for any other peer the header is ignored and
// the TCP peer address is used. This stops direct clients from spoofing the
// header to bypass rate limiting or forge their logged identity. Empty => never
// trust the forwarded header.
static char g_trusted_proxy[48];

// Admin password, read once at startup from $CHAN_ADMIN_PASS. Empty => the
// admin delete feature is disabled (a ?del request is treated as a normal GET).
static char g_admin_pass[128];

static void client_ip(struct mg_connection *c, struct mg_http_message *hm,
                      char *buf, size_t n) {
  char peer[48];
  mg_snprintf(peer, sizeof(peer), "%M", mg_print_ip, &c->rem);
  if (g_trusted_proxy[0] && strcmp(peer, g_trusted_proxy) == 0) {
    struct mg_str *fwd = mg_http_get_header(hm, CLIENT_IP_HEADER);
    if (fwd != NULL && fwd->len > 0) {
      // X-Forwarded-For: client, proxy1, proxy2 ... — the left-most entry is the
      // original client. CF-Connecting-IP is a single address, so the same
      // "up to the first comma" parse yields the whole value. Trim whitespace.
      size_t i = 0;
      while (i < fwd->len && (fwd->buf[i] == ' ' || fwd->buf[i] == '\t')) i++;
      size_t e = i;
      while (e < fwd->len && fwd->buf[e] != ',') e++;
      while (e > i && (fwd->buf[e - 1] == ' ' || fwd->buf[e - 1] == '\t')) e--;
      size_t len = e - i;
      if (len > 0 && len < n) {
        memcpy(buf, fwd->buf + i, len);
        buf[len] = '\0';
        return;
      }
    }
  }
  snprintf(buf, n, "%s", peer);
}

// ---------------------------------------------------------------------------
// Rate limiting: at most one post per IP per RATE_WINDOW seconds (in-memory).
//
// Fixed-size, direct-mapped cache: each client IP is reduced to a 32-bit key
// (see ip_key) and mapped to exactly one slot, slot = mix64(key) & (RL_SLOTS-1).
// There is no probing and no resizing -- on a collision (two different keys land
// in the same slot) the newcomer simply replaces the incumbent. The table is a
// flat array allocated once, so memory is constant regardless of how many
// distinct IPs are seen. A replaced entry just loses its timer, so the failure
// mode is fail-open (an occasional extra post slips through).
//
// Slots store the key too, so we only enforce the window on a genuine key match;
// a colliding key is treated as a fresh client. Keys are derived from validated
// client IPs (and IPv6 is folded to its /64), not attacker-chosen input, so a
// non-cryptographic integer avalanche (the splitmix64 finalizer) is sufficient.
// ---------------------------------------------------------------------------
#ifndef RL_SLOTS
#define RL_SLOTS (1u << 20)  // 1,048,576 slots * 8 bytes = 8 MiB, fixed; must be 2^k
#endif

struct rl_slot {
  uint32_t key;   // folded 32-bit IP key (key==0 && last==0 => never used)
  uint32_t last;  // unix time (seconds) of the last accepted post from this key
};
static struct rl_slot g_rl[RL_SLOTS];  // zero-initialized; never grows or moves

// splitmix64 finalizer: a strong xorshift-multiply avalanche, the single-word
// analogue of a hash finalizer. Used to spread keys across slots.
static uint64_t mix64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return x;
}

// Reduce a textual client IP to a 32-bit key. IPv4 uses the full address; IPv6
// is keyed by its /64 prefix (one actor typically owns a whole /64 and can
// rotate the low 64 bits at will, so per-address limiting is meaningless) folded
// to 32 bits. An unparseable address maps to key 0.
static uint32_t ip_key(const char *ip) {
  struct mg_addr a;
  memset(&a, 0, sizeof(a));
  if (!mg_aton(mg_str(ip), &a)) return 0;
  if (a.is_ip6) {
    // IPv4-mapped IPv6 (::ffff:a.b.c.d), e.g. an IPv4 client on our dual-stack
    // socket: key by the embedded IPv4 so v4 clients aren't all collapsed into
    // the single all-zero /64 prefix.
    static const uint8_t v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(a.addr.ip, v4mapped, 12) == 0) {
      uint32_t v4;
      memcpy(&v4, a.addr.ip + 12, 4);
      return v4;
    }
    uint64_t m = mix64(a.addr.ip6[0]);  // top 64 bits = the /64 prefix
    return (uint32_t) (m ^ (m >> 32));
  }
  return a.addr.ip4;  // 32-bit IPv4 address (network byte order)
}

// Returns 0 if a post from `key` is allowed now (recording the time); otherwise
// returns the number of seconds the caller must still wait.
static int rate_limit_check(uint32_t key, time_t now) {
  struct rl_slot *s = &g_rl[mix64(key) & (RL_SLOTS - 1)];
  // Only enforce the window on a true key match within RATE_WINDOW; unsigned
  // subtraction makes a fresh slot (last==0) always read as long-expired.
  if (s->key == key && (uint32_t) now - s->last < (uint32_t) RATE_WINDOW) {
    int wait = (int) ((uint32_t) RATE_WINDOW - ((uint32_t) now - s->last));
    return wait > 0 ? wait : 1;
  }
  // New key, expired window, or a colliding key: claim the slot (replacing any
  // incumbent) and allow. Replacement only ever costs another IP its timer.
  s->key = key;
  s->last = (uint32_t) now;
  return 0;
}

// ---------------------------------------------------------------------------
// Upload log: one line per upload recording IP, original filename, and MD5.
// ---------------------------------------------------------------------------
// Sanitize an untrusted string for safe one-line, one-field logging: keep
// printable ASCII except the tab delimiter; replace anything else (control
// chars, tabs, ANSI escapes, high bytes) with '_'. This prevents log-injection
// and terminal-escape attacks via the upload filename or a spoofed IP.
static void log_sanitize(char *dst, size_t cap, const char *src) {
  if (cap == 0) return;
  size_t j = 0;
  for (const char *p = src; *p && j + 1 < cap; p++) {
    unsigned char ch = (unsigned char) *p;
    dst[j++] = (ch >= 0x20 && ch < 0x7f && ch != '\t') ? (char) ch : '_';
  }
  dst[j] = '\0';
}

static void log_upload(const char *ip, const char *orig, struct mg_str file,
                       const char *stored) {
  char hex[33];
  md5_hex(file.buf, file.len, hex);
  FILE *f = fopen(UPLOAD_LOG, "a");
  if (f == NULL) return;
  char ts[32];
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
  // ip and filename are attacker-influenced; sanitize before writing.
  char sip[48], sname[256];
  log_sanitize(sip, sizeof(sip), ip);
  log_sanitize(sname, sizeof(sname), (orig && orig[0]) ? orig : "-");
  // Tab-separated: time, ip, md5, size, original filename, stored path.
  fprintf(f, "%s\t%s\t%s\t%zu\t%s\t%s\n", ts, sip, hex, file.len, sname, stored);
  fclose(f);
}

// ---------------------------------------------------------------------------
// Upload disk quota ("OOM killer"): when the upload directory exceeds
// MAX_DISK_BYTES, randomly purge whole threads until back under the limit.
// ---------------------------------------------------------------------------
static long long uploads_total_bytes(void) {
  DIR *d = opendir(UPLOAD_DIR);
  if (d == NULL) return 0;
  long long total = 0;
  struct dirent *e;
  char path[512];
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;  // skip ".", "..", ".gitkeep"
    snprintf(path, sizeof(path), "%s/%s", UPLOAD_DIR, e->d_name);
    struct stat stx;
    if (stat(path, &stx) == 0 && S_ISREG(stx.st_mode)) total += stx.st_size;
  }
  closedir(d);
  return total;
}

static void enforce_disk_quota(void) {
  while (uploads_total_bytes() > MAX_DISK_BYTES) {
    // Pick a random thread to sacrifice.
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_db,
            "SELECT id FROM posts WHERE thread_id IS NULL ORDER BY RANDOM() LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
      return;
    sqlite3_int64 tid = 0;
    if (sqlite3_step(st) == SQLITE_ROW) tid = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (tid == 0) return;  // no threads left to purge; avoid spinning

    delete_thread_files(tid);
    sqlite3_prepare_v2(g_db, "DELETE FROM posts WHERE id=? OR thread_id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, tid);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
    printf("disk quota exceeded: purged random thread %lld\n", (long long) tid);
  }
}

// Keep at most THREAD_LIMIT threads on the board. When a new thread pushes the
// count over the limit, prune the least-recently-bumped threads (and their
// uploads). This bounds the catalog/index page so its rendered size -- and the
// scratch arena it builds in -- stays finite regardless of how many threads are
// created. Call after inserting a new OP.
static void enforce_thread_limit(void) {
  for (;;) {
    sqlite3_stmt *st;
    int count = 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COUNT(*) FROM posts WHERE thread_id IS NULL", -1, &st,
            NULL) == SQLITE_OK) {
      if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    if (count <= THREAD_LIMIT) break;

    sqlite3_int64 tid = 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT id FROM posts WHERE thread_id IS NULL "
            "ORDER BY bumped_at ASC LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
      if (sqlite3_step(st) == SQLITE_ROW) tid = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    if (tid == 0) break;  // nothing to prune (shouldn't happen); avoid spinning

    delete_thread_files(tid);
    sqlite3_prepare_v2(g_db, "DELETE FROM posts WHERE id=? OR thread_id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, tid);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
    printf("thread limit exceeded: pruned oldest thread %lld\n", (long long) tid);
  }
}

// ---------------------------------------------------------------------------
// Handlers.
// ---------------------------------------------------------------------------
static void handle_index(struct mg_connection *c) {
  struct sbuf s = {0};
  page_head(&s, BOARD_TITLE);
  render_form(&s, 0);
  sb_puts(&s, "<hr><div class=\"catalog\" id=\"catalog\">");
  render_catalog(&s);
  sb_puts(&s, "</div>");
  page_foot(&s);
  mg_http_reply(c, 200, HTML_HDRS, "%s", s.buf ? s.buf : "");
  sb_free(&s);
}

static void handle_thread(struct mg_connection *c, long id) {
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(g_db,
          "SELECT subject,(bumplimit_at IS NOT NULL) FROM posts "
          "WHERE id=? AND thread_id IS NULL", -1, &st, NULL) != SQLITE_OK) {
    mg_http_reply(c, 500, "", "db error\n");
    return;
  }
  sqlite3_bind_int64(st, 1, id);
  if (sqlite3_step(st) != SQLITE_ROW) {
    sqlite3_finalize(st);
    mg_http_reply(c, 404, HTML_HDRS,
                  "<h1>404</h1><p>No such thread. <a href=\"/\">Back</a></p>");
    return;
  }
  const char *subj = (const char *) sqlite3_column_text(st, 0);
  char title[160];
  snprintf(title, sizeof(title), "%s - %s", (subj && subj[0]) ? subj : "Thread",
           BOARD_TITLE);
  int at_limit = sqlite3_column_int(st, 1);

  struct sbuf s = {0};
  page_head(&s, title);
  sb_puts(&s, "<div class=\"nav\">[<a href=\"/\">Return</a>]</div><hr>");
  if (at_limit) {
    sb_puts(&s, "<div class=\"bumpnotice\">Bump limit reached &mdash; this thread "
                "no longer bumps and will be pruned soon.</div>");
  }
  sqlite3_finalize(st);

  sb_printf(&s, "<div class=\"thread%s\" id=\"thread-%ld\">",
            at_limit ? " bumplimit" : "", id);
  render_thread_contents(&s, id);
  sb_puts(&s, "</div><hr>");

  render_form(&s, id);
  page_foot(&s);
  mg_http_reply(c, 200, HTML_HDRS, "%s", s.buf ? s.buf : "");
  sb_free(&s);
}

static void handle_new_thread(struct mg_connection *c, struct mg_http_message *hm) {
  struct post_input in;
  parse_multipart(hm, &in);
  char *tname = trim(in.name), *tsubj = trim(in.subject), *tcom = trim(in.comment);

  if (tcom[0] == '\0') {
    mg_http_reply(c, 400, TEXT_HDRS, "Comment required.");
    return;
  }
  
  sqlite3_int64 now = (sqlite3_int64) time(NULL);
  char ip[48];
  client_ip(c, hm, ip, sizeof(ip));
  int wait = rate_limit_check(ip_key(ip), (time_t) now);
  if (wait > 0) {
    mg_http_reply(c, 429, TEXT_HDRS,
                  "You're posting too fast. Wait %d second%s.", wait,
                  wait == 1 ? "" : "s");
    return;
  }

  sqlite3_stmt *st;
  sqlite3_prepare_v2(g_db,
      "INSERT INTO posts(thread_id,name,subject,comment,created_at,bumped_at) "
      "VALUES(NULL,?,?,?,?,?)", -1, &st, NULL);
  sqlite3_bind_text(st, 1, tname, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, tsubj, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, tcom, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, now);
  sqlite3_bind_int64(st, 5, now);
  sqlite3_step(st);
  sqlite3_int64 id = sqlite3_last_insert_rowid(g_db);
  sqlite3_finalize(st);

  char stored[128] = {0};
  if (in.has_file && upload_validate(in.file, id, stored, sizeof(stored)) == 1) {
    // Write the DB reference FIRST, then the file. A crash between the two can
    // only leave a dangling reference (a broken thumbnail that is cleaned up on
    // prune) -- never an orphan file with no owning row.
    sqlite3_prepare_v2(g_db, "UPDATE posts SET image=? WHERE id=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, stored, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, id);
    sqlite3_step(st);
    sqlite3_finalize(st);
    upload_write(in.file, stored);
    log_upload(ip, in.filename, in.file, stored);
    enforce_disk_quota();
  }

  // Bound the board: prune the oldest threads if this OP pushed us over the limit.
  enforce_thread_limit();

  // Return just the new catalog cell; htmx prepends it to #catalog.
  struct sbuf s = {0};
  render_catalog_cell(&s, id, tsubj, tcom, stored[0] ? stored : NULL, 0);
  mg_http_reply(c, 200, HTML_HDRS, "%s", s.buf ? s.buf : "");
  sb_free(&s);
}

static void handle_reply(struct mg_connection *c, struct mg_http_message *hm,
                         long tid) {
  // Ensure thread exists.
  sqlite3_stmt *st;
  sqlite3_prepare_v2(g_db,
      "SELECT 1 FROM posts WHERE id=? AND thread_id IS NULL", -1, &st, NULL);
  sqlite3_bind_int64(st, 1, tid);
  int exists = (sqlite3_step(st) == SQLITE_ROW);
  sqlite3_finalize(st);
  if (!exists) {
    mg_http_reply(c, 404, HTML_HDRS,
                  "<div class=\"empty\">Thread not found.</div>");
    return;
  }

  // Enforce the bump limit as a hard cap: once a thread holds BUMP_LIMIT posts
  // (OP + replies) it is full and accepts no further replies. Record the moment
  // the limit was reached (if not already) so pruning still kicks in, then reject.
  int existing = reply_count(tid) + 1;  // +1 for the OP
  if (existing >= BUMP_LIMIT) {
    sqlite3_prepare_v2(g_db,
        "UPDATE posts SET bumplimit_at=? WHERE id=? AND bumplimit_at IS NULL",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, (sqlite3_int64) time(NULL));
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
    mg_http_reply(c, 403, TEXT_HDRS,
                  "Thread is full (bump limit of %d reached). No more replies.",
                  BUMP_LIMIT);
    return;
  }

  struct post_input in;
  parse_multipart(hm, &in);
  char *tname = trim(in.name), *tcom = trim(in.comment);
  if (tcom[0] == '\0') {
    mg_http_reply(c, 400, TEXT_HDRS, "Comment required.");
    return;
  }

  sqlite3_int64 now = (sqlite3_int64) time(NULL);
  char ip[48];
  client_ip(c, hm, ip, sizeof(ip));
  int wait = rate_limit_check(ip_key(ip), (time_t) now);
  if (wait > 0) {
    mg_http_reply(c, 429, TEXT_HDRS,
                  "You're posting too fast. Wait %d second%s.", wait,
                  wait == 1 ? "" : "s");
    return;
  }

  sqlite3_prepare_v2(g_db,
      "INSERT INTO posts(thread_id,name,subject,comment,created_at,bumped_at) "
      "VALUES(?,?,NULL,?,?,NULL)", -1, &st, NULL);
  sqlite3_bind_int64(st, 1, tid);
  sqlite3_bind_text(st, 2, tname, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, tcom, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, now);
  sqlite3_step(st);
  sqlite3_int64 id = sqlite3_last_insert_rowid(g_db);
  sqlite3_finalize(st);

  char stored[128] = {0};
  if (in.has_file && upload_validate(in.file, id, stored, sizeof(stored)) == 1) {
    // Write the DB reference FIRST, then the file. A crash between the two can
    // only leave a dangling reference (a broken thumbnail that is cleaned up on
    // prune) -- never an orphan file with no owning row.
    sqlite3_prepare_v2(g_db, "UPDATE posts SET image=? WHERE id=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, stored, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, id);
    sqlite3_step(st);
    sqlite3_finalize(st);
    upload_write(in.file, stored);
    log_upload(ip, in.filename, in.file, stored);
    enforce_disk_quota();
  }

  // Bump the thread, unless this reply is the one that reaches the bump limit
  // (the gate above already rejected anything past it).
  int total = existing + 1;  // posts now in the thread, including this reply + OP
  if (total < BUMP_LIMIT) {
    sqlite3_prepare_v2(g_db, "UPDATE posts SET bumped_at=? WHERE id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
  } else {
    // Stop bumping and record when the limit was hit (only the first time).
    sqlite3_prepare_v2(g_db,
        "UPDATE posts SET bumplimit_at=? WHERE id=? AND bumplimit_at IS NULL",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
  }

  // Re-render the whole thread so backlinks on quoted posts stay accurate;
  // htmx swaps this into #thread-<tid>.
  struct sbuf s = {0};
  render_thread_contents(&s, tid);
  mg_http_reply(c, 200, HTML_HDRS, "%s", s.buf ? s.buf : "");
  sb_free(&s);
}

// ---------------------------------------------------------------------------
// Admin moderation: delete a thread or an uploaded file.
// ---------------------------------------------------------------------------
// A request carrying the ?del query string is an out-of-band moderation action.
// (Yes, mutating on GET breaks REST -- intentional: it lets a moderator delete
// straight from the address bar, gated only by the browser's native Basic Auth
// box.) Auth is HTTP Basic: user "admin", password from $CHAN_ADMIN_PASS.
//
//   /thread/N?del      delete the whole thread (OP + replies + uploads)
//   /thread/N?del=P    blank out just post P's text (it stays as a tombstone)
//   /uploads/F?del     delete just the uploaded file F
//
// Note a fragment like /thread/N#pP is client-only and never reaches the server,
// so the post is selected via the del=P query value, not the #pP anchor.

// Look for a "del" token in the query string. Returns 1 if present. A bare ?del
// leaves *val empty (delete the whole thread / the file); ?del=P copies P into
// val (delete just post P's text). val must hold at least 1 byte.
static int wants_delete(struct mg_str q, char *val, size_t vlen) {
  struct mg_str tok;
  val[0] = '\0';
  while (mg_span(q, &tok, &q, '&')) {
    struct mg_str k, v;
    mg_span(tok, &k, &v, '=');  // k = before '=', v = after (len 0 if no '=')
    if (mg_strcmp(k, mg_str("del")) == 0) {
      if (v.len > 0) mg_snprintf(val, vlen, "%.*s", (int) v.len, v.buf);
      return 1;
    }
  }
  return 0;
}

// Verify HTTP Basic credentials against the configured admin password.
static int admin_authed(struct mg_http_message *hm) {
  char user[64], pass[128];
  mg_http_creds(hm, user, sizeof(user), pass, sizeof(pass));
  return strcmp(user, "admin") == 0 && strcmp(pass, g_admin_pass) == 0;
}

// Delete a whole thread (OP + replies) and all its uploaded files.
static void admin_delete_thread(sqlite3_int64 tid) {
  delete_thread_files(tid);
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(g_db, "DELETE FROM posts WHERE id=? OR thread_id=?",
                         -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, tid);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
  }
  printf("admin deleted thread %lld\n", (long long) tid);
}

// Moderate a single post: delete its uploaded image (if any) and replace its
// text with "removed by admin", leaving the row in place as a tombstone. Scoped
// to the given thread: pid must be that thread's OP (id == tid) or a reply in it
// (thread_id == tid), so a /thread/T URL can only moderate posts that actually
// belong to thread T.
static void admin_delete_post(sqlite3_int64 tid, sqlite3_int64 pid) {
  sqlite3_stmt *st;
  // Unlink the image file first (the row's image path is the source of truth).
  if (sqlite3_prepare_v2(g_db,
          "SELECT image FROM posts WHERE id=? AND (id=? OR thread_id=?) "
          "AND image IS NOT NULL",
          -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, pid);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_bind_int64(st, 3, tid);
    if (sqlite3_step(st) == SQLITE_ROW) {
      const char *img = (const char *) sqlite3_column_text(st, 0);
      if (img && img[0]) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", WEB_ROOT, img);
        remove(path);
      }
    }
    sqlite3_finalize(st);
  }
  // Then blank the text and drop the image reference. (comment is NOT NULL in
  // the schema, so it carries the tombstone marker rather than being NULLed.)
  if (sqlite3_prepare_v2(g_db,
          "UPDATE posts SET comment='removed by admin', name=NULL, "
          "subject=NULL, image=NULL WHERE id=? AND (id=? OR thread_id=?)",
          -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, pid);
    sqlite3_bind_int64(st, 2, tid);
    sqlite3_bind_int64(st, 3, tid);
    sqlite3_step(st);
    sqlite3_finalize(st);
  }
  printf("admin removed post %lld in thread %lld\n", (long long) pid,
         (long long) tid);
}

// Delete one uploaded file (by its stored "uploads/<id>.<ext>" path) from disk
// and clear the DB reference so its thumbnail no longer dangles. Returns the
// thread the file belonged to (for a redirect back), or 0 if not found.
static sqlite3_int64 admin_delete_upload(const char *image) {
  sqlite3_int64 tid = 0;
  sqlite3_stmt *st;
  // An OP has thread_id NULL, so COALESCE down to its own id.
  if (sqlite3_prepare_v2(g_db,
          "SELECT COALESCE(thread_id, id) FROM posts WHERE image=?", -1, &st,
          NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, image, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) tid = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
  }
  char path[256];
  snprintf(path, sizeof(path), "%s/%s", WEB_ROOT, image);
  remove(path);
  if (sqlite3_prepare_v2(g_db, "UPDATE posts SET image=NULL WHERE image=?", -1,
                         &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, image, -1, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
  }
  printf("admin deleted upload %s\n", image);
  return tid;
}

// Handle a ?del request. Returns 1 if it consumed the request (challenge sent,
// deleted, or rejected), 0 if it is not an admin action and routing should run.
static int handle_admin_delete(struct mg_connection *c,
                               struct mg_http_message *hm) {
  char del_val[32];
  if (g_admin_pass[0] == '\0' || !wants_delete(hm->query, del_val, sizeof(del_val)))
    return 0;
  if (!admin_authed(hm)) {
    mg_http_reply(c, 401,
                  "WWW-Authenticate: Basic realm=\"chan admin\"\r\n" TEXT_HDRS,
                  "Authentication required.\n");
    return 1;
  }
  struct mg_str caps[1];
  if (mg_match(hm->uri, mg_str("/thread/*"), caps)) {
    sqlite3_int64 tid = strtoll(caps[0].buf, NULL, 10);
    if (del_val[0]) {
      // ?del=P -- moderate just post P, then return to the thread anchored at it.
      sqlite3_int64 pid = strtoll(del_val, NULL, 10);
      admin_delete_post(tid, pid);
      char loc[64];
      mg_snprintf(loc, sizeof(loc), "Location: /thread/%lld#p%lld\r\n",
                  (long long) tid, (long long) pid);
      mg_http_reply(c, 302, loc, "");
    } else {
      // bare ?del -- delete the whole thread; back to the catalog.
      admin_delete_thread(tid);
      mg_http_reply(c, 302, "Location: /\r\n", "");
    }
  } else if (mg_match(hm->uri, mg_str("/uploads/*"), caps)) {
    // "*" never spans '/', so the capture is a single flat filename; rebuild the
    // stored "uploads/<file>" path from it (uploads/ is a flat directory).
    char image[128];
    mg_snprintf(image, sizeof(image), "uploads/%.*s", (int) caps[0].len,
                caps[0].buf);
    sqlite3_int64 tid = admin_delete_upload(image);
    char loc[64];
    if (tid > 0)
      mg_snprintf(loc, sizeof(loc), "Location: /thread/%lld\r\n", (long long) tid);
    else
      mg_snprintf(loc, sizeof(loc), "Location: /\r\n");
    mg_http_reply(c, 302, loc, "");  // back to the thread (or catalog)
  } else {
    mg_http_reply(c, 404, TEXT_HDRS, "Not found.\n");
  }
  return 1;
}

// ---------------------------------------------------------------------------
// Routing.
// ---------------------------------------------------------------------------
static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (c->is_closing) return;
  if (ev == MG_EV_HTTP_HDRS) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (hm->body.len > MAX_REQUEST_BYTES) {
      c->is_closing = 1; // close right away, don't even wait to respond
    }
    return;
  }
  if (ev != MG_EV_HTTP_MSG) return;
  struct mg_http_message *hm = (struct mg_http_message *) ev_data;
  struct mg_str caps[2];

  int is_post = (mg_strcmp(hm->method, mg_str("POST")) == 0);

  // Out-of-band admin delete (?del): handled before normal routing and without
  // a scratch frame; it sends its own response (a 401 challenge or 302 redirect).
  if (handle_admin_delete(c, hm)) return;

  // Open a scratch frame for the whole request; every render allocation bump-
  // allocates from the arena and is freed in one shot when we restore below.
  // (Mongoose's event loop is single-threaded, so frames never overlap.)
  size_t scratch_frame = scratch_save();

  if (mg_match(hm->uri, mg_str("/"), NULL) && !is_post) {
    handle_index(c);
  } else if (mg_match(hm->uri, mg_str("/thread/*"), caps) && !is_post) {
    handle_thread(c, strtol(caps[0].buf, NULL, 10));
  } else if (mg_match(hm->uri, mg_str("/post"), NULL) && is_post) {
    handle_new_thread(c, hm);
  } else if (mg_match(hm->uri, mg_str("/reply/*"), caps) && is_post) {
    handle_reply(c, hm, strtol(caps[0].buf, NULL, 10));
  } else if (mg_match(hm->uri, mg_str("/uploads/#"), NULL) && !is_post) {
    // User-uploaded files: serve with nosniff and a restrictive sandbox CSP so
    // that even a polyglot (a valid GIF that is also HTML/JS) cannot run script
    // if opened directly, and is never MIME-sniffed into HTML.
    // Uploads are immutable: the stored path is "uploads/<rowid>.<ext>" and the
    // schema uses AUTOINCREMENT, so a path is never reused with different bytes.
    // Tell the browser it can serve repeat views straight from cache without
    // revalidating (no conditional round-trip) for a year. Mongoose also sends an
    // Etag, so after expiry (or a cache eviction) it still gets a cheap 304.
    struct mg_http_serve_opts opts = {
        .root_dir = WEB_ROOT,
        .mime_types = "webm=video/webm",
        .extra_headers = "X-Content-Type-Options: nosniff\r\n"
                         "Cache-Control: public, max-age=31536000, immutable\r\n"
                         "Content-Security-Policy: sandbox; default-src 'none'\r\n"};
    mg_http_serve_dir(c, hm, &opts);
  } else {
    // Other static assets (style.css, htmx.min.js) from WEB_ROOT.
    // webm is not in mongoose's built-in MIME table, so add it explicitly.
    // These can change (e.g. style.css edits), so cache for an hour rather than
    // marking immutable; the Etag still yields a cheap 304 once max-age expires.
    struct mg_http_serve_opts opts = {
        .root_dir = WEB_ROOT,
        .mime_types = "webm=video/webm",
        .extra_headers = "X-Content-Type-Options: nosniff\r\n"
                         "Cache-Control: public, max-age=3600\r\n"};
    mg_http_serve_dir(c, hm, &opts);
  }

  if (g_scratch_oom) {
    // The page exceeded the scratch arena and was truncated. With the static
    // field/bump/thread limits this should be unreachable; if it fires, raise
    // SCRATCH_BYTES. Logged (not fatal) -- the server stays up and bounded.
    printf("warning: scratch arena exhausted serving %.*s (response truncated)\n",
           (int) hm->uri.len, hm->uri.buf);
  }
  scratch_restore(scratch_frame);  // free this request's entire arena frame
}

// ---------------------------------------------------------------------------
// Pruning: delete bump-limited threads (and their uploads) after DELETE_AFTER.
// ---------------------------------------------------------------------------
// Remove the upload files belonging to a thread (OP + all replies).
static void delete_thread_files(sqlite3_int64 tid) {
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(g_db,
          "SELECT image FROM posts WHERE (id=? OR thread_id=?) AND image IS NOT NULL",
          -1, &st, NULL) != SQLITE_OK)
    return;
  sqlite3_bind_int64(st, 1, tid);
  sqlite3_bind_int64(st, 2, tid);
  while (sqlite3_step(st) == SQLITE_ROW) {
    const char *img = (const char *) sqlite3_column_text(st, 0);
    if (img && img[0]) {
      char path[256];
      snprintf(path, sizeof(path), "%s/%s", WEB_ROOT, img);
      remove(path);
    }
  }
  sqlite3_finalize(st);
}

// Delete threads that hit the bump limit more than DELETE_AFTER seconds ago,
// along with all their posts and uploaded files.
static void cleanup_expired(void) {
  sqlite3_int64 cutoff = (sqlite3_int64) time(NULL) - DELETE_AFTER;
  sqlite3_int64 tids[256];
  int n = 0;
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(g_db,
          "SELECT id FROM posts WHERE thread_id IS NULL "
          "AND bumplimit_at IS NOT NULL AND bumplimit_at<=?", -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, cutoff);
    while (sqlite3_step(st) == SQLITE_ROW && n < 256)
      tids[n++] = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
  }
  for (int i = 0; i < n; i++) {
    delete_thread_files(tids[i]);
    sqlite3_prepare_v2(g_db, "DELETE FROM posts WHERE id=? OR thread_id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, tids[i]);
    sqlite3_bind_int64(st, 2, tids[i]);
    sqlite3_step(st);
    sqlite3_finalize(st);
    printf("pruned thread %lld (bump limit + %dh)\n", (long long) tids[i],
           DELETE_AFTER / 3600);
  }
}

// ---------------------------------------------------------------------------
// Database init.
// ---------------------------------------------------------------------------
static int db_init(void) {
  if (sqlite3_open(DB_PATH, &g_db) != SQLITE_OK) {
    fprintf(stderr, "cannot open db: %s\n", sqlite3_errmsg(g_db));
    return -1;
  }
  const char *schema =
      "PRAGMA journal_mode=WAL;"
      "CREATE TABLE IF NOT EXISTS posts ("
      " id INTEGER PRIMARY KEY AUTOINCREMENT,"
      " thread_id INTEGER,"          // NULL => this post is an OP (thread)
      " name TEXT,"
      " subject TEXT,"
      " comment TEXT NOT NULL,"
      " created_at INTEGER NOT NULL,"
      " bumped_at INTEGER,"          // set on OPs only
      " image TEXT,"                 // stored upload path, e.g. "uploads/12.png"
      " bumplimit_at INTEGER,"       // OPs only: time the bump limit was hit, else NULL
      " FOREIGN KEY(thread_id) REFERENCES posts(id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_thread ON posts(thread_id);"
      "CREATE INDEX IF NOT EXISTS idx_bumped ON posts(bumped_at DESC);";
  char *err = NULL;
  if (sqlite3_exec(g_db, schema, NULL, NULL, &err) != SQLITE_OK) {
    fprintf(stderr, "schema error: %s\n", err);
    sqlite3_free(err);
    return -1;
  }
  // Migrate older DBs (ignore "duplicate column" errors on already-current DBs).
  sqlite3_exec(g_db, "ALTER TABLE posts ADD COLUMN image TEXT", NULL, NULL, NULL);
  sqlite3_exec(g_db, "ALTER TABLE posts ADD COLUMN bumplimit_at INTEGER", NULL, NULL, NULL);
  return 0;
}

int main(int argc, char **argv) {
  const char *url = (argc > 1) ? argv[1] : "http://0.0.0.0:8000";

  setvbuf(stdout, NULL, _IOLBF, 0);  // line-buffer logs so they appear promptly
  const char *tp = getenv("CHAN_TRUSTED_PROXY");
  if (tp != NULL) snprintf(g_trusted_proxy, sizeof(g_trusted_proxy), "%s", tp);
  const char *ap = getenv("CHAN_ADMIN_PASS");
  if (ap != NULL) snprintf(g_admin_pass, sizeof(g_admin_pass), "%s", ap);
  mkdir(UPLOAD_DIR, 0755);  // ensure upload directory exists (ok if present)

  // One-time scratch arena for the per-request render path (freed per request via
  // scratch_save/restore, not torn down until exit).
  g_scratch_cap = SCRATCH_BYTES;
  g_scratch = (char *) malloc(g_scratch_cap);
  if (g_scratch == NULL) {
    fprintf(stderr, "cannot allocate %zu-byte scratch arena\n", g_scratch_cap);
    return 1;
  }

  if (db_init() != 0) return 1;

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  if (mg_http_listen(&mgr, url, ev_handler, NULL) == NULL) {
    fprintf(stderr, "cannot listen on %s\n", url);
    return 1;
  }
  printf("chan listening on %s  (db: %s, trusted_proxy: %s, admin: %s)\n", url,
         DB_PATH, g_trusted_proxy[0] ? g_trusted_proxy : "(none)",
         g_admin_pass[0] ? "enabled" : "disabled");
  time_t last_cleanup = 0;
  for (;;) {
    mg_mgr_poll(&mgr, 200);
    time_t now = time(NULL);
    if (now - last_cleanup >= 60) {  // prune expired threads once a minute
      last_cleanup = now;
      cleanup_expired();
    }
  }
  mg_mgr_free(&mgr);
  sqlite3_close(g_db);
  return 0;
}

