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

#define BOARD_TITLE "/c/ - C Board"
#define BOARD_SUB "a tiny imageboard written in C"
#define WEB_ROOT "web"
#define UPLOAD_DIR WEB_ROOT "/uploads"
#define DB_PATH "chan.db"
#define MAX_NAME 64
#define MAX_SUBJECT 128
#define MAX_COMMENT 8000
#define MAX_UPLOAD (8 * 1024 * 1024)  // 8 MiB
#ifndef BUMP_LIMIT
#define BUMP_LIMIT 300                // posts (OP + replies) before a thread stops bumping
#endif
#ifndef DELETE_AFTER
#define DELETE_AFTER (8 * 3600)       // seconds after hitting the bump limit before deletion
#endif
#ifndef RATE_WINDOW
#define RATE_WINDOW 30                // min seconds between posts from one IP
#endif
#ifndef MAX_DISK_BYTES
#define MAX_DISK_BYTES (8LL * 1024 * 1024 * 1024)  // upload dir quota: 8 GiB
#endif
#define UPLOAD_LOG "uploads.log"

static sqlite3 *g_db;

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
  s->buf = (char *) realloc(s->buf, cap);
  s->cap = cap;
}

static void sb_append(struct sbuf *s, const char *data, size_t n) {
  sb_grow(s, n);
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
  va_start(ap, fmt);
  vsnprintf(s->buf + s->len, (size_t) n + 1, fmt, ap);
  va_end(ap);
  s->len += (size_t) n;
}

static void sb_free(struct sbuf *s) {
  free(s->buf);
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
      "var n=document.getElementById('notice');"
      "if(n&&e.detail.successful)n.textContent='';});</script>");
  sb_puts(s, "</head><body>");
  sb_puts(s, "<div class=\"banner\"><h1>" BOARD_TITLE "</h1>");
  sb_puts(s, "<div class=\"sub\">" BOARD_SUB "</div></div><hr>");
}

static void page_foot(struct sbuf *s) {
  sb_puts(s, "<hr><div class=\"nav\">chan &mdash; mongoose + sqlite + htmx</div>");
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
               "hx-target=\"#catalog\" hx-swap=\"afterbegin\" "
               "hx-on::after-request=\"if(event.detail.successful)this.reset()\">");
  } else {
    // Swap the whole thread so reply backlinks on quoted posts update too.
    sb_printf(s,
              "<form id=\"postform\" class=\"postform\" "
              "enctype=\"multipart/form-data\" hx-post=\"/reply/%ld\" "
              "hx-target=\"#thread-%ld\" hx-swap=\"innerHTML\" "
              "hx-on::after-request=\"if(event.detail.successful)this.reset()\">",
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

// True if `comment` contains a quote link (>>N) referencing post `target`.
static int comment_refs(const char *comment, sqlite3_int64 target) {
  if (comment == NULL) return 0;
  for (const char *p = comment; (p = strstr(p, ">>")) != NULL;) {
    p += 2;
    if (*p < '0' || *p > '9') continue;
    char *end;
    long v = strtol(p, &end, 10);
    if (v == (long) target) return 1;
    p = end;
  }
  return 0;
}

// One post loaded into memory so we can compute reply backlinks across a thread.
struct tpost {
  sqlite3_int64 id;
  char *name, *subject, *comment, *image;
  sqlite3_int64 created;
  int is_op;
};

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

  struct tpost *posts = NULL;
  int n = 0, cap = 0;
  while (sqlite3_step(st) == SQLITE_ROW) {
    if (n == cap) {
      cap = cap ? cap * 2 : 16;
      posts = (struct tpost *) realloc(posts, (size_t) cap * sizeof(*posts));
    }
    struct tpost *p = &posts[n++];
    const char *nm = (const char *) sqlite3_column_text(st, 1);
    const char *sj = (const char *) sqlite3_column_text(st, 2);
    const char *cm = (const char *) sqlite3_column_text(st, 3);
    const char *im = (const char *) sqlite3_column_text(st, 5);
    p->id = sqlite3_column_int64(st, 0);
    p->name = nm ? strdup(nm) : NULL;
    p->subject = sj ? strdup(sj) : NULL;
    p->comment = cm ? strdup(cm) : strdup("");
    p->created = sqlite3_column_int64(st, 4);
    p->image = im ? strdup(im) : NULL;
    p->is_op = sqlite3_column_int(st, 6);
  }
  sqlite3_finalize(st);

  // posts[0] is the OP (lowest id). Render OP, open .replies, then the replies.
  for (int i = 0; i < n; i++) {
    struct sbuf bl = {0};
    for (int j = 0; j < n; j++) {
      if (j != i && comment_refs(posts[j].comment, posts[i].id)) {
        sb_printf(&bl,
                  "<a class=\"quotelink backlink\" href=\"#p%lld\" "
                  "onclick=\"return quote(%lld)\">&gt;&gt;%lld</a> ",
                  (long long) posts[j].id, (long long) posts[j].id,
                  (long long) posts[j].id);
      }
    }
    render_post(s, posts[i].is_op, posts[i].id, posts[i].name, posts[i].subject,
                posts[i].comment, posts[i].created, (long) tid, posts[i].image,
                bl.buf);
    sb_free(&bl);
    if (i == 0) sb_puts(s, "<div class=\"replies\">");
  }
  if (n > 0) sb_puts(s, "</div>");  // close .replies

  for (int i = 0; i < n; i++) {
    free(posts[i].name);
    free(posts[i].subject);
    free(posts[i].comment);
    free(posts[i].image);
  }
  free(posts);
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

// Validate and persist an upload for post `id`. On success writes the stored
// relative path (e.g. "uploads/12.png") into `stored` and returns 1.
// Returns 0 if there is no file; -1 if the file is rejected (too big / bad type).
static int save_upload(struct mg_str file, sqlite3_int64 id, char *stored,
                       size_t storedn) {
  if (file.len == 0) return 0;
  if (file.len > MAX_UPLOAD) return -1;
  const char *ext = sniff_ext(file);
  if (ext == NULL) return -1;

  char path[256];
  snprintf(path, sizeof(path), "%s/%lld.%s", UPLOAD_DIR, (long long) id, ext);
  FILE *f = fopen(path, "wb");
  if (f == NULL) return -1;
  size_t wrote = fwrite(file.buf, 1, file.len, f);
  fclose(f);
  if (wrote != file.len) {
    remove(path);
    return -1;
  }
  snprintf(stored, storedn, "uploads/%lld.%s", (long long) id, ext);
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
// Set from $CHAN_TRUST_PROXY at startup. When enabled we trust the
// X-Forwarded-For header (for deployments behind a reverse proxy); otherwise we
// use the TCP peer address, which cannot be trivially spoofed.
static int g_trust_proxy;

static void client_ip(struct mg_connection *c, struct mg_http_message *hm,
                      char *buf, size_t n) {
  if (g_trust_proxy) {
    struct mg_str *xff = mg_http_get_header(hm, "X-Forwarded-For");
    if (xff != NULL && xff->len > 0) {
      // X-Forwarded-For: client, proxy1, proxy2 ... — the left-most entry is
      // the original client. Take it and trim surrounding whitespace.
      size_t i = 0;
      while (i < xff->len && (xff->buf[i] == ' ' || xff->buf[i] == '\t')) i++;
      size_t e = i;
      while (e < xff->len && xff->buf[e] != ',') e++;
      while (e > i && (xff->buf[e - 1] == ' ' || xff->buf[e - 1] == '\t')) e--;
      size_t len = e - i;
      if (len > 0 && len < n) {
        memcpy(buf, xff->buf + i, len);
        buf[len] = '\0';
        return;
      }
    }
  }
  mg_snprintf(buf, n, "%M", mg_print_ip, &c->rem);
}

// ---------------------------------------------------------------------------
// Rate limiting: at most one post per IP per RATE_WINDOW seconds (in-memory).
//
// Backed by an open-addressed hash table (linear probing) keyed by the IP
// string. Hashing uses FNV-1a (Fowler-Noll-Vo), a well-known non-cryptographic
// string hash with good distribution for short keys. (FNV is not resistant to
// crafted-collision DoS; a keyed hash such as SipHash would be needed for
// attacker-chosen keys, but these keys are peer IPs, not user input.)
// Entries older than RATE_WINDOW count as free and are reclaimed in place.
// ---------------------------------------------------------------------------
struct rl_slot {
  char ip[48];  // empty string => unused slot
  time_t last;
};
static struct rl_slot *g_rl;
static size_t g_rl_cap;   // always a power of two
static size_t g_rl_used;  // occupied slots (live or not-yet-reclaimed)

static uint64_t fnv1a(const char *s) {
  uint64_t h = 1469598103934665603ULL;  // FNV-1a 64-bit offset basis
  for (; *s; s++) {
    h ^= (unsigned char) *s;
    h *= 1099511628211ULL;  // FNV-1a 64-bit prime
  }
  return h;
}

// Grow (or initialize) the table to newcap slots, rehashing only live entries
// (expired ones are dropped, which incidentally cleans the table).
static void rl_resize(size_t newcap, time_t now) {
  struct rl_slot *old = g_rl;
  size_t oldcap = g_rl_cap;
  g_rl = (struct rl_slot *) calloc(newcap, sizeof(*g_rl));
  g_rl_cap = newcap;
  g_rl_used = 0;
  for (size_t i = 0; i < oldcap; i++) {
    if (old[i].ip[0] && (now - old[i].last) < RATE_WINDOW) {
      size_t idx = fnv1a(old[i].ip) & (newcap - 1);
      while (g_rl[idx].ip[0]) idx = (idx + 1) & (newcap - 1);
      g_rl[idx] = old[i];
      g_rl_used++;
    }
  }
  free(old);
}

// Returns 0 if a post from `ip` is allowed now (recording the time); otherwise
// returns the number of seconds the caller must still wait.
static int rate_limit_check(const char *ip, time_t now) {
  if (g_rl == NULL) rl_resize(1024, now);
  size_t mask = g_rl_cap - 1;
  size_t idx = fnv1a(ip) & mask;
  long reuse = -1;  // first expired slot we may reclaim if the key is absent

  for (size_t n = 0; n < g_rl_cap; n++) {
    struct rl_slot *s = &g_rl[idx];
    if (s->ip[0] == '\0') {  // empty slot => key not present, insert it
      size_t t = (reuse >= 0) ? (size_t) reuse : idx;
      if (g_rl[t].ip[0] == '\0') g_rl_used++;  // only a fresh slot grows usage
      snprintf(g_rl[t].ip, sizeof(g_rl[t].ip), "%s", ip);
      g_rl[t].last = now;
      if (g_rl_used * 10 > g_rl_cap * 7) rl_resize(g_rl_cap * 2, now);
      return 0;
    }
    if (strcmp(s->ip, ip) == 0) {  // found the key's canonical slot
      if ((now - s->last) >= RATE_WINDOW) {  // window elapsed => allow
        s->last = now;
        return 0;
      }
      int wait = RATE_WINDOW - (int) (now - s->last);
      return wait > 0 ? wait : 1;
    }
    if (reuse < 0 && (now - s->last) >= RATE_WINDOW) reuse = (long) idx;
    idx = (idx + 1) & mask;
  }
  // Table full of live entries (pathological); reuse an expired slot if any.
  if (reuse >= 0) {
    snprintf(g_rl[reuse].ip, sizeof(g_rl[reuse].ip), "%s", ip);
    g_rl[reuse].last = now;
  }
  return 0;  // fail open
}

// ---------------------------------------------------------------------------
// Upload log: one line per upload recording IP, original filename, and MD5.
// ---------------------------------------------------------------------------
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
  // Tab-separated: time, ip, md5, size, original filename, stored path.
  fprintf(f, "%s\t%s\t%s\t%zu\t%s\t%s\n", ts, ip, hex, file.len,
          (orig && orig[0]) ? orig : "-", stored);
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
  mg_http_reply(c, 200, "Content-Type: text/html; charset=utf-8\r\n", "%s", s.buf);
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
    mg_http_reply(c, 404, "Content-Type: text/html\r\n",
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
  mg_http_reply(c, 200, "Content-Type: text/html; charset=utf-8\r\n", "%s", s.buf);
  sb_free(&s);
}

static void handle_new_thread(struct mg_connection *c, struct mg_http_message *hm) {
  struct post_input in;
  parse_multipart(hm, &in);
  char *tname = trim(in.name), *tsubj = trim(in.subject), *tcom = trim(in.comment);

  if (tcom[0] == '\0') {
    mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Comment required.");
    return;
  }

  sqlite3_int64 now = (sqlite3_int64) time(NULL);
  char ip[48];
  client_ip(c, hm, ip, sizeof(ip));
  int wait = rate_limit_check(ip, (time_t) now);
  if (wait > 0) {
    mg_http_reply(c, 429, "Content-Type: text/plain\r\n",
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
  if (in.has_file && save_upload(in.file, id, stored, sizeof(stored)) == 1) {
    sqlite3_prepare_v2(g_db, "UPDATE posts SET image=? WHERE id=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, stored, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, id);
    sqlite3_step(st);
    sqlite3_finalize(st);
    log_upload(ip, in.filename, in.file, stored);
    enforce_disk_quota();
  }

  // Return just the new catalog cell; htmx prepends it to #catalog.
  struct sbuf s = {0};
  render_catalog_cell(&s, id, tsubj, tcom, stored[0] ? stored : NULL, 0);
  mg_http_reply(c, 200, "Content-Type: text/html; charset=utf-8\r\n", "%s", s.buf);
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
    mg_http_reply(c, 404, "Content-Type: text/html\r\n",
                  "<div class=\"empty\">Thread not found.</div>");
    return;
  }

  struct post_input in;
  parse_multipart(hm, &in);
  char *tname = trim(in.name), *tcom = trim(in.comment);
  if (tcom[0] == '\0') {
    mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Comment required.");
    return;
  }

  sqlite3_int64 now = (sqlite3_int64) time(NULL);
  char ip[48];
  client_ip(c, hm, ip, sizeof(ip));
  int wait = rate_limit_check(ip, (time_t) now);
  if (wait > 0) {
    mg_http_reply(c, 429, "Content-Type: text/plain\r\n",
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
  if (in.has_file && save_upload(in.file, id, stored, sizeof(stored)) == 1) {
    sqlite3_prepare_v2(g_db, "UPDATE posts SET image=? WHERE id=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, stored, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, id);
    sqlite3_step(st);
    sqlite3_finalize(st);
    log_upload(ip, in.filename, in.file, stored);
    enforce_disk_quota();
  }

  // Bump the thread, unless it has reached the bump limit (OP + replies >= limit).
  int total = reply_count(tid) + 1;  // +1 for the OP
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
  mg_http_reply(c, 200, "Content-Type: text/html; charset=utf-8\r\n", "%s", s.buf);
  sb_free(&s);
}

// ---------------------------------------------------------------------------
// Routing.
// ---------------------------------------------------------------------------
static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev != MG_EV_HTTP_MSG) return;
  struct mg_http_message *hm = (struct mg_http_message *) ev_data;
  struct mg_str caps[2];

  int is_post = (mg_strcmp(hm->method, mg_str("POST")) == 0);

  if (mg_match(hm->uri, mg_str("/"), NULL) && !is_post) {
    handle_index(c);
  } else if (mg_match(hm->uri, mg_str("/thread/*"), caps) && !is_post) {
    handle_thread(c, strtol(caps[0].buf, NULL, 10));
  } else if (mg_match(hm->uri, mg_str("/post"), NULL) && is_post) {
    handle_new_thread(c, hm);
  } else if (mg_match(hm->uri, mg_str("/reply/*"), caps) && is_post) {
    handle_reply(c, hm, strtol(caps[0].buf, NULL, 10));
  } else {
    // Static assets (style.css, htmx.min.js, uploads/*) from WEB_ROOT.
    // webm is not in mongoose's built-in MIME table, so add it explicitly.
    struct mg_http_serve_opts opts = {.root_dir = WEB_ROOT,
                                      .mime_types = "webm=video/webm"};
    mg_http_serve_dir(c, hm, &opts);
  }
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
  const char *tp = getenv("CHAN_TRUST_PROXY");
  g_trust_proxy = (tp != NULL && tp[0] && tp[0] != '0');
  mkdir(UPLOAD_DIR, 0755);  // ensure upload directory exists (ok if present)
  if (db_init() != 0) return 1;

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  if (mg_http_listen(&mgr, url, ev_handler, NULL) == NULL) {
    fprintf(stderr, "cannot listen on %s\n", url);
    return 1;
  }
  printf("chan listening on %s  (db: %s, trust_proxy: %s)\n", url, DB_PATH,
         g_trust_proxy ? "on" : "off");
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
