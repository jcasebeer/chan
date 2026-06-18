# chan

A minimal single-board imageboard (4chan-style textboard) written in C.

**Stack**
- [mongoose](https://github.com/cesanta/mongoose) — embedded HTTP server (vendored)
- [SQLite](https://sqlite.org) — storage, amalgamation build (vendored)
- [htmx](https://htmx.org) — frontend interactivity, no page reloads (vendored)
- a small single-header MD5 (`vendor/md5.h`) for the upload log

It's one board — no `/v/`, `/b/`, `/x/` routing. Just threads and replies.

## Build & run

```sh
make
./chan                      # listens on http://0.0.0.0:8000
./chan http://127.0.0.1:9000  # custom bind address
```

Then open the URL in a browser. State is stored in `chan.db` (created on first run).

Several limits are compile-time tunables: `BUMP_LIMIT` (300 posts), `DELETE_AFTER`
(8h, seconds), `RATE_WINDOW` (30s between posts per IP), and `MAX_DISK_BYTES`
(8 GiB upload quota). Override them for testing, e.g.
`make CFLAGS="-O2 -DBUMP_LIMIT=4 -DDELETE_AFTER=3 -DRATE_WINDOW=0"`.

## Features

- Start threads (name / subject / comment) and reply to them
- htmx-powered posting: new threads and replies appear without a full reload
- **Catalog-style index**: threads shown as a grid of thumbnail cells with
  reply counts; click a cell to open the thread
- **File uploads**: PNG / JPG / GIF / WEBM, up to 8 MiB. Type is validated by
  magic bytes (not the filename); images thumbnail and link to full size, webm
  plays inline
- **Click a post number** (`No.123`) in a thread to quote it — inserts `>>123`
  into the reply box and focuses it. Post numbers are green to signal they're
  clickable, and the post you jump to via a `>>123` link is highlighted
- **Reply backlinks**: each post shows clickable links to the posts that reply
  to it (computed from `>>NN` quotes across the thread)
- **Bump limit**: after 300 posts a thread stops bumping and is marked red (in
  the catalog and on the thread page); 8 hours later the thread and all its
  uploads are pruned automatically
- Comments fill the width beside an uploaded image (media-object layout) rather
  than wrapping into a narrow column
- **Rate limiting**: at most one post per IP per minute, held in an in-memory
  open-addressed hash table (FNV-1a hashing, linear probing, auto-resizing);
  over-limit posts get a message without losing the typed text. Behind a reverse
  proxy, set `CHAN_TRUST_PROXY=1` to key off the left-most `X-Forwarded-For`
  entry instead of the TCP peer address
- **Upload log** (`uploads.log`): one tab-separated line per upload recording
  time, IP, MD5, size, original filename, and stored path
- **Disk quota / "OOM killer"**: when the upload directory exceeds a configurable
  size (default 8 GiB) whole threads are purged at random until back under it
- Threads bump to the top of the catalog when they get a reply
- Greentext (`>like this`) and quote links (`>>123`)
- All user input is HTML-escaped server-side (XSS-safe)

Uploads are written to `web/uploads/` and served as static files.

## Layout

```
src/main.c      application: routing, HTML rendering, SQL
vendor/         mongoose + sqlite amalgamation
web/            style.css, htmx.min.js (served as static assets)
Makefile
```

## Data model

A single `posts` table. A row with `thread_id IS NULL` is an opening post (a
thread); a row with `thread_id` set is a reply to that thread. Threads carry a
`bumped_at` used for index ordering.

## LLM note

This entire thing was built with a (guided) llm (opus 4.8) in 2 hours. You can
see the prompts used in plan.txt. Each instruction to the llm was just /goal read 
and execute the next part of the PLAN. 
