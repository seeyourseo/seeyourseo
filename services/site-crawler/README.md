# Site Crawler

Standalone Rust HTTP API for crawling a website and extracting page metadata and
links. It has no database dependency. Crawl state and results live in memory and
are removed when the process exits or the task expires.

## Run

```sh
cargo run --release
```

The service listens on `127.0.0.1:8090` by default. Set `CRAWLER_API_KEY` to
protect API routes when exposing it beyond loopback; the health endpoint stays
unauthenticated. Configure it with
`CRAWLER_LISTEN`, `CRAWLER_CONCURRENCY`, `CRAWLER_MAX_PAGES`,
`CRAWLER_MAX_DEPTH`, `CRAWLER_MAX_CRAWLS`, `CRAWLER_MAX_BODY_BYTES`,
`CRAWLER_TASK_TTL_SECONDS`, `CRAWLER_REQUEST_TIMEOUT_SECONDS`,
`CRAWLER_MAX_EXTERNAL_LINK_CHECKS` (default 500), and
`CRAWLER_EXTERNAL_LINK_TIMEOUT_SECONDS` (default 5). `CRAWLER_USER_AGENT`
overrides the browser-like default User-Agent.

The crawl scheduler uses the Spider Rust crawler by default. It runs at most
four same-site page requests concurrently, waits 150 ms between requests, and
retries a transient page-fetch failure once. A project-owned fetch adapter
still pins each public DNS result and validates every redirect hop before
connecting. Robots rules do not restrict the crawl. Set `CRAWLER_ENGINE=legacy`
to switch back to the previous scheduler while comparing results.

## API

Create a crawl:

```http
POST /v1/crawls
Content-Type: application/json

{"start_url":"https://example.com","max_pages":500,"max_depth":8}
```

The response is `202 Accepted` with a `crawl_id`. Poll
`GET /v1/crawls/{crawl_id}` for status and progress. Read results with
`GET /v1/crawls/{crawl_id}/pages?limit=100&cursor=0`; follow `next_cursor` to
read more. When `has_more` is false and the task is still running, poll again
with the returned cursor to read results discovered later. `status` reports
whether crawling is still running. `DELETE /v1/crawls/{id}`
cancels the crawl. Expired tasks are removed after the configured TTL.

Each crawl checks `/sitemap.xml` and `/sitemap_index.xml` as optional page
seeds, follows bounded sitemap indexes, and only adds URLs on the scanned host.
Each page result includes status, title, description, canonical URL, robots
meta, H1 count, content type, redirect chain, depth, total fetch duration,
time to first byte (TTFB), response size, and extracted links. Link records
include their anchor text and position in the source page.
Only same-host links are crawled. HTTP(S) links to other hosts are checked with
HEAD requests, with a small-range GET fallback for servers that reject HEAD.
Each external link includes its status code, check duration, accessibility, and
error when applicable. The checker retries any failing HEAD response with GET;
if GET still fails, it asks `site-renderer` to render the URL with installed
Chrome or Chromium and execute JavaScript. A browser success confirms
accessibility. 401, 403, 429, server errors, and network failures are reported
as restricted or unverified because they do not prove that a link is dead. The
number of unique external targets checked per crawl
is capped by `CRAWLER_MAX_EXTERNAL_LINK_CHECKS`; additional targets are marked
unchecked. Redirect destinations are checked against the same public-network
restriction as crawled pages. HTTP requests include a browser-like User-Agent,
Accept, and Accept-Language header. The renderer executes JavaScript but does
not solve CAPTCHAs or bypass browser fingerprint checks; unresolved challenges
remain restricted.

## Runtime model

Tokio runs a multi-thread asynchronous runtime and bounds concurrent network
requests. Each process owns its in-memory crawl tasks. Run one process per
instance unless the API gateway provides sticky routing by `crawl_id`; a task
cannot be read from a different process, and restarting a process discards its
tasks.

The crawler rejects non-public IP targets and validates redirect destinations.
Deploy it behind suitable network controls and keep its page, body, concurrency,
and timeout limits configured for the expected workload.
