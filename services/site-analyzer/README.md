# Site Analyzer

Standalone Rust HTTP API that analyzes JSON page records from the site crawler.
It does not fetch websites, call third-party APIs, or use a database. Analysis
tasks and results remain in process memory and disappear on restart or expiry.

## Run

```sh
cargo run --release
```

The default listener is `127.0.0.1:8091`. Set `ANALYZER_API_KEY` when binding
to a non-loopback address. Configuration variables are `ANALYZER_LISTEN`,
`ANALYZER_API_KEY`, `ANALYZER_MAX_ANALYSES`, `ANALYZER_MAX_PAGES`,
`ANALYZER_MAX_BATCH_PAGES`, `ANALYZER_MAX_BODY_BYTES`, and
`ANALYZER_TASK_TTL_SECONDS`.

## API

Create an analysis with `POST /v1/analyses`, then submit crawler pages in
batches to `POST /v1/analyses/{analysis_id}/pages` using
`{"pages":[...]}`. The page objects are compatible with the crawler's page
JSON; fields not used by the analyzer are ignored. Repeated page URLs are
deduplicated. Call `POST /v1/analyses/{analysis_id}/complete` when all batches
have been submitted. Poll `GET /v1/analyses/{analysis_id}` until status is
`completed`, then read issues from
`GET /v1/analyses/{analysis_id}/issues?limit=100&cursor=0`.

The analyzer reports fetch and HTTP failures, missing title/description/
canonical/H1, common title and description length outliers, multiple H1s,
`noindex`, duplicate title/description/canonical values, broken internal links
to crawled pages, failed or redirecting canonical targets when the target was
crawled, and pages without inbound links in the submitted crawl graph. Broken
internal-link issues include the source page, target URL, anchor text, and
link position. The summary includes page failures, link counts, orphan page
count, and issue counts by code.

After completion, `GET /v1/analyses/{analysis_id}/pages?limit=100&cursor=0`
returns paginated per-page audit data: HTTP status, total crawler duration,
TTFB, response size, H1 count, whether the page itself failed, internal/
external link counts, and internal links that point to failed crawled pages.
External links are counted and checked by the crawler.

The health endpoint is `GET /healthz`. API routes use a bearer token when
`ANALYZER_API_KEY` is configured. Each process owns its tasks; multi-process
deployments need sticky routing by `analysis_id`.
