# Site Audit Server

Rust async web frontend and orchestration API for `site-crawler`, `site-analyzer`, and `site-renderer`.

## Run

Build all four services from the repository root:

```sh
./build.sh
```

The binaries are written to `build/bin/`. The website listens on `127.0.0.1:8080`. Configure `WEB_LISTEN`, `WEB_MAX_PAGES`, `WEB_MAX_DEPTH`, `CRAWLER_URL`, `ANALYZER_URL`, `CRAWLER_API_KEY`, `ANALYZER_API_KEY`, `CRAWLER_USER_AGENT`, `RENDERER_URL`, and `RENDERER_API_KEY` through environment variables before installing services. `site-renderer` prefers the Obscura binary built into `build/bin` and runs only after an HTTP failure; Chrome or Chromium is an optional fallback.

To register all four as native OS services with automatic start at login/boot and restart-on-failure, run `./install-service.sh`. On macOS and Linux, add `--user` to install user-level services where supported. Remove them with `./uninstall-service.sh` (use the same `--user` option if applicable). System-level installation may require administrator privileges. Configure environment variables before installation; the installer stores relevant service settings with the registrations.

## Multi-process deployment

The server uses Tokio's multi-thread runtime and asynchronous HTTP calls. Run multiple instances behind a reverse proxy for parallel request handling. Scan orchestration state is currently held in each process, and the crawler/analyzer also hold their task state in memory. Route each browser session and its scan polling requests to the same web instance, and route each upstream task ID to the same crawler/analyzer instance. A shared task store is needed to remove sticky routing and survive restarts.

The browser submits `POST /api/scans`, polls `GET /api/scans/{scan_id}`, and displays the combined report. The crawler seeds discovery from the site's root sitemap when available, in addition to following page links. Per-page results are available at `GET /api/scans/{scan_id}/pages?limit=50&cursor=0`, including fetch duration, TTFB, response size, H1 count, HTTP status, dead-page status, broken internal links, and each external link's accessibility, HTTP status, and check duration. Broken-link issues show the source page, target, anchor text, and link position. External links that exceed the crawler's configured check limit are labeled unchecked.
