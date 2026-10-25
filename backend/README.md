# Site Audit Server

Rust async web frontend and orchestration API for `site-crawler`, `site-analyzer`, and `site-renderer`.

## Run

Build all four services from the repository root:

```sh
./build.sh
```

The binaries are written to `build/bin/`. The website listens on `127.0.0.1:8080`. Configure `WEB_LISTEN`, `WEB_MAX_PAGES`, `WEB_MAX_DEPTH`, `CRAWLER_URL`, `ANALYZER_URL`, `CRAWLER_API_KEY`, `ANALYZER_API_KEY`, `CRAWLER_USER_AGENT`, `RENDERER_URL`, and `RENDERER_API_KEY` through environment variables before installing services. `site-renderer` prefers the Obscura binary built into `build/bin` and runs only after an HTTP failure; Chrome or Chromium is an optional fallback.

To register all four as native OS services with automatic start at login/boot and restart-on-failure, run `./install-service.sh`. On macOS and Linux, add `--user` to install user-level services where supported. Remove them with `./uninstall-service.sh` (use the same `--user` option if applicable). System-level installation may require administrator privileges. Configure environment variables before installation; the installer stores relevant service settings with the registrations.

The private `/admin` dashboard includes page-access IPs from Cloudflare's `CF-Connecting-IP` header. It records public HTML page requests only (not assets or API calls), excludes query strings, and retains events for up to seven days in `VISITOR_LOG_PATH` (default: `data/visitor-access.jsonl`). Keep the origin bound to localhost or otherwise ensure requests reach it through Cloudflare before trusting that header.

## Linux process sandbox

Linux builds apply a Landlock filesystem allowlist and seccomp filter before starting Tokio. Website, crawler, analyzer, and renderer processes cannot launch subprocesses. The renderer starts an isolated Obscura worker first; that worker opens the configured Obscura binary, applies its own Landlock policy, then executes only that open file descriptor with `execveat`. The worker can no longer substitute another executable, and it exits when its renderer parent exits. Network access remains enabled for scanning and database/payment calls. Other operating systems retain their existing behavior.

The Linux kernel must support and fully enforce Landlock filesystem ABI v1. A service exits with an error instead of starting without the filesystem sandbox if the kernel cannot enforce it. The policy grants runtime libraries, DNS and TLS certificate inputs, each service's required data paths, and one exact Obscura executable. Linux rendering requires Obscura; it does not fall back to launching a general Chrome/Chromium binary inside the sandbox. The website payment environment file is granted by its exact path when present.

## Multi-process deployment

The server uses Tokio's multi-thread runtime and asynchronous HTTP calls. Run multiple instances behind a reverse proxy for parallel request handling. Scan orchestration state is currently held in each process, and the crawler/analyzer also hold their task state in memory. Route each browser session and its scan polling requests to the same web instance, and route each upstream task ID to the same crawler/analyzer instance. A shared task store is needed to remove sticky routing and survive restarts.

The browser submits `POST /api/scans`, polls `GET /api/scans/{scan_id}`, and displays the combined report. The crawler seeds discovery from the site's root sitemap when available, in addition to following page links. Per-page results are available at `GET /api/scans/{scan_id}/pages?limit=50&cursor=0`, including fetch duration, TTFB, response size, H1 count, HTTP status, dead-page status, broken internal links, and each external link's accessibility, HTTP status, and check duration. Broken-link issues show the source page, target, anchor text, and link position. External links that exceed the crawler's configured check limit are labeled unchecked.
