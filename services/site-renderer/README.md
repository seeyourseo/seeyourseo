# Site Renderer

Internal Rust API that uses the locally built Obscura browser first to render
pages with JavaScript after the crawler's normal HTTP request fails. It falls
back to installed Google Chrome or Chromium if Obscura is unavailable or errors.
It is a fallback confirmation service, not a CAPTCHA solver. Pages that remain
on an access challenge are returned as restricted.

The service listens on `127.0.0.1:8092` by default. Configure it with
`RENDERER_LISTEN`, `RENDERER_API_KEY`, `RENDERER_CONCURRENCY` (default 2), and
`RENDERER_TIMEOUT_SECONDS` (default 20). The outer `build.sh` builds Obscura
v0.2.5 from its pinned upstream source and places `obscura` beside the service
binary. Set `OBSCURA_BIN` to use a different binary. Obscura runs as a
loopback-only CDP process; `RENDERER_OBSCURA_PORT` changes its default port
19222. The renderer validates that the
requested hostname resolves only to public IP addresses, limits concurrent
browser sessions, and returns the rendered HTML and final response status.
It uses a 1365×768 desktop viewport, `zh-CN` locale, sRGB color, waits for
post-load JavaScript updates, and allows managed browser challenges up to eight
seconds to finish. It uses Obscura's standard rendering mode and does not
enable its optional stealth transport. It does not attempt to solve CAPTCHA
or access challenges.

`POST /v1/render` accepts `{"url":"https://example.com"}`. When
`RENDERER_API_KEY` is configured, pass it as the `x-api-key` header. `/healthz`
does not require authentication.
