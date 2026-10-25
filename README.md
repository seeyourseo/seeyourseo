# SeeYourSEO

**A practical website SEO audit for pages, links, content patterns, and technical issues.**

<p>
  <a href="https://seeyourseo.com/">Try SeeYourSEO online</a> ·
  <a href="https://seeyourseo.com/pricing">See paid scan plans</a>
</p>

Start with a free scan of up to 20 pages. When you need a deeper crawl, paid one-time plans cover up to 2,000 pages, with no subscription or automatic renewal. See the website for current plans and pricing.

## What it does

- Crawls discoverable pages and follows sitemap and page links.
- Checks page metadata, canonical URLs, headings, robots directives, duplicate metadata, and internal link structure.
- Finds broken internal links and reports the status of external links.
- Highlights content themes, thin or similar pages, keyword overlap, and orphan pages.
- Measures page loading signals and presents findings in a visual report.
- Lets you download the report as Markdown.

Only scan public websites you own or are authorized to review. Scan reports are temporary; download a Markdown copy to keep one.

## Repository layout

| Path | Purpose |
| --- | --- |
| `backend/` | Website, HTTP API, and static pages |
| `services/site-crawler/` | Page discovery, fetching, and link checks |
| `services/site-analyzer/` | Technical SEO and content analysis |
| `services/site-renderer/` | Browser rendering for pages that need JavaScript |
| `services/site-payments/` | Optional payment and account support |
| `third_party/obscura/` | Pinned Obscura browser-rendering dependency (Git submodule) |

The backend coordinates the crawler, analyzer, and renderer. Service tasks and scan reports are held in process memory and are temporary.

## Build

You need a Rust toolchain with Cargo. From the repository root:

```sh
./build.sh
```

The binaries are placed in `build/bin/`. The build script fetches the pinned Obscura source if it is not already present. On macOS, the build also requires a valid code-signing identity. On Linux, the runtime sandbox requires a kernel with Landlock filesystem ABI v1 support.

For service installation, runtime configuration, and deployment details, see [`backend/README.md`](backend/README.md). Start with [`backend/.env.example`](backend/.env.example) for configuration variable names. Keep real credentials in a private server-side environment file; never commit API keys, database passwords, or payment secrets.

## Try the hosted service

Run a free scan at [seeyourseo.com](https://seeyourseo.com/). For larger sites, [view the paid plans](https://seeyourseo.com/pricing): each purchase adds one scan credit, with page limits from 100 to 2,000 pages. Checkout is a one-time payment with no recurring subscription.

## License

This repository does not currently include a root-level license. Third-party components may have separate licenses; check their directories before reuse.
