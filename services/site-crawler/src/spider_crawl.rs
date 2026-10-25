use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::StreamExt;
use reqwest::{Client, redirect::Policy};
use spider::{
    CaseInsensitiveString, PageData,
    fetcher::{FetchContext, RemoteFetcher},
    traits::PageTimingExt,
    website::Website,
};
use tokio::sync::RwLock;
use url::Url;

use super::{
    Config, CrawlProgress, CrawlStatus, CrawlTask, PageRecord, browser_headers,
    check_external_link, crawl_host, crawl_key, decode_content, decode_partial_content,
    fingerprint, is_html_content_type, looks_like_unrendered_html_shell, parse_html,
    probe_special_file, read_partial_body, request_failure, request_renderer, resolve_public_host,
    should_render_html_target,
};

#[derive(Clone, Default)]
struct FetchMeta {
    status_code: Option<u16>,
    initial_status_code: Option<u16>,
    final_url: String,
    redirect_chain: Vec<String>,
    ttfb_ms: Option<u128>,
    duration_ms: u128,
    content_type: Option<String>,
    content_encoding: Option<String>,
    cache_control: Option<String>,
    decoded_body: Vec<u8>,
    response_size_bytes: Option<usize>,
    raw_response_size_bytes: Option<usize>,
    partial_content: bool,
    error: Option<String>,
}

#[derive(Clone)]
struct SafeSpiderFetcher {
    config: Config,
    root_host: String,
    records: Arc<Mutex<HashMap<String, FetchMeta>>>,
}

#[async_trait::async_trait]
impl RemoteFetcher for SafeSpiderFetcher {
    async fn fetch(&self, ctx: FetchContext<'_>) -> spider::utils::PageResponse {
        let started = Instant::now();
        let mut last = FetchMeta {
            final_url: ctx.url.to_owned(),
            ..FetchMeta::default()
        };
        // One bounded retry handles transient connect and incomplete-body failures.
        for attempt in 0..=1 {
            last = self.fetch_once(ctx.url).await;
            let retryable_status = last
                .status_code
                .is_some_and(|status| status == 408 || status == 429 || status >= 500);
            // A partial HTML body is still useful to the audit and has already
            // consumed the request timeout. Retrying the same slow response
            // doubles the wait without making the page more complete.
            let usable_partial_html = last.partial_content
                && !last.decoded_body.is_empty()
                && last
                    .content_type
                    .as_deref()
                    .is_some_and(is_html_content_type);
            if (last.error.is_none() && !retryable_status) || usable_partial_html {
                break;
            }
            if attempt == 0 {
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
        }
        last.duration_ms = started.elapsed().as_millis();
        let requested_key = Url::parse(ctx.url)
            .map(|url| crawl_key(&url))
            .unwrap_or_else(|_| ctx.url.to_owned());
        if let Ok(mut records) = self.records.lock() {
            records.insert(requested_key, last.clone());
        }

        let status = spider::client::StatusCode::from_u16(last.status_code.unwrap_or(503))
            .unwrap_or(spider::client::StatusCode::BAD_GATEWAY);
        let mut response = spider::utils::PageResponse::default();
        response.status_code = status;
        response.final_url = Some(last.final_url.clone());
        response.headers = last
            .content_type
            .as_ref()
            .map(|_| spider_headers_from_url(ctx.url, &last));
        response.content = Some(last.decoded_body.clone());
        response.content_truncated = last.partial_content;
        response
    }
}

impl SafeSpiderFetcher {
    async fn fetch_once(&self, requested: &str) -> FetchMeta {
        let started = Instant::now();
        let mut current = match Url::parse(requested) {
            Ok(url)
                if matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && crawl_host(&url) == self.root_host =>
            {
                url
            }
            _ => {
                return FetchMeta {
                    final_url: requested.to_owned(),
                    error: Some("URL is outside the public scan scope".into()),
                    duration_ms: started.elapsed().as_millis(),
                    ..FetchMeta::default()
                };
            }
        };
        let mut result = FetchMeta {
            final_url: current.to_string(),
            ..FetchMeta::default()
        };

        for _ in 0..6 {
            let addresses = match resolve_public_host(&current).await {
                Ok(addresses) => addresses,
                Err(message) => {
                    result.error = Some(message);
                    break;
                }
            };
            let Some(host) = current.host_str() else {
                result.error = Some("URL has no host".into());
                break;
            };
            let client = match Client::builder()
                .http1_only()
                .redirect(Policy::none())
                .timeout(self.config.request_timeout)
                .user_agent(&self.config.user_agent)
                .default_headers(browser_headers())
                .resolve_to_addrs(host, &addresses)
                .build()
            {
                Ok(client) => client,
                Err(error) => {
                    result.error = Some(error.to_string());
                    break;
                }
            };

            let request_started = Instant::now();
            match client.get(current.clone()).send().await {
                Ok(response) => {
                    let code = response.status().as_u16();
                    result.initial_status_code.get_or_insert(code);
                    if response.status().is_redirection() {
                        let Some(location) = response
                            .headers()
                            .get(reqwest::header::LOCATION)
                            .and_then(|value| value.to_str().ok())
                        else {
                            result.status_code = Some(code);
                            result.ttfb_ms = Some(request_started.elapsed().as_millis());
                            result.error =
                                Some("redirect response has no valid Location header".into());
                            break;
                        };
                        let Ok(next) = current.join(location) else {
                            result.error = Some("redirect target is invalid".into());
                            break;
                        };
                        if !matches!(next.scheme(), "http" | "https")
                            || !next.username().is_empty()
                            || next.password().is_some()
                            || crawl_host(&next) != self.root_host
                        {
                            result.status_code = Some(code);
                            result.error = Some("redirect leaves the scanned site".into());
                            break;
                        }
                        result
                            .redirect_chain
                            .push(format!("{} (HTTP {}) → {}", current, code, next));
                        result.status_code = Some(code);
                        result
                            .ttfb_ms
                            .get_or_insert(request_started.elapsed().as_millis());
                        current = next;
                    } else {
                        result.status_code = Some(code);
                        result.ttfb_ms = Some(request_started.elapsed().as_millis());
                        result.content_type = response
                            .headers()
                            .get(reqwest::header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        result.content_encoding = response
                            .headers()
                            .get(reqwest::header::CONTENT_ENCODING)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        result.cache_control = response
                            .headers()
                            .get(reqwest::header::CACHE_CONTROL)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        if result
                            .content_type
                            .as_deref()
                            .is_some_and(is_html_content_type)
                        {
                            let encoding = result.content_encoding.as_deref();
                            let (raw, read_error) =
                                read_partial_body(response, self.config.max_body_bytes).await;
                            result.raw_response_size_bytes = Some(raw.len());
                            let decoded = if read_error.is_some() {
                                decode_partial_content(&raw, encoding, self.config.max_body_bytes)
                            } else {
                                match decode_content(&raw, encoding, self.config.max_body_bytes) {
                                    Ok(body) => body,
                                    Err(message) => {
                                        result.error = Some(message);
                                        Vec::new()
                                    }
                                }
                            };
                            if let Some(message) = read_error {
                                result.error = Some(message);
                                result.partial_content = !decoded.is_empty();
                            }
                            if !decoded.is_empty() {
                                result.response_size_bytes = Some(decoded.len());
                                result.decoded_body = decoded;
                            }
                        }
                        result.final_url = current.to_string();
                        break;
                    }
                }
                Err(error) => {
                    result.error = Some(request_failure(&error));
                    result.final_url = current.to_string();
                    break;
                }
            }
        }
        result.final_url = current.to_string();
        result.duration_ms = started.elapsed().as_millis();
        result
    }
}

fn spider_headers_from_url(_url: &str, meta: &FetchMeta) -> spider::client::header::HeaderMap {
    let mut headers = spider::client::header::HeaderMap::new();
    if let Some(content_type) = meta.content_type.as_deref() {
        if let Ok(value) = spider::client::header::HeaderValue::from_str(content_type) {
            headers.insert(spider::client::header::CONTENT_TYPE, value);
        }
    }
    if let Some(encoding) = meta.content_encoding.as_deref() {
        if let Ok(value) = spider::client::header::HeaderValue::from_str(encoding) {
            headers.insert(spider::client::header::CONTENT_ENCODING, value);
        }
    }
    if let Some(cache_control) = meta.cache_control.as_deref() {
        if let Ok(value) = spider::client::header::HeaderValue::from_str(cache_control) {
            headers.insert(spider::client::header::CACHE_CONTROL, value);
        }
    }
    headers
}

pub(super) async fn run_crawl(
    task: Arc<RwLock<CrawlTask>>,
    start: Url,
    max_pages: Option<usize>,
    max_depth: Option<usize>,
    config: Config,
) {
    {
        let mut task = task.write().await;
        if matches!(task.status, CrawlStatus::Cancelled) {
            return;
        }
        task.status = CrawlStatus::Running;
        task.updated_at = Instant::now();
    }

    let page_limit = max_pages
        .unwrap_or(config.max_pages)
        .clamp(1, config.max_pages);
    let depth_limit = max_depth.unwrap_or(config.max_depth).min(config.max_depth);
    let root_host = crawl_host(&start);
    let (sitemap_result, robots_result, llms_result) = tokio::join!(
        super::discover_sitemap_pages(&start, &config, page_limit.saturating_sub(1)),
        probe_special_file(&start, "/robots.txt", &config),
        probe_special_file(&start, "/llms.txt", &config),
    );
    let (sitemap_pages, mut special_files) = sitemap_result;
    special_files.extend([robots_result, llms_result]);
    task.write().await.special_files = special_files;

    let records = Arc::new(Mutex::new(HashMap::<String, FetchMeta>::new()));
    let fetcher = SafeSpiderFetcher {
        config: config.clone(),
        root_host: root_host.clone(),
        records: records.clone(),
    };
    let discovered = Arc::new(Mutex::new(HashSet::<String>::new()));
    let callback_discovered = discovered.clone();
    let callback_host = root_host.clone();
    let mut website = Website::new(start.as_str())
        .with_respect_robots_txt(false)
        .with_subdomains(true)
        .with_limit(page_limit.min(u32::MAX as usize) as u32)
        .with_depth(depth_limit)
        .with_concurrency_limit(Some(config.concurrency.min(8).max(1)))
        .with_delay(75)
        .with_request_timeout(Some(config.request_timeout))
        .with_user_agent(Some(&config.user_agent))
        .with_retry(0)
        .build()
        .expect("validated scan URL creates a Spider website");
    website.with_remote_fetcher(fetcher);
    website.on_link_find_callback = Some(Arc::new(move |link, anchor| {
        let value = link.to_string();
        if let Ok(url) = Url::parse(&value)
            && crawl_host(&url) == callback_host
            && let Ok(mut seen) = callback_discovered.lock()
        {
            seen.insert(crawl_key(&url));
        }
        (link, anchor)
    }));
    for url in sitemap_pages {
        if crawl_host(&url) == root_host {
            let value = url.to_string();
            website
                .insert_link(&CaseInsensitiveString::new(&value))
                .await;
        }
    }

    let mut page_events = website.subscribe(page_limit.clamp(8, 256));
    let mut scrape = Box::pin(website.scrape());
    let mut crawled = 0usize;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = &mut scrape => break,
            event = page_events.recv() => {
                if let Ok(page) = event {
                    crawled = crawled.saturating_add(1);
                    let failed = page.error_status.is_some() || !page.status_code.is_success();
                    let discovered_count = discovered
                        .lock()
                        .map(|seen| seen.len().saturating_add(1))
                        .unwrap_or(crawled)
                        .max(crawled);
                    let mut task_guard = task.write().await;
                    task_guard.progress.crawled = crawled;
                    task_guard.progress.discovered = discovered_count;
                    if failed {
                        task_guard.progress.failed = task_guard.progress.failed.saturating_add(1);
                    }
                    task_guard.updated_at = Instant::now();
                }
            }
            _ = tick.tick() => {
                if matches!(task.read().await.status, CrawlStatus::Cancelled) {
                    return;
                }
            }
        }
    }
    drop(scrape);

    let spider_pages = website.get_pages().cloned().unwrap_or_default();
    let fetch_meta = records.lock().map(|meta| meta.clone()).unwrap_or_default();
    let mut page_records = Vec::with_capacity(spider_pages.len());
    for page in &spider_pages {
        let requested_url = page.get_url().to_owned();
        let requested_key = Url::parse(&requested_url)
            .map(|url| crawl_key(&url))
            .unwrap_or_else(|_| requested_url.clone());
        let meta = fetch_meta
            .get(&requested_key)
            .cloned()
            .unwrap_or_else(|| FetchMeta {
                status_code: Some(page.status_code.as_u16()),
                final_url: page
                    .final_redirect_destination
                    .clone()
                    .unwrap_or_else(|| requested_url.clone()),
                error: page.error_status.clone(),
                ..FetchMeta::default()
            });
        let final_url = Url::parse(&meta.final_url)
            .unwrap_or_else(|_| Url::parse(&requested_url).expect("Spider page URLs are absolute"));
        let bytes = page.html_bytes_u8().to_vec();
        let mut title = None;
        let mut description = None;
        let mut canonical = None;
        let mut robots = None;
        let mut h1_count = 0;
        let mut content_text = String::new();
        let mut headings = Vec::new();
        let mut links = Vec::new();
        if meta
            .content_type
            .as_deref()
            .is_some_and(is_html_content_type)
            && !bytes.is_empty()
        {
            parse_html(
                &final_url,
                &bytes,
                &mut title,
                &mut description,
                &mut canonical,
                &mut robots,
                &mut h1_count,
                &mut content_text,
                &mut headings,
                &mut links,
            );
        }
        let html_shell_candidate =
            looks_like_unrendered_html_shell(&bytes, title.as_deref(), &content_text, &links);
        let should_retry_in_browser = (!meta.partial_content
            && (meta.status_code.is_some_and(|status| status >= 400)
                || meta.error.is_some()
                || html_shell_candidate
                || meta.content_type.is_none()))
            && should_render_html_target(&final_url, meta.content_type.as_deref());
        let mut status_code = meta.status_code;
        let mut content_type = meta.content_type.clone();
        let mut body_fingerprint =
            (!bytes.is_empty()).then(|| format!("{:016x}", fingerprint(&bytes)));
        let mut response_size_bytes = meta.response_size_bytes;
        let mut raw_response_size_bytes = meta.raw_response_size_bytes;
        let mut partial_content = meta.partial_content || page.content_truncated;
        let mut error = meta.error.clone().or_else(|| page.error_status.clone());
        if should_retry_in_browser {
            if let Some(rendered) = request_renderer(
                &config.renderer_url,
                config.renderer_api_key.as_deref(),
                final_url.as_str(),
            )
            .await
            {
                if rendered.accessible {
                    if let (Some(html), Ok(rendered_url)) =
                        (rendered.html, Url::parse(&rendered.url))
                    {
                        title = None;
                        description = None;
                        canonical = None;
                        robots = None;
                        h1_count = 0;
                        content_text.clear();
                        headings.clear();
                        links.clear();
                        response_size_bytes = Some(html.len());
                        raw_response_size_bytes = Some(html.len());
                        body_fingerprint = Some(format!("{:016x}", fingerprint(html.as_bytes())));
                        parse_html(
                            &rendered_url,
                            html.as_bytes(),
                            &mut title,
                            &mut description,
                            &mut canonical,
                            &mut robots,
                            &mut h1_count,
                            &mut content_text,
                            &mut headings,
                            &mut links,
                        );
                        status_code = rendered.status_code.or(Some(200));
                        content_type = Some("text/html; rendered".into());
                        error = None;
                        partial_content = false;
                    }
                }
            }
        }
        page_records.push(PageRecord {
            url: requested_url,
            final_url: meta.final_url,
            status_code,
            initial_status_code: meta.initial_status_code,
            title,
            description,
            canonical,
            robots,
            h1_count,
            content_text,
            headings,
            content_type,
            content_encoding: meta.content_encoding,
            cache_control: meta.cache_control,
            body_fingerprint,
            redirect_chain: meta.redirect_chain,
            ttfb_ms: meta.ttfb_ms,
            response_size_bytes,
            raw_response_size_bytes,
            partial_content,
            links,
            depth: 1,
            duration_ms: meta.duration_ms.max(page.duration_elapsed().as_millis()),
            error,
        });
    }

    assign_depths(&start, &mut page_records);
    let failed = page_records
        .iter()
        .filter(|page| page.error.is_some())
        .count();
    {
        let mut task_guard = task.write().await;
        task_guard.progress = CrawlProgress {
            discovered: page_records
                .len()
                .max(discovered.lock().map(|seen| seen.len() + 1).unwrap_or(1)),
            crawled: page_records.len(),
            failed,
        };
        task_guard.results = page_records;
        task_guard.updated_at = Instant::now();
    }

    let external_urls = {
        let task_guard = task.read().await;
        let mut seen_external = HashSet::new();
        let mut urls = Vec::new();
        for link in task_guard.results.iter().flat_map(|page| &page.links) {
            if !link.is_internal
                && urls.len() < config.max_external_link_checks
                && let Some(key) = super::external_link_key(&link.url)
                && seen_external.insert(key.clone())
            {
                urls.push((key, link.url.clone()));
            }
        }
        urls
    };
    let link_checks = futures::stream::iter(external_urls.into_iter().map(|(key, url)| {
        let timeout = config.external_link_timeout;
        let user_agent = config.user_agent.clone();
        async move { (key, check_external_link(&url, timeout, &user_agent).await) }
    }))
    .buffer_unordered(config.concurrency.min(64))
    .collect::<HashMap<_, _>>()
    .await;
    let mut task_guard = task.write().await;
    for page in &mut task_guard.results {
        for link in &mut page.links {
            if !link.is_internal
                && let Some(key) = super::external_link_key(&link.url)
            {
                if let Some(check) = link_checks.get(&key) {
                    link.status_code = check.status_code;
                    link.duration_ms = Some(check.duration_ms);
                    link.accessible = check.accessible;
                    link.error = check.error.clone();
                } else {
                    link.error = Some("External link check limit reached".into());
                }
            }
        }
    }
    task_guard.updated_at = Instant::now();
    if !matches!(task_guard.status, CrawlStatus::Cancelled) {
        task_guard.status = CrawlStatus::Completed;
    }
    task_guard.updated_at = Instant::now();
}

fn assign_depths(start: &Url, pages: &mut [PageRecord]) {
    let by_url = pages
        .iter()
        .enumerate()
        .map(|(index, page)| {
            Url::parse(&page.url)
                .map(|url| (crawl_key(&url), index))
                .unwrap_or_default()
        })
        .filter(|(url, _)| !url.is_empty())
        .collect::<HashMap<_, _>>();
    let root_key = crawl_key(start);
    let Some(&root_index) = by_url.get(&root_key) else {
        return;
    };
    let mut depth_by_index = HashMap::from([(root_index, 0usize)]);
    let mut queue = VecDeque::from([root_index]);
    while let Some(index) = queue.pop_front() {
        let depth = depth_by_index[&index];
        let links = pages[index]
            .links
            .iter()
            .filter(|link| link.is_internal)
            .filter_map(|link| Url::parse(&link.url).ok().map(|url| crawl_key(&url)))
            .collect::<Vec<_>>();
        for key in links {
            if let Some(&next) = by_url.get(&key)
                && let std::collections::hash_map::Entry::Vacant(entry) = depth_by_index.entry(next)
            {
                entry.insert(depth + 1);
                queue.push_back(next);
            }
        }
    }
    for (index, page) in pages.iter_mut().enumerate() {
        page.depth = depth_by_index.get(&index).copied().unwrap_or(1);
    }
}
