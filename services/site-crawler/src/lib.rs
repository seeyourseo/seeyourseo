use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures::{StreamExt, stream};
use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, HeaderMap, HeaderValue};
use reqwest::{Client, redirect::Policy};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::{net::lookup_host, sync::RwLock};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub api_key: Option<String>,
    pub concurrency: usize,
    pub max_crawls: usize,
    pub max_pages: usize,
    pub max_depth: usize,
    pub max_external_link_checks: usize,
    pub max_body_bytes: usize,
    pub task_ttl: Duration,
    pub request_timeout: Duration,
    pub external_link_timeout: Duration,
    pub user_agent: String,
    pub renderer_url: String,
    pub renderer_api_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let listen: SocketAddr = std::env::var("CRAWLER_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8090".into())
            .parse()?;
        let api_key = std::env::var("CRAWLER_API_KEY")
            .ok()
            .filter(|key| !key.is_empty());
        if !listen.ip().is_loopback() && api_key.is_none() {
            return Err(
                "CRAWLER_API_KEY is required when listening on a non-loopback address".into(),
            );
        }
        Ok(Self {
            listen,
            api_key,
            concurrency: env_usize("CRAWLER_CONCURRENCY", 32).clamp(1, 256),
            max_crawls: env_usize("CRAWLER_MAX_CRAWLS", 32).clamp(1, 256),
            max_pages: env_usize("CRAWLER_MAX_PAGES", 10_000).clamp(1, 100_000),
            max_depth: env_usize("CRAWLER_MAX_DEPTH", 20).clamp(1, 100),
            max_external_link_checks: env_usize("CRAWLER_MAX_EXTERNAL_LINK_CHECKS", 500)
                .clamp(1, 20_000),
            max_body_bytes: env_usize("CRAWLER_MAX_BODY_BYTES", 2_000_000).clamp(1_024, 20_000_000),
            task_ttl: Duration::from_secs(
                env_usize("CRAWLER_TASK_TTL_SECONDS", 3600).clamp(60, 86_400) as u64,
            ),
            request_timeout: Duration::from_secs(
                env_usize("CRAWLER_REQUEST_TIMEOUT_SECONDS", 15).clamp(1, 120) as u64,
            ),
            external_link_timeout: Duration::from_secs(
                env_usize("CRAWLER_EXTERNAL_LINK_TIMEOUT_SECONDS", 5).clamp(1, 30) as u64,
            ),
            user_agent: std::env::var("CRAWLER_USER_AGENT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| {
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.8078.48 Safari/537.36".into()
                }),
            renderer_url: std::env::var("RENDERER_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8092".into()),
            renderer_api_key: std::env::var("RENDERER_API_KEY")
                .ok().filter(|key| !key.is_empty()),
        })
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone)]
pub struct AppState {
    config: Config,
    tasks: Arc<RwLock<HashMap<Uuid, Arc<RwLock<CrawlTask>>>>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn cleanup_expired(&self) {
        let cutoff = Instant::now() - self.config.task_ttl;
        self.tasks.write().await.retain(|_, task| {
            task.try_read()
                .map(|task| {
                    task.updated_at > cutoff && !matches!(task.status, CrawlStatus::Cancelled)
                })
                .unwrap_or(true)
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkRecord {
    pub url: String,
    pub text: String,
    pub position: usize,
    pub rel: Vec<String>,
    pub is_internal: bool,
    pub status_code: Option<u16>,
    pub duration_ms: Option<u128>,
    pub accessible: Option<bool>,
    pub error: Option<String>,
}

#[derive(Clone)]
struct LinkCheck {
    status_code: Option<u16>,
    duration_ms: u128,
    accessible: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PageRecord {
    pub url: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub canonical: Option<String>,
    pub robots: Option<String>,
    pub h1_count: usize,
    pub content_text: String,
    pub headings: Vec<ContentHeading>,
    pub content_type: Option<String>,
    pub redirect_chain: Vec<String>,
    pub ttfb_ms: Option<u128>,
    pub response_size_bytes: Option<usize>,
    pub links: Vec<LinkRecord>,
    pub depth: usize,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentHeading {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlProgress {
    pub discovered: usize,
    pub crawled: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawlTaskView {
    pub crawl_id: Uuid,
    pub status: CrawlStatus,
    pub progress: CrawlProgress,
    pub error: Option<String>,
}

struct CrawlTask {
    id: Uuid,
    status: CrawlStatus,
    progress: CrawlProgress,
    results: Vec<PageRecord>,
    error: Option<String>,
    updated_at: Instant,
}

impl CrawlTask {
    fn view(&self) -> CrawlTaskView {
        CrawlTaskView {
            crawl_id: self.id,
            status: self.status.clone(),
            progress: self.progress.clone(),
            error: self.error.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateCrawlRequest {
    pub start_url: String,
    #[serde(default)]
    pub max_pages: Option<usize>,
    #[serde(default)]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageBatch {
    pub crawl_id: Uuid,
    pub status: CrawlStatus,
    pub progress: CrawlProgress,
    pub pages: Vec<PageRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("crawl not found")]
    NotFound,
    #[error("service is at capacity")]
    Capacity,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "crawl_not_found"),
            Self::Capacity => (StatusCode::SERVICE_UNAVAILABLE, "capacity_reached"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status":"ok"}))
}

pub async fn require_api_key(
    State(expected): State<Option<String>>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    if let Some(expected) = expected {
        let valid = request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|provided| {
                provided.len() == expected.len()
                    && bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
            });
        if !valid {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"unauthorized","message":"valid bearer token required"})),
            )
                .into_response();
        }
    }
    next.run(request).await
}

pub async fn create_crawl(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateCrawlRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let start = normalize_url(&request.start_url).map_err(ApiError::BadRequest)?;
    resolve_public_host(&start)
        .await
        .map_err(ApiError::BadRequest)?;
    let id = Uuid::new_v4();
    let task = Arc::new(RwLock::new(CrawlTask {
        id,
        status: CrawlStatus::Queued,
        progress: CrawlProgress {
            discovered: 1,
            crawled: 0,
            failed: 0,
        },
        results: Vec::new(),
        error: None,
        updated_at: Instant::now(),
    }));
    {
        let mut tasks = state.tasks.write().await;
        if tasks.len() >= state.config.max_crawls {
            return Err(ApiError::Capacity);
        }
        tasks.insert(id, task.clone());
    }
    let config = state.config.clone();
    tokio::spawn(async move {
        run_crawl(task, start, request.max_pages, request.max_depth, config).await;
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"crawl_id": id, "status":"queued"})),
    ))
}

pub async fn get_crawl(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<CrawlTaskView>, ApiError> {
    let task = state
        .tasks
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    Ok(Json(task.read().await.view()))
}

pub async fn delete_crawl(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let task = state
        .tasks
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let mut task = task.write().await;
    task.status = CrawlStatus::Cancelled;
    task.updated_at = Instant::now();
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_pages(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageBatch>, ApiError> {
    let task = state
        .tasks
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let mut task = task.write().await;
    task.updated_at = Instant::now();
    let cursor = query
        .cursor
        .as_deref()
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| ApiError::BadRequest("invalid cursor".into()))
        })
        .transpose()?
        .unwrap_or(0);
    if cursor > task.results.len() {
        return Err(ApiError::BadRequest(
            "cursor is ahead of available results".into(),
        ));
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let end = (cursor + limit).min(task.results.len());
    let pages = task.results[cursor..end].to_vec();
    let has_more = end < task.results.len();
    let next_cursor = Some(end.to_string());
    Ok(Json(PageBatch {
        crawl_id: id,
        status: task.status.clone(),
        progress: task.progress.clone(),
        pages,
        next_cursor,
        has_more,
    }))
}

async fn run_crawl(
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
    let mut seen = HashSet::from([crawl_key(&start)]);
    let mut queue = VecDeque::from([(start.clone(), 0usize)]);
    if depth_limit > 0 {
        for url in discover_sitemap_pages(&start, &config, page_limit.saturating_sub(1)).await {
            if seen.len() >= page_limit {
                break;
            }
            if seen.insert(crawl_key(&url)) {
                queue.push_back((url, 1));
            }
        }
    }
    task.write().await.progress.discovered = seen.len();
    while !queue.is_empty() && seen.len() <= page_limit {
        if matches!(task.read().await.status, CrawlStatus::Cancelled) {
            return;
        }
        let batch_len = queue
            .len()
            .min(config.concurrency)
            .min(page_limit.saturating_sub(task.read().await.progress.crawled));
        if batch_len == 0 {
            break;
        }
        let batch: Vec<_> = queue.drain(..batch_len).collect();
        let results = stream::iter(batch.into_iter().map(|(url, depth)| {
            let config = config.clone();
            async move { crawl_page(url, depth, &config).await }
        }))
        .buffer_unordered(config.concurrency)
        .collect::<Vec<_>>()
        .await;
        let mut discovered = Vec::new();
        for (record, depth) in results {
            let mut task_guard = task.write().await;
            if record.error.is_some() {
                task_guard.progress.failed += 1;
            }
            task_guard.progress.crawled += 1;
            for link in &record.links {
                if link.is_internal && depth < depth_limit && seen.len() < page_limit {
                    if let Ok(next) = Url::parse(&link.url) {
                        if seen.insert(crawl_key(&next)) {
                            discovered.push((next, depth + 1));
                        }
                    }
                }
            }
            task_guard.results.push(record);
            task_guard.updated_at = Instant::now();
            drop(task_guard);
        }
        queue.extend(discovered);
        let mut task_guard = task.write().await;
        task_guard.progress.discovered = seen.len();
        task_guard.updated_at = Instant::now();
    }

    let external_urls = {
        let task = task.read().await;
        let mut seen_external = HashSet::new();
        let mut urls = Vec::new();
        for link in task.results.iter().flat_map(|page| &page.links) {
            if !link.is_internal
                && urls.len() < config.max_external_link_checks
                && let Some(key) = external_link_key(&link.url)
                && seen_external.insert(key.clone())
            {
                urls.push((key, link.url.clone()));
            }
        }
        urls
    };
    let link_checks = stream::iter(external_urls.into_iter().map(|(key, url)| {
        let timeout = config.external_link_timeout;
        let user_agent = config.user_agent.clone();
        let renderer_url = config.renderer_url.clone();
        let renderer_api_key = config.renderer_api_key.clone();
        async move {
            (
                key,
                check_external_link(
                    &url,
                    timeout,
                    &user_agent,
                    &renderer_url,
                    renderer_api_key.as_deref(),
                )
                .await,
            )
        }
    }))
    .buffer_unordered(config.concurrency.min(64))
    .collect::<HashMap<_, _>>()
    .await;

    let mut task = task.write().await;
    for page in &mut task.results {
        for link in &mut page.links {
            if link.is_internal {
                continue;
            }
            if let Some(key) = external_link_key(&link.url) {
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
    task.updated_at = Instant::now();
    if !matches!(task.status, CrawlStatus::Cancelled) {
        task.status = CrawlStatus::Completed;
    }
    task.updated_at = Instant::now();
}

async fn discover_sitemap_pages(start: &Url, config: &Config, limit: usize) -> Vec<Url> {
    if limit == 0 {
        return Vec::new();
    }
    let Ok(sitemap) = start.join("/sitemap.xml") else {
        return Vec::new();
    };
    let Ok(index_sitemap) = start.join("/sitemap_index.xml") else {
        return Vec::new();
    };
    let mut sitemaps = VecDeque::from([sitemap, index_sitemap]);
    let mut seen_sitemaps = HashSet::new();
    let mut pages = Vec::new();
    let start_host = crawl_host(start);
    while let Some(sitemap) = sitemaps.pop_front() {
        if seen_sitemaps.len() >= 20
            || pages.len() >= limit
            || !seen_sitemaps.insert(crawl_key(&sitemap))
            || crawl_host(&sitemap) != start_host
        {
            continue;
        }
        let mut current = sitemap;
        let response = 'redirects: {
            for _ in 0..6 {
                let addresses = match resolve_public_host(&current).await {
                    Ok(addresses) => addresses,
                    Err(_) => break 'redirects None,
                };
                let Some(host) = current.host_str() else {
                    break 'redirects None;
                };
                let client = match Client::builder()
                    .redirect(Policy::none())
                    .timeout(config.request_timeout.min(Duration::from_secs(5)))
                    .user_agent(&config.user_agent)
                    .default_headers(browser_headers())
                    .resolve_to_addrs(host, &addresses)
                    .build()
                {
                    Ok(client) => client,
                    Err(_) => break 'redirects None,
                };
                match client.get(current.clone()).send().await {
                    Ok(response) if response.status().is_redirection() => {
                        let Some(location) = response
                            .headers()
                            .get(reqwest::header::LOCATION)
                            .and_then(|value| value.to_str().ok())
                        else {
                            break 'redirects None;
                        };
                        let Ok(next) = current.join(location) else {
                            break 'redirects None;
                        };
                        if crawl_host(&next) != start_host
                            || !matches!(next.scheme(), "http" | "https")
                        {
                            break 'redirects None;
                        }
                        current = next;
                    }
                    Ok(response) if response.status().is_success() => {
                        break 'redirects Some(response);
                    }
                    _ => break 'redirects None,
                }
            }
            None
        };
        let Some(response) = response else {
            continue;
        };
        let Ok(body) = read_limited_body(response, config.max_body_bytes).await else {
            continue;
        };
        let xml = String::from_utf8_lossy(&body);
        let is_index = xml.to_ascii_lowercase().contains("<sitemapindex");
        for location in xml_loc_values(&xml) {
            let Ok(url) = current.join(&location) else {
                continue;
            };
            if crawl_host(&url) != start_host
                || !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                continue;
            }
            if is_index {
                if sitemaps.len() + seen_sitemaps.len() < 20 {
                    sitemaps.push_back(url);
                }
            } else if pages.len() < limit {
                pages.push(url);
            }
        }
    }
    pages
}

fn xml_loc_values(xml: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = xml;
    while let Some(start) = find_ascii_case_insensitive(rest, "<loc>") {
        rest = &rest[start + 5..];
        let Some(end) = find_ascii_case_insensitive(rest, "</loc>") else {
            break;
        };
        let value = html_escape::decode_html_entities(rest[..end].trim()).into_owned();
        if !value.is_empty() {
            values.push(value);
        }
        rest = &rest[end + 6..];
    }
    values
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn crawl_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    host.strip_prefix("www.").unwrap_or(&host).to_owned()
}

fn browser_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
    );
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("zh-CN,zh;q=0.9,en;q=0.8"),
    );
    headers
}

fn external_link_key(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    url.set_fragment(None);
    Some(url.to_string())
}

async fn check_external_link(
    value: &str,
    timeout: Duration,
    user_agent: &str,
    renderer_url: &str,
    renderer_api_key: Option<&str>,
) -> LinkCheck {
    let started = Instant::now();
    let mut current = match Url::parse(value) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => url,
        _ => {
            return LinkCheck {
                status_code: None,
                duration_ms: started.elapsed().as_millis(),
                accessible: Some(false),
                error: Some("Unsupported external URL".into()),
            };
        }
    };
    if !current.username().is_empty() || current.password().is_some() {
        return LinkCheck {
            status_code: None,
            duration_ms: started.elapsed().as_millis(),
            accessible: Some(false),
            error: Some("URLs containing credentials are not allowed".into()),
        };
    }

    let mut use_get = false;
    let mut final_status = None;
    let mut failure = None;
    for hop in 0..6 {
        if !current.username().is_empty() || current.password().is_some() {
            failure = Some("URLs containing credentials are not allowed".into());
            break;
        }
        let addresses = match resolve_public_host(&current).await {
            Ok(addresses) => addresses,
            Err(message) => {
                failure = Some(message);
                break;
            }
        };
        let Some(host) = current.host_str() else {
            failure = Some("URL has no host".into());
            break;
        };
        let client = match Client::builder()
            .redirect(Policy::none())
            .timeout(timeout)
            .user_agent(user_agent)
            .default_headers(browser_headers())
            .resolve_to_addrs(host, &addresses)
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                failure = Some(err.to_string());
                break;
            }
        };
        let request = if use_get {
            client
                .get(current.clone())
                .header(reqwest::header::RANGE, "bytes=0-0")
        } else {
            client.head(current.clone())
        };
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                if !use_get && status.is_client_error() || !use_get && status.is_server_error() {
                    use_get = true;
                    continue;
                }
                if status.is_redirection() {
                    if hop == 5 {
                        final_status = Some(status.as_u16());
                        failure = Some("Too many redirects".into());
                        break;
                    }
                    let Some(location) = response
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                    else {
                        final_status = Some(status.as_u16());
                        failure = Some("Redirect response has no valid Location".into());
                        break;
                    };
                    match current.join(location) {
                        Ok(next) if matches!(next.scheme(), "http" | "https") => current = next,
                        _ => {
                            final_status = Some(status.as_u16());
                            failure = Some("Redirect target is not HTTP or HTTPS".into());
                            break;
                        }
                    }
                    continue;
                }
                final_status = Some(status.as_u16());
                break;
            }
            Err(err) => {
                failure = Some(err.to_string());
                break;
            }
        }
    }
    let accessible = Some(final_status.is_some_and(|status| status < 400));
    if failure.is_none() && final_status.is_some_and(|status| status >= 400) {
        failure = final_status.map(|status| format!("HTTP {status}"));
    }
    let mut result = LinkCheck {
        status_code: final_status,
        duration_ms: started.elapsed().as_millis(),
        accessible,
        error: failure,
    };
    if result.accessible != Some(true)
        && let Some(rendered) = request_renderer(renderer_url, renderer_api_key, value).await
    {
        result.duration_ms = started.elapsed().as_millis();
        if rendered.accessible {
            result.status_code = rendered.status_code;
            result.accessible = Some(true);
            result.error = None;
        } else if rendered.challenge {
            result.status_code = rendered.status_code.or(result.status_code);
            result.accessible = Some(false);
            result.error = Some("Browser rendering reached an access challenge".into());
        } else if rendered.status_code.is_some() {
            result.status_code = rendered.status_code;
            result.accessible = Some(false);
            result.error = rendered.error;
        }
    }
    result
}

#[derive(Deserialize)]
struct RendererResponse {
    url: String,
    status_code: Option<u16>,
    accessible: bool,
    challenge: bool,
    html: Option<String>,
    error: Option<String>,
}

async fn request_renderer(
    renderer_url: &str,
    api_key: Option<&str>,
    url: &str,
) -> Option<RendererResponse> {
    let client = Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .ok()?;
    let mut request = client
        .post(format!("{}/v1/render", renderer_url.trim_end_matches('/')))
        .json(&serde_json::json!({"url": url}));
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    request
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()
}

async fn crawl_page(url: Url, depth: usize, config: &Config) -> (PageRecord, usize) {
    let started = Instant::now();
    let mut current = url.clone();
    let mut redirect_chain = Vec::new();
    let mut last_response = None;
    let mut ttfb_ms = None;
    let mut error = None;
    for _ in 0..6 {
        let addresses = match resolve_public_host(&current).await {
            Ok(addresses) => addresses,
            Err(message) => {
                error = Some(message);
                break;
            }
        };
        let Some(host) = current.host_str() else {
            error = Some("URL has no host".into());
            break;
        };
        let pinned_client = match Client::builder()
            .redirect(Policy::none())
            .timeout(config.request_timeout)
            .user_agent(&config.user_agent)
            .default_headers(browser_headers())
            .resolve_to_addrs(host, &addresses)
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                error = Some(err.to_string());
                break;
            }
        };
        let request_started = Instant::now();
        match pinned_client.get(current.clone()).send().await {
            Ok(response) => {
                if response.status().is_redirection() {
                    let Some(location) = response
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                    else {
                        ttfb_ms = Some(request_started.elapsed().as_millis());
                        last_response = Some(response);
                        break;
                    };
                    let Ok(next) = current.join(location) else {
                        error = Some("invalid redirect URL".into());
                        break;
                    };
                    redirect_chain.push(current.to_string());
                    current = next;
                } else {
                    ttfb_ms = Some(request_started.elapsed().as_millis());
                    last_response = Some(response);
                    break;
                }
            }
            Err(err) => {
                error = Some(err.to_string());
                break;
            }
        }
    }
    let mut status_code = None;
    let mut content_type = None;
    let mut title = None;
    let mut description = None;
    let mut canonical = None;
    let mut robots = None;
    let mut h1_count = 0;
    let mut content_text = String::new();
    let mut headings = Vec::new();
    let mut response_size_bytes = None;
    let mut links = Vec::new();
    if let Some(response) = last_response {
        status_code = Some(response.status().as_u16());
        content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("text/html")
        {
            match read_limited_body(response, config.max_body_bytes).await {
                Ok(bytes) => {
                    response_size_bytes = Some(bytes.len());
                    parse_html(
                        &current,
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
                Err(message) => error = Some(message),
            }
        }
    }
    if status_code.is_some_and(|status| status >= 400) || error.is_some() {
        if let Some(rendered) = request_renderer(
            &config.renderer_url,
            config.renderer_api_key.as_deref(),
            current.as_str(),
        )
        .await
        {
            if rendered.accessible {
                if let (Some(html), Ok(rendered_url)) = (rendered.html, Url::parse(&rendered.url)) {
                    title = None;
                    description = None;
                    canonical = None;
                    robots = None;
                    h1_count = 0;
                    content_text.clear();
                    headings.clear();
                    links.clear();
                    response_size_bytes = Some(html.len());
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
                }
            } else if rendered.challenge {
                status_code = rendered.status_code.or(status_code);
                error = None;
            } else if rendered.status_code.is_some() {
                status_code = rendered.status_code;
                error = None;
            }
        }
    }
    (
        PageRecord {
            url: url.to_string(),
            status_code,
            title,
            description,
            canonical,
            robots,
            h1_count,
            content_text,
            headings,
            content_type,
            redirect_chain,
            ttfb_ms,
            response_size_bytes,
            links,
            depth,
            duration_ms: started.elapsed().as_millis(),
            error,
        },
        depth,
    )
}

fn parse_html(
    final_url: &Url,
    bytes: &[u8],
    title: &mut Option<String>,
    description: &mut Option<String>,
    canonical: &mut Option<String>,
    robots: &mut Option<String>,
    h1_count: &mut usize,
    content_text: &mut String,
    headings: &mut Vec<ContentHeading>,
    links: &mut Vec<LinkRecord>,
) {
    let html = String::from_utf8_lossy(bytes);
    let document = Html::parse_document(&html);
    let title_selector = Selector::parse("title").unwrap();
    let meta_selector = Selector::parse("meta[name]").unwrap();
    let canonical_selector = Selector::parse("link[rel~=canonical]").unwrap();
    let anchor_selector = Selector::parse("a[href]").unwrap();
    let h1_selector = Selector::parse("h1").unwrap();
    let content_selector = Selector::parse("main p, main h1, main h2, main h3, main h4, main li, main blockquote, main div, article p, article h1, article h2, article h3, article h4, article li, article blockquote, article div, body p, body h1, body h2, body h3, body h4, body li, body blockquote, body div").unwrap();
    *title = document
        .select(&title_selector)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string())
        .filter(|v| !v.is_empty());
    for meta in document.select(&meta_selector) {
        let name = meta.value().attr("name").unwrap_or("").to_ascii_lowercase();
        let content = meta
            .value()
            .attr("content")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if name == "description" {
            *description = content.clone();
        }
        if name == "robots" {
            *robots = content;
        }
    }
    *canonical = document
        .select(&canonical_selector)
        .next()
        .and_then(|el| el.value().attr("href"))
        .and_then(|href| final_url.join(href).ok())
        .map(|u| u.to_string());
    *h1_count = document.select(&h1_selector).count();
    let mut seen_blocks = HashSet::new();
    let mut content_char_count = 0usize;
    for element in document.select(&content_selector) {
        if element.select(&content_selector).next().is_some() {
            continue;
        }
        let mut is_boilerplate = false;
        for ancestor in element.ancestors() {
            if let Some(parent) = scraper::ElementRef::wrap(ancestor)
                && matches!(
                    parent.value().name(),
                    "nav"
                        | "footer"
                        | "header"
                        | "aside"
                        | "script"
                        | "style"
                        | "noscript"
                        | "form"
                )
            {
                is_boilerplate = true;
                break;
            }
        }
        if is_boilerplate {
            continue;
        }
        let text = element.text().collect::<Vec<_>>().join(" ");
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.is_empty() || !seen_blocks.insert(text.clone()) {
            continue;
        }
        let tag = element.value().name();
        if let Some(level) = tag.strip_prefix('h').and_then(|n| n.parse::<u8>().ok()) {
            if level <= 4 && headings.len() < 100 {
                headings.push(ContentHeading {
                    level,
                    text: text.clone(),
                });
            }
        }
        if content_char_count < 12_000 {
            if !content_text.is_empty() {
                content_text.push('\n');
                content_char_count += 1;
            }
            let remaining = 12_000usize.saturating_sub(content_char_count);
            let block = text.chars().take(remaining).collect::<String>();
            content_char_count += block.chars().count();
            content_text.push_str(&block);
        }
    }
    let host = final_url
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    for (position, anchor) in document.select(&anchor_selector).enumerate() {
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        let Ok(target) = final_url.join(href) else {
            continue;
        };
        if !matches!(target.scheme(), "http" | "https") {
            continue;
        }
        let target_host = target.host_str().unwrap_or_default().to_ascii_lowercase();
        let target_host = target_host.strip_prefix("www.").unwrap_or(&target_host);
        links.push(LinkRecord {
            url: target.to_string(),
            text: html_escape::decode_html_entities(&anchor.text().collect::<String>())
                .trim()
                .to_string(),
            position: position + 1,
            rel: anchor
                .value()
                .attr("rel")
                .unwrap_or("")
                .split_ascii_whitespace()
                .map(str::to_ascii_lowercase)
                .collect(),
            is_internal: target_host == host,
            status_code: None,
            duration_ms: None,
            accessible: None,
            error: None,
        });
    }
}

fn crawl_key(url: &Url) -> String {
    let mut key = url.clone();
    key.set_fragment(None);
    let host_without_www = key
        .host_str()
        .and_then(|host| host.strip_prefix("www."))
        .map(str::to_owned);
    if let Some(host) = host_without_www {
        let _ = key.set_host(Some(&host));
    }
    key.to_string()
}

fn normalize_url(value: &str) -> Result<Url, String> {
    let mut url = Url::parse(value)
        .map_err(|_| "start_url must be an absolute HTTP or HTTPS URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("only HTTP and HTTPS URLs are supported".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs containing credentials are not allowed".into());
    }
    url.set_fragment(None);
    Ok(url)
}

async fn resolve_public_host(url: &Url) -> Result<Vec<SocketAddr>, String> {
    let host = url.host_str().ok_or("URL has no host")?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_public_ip(ip) {
            Ok(vec![SocketAddr::new(
                ip,
                url.port_or_known_default().ok_or("unsupported URL port")?,
            )])
        } else {
            Err("private or reserved network targets are not allowed".into())
        };
    }
    let port = url.port_or_known_default().ok_or("unsupported URL port")?;
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| "host could not be resolved".to_string())?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("host resolves to a private or reserved address".into());
    }
    Ok(addresses)
}

async fn read_limited_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| err.to_string())? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err("response body exceeds configured limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                || (ip.octets()[0] >= 224))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(ipv4));
            }
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.segments()[0] & 0xff00 == 0xff00)
        }
    }
}
