use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{Request, StatusCode, header::AUTHORIZATION},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

mod content;

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub api_key: Option<String>,
    pub max_analyses: usize,
    pub max_pages: usize,
    pub max_batch_pages: usize,
    pub max_body_bytes: usize,
    pub task_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let listen: SocketAddr = std::env::var("ANALYZER_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8091".into())
            .parse()?;
        let api_key = std::env::var("ANALYZER_API_KEY")
            .ok()
            .filter(|value| !value.is_empty());
        if !listen.ip().is_loopback() && api_key.is_none() {
            return Err(
                "ANALYZER_API_KEY is required when listening on a non-loopback address".into(),
            );
        }
        Ok(Self {
            listen,
            api_key,
            max_analyses: env_usize("ANALYZER_MAX_ANALYSES", 32).clamp(1, 256),
            max_pages: env_usize("ANALYZER_MAX_PAGES", 10_000).clamp(1, 100_000),
            max_batch_pages: env_usize("ANALYZER_MAX_BATCH_PAGES", 250).clamp(1, 2_000),
            max_body_bytes: env_usize("ANALYZER_MAX_BODY_BYTES", 8_000_000)
                .clamp(16_384, 64_000_000),
            task_ttl: Duration::from_secs(
                env_usize("ANALYZER_TASK_TTL_SECONDS", 3600).clamp(60, 86_400) as u64,
            ),
        })
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone)]
pub struct AppState {
    config: Config,
    tasks: Arc<RwLock<HashMap<Uuid, Arc<RwLock<AnalysisTask>>>>>,
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
                    matches!(task.status, AnalysisStatus::Analyzing) || task.updated_at > cutoff
                })
                .unwrap_or(true)
        });
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/v1/analyses", post(create_analysis))
        .route(
            "/v1/analyses/{analysis_id}/pages",
            get(get_pages).post(add_pages),
        )
        .route(
            "/v1/analyses/{analysis_id}/complete",
            post(complete_analysis),
        )
        .route("/v1/analyses/{analysis_id}", get(get_analysis))
        .route("/v1/analyses/{analysis_id}/issues", get(get_issues))
        .layer(DefaultBodyLimit::max(state.config.max_body_bytes))
        .layer(from_fn_with_state(
            state.config.api_key.clone(),
            require_api_key,
        ));
    Router::new()
        .route("/healthz", get(health))
        .merge(api)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn require_api_key(
    axum::extract::State(expected): axum::extract::State<Option<String>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Some(expected) = expected {
        let valid = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|provided| {
                provided.len() == expected.len()
                    && bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
            });
        if !valid {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "unauthorized",
                    message: "valid bearer token required".into(),
                }),
            )
                .into_response();
        }
    }
    next.run(request).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Receiving,
    Analyzing,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PageInput {
    pub url: String,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub canonical: Option<String>,
    #[serde(default)]
    pub robots: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub redirect_chain: Vec<String>,
    #[serde(default)]
    pub h1_count: usize,
    #[serde(default)]
    pub content_text: Option<String>,
    #[serde(default)]
    pub headings: Vec<InputHeading>,
    #[serde(default)]
    pub links: Vec<LinkInput>,
    #[serde(default)]
    pub depth: usize,
    #[serde(default)]
    pub duration_ms: Option<u128>,
    #[serde(default)]
    pub ttfb_ms: Option<u128>,
    #[serde(default)]
    pub response_size_bytes: Option<usize>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InputHeading {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkInput {
    pub url: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub position: usize,
    #[serde(default)]
    pub rel: Vec<String>,
    #[serde(default)]
    pub is_internal: bool,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub duration_ms: Option<u128>,
    #[serde(default)]
    pub accessible: Option<bool>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAnalysisRequest {
    #[serde(default)]
    pub source_crawl_id: Option<String>,
    #[serde(default)]
    pub expected_pages: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct AddPagesRequest {
    pub pages: Vec<PageInput>,
}

#[derive(Debug, Deserialize)]
pub struct IssueQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PageIssue {
    pub code: String,
    pub severity: Severity,
    pub url: String,
    pub target_url: Option<String>,
    pub anchor_text: Option<String>,
    pub link_position: Option<usize>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub pages_analyzed: usize,
    pub failed_pages: usize,
    pub internal_links: usize,
    pub external_links: usize,
    pub orphan_pages: usize,
    pub issue_counts: BTreeMap<String, usize>,
    pub content_analysis: content::ContentAnalysis,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisView {
    pub analysis_id: Uuid,
    pub source_crawl_id: Option<String>,
    pub status: AnalysisStatus,
    pub pages_received: usize,
    pub expected_pages: Option<usize>,
    pub summary: Option<AnalysisSummary>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssueBatch {
    pub analysis_id: Uuid,
    pub issues: Vec<PageIssue>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PageAudit {
    pub url: String,
    pub depth: usize,
    pub inbound_link_count: usize,
    pub status_code: Option<u16>,
    pub load_duration_ms: Option<u128>,
    pub ttfb_ms: Option<u128>,
    pub response_size_bytes: Option<usize>,
    pub h1_count: usize,
    pub is_dead_page: bool,
    pub error: Option<String>,
    pub title: Option<String>,
    pub content: content::ContentPageMetrics,
    pub internal_link_count: usize,
    pub external_link_count: usize,
    pub broken_internal_links: Vec<String>,
    pub internal_links: Vec<InternalLinkAudit>,
    pub external_links: Vec<ExternalLinkAudit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InternalLinkAudit {
    pub url: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalLinkAudit {
    pub url: String,
    pub text: String,
    pub status_code: Option<u16>,
    pub duration_ms: Option<u128>,
    pub accessible: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageAuditBatch {
    pub analysis_id: Uuid,
    pub pages: Vec<PageAudit>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

struct AnalysisTask {
    id: Uuid,
    source_crawl_id: Option<String>,
    expected_pages: Option<usize>,
    status: AnalysisStatus,
    pages: Vec<PageInput>,
    pages_received: usize,
    page_urls: HashSet<String>,
    result: Option<AnalysisResult>,
    error: Option<String>,
    updated_at: Instant,
}

impl AnalysisTask {
    fn view(&self) -> AnalysisView {
        AnalysisView {
            analysis_id: self.id,
            source_crawl_id: self.source_crawl_id.clone(),
            status: self.status.clone(),
            pages_received: self.pages_received,
            expected_pages: self.expected_pages,
            summary: self.result.as_ref().map(|result| result.summary.clone()),
            error: self.error.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct AnalysisResult {
    summary: AnalysisSummary,
    issues: Vec<PageIssue>,
    pages: Vec<PageAudit>,
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
    #[error("analysis not found")]
    NotFound,
    #[error("analysis is not accepting pages in its current state")]
    Conflict,
    #[error("service is at capacity")]
    Capacity,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "analysis_not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "invalid_analysis_state"),
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

async fn create_analysis(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateAnalysisRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if request
        .expected_pages
        .is_some_and(|count| count > state.config.max_pages)
    {
        return Err(ApiError::BadRequest(
            "expected_pages exceeds configured maximum".into(),
        ));
    }
    let id = Uuid::new_v4();
    let task = Arc::new(RwLock::new(AnalysisTask {
        id,
        source_crawl_id: request.source_crawl_id,
        expected_pages: request.expected_pages,
        status: AnalysisStatus::Receiving,
        pages: Vec::new(),
        pages_received: 0,
        page_urls: HashSet::new(),
        result: None,
        error: None,
        updated_at: Instant::now(),
    }));
    {
        let mut tasks = state.tasks.write().await;
        if tasks.len() >= state.config.max_analyses {
            return Err(ApiError::Capacity);
        }
        tasks.insert(id, task);
    }
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "analysis_id": id, "status": "receiving" })),
    ))
}

async fn add_pages(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(request): Json<AddPagesRequest>,
) -> Result<Json<AnalysisView>, ApiError> {
    if request.pages.len() > state.config.max_batch_pages {
        return Err(ApiError::BadRequest(
            "batch exceeds configured page limit".into(),
        ));
    }
    let prepared = request
        .pages
        .into_iter()
        .map(|page| {
            let key = normalize_url(&page.url)
                .ok_or_else(|| ApiError::BadRequest(format!("invalid page URL: {}", page.url)))?;
            Ok((key, page))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let task = find_task(&state, id).await?;
    let mut task = task.write().await;
    if !matches!(task.status, AnalysisStatus::Receiving) {
        return Err(ApiError::Conflict);
    }
    let new_count = prepared
        .iter()
        .filter(|(key, _)| !task.page_urls.contains(key))
        .map(|(key, _)| key)
        .collect::<HashSet<_>>()
        .len();
    if task.pages.len() + new_count > state.config.max_pages {
        return Err(ApiError::BadRequest(
            "analysis exceeds configured page limit".into(),
        ));
    }
    for (key, page) in prepared {
        if task.page_urls.insert(key) {
            task.pages.push(page);
        }
    }
    task.pages_received = task.pages.len();
    task.updated_at = Instant::now();
    Ok(Json(task.view()))
}

async fn complete_analysis(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<AnalysisView>), ApiError> {
    let task = find_task(&state, id).await?;
    let pages = {
        let mut task_guard = task.write().await;
        if !matches!(task_guard.status, AnalysisStatus::Receiving) {
            return Err(ApiError::Conflict);
        }
        task_guard.status = AnalysisStatus::Analyzing;
        task_guard.updated_at = Instant::now();
        std::mem::take(&mut task_guard.pages)
    };
    let task_for_work = task.clone();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || analyze_pages(&pages)).await;
        let mut task = task_for_work.write().await;
        match result {
            Ok(result) => {
                task.result = Some(result);
                task.status = AnalysisStatus::Completed;
            }
            Err(error) => {
                task.error = Some(error.to_string());
                task.status = AnalysisStatus::Failed;
            }
        }
        task.updated_at = Instant::now();
    });
    Ok((StatusCode::ACCEPTED, Json(task.read().await.view())))
}

async fn get_analysis(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AnalysisView>, ApiError> {
    let task = find_task(&state, id).await?;
    Ok(Json(task.read().await.view()))
}

async fn get_issues(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<IssueQuery>,
) -> Result<Json<IssueBatch>, ApiError> {
    let task = find_task(&state, id).await?;
    let task = task.read().await;
    let result = task.result.as_ref().ok_or(ApiError::Conflict)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| ApiError::BadRequest("invalid cursor".into()))
        })
        .transpose()?
        .unwrap_or(0);
    if cursor > result.issues.len() {
        return Err(ApiError::BadRequest(
            "cursor is past the end of results".into(),
        ));
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let end = (cursor + limit).min(result.issues.len());
    Ok(Json(IssueBatch {
        analysis_id: id,
        issues: result.issues[cursor..end].to_vec(),
        next_cursor: (end < result.issues.len()).then(|| end.to_string()),
        has_more: end < result.issues.len(),
    }))
}

async fn get_pages(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<IssueQuery>,
) -> Result<Json<PageAuditBatch>, ApiError> {
    let task = find_task(&state, id).await?;
    let task = task.read().await;
    let result = task.result.as_ref().ok_or(ApiError::Conflict)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| ApiError::BadRequest("invalid cursor".into()))
        })
        .transpose()?
        .unwrap_or(0);
    if cursor > result.pages.len() {
        return Err(ApiError::BadRequest(
            "cursor is past the end of pages".into(),
        ));
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let end = (cursor + limit).min(result.pages.len());
    Ok(Json(PageAuditBatch {
        analysis_id: id,
        pages: result.pages[cursor..end].to_vec(),
        next_cursor: (end < result.pages.len()).then(|| end.to_string()),
        has_more: end < result.pages.len(),
    }))
}

async fn find_task(state: &AppState, id: Uuid) -> Result<Arc<RwLock<AnalysisTask>>, ApiError> {
    state
        .tasks
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)
}

fn analyze_pages(pages: &[PageInput]) -> AnalysisResult {
    let mut issues = Vec::new();
    let mut url_to_page = HashMap::new();
    let mut incoming = HashMap::<String, usize>::new();
    let mut internal_links = 0;
    let mut external_links = 0;
    let mut failed_pages = 0;
    let mut failed_urls = HashSet::new();

    for (index, page) in pages.iter().enumerate() {
        let page_url = normalize_url(&page.url).unwrap_or_else(|| page.url.clone());
        url_to_page.insert(page_url.clone(), index);
        if page.error.is_some() || page.status_code.is_some_and(|status| status >= 400) {
            failed_pages += 1;
            failed_urls.insert(page_url);
        }
    }

    for page in pages {
        let page_url = normalize_url(&page.url).unwrap_or_else(|| page.url.clone());
        if page.error.is_some() {
            push_issue(
                &mut issues,
                "fetch_error",
                Severity::Error,
                &page_url,
                None,
                "The crawler could not fetch this page.",
            );
        }
        if let Some(status) = page.status_code.filter(|status| *status >= 400) {
            let (code, severity, message) = match status {
                401 | 403 | 429 => (
                    "page_access_restricted",
                    Severity::Warning,
                    format!(
                        "The page returned HTTP {status} to the crawler; automated access may be restricted."
                    ),
                ),
                404 | 410 => (
                    "http_error",
                    Severity::Error,
                    format!("The page returned HTTP {status}."),
                ),
                500..=599 => (
                    "page_server_error",
                    Severity::Warning,
                    format!("The page returned HTTP {status} during the scan."),
                ),
                _ => (
                    "http_error",
                    Severity::Warning,
                    format!("The page returned HTTP {status} to the crawler."),
                ),
            };
            push_issue(&mut issues, code, severity, &page_url, None, &message);
        }
        if is_blank(&page.title) {
            push_issue(
                &mut issues,
                "missing_title",
                Severity::Warning,
                &page_url,
                None,
                "The page has no title.",
            );
        }
        if let Some(title) = page
            .title
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let length = title.chars().count();
            if !(15..=60).contains(&length) {
                push_issue(
                    &mut issues,
                    if length < 30 {
                        "short_title"
                    } else {
                        "long_title"
                    },
                    Severity::Info,
                    &page_url,
                    None,
                    &format!("The title has {length} characters; a common guideline is 15–60."),
                );
            }
        }
        if is_blank(&page.description) {
            push_issue(
                &mut issues,
                "missing_description",
                Severity::Warning,
                &page_url,
                None,
                "The page has no meta description.",
            );
        }
        if let Some(description) = page
            .description
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let length = description.chars().count();
            if !(50..=160).contains(&length) {
                push_issue(
                    &mut issues,
                    if length < 70 {
                        "short_description"
                    } else {
                        "long_description"
                    },
                    Severity::Info,
                    &page_url,
                    None,
                    &format!(
                        "The meta description has {length} characters; a common guideline is 50–160."
                    ),
                );
            }
        }
        let is_html_page = page
            .content_type
            .as_deref()
            .is_none_or(|content_type| content_type.to_ascii_lowercase().contains("text/html"));
        if is_html_page
            && page
                .status_code
                .is_none_or(|status| (200..400).contains(&status))
        {
            match page.h1_count {
                0 => push_issue(
                    &mut issues,
                    "missing_h1",
                    Severity::Warning,
                    &page_url,
                    None,
                    "The page has no H1 heading.",
                ),
                2.. => push_issue(
                    &mut issues,
                    "multiple_h1",
                    Severity::Info,
                    &page_url,
                    None,
                    &format!("The page has {} H1 headings.", page.h1_count),
                ),
                _ => {}
            }
        }
        if is_blank(&page.canonical) {
            push_issue(
                &mut issues,
                "missing_canonical",
                Severity::Info,
                &page_url,
                None,
                "The page has no canonical URL.",
            );
        }
        if page.robots.as_deref().is_some_and(has_noindex) {
            push_issue(
                &mut issues,
                "noindex",
                Severity::Warning,
                &page_url,
                None,
                "The page has a noindex directive.",
            );
        }
        if let Some(canonical) = page.canonical.as_deref()
            && let Some(canonical_key) = normalize_url(canonical)
            && canonical_key != page_url
            && let Some(target_page) = url_to_page.get(&canonical_key).map(|index| &pages[*index])
        {
            if target_page.error.is_some()
                || target_page
                    .status_code
                    .is_some_and(|status| matches!(status, 404 | 410))
            {
                push_issue(
                    &mut issues,
                    "canonical_target_failed",
                    Severity::Warning,
                    &page_url,
                    Some(&canonical_key),
                    "The canonical URL points to a page that failed to load.",
                );
            } else if !target_page.redirect_chain.is_empty() {
                push_issue(
                    &mut issues,
                    "canonical_target_redirects",
                    Severity::Info,
                    &page_url,
                    Some(&canonical_key),
                    "The canonical URL redirects to another URL.",
                );
            }
        }
        for link in &page.links {
            if link.is_internal {
                internal_links += 1;
                if let Some(target) = normalize_url(&link.url) {
                    *incoming.entry(target.clone()).or_default() += 1;
                    if let Some(target_page) = url_to_page.get(&target).map(|index| &pages[*index])
                        && (target_page.error.is_some()
                            || target_page.status_code.is_some_and(|status| status >= 400))
                    {
                        let status = target_page.status_code.unwrap_or_default();
                        let (code, severity, message) = match status {
                            0 => (
                                "broken_internal_link",
                                Severity::Error,
                                "An internal link points to a page the crawler could not fetch.",
                            ),
                            401 | 403 | 429 => (
                                "internal_link_access_restricted",
                                Severity::Warning,
                                "An internal link returned an access-restricted response.",
                            ),
                            404 | 410 => (
                                "broken_internal_link",
                                Severity::Error,
                                "An internal link points to a missing page.",
                            ),
                            500..=599 => (
                                "internal_link_server_error",
                                Severity::Warning,
                                "An internal link points to a page with a server error.",
                            ),
                            _ => (
                                "broken_internal_link",
                                Severity::Warning,
                                "An internal link points to a page that returned an error.",
                            ),
                        };
                        push_issue(
                            &mut issues,
                            code,
                            severity,
                            &page_url,
                            Some(&target),
                            message,
                        );
                        if let Some(issue) = issues.last_mut() {
                            issue.anchor_text =
                                (!link.text.trim().is_empty()).then(|| link.text.trim().to_owned());
                            issue.link_position = Some(link.position);
                        }
                    }
                }
            } else {
                external_links += 1;
                if link.accessible == Some(false) {
                    let (code, severity, message) = match link.status_code {
                        Some(status @ (404 | 410)) => (
                            "external_link_not_found_response",
                            Severity::Warning,
                            format!(
                                "The destination returned HTTP {status} to the crawler; confirm in a browser because automated checks can receive a different response."
                            ),
                        ),
                        Some(status @ (401 | 403 | 429)) => (
                            "external_link_access_restricted",
                            Severity::Warning,
                            format!(
                                "The destination returned HTTP {status}, which may block automated checks."
                            ),
                        ),
                        Some(status @ 500..=599) => (
                            "external_link_server_error",
                            Severity::Warning,
                            format!("The destination returned HTTP {status} during the scan."),
                        ),
                        Some(status) => (
                            "external_link_check_failed",
                            Severity::Warning,
                            format!("The destination returned HTTP {status} during the scan."),
                        ),
                        None => (
                            "external_link_check_failed",
                            Severity::Warning,
                            format!(
                                "The crawler could not verify this destination: {}.",
                                link.error.as_deref().unwrap_or("request failed")
                            ),
                        ),
                    };
                    push_issue(
                        &mut issues,
                        code,
                        severity,
                        &page_url,
                        Some(&link.url),
                        &message,
                    );
                    if let Some(issue) = issues.last_mut() {
                        issue.anchor_text =
                            (!link.text.trim().is_empty()).then(|| link.text.trim().to_owned());
                        issue.link_position = Some(link.position);
                    }
                }
            }
        }
    }

    add_duplicate_issues(
        pages,
        &mut issues,
        |page| page.title.as_deref(),
        "duplicate_title",
        "The title is shared by multiple pages.",
    );
    add_duplicate_issues(
        pages,
        &mut issues,
        |page| page.description.as_deref(),
        "duplicate_description",
        "The meta description is shared by multiple pages.",
    );
    add_duplicate_issues(
        pages,
        &mut issues,
        |page| page.canonical.as_deref(),
        "duplicate_canonical",
        "The canonical URL is shared by multiple pages.",
    );

    let mut orphan_pages = 0;
    for page in pages {
        let key = normalize_url(&page.url).unwrap_or_else(|| page.url.clone());
        if page.depth > 0 && incoming.get(&key).copied().unwrap_or_default() == 0 {
            orphan_pages += 1;
            push_issue(
                &mut issues,
                "orphan_page",
                Severity::Warning,
                &key,
                None,
                "No crawled page links to this page.",
            );
        }
    }

    let (content_analysis, content_metrics) = content::analyze(pages, &incoming);
    let page_audits = pages
        .iter()
        .zip(content_metrics)
        .map(|(page, content)| {
            let url = normalize_url(&page.url).unwrap_or_else(|| page.url.clone());
            let broken_internal_links = page
                .links
                .iter()
                .filter(|link| link.is_internal)
                .filter_map(|link| normalize_url(&link.url))
                .filter(|target| failed_urls.contains(target))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut broken_internal_links = broken_internal_links;
            broken_internal_links.sort();
            let inbound_link_count = incoming.get(&url).copied().unwrap_or_default();
            PageAudit {
                url,
                depth: page.depth,
                inbound_link_count,
                status_code: page.status_code,
                load_duration_ms: page.duration_ms,
                ttfb_ms: page.ttfb_ms,
                response_size_bytes: page.response_size_bytes,
                h1_count: page.h1_count,
                is_dead_page: page.error.is_some()
                    || page
                        .status_code
                        .is_some_and(|status| matches!(status, 404 | 410)),
                error: page.error.clone(),
                title: page.title.clone(),
                content,
                internal_link_count: page.links.iter().filter(|link| link.is_internal).count(),
                external_link_count: page.links.iter().filter(|link| !link.is_internal).count(),
                broken_internal_links,
                internal_links: page
                    .links
                    .iter()
                    .filter(|link| link.is_internal)
                    .filter_map(|link| {
                        normalize_url(&link.url).map(|url| InternalLinkAudit {
                            url,
                            text: link.text.clone(),
                        })
                    })
                    .collect(),
                external_links: page
                    .links
                    .iter()
                    .filter(|link| !link.is_internal)
                    .map(|link| ExternalLinkAudit {
                        url: link.url.clone(),
                        text: link.text.clone(),
                        status_code: link.status_code,
                        duration_ms: link.duration_ms,
                        accessible: link.accessible,
                        error: link.error.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    issues.sort_by(|a, b| (&a.url, &a.code, &a.target_url).cmp(&(&b.url, &b.code, &b.target_url)));
    let mut issue_counts = BTreeMap::new();
    for issue in &issues {
        *issue_counts.entry(issue.code.clone()).or_insert(0) += 1;
    }
    AnalysisResult {
        summary: AnalysisSummary {
            pages_analyzed: pages.len(),
            failed_pages,
            internal_links,
            external_links,
            orphan_pages,
            issue_counts,
            content_analysis,
        },
        issues,
        pages: page_audits,
    }
}

fn add_duplicate_issues(
    pages: &[PageInput],
    issues: &mut Vec<PageIssue>,
    value: impl Fn(&PageInput) -> Option<&str>,
    code: &'static str,
    message: &'static str,
) {
    let mut groups = HashMap::<String, Vec<String>>::new();
    for page in pages {
        let Some(value) = value(page).map(str::trim).filter(|value| !value.is_empty()) else {
            continue;
        };
        groups
            .entry(
                value
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase(),
            )
            .or_default()
            .push(normalize_url(&page.url).unwrap_or_else(|| page.url.clone()));
    }
    for urls in groups.values().filter(|urls| urls.len() > 1) {
        for url in urls {
            push_issue(issues, code, Severity::Warning, url, None, message);
        }
    }
}

fn push_issue(
    issues: &mut Vec<PageIssue>,
    code: &'static str,
    severity: Severity,
    url: &str,
    target_url: Option<&str>,
    message: &str,
) {
    issues.push(PageIssue {
        code: code.into(),
        severity,
        url: url.into(),
        target_url: target_url.map(str::to_owned),
        anchor_text: None,
        link_position: None,
        message: message.into(),
    });
}

fn is_blank(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|value| value.trim().is_empty())
}

fn has_noindex(value: &str) -> bool {
    value
        .split([',', ' ', '\t', '\n'])
        .any(|directive| directive.eq_ignore_ascii_case("noindex"))
}

fn normalize_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}
