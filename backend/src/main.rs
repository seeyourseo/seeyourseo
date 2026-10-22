use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use tokio::sync::RwLock;
use tower_http::{services::ServeDir, trace::TraceLayer};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    http: Client,
    crawler: String,
    analyzer: String,
    crawler_key: Option<String>,
    analyzer_key: Option<String>,
    max_pages: usize,
    max_depth: usize,
    scans: Arc<RwLock<HashMap<Uuid, ScanView>>>,
}

#[derive(Clone, Serialize)]
struct ScanView {
    scan_id: Uuid,
    start_url: String,
    status: String,
    stage: String,
    progress: Option<Value>,
    summary: Option<Value>,
    issues: Vec<Value>,
    #[serde(skip_serializing)]
    pages: Vec<Value>,
    error: Option<String>,
    crawl_id: Option<String>,
    analysis_id: Option<String>,
    #[serde(skip)]
    finished_at: Option<Instant>,
}

const REPORT_RETENTION: Duration = Duration::from_secs(20 * 60);

#[derive(Deserialize)]
struct CreateScan {
    start_url: String,
    max_pages: Option<usize>,
    max_depth: Option<usize>,
}

#[derive(Deserialize)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<usize>,
}

#[derive(Debug)]
struct ServiceError(String);

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_GATEWAY, Json(json!({"error": self.0}))).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("install-services") => {
            return install_services(args.iter().any(|arg| arg == "--user"));
        }
        Some("uninstall-services") => {
            return uninstall_services(args.iter().any(|arg| arg == "--user"));
        }
        _ => {}
    }
    let listen: SocketAddr = env("WEB_LISTEN", "127.0.0.1:8080").parse()?;
    let state = AppState {
        http: Client::builder().timeout(Duration::from_secs(60)).build()?,
        crawler: env("CRAWLER_URL", "http://127.0.0.1:8090"),
        analyzer: env("ANALYZER_URL", "http://127.0.0.1:8091"),
        crawler_key: std::env::var("CRAWLER_API_KEY").ok(),
        analyzer_key: std::env::var("ANALYZER_API_KEY").ok(),
        max_pages: env("WEB_MAX_PAGES", "10000").parse().unwrap_or(10_000),
        max_depth: env("WEB_MAX_DEPTH", "20").parse().unwrap_or(20),
        scans: Arc::new(RwLock::new(HashMap::new())),
    };
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            purge_expired(&cleanup_state).await;
        }
    });
    let app = Router::new()
        .route("/", get(index))
        .route("/api/scans", post(create_scan))
        .route("/api/scans/{id}", get(get_scan))
        .route("/api/scans/{id}/pages", get(get_scan_pages))
        .route("/api/scans/{id}/blueprint", get(get_scan_blueprint))
        .route("/api/scans/{id}/download", get(download_scan))
        .nest_service("/assets", ServeDir::new("static"))
        .fallback(|| async { Redirect::to("/") })
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    eprintln!("Website service listening on {listen}");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

const SERVICES: [(&str, &str); 4] = [
    ("local.sitesissues.renderer", "site-renderer"),
    ("local.sitesissues.crawler", "site-crawler"),
    ("local.sitesissues.analyzer", "site-analyzer"),
    ("local.sitesissues.site-audit-server", "site-audit-server"),
];

fn service_manager(user: bool) -> Result<Box<dyn ServiceManager>, Box<dyn std::error::Error>> {
    let mut manager = <dyn ServiceManager>::native()?;
    if user {
        manager.set_level(service_manager::ServiceLevel::User)?;
    }
    Ok(manager)
}

fn install_services(user: bool) -> Result<(), Box<dyn std::error::Error>> {
    let manager = service_manager(user)?;
    let executable = std::env::current_exe()?;
    let bin_dir = executable
        .parent()
        .ok_or("cannot locate executable directory")?;
    let working_dir = bin_dir.to_path_buf();
    let environment = service_environment();
    let mut labels = Vec::new();

    for (label_text, binary) in SERVICES {
        let label: ServiceLabel = label_text.parse()?;
        let program = bin_dir.join(binary);
        if !program.is_file() {
            return Err(format!("missing service binary: {}", program.display()).into());
        }
        match manager.status(ServiceStatusCtx {
            label: label.clone(),
        })? {
            ServiceStatus::Running => manager.stop(ServiceStopCtx {
                label: label.clone(),
            })?,
            ServiceStatus::Stopped(_) => {}
            ServiceStatus::NotInstalled => {}
        }
        if !matches!(
            manager.status(ServiceStatusCtx {
                label: label.clone()
            })?,
            ServiceStatus::NotInstalled
        ) {
            manager.uninstall(ServiceUninstallCtx {
                label: label.clone(),
            })?;
        }
        manager.install(ServiceInstallCtx {
            label: label.clone(),
            program,
            args: vec![],
            contents: None,
            username: None,
            working_directory: Some(working_dir.clone()),
            environment: Some(environment.clone()),
            autostart: true,
            restart_policy: RestartPolicy::default(),
        })?;
        labels.push(label);
        eprintln!("Registered {label_text} (auto-start enabled)");
    }

    for label in labels {
        manager.start(ServiceStartCtx {
            label: label.clone(),
        })?;
        eprintln!("Started {label}");
    }
    Ok(())
}

fn uninstall_services(user: bool) -> Result<(), Box<dyn std::error::Error>> {
    let manager = service_manager(user)?;
    for (label_text, _) in SERVICES.into_iter().rev() {
        let label: ServiceLabel = label_text.parse()?;
        match manager.status(ServiceStatusCtx {
            label: label.clone(),
        })? {
            ServiceStatus::NotInstalled => {
                eprintln!("{label_text} is not installed");
                continue;
            }
            ServiceStatus::Running => manager.stop(ServiceStopCtx {
                label: label.clone(),
            })?,
            ServiceStatus::Stopped(_) => {}
        }
        manager.uninstall(ServiceUninstallCtx { label })?;
        eprintln!("Removed {label_text}");
    }
    Ok(())
}

fn service_environment() -> Vec<(String, String)> {
    [
        "WEB_LISTEN",
        "WEB_MAX_PAGES",
        "WEB_MAX_DEPTH",
        "CRAWLER_URL",
        "ANALYZER_URL",
        "CRAWLER_API_KEY",
        "ANALYZER_API_KEY",
        "CRAWLER_LISTEN",
        "CRAWLER_CONCURRENCY",
        "CRAWLER_MAX_PAGES",
        "CRAWLER_MAX_DEPTH",
        "CRAWLER_MAX_CRAWLS",
        "CRAWLER_MAX_EXTERNAL_LINK_CHECKS",
        "CRAWLER_MAX_BODY_BYTES",
        "CRAWLER_TASK_TTL_SECONDS",
        "CRAWLER_REQUEST_TIMEOUT_SECONDS",
        "CRAWLER_EXTERNAL_LINK_TIMEOUT_SECONDS",
        "CRAWLER_USER_AGENT",
        "RENDERER_LISTEN",
        "RENDERER_API_KEY",
        "RENDERER_CONCURRENCY",
        "RENDERER_TIMEOUT_SECONDS",
        "RENDERER_OBSCURA_PORT",
        "RENDERER_URL",
        "OBSCURA_BIN",
        "ANALYZER_LISTEN",
        "ANALYZER_MAX_ANALYSES",
        "ANALYZER_MAX_PAGES",
        "ANALYZER_MAX_BATCH_PAGES",
        "ANALYZER_MAX_BODY_BYTES",
        "ANALYZER_TASK_TTL_SECONDS",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect()
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn create_scan(
    State(state): State<AppState>,
    Json(input): Json<CreateScan>,
) -> Result<(StatusCode, Json<ScanView>), ServiceError> {
    let url = input.start_url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(ServiceError("Enter a complete HTTP or HTTPS URL.".into()));
    }
    let pages = input
        .max_pages
        .unwrap_or(state.max_pages)
        .clamp(1, state.max_pages);
    let depth = input
        .max_depth
        .unwrap_or(state.max_depth)
        .min(state.max_depth);
    let mut req = state
        .http
        .post(format!("{}/v1/crawls", state.crawler))
        .json(&json!({
            "start_url": url, "max_pages": pages, "max_depth": depth
        }));
    if let Some(key) = &state.crawler_key {
        req = req.bearer_auth(key);
    }
    let result = req.send().await.map_err(upstream)?;
    let status = result.status();
    let payload: Value = result.json().await.map_err(upstream)?;
    if !status.is_success() {
        return Err(ServiceError(format!(
            "Crawler rejected the scan: {}",
            payload
        )));
    }
    let crawl_id = payload["crawl_id"]
        .as_str()
        .ok_or_else(|| ServiceError("Crawler did not return a task ID.".into()))?
        .to_owned();
    let id = Uuid::new_v4();
    let view = ScanView {
        scan_id: id,
        start_url: url.to_owned(),
        status: "running".into(),
        stage: "crawling".into(),
        progress: None,
        summary: None,
        issues: vec![],
        pages: vec![],
        error: None,
        crawl_id: Some(crawl_id.clone()),
        analysis_id: None,
        finished_at: None,
    };
    state.scans.write().await.insert(id, view.clone());
    tokio::spawn(run_scan(state, id, crawl_id));
    Ok((StatusCode::ACCEPTED, Json(view)))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanView>, StatusCode> {
    purge_expired(&state).await;
    state
        .scans
        .read()
        .await
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_scan_pages(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, StatusCode> {
    purge_expired(&state).await;
    let scans = state.scans.read().await;
    let scan = scans.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    let cursor = query.cursor.unwrap_or(0);
    if cursor > scan.pages.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let end = (cursor + limit).min(scan.pages.len());
    Ok(Json(json!({
        "scan_id": id,
        "pages": &scan.pages[cursor..end],
        "next_cursor": (end < scan.pages.len()).then(|| end.to_string()),
        "has_more": end < scan.pages.len(),
    })))
}

async fn get_scan_blueprint(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    purge_expired(&state).await;
    let scans = state.scans.read().await;
    let scan = scans.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    if scan.status == "running" {
        return Err(StatusCode::CONFLICT);
    }
    const BLUEPRINT_PAGE_LIMIT: usize = 500;
    let pages = scan
        .pages
        .iter()
        .take(BLUEPRINT_PAGE_LIMIT)
        .map(|page| {
            json!({
                "url": page["url"],
                "title": page["title"],
                "depth": page["depth"],
                "inbound_link_count": page["inbound_link_count"],
                "word_count": page["content"]["word_count"],
                "keywords": page["content"]["keywords"],
                "headings": page["content"]["headings"],
                "internal_links": page["internal_links"],
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "pages": pages,
        "total_pages": scan.pages.len(),
        "truncated": scan.pages.len() > BLUEPRINT_PAGE_LIMIT,
    })))
}

async fn download_scan(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    purge_expired(&state).await;
    let scan = state
        .scans
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    if scan.status == "running" {
        return Err(StatusCode::CONFLICT);
    }
    let markdown = render_markdown(&scan);
    Ok((
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"site-audit-report.md\"",
            ),
        ],
        markdown,
    ))
}

async fn purge_expired(state: &AppState) {
    state.scans.write().await.retain(|_, scan| {
        scan.finished_at
            .is_none_or(|finished| finished.elapsed() < REPORT_RETENTION)
    });
}

fn render_markdown(scan: &ScanView) -> String {
    let mut out = format!(
        "# Website SEO audit report\n\n- **Website:** {}\n- **Status:** {}\n- **Scan ID:** `{}`\n- **Retention:** Report link remains available for 20 minutes after completion.\n\n",
        md_cell(&scan.start_url),
        md_cell(&scan.status),
        scan.scan_id
    );
    if let Some(error) = &scan.error {
        out.push_str(&format!("## Scan error\n\n{}\n\n", md_cell(error)));
    }
    let summary = scan.summary.as_ref().unwrap_or(&Value::Null);
    out.push_str("## Overview\n\n| Metric | Count |\n|---|---:|\n");
    for (label, key) in [
        ("Pages analyzed", "pages_analyzed"),
        ("Failed pages", "failed_pages"),
        ("Internal links", "internal_links"),
        ("External links", "external_links"),
        ("Orphan pages", "orphan_pages"),
    ] {
        out.push_str(&format!("| {label} | {} |\n", display_value(&summary[key])));
    }
    out.push_str("\n### Findings by severity\n\n| Severity | Count |\n|---|---:|\n");
    if let Some(counts) = summary["issue_counts"].as_object() {
        for (severity, count) in counts {
            out.push_str(&format!("| {} | {} |\n", md_cell(severity), display_value(count)));
        }
    }

    out.push_str("\n## Content analysis\n\n");
    let content = &summary["content_analysis"];
    out.push_str(&format!(
        "- Pages with text: {}\n- Thin content pages: {}\n- Similar page groups: {}\n- Keyword overlap groups: {}\n\n",
        display_value(&content["pages_with_content"]),
        display_value(&content["thin_content_pages"]),
        content["similar_content_groups"].as_array().map_or(0, Vec::len),
        content["keyword_overlap_groups"].as_array().map_or(0, Vec::len),
    ));
    out.push_str("### Popular keywords\n\n| Keyword | Occurrences |\n|---|---:|\n");
    if let Some(keywords) = content["top_keywords"].as_array() {
        for keyword in keywords {
            out.push_str(&format!(
                "| {} | {} |\n",
                md_cell(keyword["term"].as_str().unwrap_or("")),
                display_value(&keyword["frequency"])
            ));
        }
    }

    out.push_str("\n### Thin content pages\n\n| Page | Words | Internal links |\n|---|---:|---:|\n");
    if let Some(thin_pages) = content["thin_pages"].as_array() {
        for page in thin_pages {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                md_cell(page["url"].as_str().unwrap_or("")),
                display_value(&page["word_count"]),
                display_value(&page["inbound_links"]),
            ));
        }
    }
    append_content_groups(
        &mut out,
        "Similar page groups",
        &content["similar_content_groups"],
    );
    append_content_groups(
        &mut out,
        "Keyword overlap groups",
        &content["keyword_overlap_groups"],
    );

    out.push_str("\n## Issues\n\n");
    if scan.issues.is_empty() {
        out.push_str("No issues found.\n\n");
    } else {
        out.push_str("| Severity | Finding | Page | Target |\n|---|---|---|---|\n");
        for issue in &scan.issues {
            out.push_str(&format!(
                "| {} | {} ({}) | {} | {} |\n",
                md_cell(issue["severity"].as_str().unwrap_or("")),
                md_cell(issue["message"].as_str().unwrap_or("")),
                md_cell(issue["code"].as_str().unwrap_or("")),
                md_cell(issue["url"].as_str().unwrap_or("")),
                md_cell(issue["target_url"].as_str().unwrap_or("")),
            ));
        }
        out.push('\n');
    }

    out.push_str("## Pages\n\n| Page | HTTP | Load (ms) | TTFB (ms) | Size (bytes) | H1s | Broken internal links | External links |\n|---|---:|---:|---:|---:|---:|---:|---:|\n");
    for page in &scan.pages {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(page["url"].as_str().unwrap_or("")),
            display_value(&page["status_code"]),
            display_value(&page["load_duration_ms"]),
            display_value(&page["ttfb_ms"]),
            display_value(&page["response_size_bytes"]),
            display_value(&page["h1_count"]),
            page["broken_internal_links"].as_array().map_or(0, Vec::len),
            display_value(&page["external_link_count"]),
        ));
    }
    out.push('\n');
    out.push_str("### External link checks\n\n| Source page | Destination | Status | Accessible | Time (ms) |\n|---|---|---:|---|---:|\n");
    for page in &scan.pages {
        if let Some(links) = page["external_links"].as_array() {
            for link in links {
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    md_cell(page["url"].as_str().unwrap_or("")),
                    md_cell(link["url"].as_str().unwrap_or("")),
                    display_value(&link["status_code"]),
                    display_value(&link["accessible"]),
                    display_value(&link["duration_ms"]),
                ));
            }
        }
    }
    out
}

fn append_content_groups(out: &mut String, title: &str, value: &Value) {
    out.push_str(&format!("\n### {title}\n\n"));
    out.push_str("| Group | Recommended page | Pages | Notes |\n|---:|---|---|---|\n");
    if let Some(groups) = value.as_array() {
        for (index, group) in groups.iter().enumerate() {
            let pages = group["pages"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|page| page["url"].as_str())
                .map(md_cell)
                .collect::<Vec<_>>()
                .join("; ");
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                index + 1,
                md_cell(group["recommended_page"].as_str().unwrap_or("")),
                pages,
                md_cell(group["reason"].as_str().unwrap_or("")),
            ));
        }
    }
}

fn md_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace('\r', " ")
        .replace('\n', " ")
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "—".into(),
        Value::String(value) => md_cell(value),
        _ => value.to_string(),
    }
}

async fn run_scan(state: AppState, id: Uuid, crawl_id: String) {
    let result = run_pipeline(&state, id, &crawl_id).await;
    if let Err(error) = result {
        update(&state, id, |scan| {
            scan.status = "failed".into();
            scan.stage = "failed".into();
            scan.error = Some(error.0);
            scan.finished_at = Some(Instant::now());
        })
        .await;
    }
}

async fn run_pipeline(state: &AppState, id: Uuid, crawl_id: &str) -> Result<(), ServiceError> {
    loop {
        let crawl = service_get(
            state,
            &state.crawler,
            state.crawler_key.as_deref(),
            &format!("/v1/crawls/{crawl_id}"),
        )
        .await?;
        update(state, id, |scan| {
            scan.progress = Some(crawl["progress"].clone())
        })
        .await;
        match crawl["status"].as_str().unwrap_or("") {
            "completed" => break,
            "failed" | "cancelled" => {
                return Err(ServiceError(
                    crawl["error"]
                        .as_str()
                        .unwrap_or("Crawl task failed.")
                        .into(),
                ));
            }
            _ => tokio::time::sleep(Duration::from_millis(800)).await,
        }
    }
    update(state, id, |scan| scan.stage = "analyzing".into()).await;
    let created = service_post(
        state,
        &state.analyzer,
        state.analyzer_key.as_deref(),
        "/v1/analyses",
        json!({"source_crawl_id":crawl_id}),
    )
    .await?;
    let analysis_id = created["analysis_id"]
        .as_str()
        .ok_or_else(|| ServiceError("Analyzer did not return a task ID.".into()))?
        .to_owned();
    update(state, id, |scan| {
        scan.analysis_id = Some(analysis_id.clone())
    })
    .await;
    let mut cursor = "0".to_owned();
    loop {
        let batch = service_get(
            state,
            &state.crawler,
            state.crawler_key.as_deref(),
            &format!("/v1/crawls/{crawl_id}/pages?limit=50&cursor={cursor}"),
        )
        .await?;
        let pages = batch["pages"].as_array().cloned().unwrap_or_default();
        if !pages.is_empty() {
            service_post(
                state,
                &state.analyzer,
                state.analyzer_key.as_deref(),
                &format!("/v1/analyses/{analysis_id}/pages"),
                json!({"pages":pages}),
            )
            .await?;
        }
        if !batch["has_more"].as_bool().unwrap_or(false) {
            break;
        }
        cursor = batch["next_cursor"].as_str().unwrap_or("0").to_owned();
    }
    let _ = service_post(
        state,
        &state.analyzer,
        state.analyzer_key.as_deref(),
        &format!("/v1/analyses/{analysis_id}/complete"),
        json!({}),
    )
    .await?;
    let report = loop {
        let report = service_get(
            state,
            &state.analyzer,
            state.analyzer_key.as_deref(),
            &format!("/v1/analyses/{analysis_id}"),
        )
        .await?;
        update(state, id, |scan| {
            scan.summary = report["summary"]
                .as_object()
                .map(|_| report["summary"].clone())
        })
        .await;
        match report["status"].as_str().unwrap_or("") {
            "completed" => break report,
            "failed" => {
                return Err(ServiceError(
                    report["error"]
                        .as_str()
                        .unwrap_or("Analysis task failed.")
                        .into(),
                ));
            }
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    };
    let mut cursor = "0".to_owned();
    let mut issues = Vec::new();
    loop {
        let batch = service_get(
            state,
            &state.analyzer,
            state.analyzer_key.as_deref(),
            &format!("/v1/analyses/{analysis_id}/issues?limit=500&cursor={cursor}"),
        )
        .await?;
        issues.extend(batch["issues"].as_array().cloned().unwrap_or_default());
        if !batch["has_more"].as_bool().unwrap_or(false) {
            break;
        }
        cursor = batch["next_cursor"].as_str().unwrap_or("0").to_owned();
    }
    let mut cursor = "0".to_owned();
    let mut pages = Vec::new();
    loop {
        let batch = service_get(
            state,
            &state.analyzer,
            state.analyzer_key.as_deref(),
            &format!("/v1/analyses/{analysis_id}/pages?limit=500&cursor={cursor}"),
        )
        .await?;
        pages.extend(batch["pages"].as_array().cloned().unwrap_or_default());
        if !batch["has_more"].as_bool().unwrap_or(false) {
            break;
        }
        cursor = batch["next_cursor"].as_str().unwrap_or("0").to_owned();
    }
    update(state, id, |scan| {
        scan.status = "completed".into();
        scan.stage = "completed".into();
        scan.progress = Some(
            json!({"crawled":report["pages_received"], "discovered":report["pages_received"]}),
        );
        scan.summary = Some(report["summary"].clone());
        scan.issues = issues;
        scan.pages = pages;
        scan.finished_at = Some(Instant::now());
    })
    .await;
    Ok(())
}

async fn service_get(
    state: &AppState,
    base: &str,
    key: Option<&str>,
    path: &str,
) -> Result<Value, ServiceError> {
    let mut req = state.http.get(format!("{base}{path}"));
    if let Some(key) = key {
        req = req.bearer_auth(key);
    }
    let response = req.send().await.map_err(upstream)?;
    let status = response.status();
    let body: Value = response.json().await.map_err(upstream)?;
    if !status.is_success() {
        return Err(ServiceError(format!(
            "Upstream service returned {status}: {body}"
        )));
    }
    Ok(body)
}

async fn service_post(
    state: &AppState,
    base: &str,
    key: Option<&str>,
    path: &str,
    payload: Value,
) -> Result<Value, ServiceError> {
    let mut req = state.http.post(format!("{base}{path}")).json(&payload);
    if let Some(key) = key {
        req = req.bearer_auth(key);
    }
    let response = req.send().await.map_err(upstream)?;
    let status = response.status();
    let body: Value = response.json().await.map_err(upstream)?;
    if !status.is_success() {
        return Err(ServiceError(format!(
            "Upstream service returned {status}: {body}"
        )));
    }
    Ok(body)
}

fn upstream(error: reqwest::Error) -> ServiceError {
    ServiceError(format!("Could not connect to scan service: {error}"))
}

async fn update(state: &AppState, id: Uuid, f: impl FnOnce(&mut ScanView)) {
    if let Some(scan) = state.scans.write().await.get_mut(&id) {
        f(scan);
    }
}
