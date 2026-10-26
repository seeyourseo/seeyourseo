use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use reqwest::Client;
use rust_stemmers::{Algorithm, Stemmer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use site_payments::{Config as PaymentConfig, PaymentService};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::{Mutex, RwLock},
};
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
    analytics: AnalyticsStore,
    access_log: AccessLogStore,
    admin_token: Option<String>,
    payments: Option<PaymentService>,
}

#[derive(Clone, Serialize)]
struct ScanView {
    scan_id: Uuid,
    start_url: String,
    max_pages: usize,
    status: String,
    stage: String,
    progress: Option<Value>,
    summary: Option<Value>,
    issues: Vec<Value>,
    special_files: Vec<Value>,
    #[serde(skip_serializing)]
    pages: Vec<Value>,
    error: Option<String>,
    crawl_id: Option<String>,
    analysis_id: Option<String>,
    #[serde(skip_serializing)]
    started_at: i64,
    #[serde(skip)]
    finished_at: Option<Instant>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScanMetric {
    scan_id: Uuid,
    started_at: i64,
    domain: String,
    status: String,
    pages: usize,
}

#[derive(Clone)]
struct AnalyticsStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl AnalyticsStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    async fn append(&self, event: &ScanMetric) -> std::io::Result<()> {
        let _guard = self.lock.lock().await;
        #[cfg(not(target_os = "linux"))]
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut options = OpenOptions::new();
        options.append(true);
        #[cfg(not(target_os = "linux"))]
        options.create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&self.path).await?;
        let mut row = serde_json::to_vec(event).map_err(std::io::Error::other)?;
        row.push(b'\n');
        file.write_all(&row).await?;
        file.flush().await
    }

    async fn retained(&self) -> std::io::Result<Vec<ScanMetric>> {
        let _guard = self.lock.lock().await;
        let contents = match fs::read_to_string(&self.path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let cutoff = unix_now().saturating_sub(30 * 24 * 60 * 60);
        let mut latest = HashMap::<Uuid, ScanMetric>::new();
        for line in contents.lines() {
            if let Ok(event) = serde_json::from_str::<ScanMetric>(line)
                && event.started_at >= cutoff
            {
                latest.insert(event.scan_id, event);
            }
        }
        let mut events = latest.into_values().collect::<Vec<_>>();
        events.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        let compacted = events
            .iter()
            .filter_map(|event| serde_json::to_string(event).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let compacted = if compacted.is_empty() {
            String::new()
        } else {
            format!("{compacted}\n")
        };
        #[cfg(target_os = "linux")]
        fs::write(&self.path, compacted).await?;
        #[cfg(not(target_os = "linux"))]
        {
            let temporary = self.path.with_extension("jsonl.tmp");
            fs::write(&temporary, compacted).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).await?;
            }
            fs::rename(temporary, &self.path).await?;
        }
        Ok(events)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct VisitorEvent {
    visited_at: i64,
    ip: String,
    path: String,
    status: u16,
}

#[derive(Clone)]
struct AccessLogStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl AccessLogStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    async fn append(&self, event: &VisitorEvent) -> std::io::Result<()> {
        let _guard = self.lock.lock().await;
        #[cfg(not(target_os = "linux"))]
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut options = OpenOptions::new();
        options.append(true);
        #[cfg(not(target_os = "linux"))]
        options.create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&self.path).await?;
        let mut row = serde_json::to_vec(event).map_err(std::io::Error::other)?;
        row.push(b'\n');
        file.write_all(&row).await?;
        file.flush().await
    }

    async fn retained(&self) -> std::io::Result<Vec<VisitorEvent>> {
        let _guard = self.lock.lock().await;
        let contents = match fs::read_to_string(&self.path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let cutoff = unix_now().saturating_sub(VISITOR_LOG_RETENTION_SECONDS);
        let mut events = contents
            .lines()
            .filter_map(|line| serde_json::from_str::<VisitorEvent>(line).ok())
            .filter(|event| event.visited_at >= cutoff)
            .collect::<Vec<_>>();
        events.sort_by(|a, b| b.visited_at.cmp(&a.visited_at));
        events.truncate(MAX_VISITOR_LOG_EVENTS);
        let compacted = events
            .iter()
            .filter_map(|event| serde_json::to_string(event).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let compacted = if compacted.is_empty() {
            String::new()
        } else {
            format!("{compacted}\n")
        };
        #[cfg(target_os = "linux")]
        fs::write(&self.path, compacted).await?;
        #[cfg(not(target_os = "linux"))]
        {
            let temporary = self.path.with_extension("jsonl.tmp");
            fs::write(&temporary, compacted).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).await?;
            }
            fs::rename(temporary, &self.path).await?;
        }
        Ok(events)
    }
}

const REPORT_RETENTION: Duration = Duration::from_secs(20 * 60);
const ANALYTICS_RETENTION_DAYS: usize = 30;
const VISITOR_LOG_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_VISITOR_LOG_EVENTS: usize = 10_000;

#[derive(Deserialize)]
struct CreateScan {
    start_url: String,
    max_pages: Option<usize>,
    max_depth: Option<usize>,
}

#[derive(Deserialize)]
struct PaymentCheckoutRequest {
    email: String,
    email_confirmation: String,
    plan_id: String,
}
#[derive(Deserialize)]
struct EmailLoginRequest {
    email: String,
}
#[derive(Deserialize)]
struct CreateOrderRequest {
    checkout_id: String,
    immediate_consent: bool,
}
#[derive(Deserialize)]
struct CaptureOrderPath {
    id: String,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    site_sandbox::apply(site_sandbox::Service::Website)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listen: SocketAddr = env("WEB_LISTEN", "127.0.0.1:8080").parse()?;
    let payments = match PaymentConfig::from_env() {
        Ok(config) => match PaymentService::new(config).await {
            Ok(service) => Some(service),
            Err(error) => {
                eprintln!("Payments are disabled: {error}");
                None
            }
        },
        Err(_) => {
            eprintln!("Payments are not configured; checkout routes will return unavailable.");
            None
        }
    };
    let state = AppState {
        http: Client::builder().timeout(Duration::from_secs(60)).build()?,
        crawler: env("CRAWLER_URL", "http://127.0.0.1:8090"),
        analyzer: env("ANALYZER_URL", "http://127.0.0.1:8091"),
        crawler_key: std::env::var("CRAWLER_API_KEY").ok(),
        analyzer_key: std::env::var("ANALYZER_API_KEY").ok(),
        max_pages: env("WEB_MAX_PAGES", "10000").parse().unwrap_or(10_000),
        max_depth: env("WEB_MAX_DEPTH", "20").parse().unwrap_or(20),
        scans: Arc::new(RwLock::new(HashMap::new())),
        analytics: AnalyticsStore::new(PathBuf::from(env(
            "SCAN_ANALYTICS_PATH",
            "data/scan-analytics.jsonl",
        ))),
        access_log: AccessLogStore::new(PathBuf::from(env(
            "VISITOR_LOG_PATH",
            "data/visitor-access.jsonl",
        ))),
        admin_token: std::env::var("ADMIN_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
        payments,
    };
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            purge_expired(&cleanup_state).await;
        }
    });
    let access_log_cleanup = state.access_log.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            if let Err(error) = access_log_cleanup.retained().await {
                eprintln!("Could not clean expired website access logs: {error}");
            }
        }
    });
    let access_log = state.access_log.clone();
    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.svg", get(favicon))
        .route("/assets/og-image.png", get(og_image))
        .route("/sitemap.xml", get(sitemap))
        .route("/llms.txt", get(llms_text))
        .route("/robots.txt", get(robots_txt))
        .route("/admin", get(admin_page))
        .route("/scan", get(scan_page))
        .route("/pricing", get(pricing_page))
        .route("/checkout", get(checkout_page))
        .route("/account", get(account_page))
        .route("/login", get(login_page))
        .route("/sample-report", get(sample_report))
        .route("/blog", get(blog_index))
        .route("/blog/{slug}", get(blog_article))
        .route("/privacy", get(privacy))
        .route("/terms", get(terms))
        .route("/api/scans", post(create_scan))
        .route("/api/payments/plans", get(payment_plans))
        .route("/api/payments/config", get(payment_config))
        .route("/api/payments/checkout", post(begin_checkout))
        .route("/api/payments/orders", post(create_payment_order))
        .route(
            "/api/payments/orders/{id}/capture",
            post(capture_payment_order),
        )
        .route("/api/payments/webhook", post(paypal_webhook))
        .route("/api/auth/login", post(email_login))
        .route("/api/auth/me", get(account_me))
        .route("/api/auth/logout", post(logout))
        .route("/api/scans/{id}", get(get_scan))
        .route("/api/scans/{id}/pages", get(get_scan_pages))
        .route("/api/scans/{id}/blueprint", get(get_scan_blueprint))
        .route("/api/scans/{id}/download", get(download_scan))
        .route("/api/admin/metrics", get(admin_metrics))
        .nest_service("/assets", ServeDir::new("static"))
        .fallback(|| async { Redirect::to("/") })
        .layer(middleware::from_fn_with_state(
            access_log,
            record_public_visit,
        ))
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
            environment: Some(service_environment(binary)),
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

fn service_environment(binary: &str) -> Vec<(String, String)> {
    let keys: &[&str] = match binary {
        "site-audit-server" => &[
            "WEB_LISTEN",
            "WEB_MAX_PAGES",
            "WEB_MAX_DEPTH",
            "CRAWLER_URL",
            "ANALYZER_URL",
            "CRAWLER_API_KEY",
            "ANALYZER_API_KEY",
            "SCAN_ANALYTICS_PATH",
            "VISITOR_LOG_PATH",
            "PAYMENTS_DATABASE_URL",
            "PAYMENTS_ENV_FILE",
            "PAYPAL_MODE",
            "PAYPAL_CLIENT_ID",
            "PAYPAL_CLIENT_SECRET",
            "PAYPAL_WEBHOOK_ID",
            "PUBLIC_BASE_URL",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USERNAME",
            "SMTP_PASSWORD",
            "MAIL_FROM",
            "MAIL_FROM_NAME",
            "ADMIN_TOKEN",
        ],
        "site-crawler" => &[
            "CRAWLER_LISTEN",
            "CRAWLER_API_KEY",
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
            "RENDERER_URL",
            "RENDERER_API_KEY",
        ],
        "site-analyzer" => &[
            "ANALYZER_LISTEN",
            "ANALYZER_API_KEY",
            "ANALYZER_MAX_ANALYSES",
            "ANALYZER_MAX_PAGES",
            "ANALYZER_MAX_BATCH_PAGES",
            "ANALYZER_MAX_BODY_BYTES",
            "ANALYZER_TASK_TTL_SECONDS",
        ],
        "site-renderer" => &[
            "RENDERER_LISTEN",
            "RENDERER_API_KEY",
            "RENDERER_CONCURRENCY",
            "RENDERER_TIMEOUT_SECONDS",
            "RENDERER_OBSCURA_PORT",
            "OBSCURA_BIN",
        ],
        _ => &[],
    };
    keys.into_iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| ((*key).to_owned(), value))
        })
        .collect()
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        include_str!("../static/favicon.svg"),
    )
}

async fn og_image() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        include_bytes!("../static/og-image.png").as_slice(),
    )
}

async fn sitemap() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../static/sitemap.xml"),
    )
}

async fn llms_text() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../static/llms.txt"),
    )
}

async fn robots_txt() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../static/robots.txt"),
    )
}

async fn record_public_visit(
    State(access_log): State<AccessLogStore>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let visit = if request.method().as_str() == "GET" && is_public_page_path(path) {
        request
            .headers()
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .map(|ip| (ip.to_string(), path.to_owned()))
    } else {
        None
    };

    let response = next.run(request).await;
    if let Some((ip, path)) = visit {
        let event = VisitorEvent {
            visited_at: unix_now(),
            ip,
            path,
            status: response.status().as_u16(),
        };
        if let Err(error) = access_log.append(&event).await {
            eprintln!("Could not record website access: {error}");
        }
    }
    response
}

fn is_public_page_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/scan" | "/pricing" | "/sample-report" | "/blog" | "/privacy" | "/terms"
    ) || path.starts_with("/blog/")
}

async fn admin_page() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::HeaderName::from_static("x-robots-tag"),
                "noindex, nofollow",
            ),
        ],
        Html(include_str!("../static/admin.html")),
    )
}

async fn admin_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    let expected_header = expected
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !constant_time_eq(provided.as_bytes(), expected_header.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let events = state
        .analytics
        .retained()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let visitor_events = state
        .access_log
        .retained()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut running = 0usize;
    let mut completed = 0usize;
    let mut failed = 0usize;
    let mut pages_scanned = 0usize;
    let mut by_domain = HashMap::<String, (usize, i64, usize, usize, usize)>::new();
    let mut by_day = BTreeMap::<i64, usize>::new();
    for event in &events {
        match event.status.as_str() {
            "completed" => completed += 1,
            "failed" => failed += 1,
            _ => running += 1,
        }
        pages_scanned += event.pages;
        let day = event.started_at.div_euclid(86_400);
        *by_day.entry(day).or_default() += 1;
        let stats = by_domain
            .entry(event.domain.clone())
            .or_insert((0, 0, 0, 0, 0));
        stats.0 += 1;
        stats.1 = stats.1.max(event.started_at);
        stats.2 += usize::from(event.status == "completed");
        stats.3 += usize::from(event.status == "failed");
        stats.4 += event.pages;
    }
    let mut domains = by_domain
        .into_iter()
        .map(|(domain, (scans, latest_at, completed, failed, pages))| {
            json!({
                "domain": domain,
                "scans": scans,
                "latest_scan_at": latest_at,
                "completed": completed,
                "failed": failed,
                "pages_scanned": pages,
            })
        })
        .collect::<Vec<_>>();
    domains.sort_by(|a, b| {
        b["scans"].as_u64().cmp(&a["scans"].as_u64()).then_with(|| {
            b["latest_scan_at"]
                .as_i64()
                .cmp(&a["latest_scan_at"].as_i64())
        })
    });
    domains.truncate(100);

    let today = unix_now().div_euclid(86_400);
    let daily = (0..ANALYTICS_RETENTION_DAYS)
        .rev()
        .map(|offset| {
            let day = today - offset as i64;
            json!({"day": day, "scans": by_day.get(&day).copied().unwrap_or_default()})
        })
        .collect::<Vec<_>>();

    let mut visitors_by_ip = HashMap::<String, (usize, VisitorEvent)>::new();
    for event in &visitor_events {
        visitors_by_ip
            .entry(event.ip.clone())
            .and_modify(|(visits, latest)| {
                *visits += 1;
                if event.visited_at > latest.visited_at {
                    *latest = event.clone();
                }
            })
            .or_insert_with(|| (1, event.clone()));
    }
    let unique_visitor_ips = visitors_by_ip.len();
    let mut visitors = visitors_by_ip
        .into_iter()
        .map(|(ip, (visits, latest))| {
            json!({
                "ip": ip,
                "page_visits": visits,
                "latest_at": latest.visited_at,
                "last_page": latest.path,
                "last_status": latest.status,
            })
        })
        .collect::<Vec<_>>();
    visitors.sort_by(|a, b| b["latest_at"].as_i64().cmp(&a["latest_at"].as_i64()));
    visitors.truncate(200);

    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "window_days": ANALYTICS_RETENTION_DAYS,
            "total_scans": events.len(),
            "running": running,
            "completed": completed,
            "failed": failed,
            "unique_domains": events.iter().map(|event| event.domain.as_str()).collect::<std::collections::HashSet<_>>().len(),
            "pages_scanned": pages_scanned,
            "daily": daily,
            "domains": domains,
            "visitor_window_days": 7,
            "visitor_page_views": visitor_events.len(),
            "unique_visitor_ips": unique_visitor_ips,
            "visitors": visitors,
        })),
    ))
}

async fn scan_page() -> impl IntoResponse {
    (
        [(
            header::HeaderName::from_static("x-robots-tag"),
            "noindex, nofollow, noarchive",
        )],
        Html(include_str!("../static/scan.html")),
    )
}

async fn pricing_page() -> Html<&'static str> {
    Html(include_str!("../static/pricing.html"))
}
async fn checkout_page() -> impl IntoResponse {
    private_page(include_str!("../static/checkout.html"))
}
async fn account_page() -> impl IntoResponse {
    private_page(include_str!("../static/account.html"))
}

async fn login_page() -> impl IntoResponse {
    private_page(include_str!("../static/account.html"))
}

fn private_page(contents: &'static str) -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::HeaderName::from_static("x-robots-tag"),
                "noindex, nofollow, noarchive",
            ),
        ],
        Html(contents),
    )
}

fn payments_or_error(state: &AppState) -> Result<&PaymentService, ServiceError> {
    state.payments.as_ref().ok_or_else(|| {
        ServiceError("Payments are temporarily unavailable. Please try again later.".into())
    })
}

async fn payment_plans(State(state): State<AppState>) -> Result<Json<Value>, ServiceError> {
    let service = payments_or_error(&state)?;
    Ok(Json(
        json!({"plans":site_payments::PLANS,"currency":"USD","sandbox":service.is_sandbox()}),
    ))
}

async fn payment_config(State(state): State<AppState>) -> Result<Json<Value>, ServiceError> {
    let service = payments_or_error(&state)?;
    Ok(Json(
        json!({"client_id":service.client_id(),"sandbox":service.is_sandbox()}),
    ))
}

async fn begin_checkout(
    State(state): State<AppState>,
    Json(input): Json<PaymentCheckoutRequest>,
) -> Result<Json<site_payments::CheckoutStarted>, ServiceError> {
    if input.email.trim().to_lowercase() != input.email_confirmation.trim().to_lowercase() {
        return Err(ServiceError("Email addresses do not match".into()));
    }
    let service = payments_or_error(&state)?;
    service
        .request_checkout(&input.email, &input.plan_id)
        .await
        .map(Json)
        .map_err(ServiceError)
}

async fn create_payment_order(
    State(state): State<AppState>,
    Json(input): Json<CreateOrderRequest>,
) -> Result<Json<Value>, ServiceError> {
    payments_or_error(&state)?
        .create_paypal_order(&input.checkout_id, input.immediate_consent)
        .await
        .map(Json)
        .map_err(ServiceError)
}

async fn capture_payment_order(
    State(state): State<AppState>,
    Path(path): Path<CaptureOrderPath>,
) -> axum::response::Response {
    let service = match payments_or_error(&state) {
        Ok(service) => service,
        Err(error) => return payment_error_response(error.0),
    };
    let payment = match service.capture_order(&path.id).await {
        Ok(payment) => payment,
        Err(error) => return payment_error_response(error),
    };
    let session = payment.session_token.clone();
    let mut response = Json(payment).into_response();
    let cookie =
        format!("sys_session={session}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax");
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie.parse().unwrap());
    response
}

fn payment_error_response(message: String) -> axum::response::Response {
    (
        StatusCode::FAILED_DEPENDENCY,
        Json(json!({"error":message})),
    )
        .into_response()
}

async fn paypal_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<Value>,
) -> Result<StatusCode, ServiceError> {
    let pairs = headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    payments_or_error(&state)?
        .verify_webhook(&pairs, &event)
        .await
        .map_err(ServiceError)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn email_login(
    State(state): State<AppState>,
    Json(input): Json<EmailLoginRequest>,
) -> Result<axum::response::Response, ServiceError> {
    let service = payments_or_error(&state)?;
    match service
        .login_by_email(&input.email)
        .await
        .map_err(ServiceError)?
    {
        site_payments::EmailLoginResult::SignedIn {
            account,
            session_token,
        } => {
            let mut response =
                Json(json!({"status":"signed_in","account":account})).into_response();
            let cookie = format!(
                "sys_session={session_token}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
            );
            response.headers_mut().append(
                header::SET_COOKIE,
                cookie
                    .parse()
                    .map_err(|e| ServiceError(format!("Could not set account session: {e}")))?,
            );
            Ok(response)
        }
        site_payments::EmailLoginResult::NoPayment => {
            let mut response =
                Json(json!({"status":"payment_required","reason":"no_payment"})).into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                "sys_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
                    .parse()
                    .unwrap(),
            );
            Ok(response)
        }
        site_payments::EmailLoginResult::CreditUsed => {
            let mut response =
                Json(json!({"status":"payment_required","reason":"credit_used"})).into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                "sys_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
                    .parse()
                    .unwrap(),
            );
            Ok(response)
        }
    }
}

async fn account_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<site_payments::AccountSummary>, StatusCode> {
    let service = state
        .payments
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let token = cookie_value(&headers, "sys_session").ok_or(StatusCode::UNAUTHORIZED)?;
    service
        .account_for_session(&token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let (Some(service), Some(token)) = (&state.payments, cookie_value(&headers, "sys_session")) {
        let _ = service.revoke_session(&token).await;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        "sys_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
            .parse()
            .unwrap(),
    );
    response
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

async fn sample_report() -> Html<&'static str> {
    Html(include_str!("../static/sample-report.html"))
}

async fn blog_index() -> Html<&'static str> {
    Html(include_str!("../static/blog.html"))
}

async fn blog_article(Path(slug): Path<String>) -> axum::response::Response {
    let page = match slug.as_str() {
        "seo-research-workflow" => {
            include_str!("../static/blog-articles/seo-research-workflow.html")
        }
        "open-source-seo-toolkit" => {
            include_str!("../static/blog-articles/open-source-seo-toolkit.html")
        }
        "google-seo-step-by-step" => {
            include_str!("../static/blog-articles/google-seo-step-by-step.html")
        }
        "google-preferred-sources" => {
            include_str!("../static/blog-articles/google-preferred-sources.html")
        }
        "keyword-research" => include_str!("../static/blog-articles/keyword-research.html"),
        "website-launch-checkup" => {
            include_str!("../static/blog-articles/website-launch-checkup.html")
        }
        "on-page-seo" => include_str!("../static/blog-articles/on-page-seo.html"),
        "growth-distribution" => include_str!("../static/blog-articles/growth-distribution.html"),
        "technical-seo" => include_str!("../static/blog-articles/technical-seo.html"),
        "tools" => include_str!("../static/blog-articles/tools.html"),
        "open-seo-review" => include_str!("../static/blog-articles/open-seo-review.html"),
        "claude-seo-review" => include_str!("../static/blog-articles/claude-seo-review.html"),
        "chatgpt-seo-review" => include_str!("../static/blog-articles/chatgpt-seo-review.html"),
        "jev-seo-review" => include_str!("../static/blog-articles/jev-seo-review.html"),
        _ => return Redirect::to("/blog").into_response(),
    };
    Html(page).into_response()
}

async fn privacy() -> Html<&'static str> {
    Html(include_str!("../static/privacy.html"))
}

async fn terms() -> Html<&'static str> {
    Html(include_str!("../static/terms.html"))
}

async fn create_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateScan>,
) -> Result<(StatusCode, Json<ScanView>), ServiceError> {
    let url = input.start_url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(ServiceError("Enter a complete HTTP or HTTPS URL.".into()));
    }
    let session = cookie_value(&headers, "sys_session");
    let paid_credit = if let (Some(service), Some(token)) = (&state.payments, session.as_deref()) {
        service
            .consume_scan_credit(token)
            .await
            .map_err(ServiceError)?
    } else {
        None
    };
    let pages = paid_credit
        .as_ref()
        .map(|credit| credit.page_limit)
        .unwrap_or_else(|| {
            input
                .max_pages
                .unwrap_or(state.max_pages)
                .clamp(1, state.max_pages.max(1))
        })
        .clamp(1, state.max_pages.max(1));
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
    let result = match req.send().await {
        Ok(result) => result,
        Err(error) => {
            if let (Some(credit), Some(service), Some(token)) =
                (paid_credit.as_ref(), &state.payments, session.as_deref())
            {
                let _ = service
                    .restore_scan_credit(token, &credit.paypal_order_id)
                    .await;
            }
            return Err(upstream(error));
        }
    };
    let status = result.status();
    let payload: Value = match result.json().await {
        Ok(payload) => payload,
        Err(error) => {
            if let (Some(credit), Some(service), Some(token)) =
                (paid_credit.as_ref(), &state.payments, session.as_deref())
            {
                let _ = service
                    .restore_scan_credit(token, &credit.paypal_order_id)
                    .await;
            }
            return Err(upstream(error));
        }
    };
    if !status.is_success() {
        if let (Some(credit), Some(service), Some(token)) =
            (paid_credit.as_ref(), &state.payments, session.as_deref())
        {
            let _ = service
                .restore_scan_credit(token, &credit.paypal_order_id)
                .await;
        }
        return Err(ServiceError(format!(
            "Crawler rejected the scan: {}",
            payload
        )));
    }
    let crawl_id = match payload["crawl_id"].as_str() {
        Some(crawl_id) => crawl_id.to_owned(),
        None => {
            if let (Some(credit), Some(service), Some(token)) =
                (paid_credit.as_ref(), &state.payments, session.as_deref())
            {
                let _ = service
                    .restore_scan_credit(token, &credit.paypal_order_id)
                    .await;
            }
            return Err(ServiceError("Crawler did not return a task ID.".into()));
        }
    };
    let id = Uuid::new_v4();
    let started_at = unix_now();
    let view = ScanView {
        scan_id: id,
        start_url: url.to_owned(),
        max_pages: pages,
        status: "running".into(),
        stage: "crawling".into(),
        progress: None,
        summary: None,
        issues: vec![],
        special_files: vec![],
        pages: vec![],
        error: None,
        crawl_id: Some(crawl_id.clone()),
        analysis_id: None,
        started_at,
        finished_at: None,
    };
    state.scans.write().await.insert(id, view.clone());
    if let Err(error) = record_scan_metric(&state.analytics, &view).await {
        eprintln!("Could not record scan metrics: {error}");
    }
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
    let english_stemmer = Stemmer::create(Algorithm::English);
    let pages = scan
        .pages
        .iter()
        .take(BLUEPRINT_PAGE_LIMIT)
        .map(|page| {
            json!({
                "url": page["url"],
                "title": page["title"],
                "description": page["description"],
                "depth": page["depth"],
                "inbound_link_count": page["inbound_link_count"],
                "word_count": page["content"]["word_count"],
                "keywords": page["content"]["keywords"],
                "keyword_alignment": page_keyword_alignment(page, &english_stemmer),
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

fn page_keyword_alignment(page: &Value, english_stemmer: &Stemmer) -> Value {
    let title = page["title"].as_str().unwrap_or_default();
    let description = page["description"].as_str().unwrap_or_default();
    let h1 = page["content"]["headings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|heading| heading["level"].as_u64() == Some(1))
        .filter_map(|heading| heading["text"].as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let terms = page["content"]["keywords"]
        .as_array()
        .into_iter()
        .flatten()
        .take(5)
        .map(|keyword| {
            let term = keyword["term"].as_str().unwrap_or_default();
            json!({
                "term": term,
                "frequency": keyword["frequency"],
                "title": field_matches_keyword(title, term, english_stemmer),
                "description": field_matches_keyword(description, term, english_stemmer),
                "h1": field_matches_keyword(&h1, term, english_stemmer),
            })
        })
        .collect::<Vec<_>>();
    json!({"terms": terms})
}

fn field_matches_keyword(field: &str, keyword: &str, english_stemmer: &Stemmer) -> bool {
    let normalized_keyword = keyword.to_lowercase();
    if normalized_keyword.is_empty() {
        return false;
    }
    if normalized_keyword.chars().any(is_cjk_character) {
        return field.to_lowercase().contains(&normalized_keyword);
    }

    let normalize = |token: &str| {
        let lowercase = token.to_lowercase();
        if lowercase.is_ascii() && lowercase.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            english_stemmer.stem(&lowercase).into_owned()
        } else {
            lowercase
        }
    };
    let field_tokens = field
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(normalize)
        .collect::<std::collections::HashSet<_>>();
    let keyword_tokens = normalized_keyword
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(normalize)
        .collect::<Vec<_>>();
    !keyword_tokens.is_empty()
        && keyword_tokens
            .iter()
            .all(|token| field_tokens.contains(token))
}

fn is_cjk_character(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF
    )
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
    if summary["page_limit_reached"].as_bool().unwrap_or(false) {
        out.push_str(&format!("\nThe scan reached its {}-page limit. Orphan findings reflect only scanned pages and may change if more pages are scanned.\n", display_value(&summary["page_limit"])));
    }
    out.push_str("\n### Findings by issue type\n\n| Issue type | Count |\n|---|---:|\n");
    if let Some(counts) = summary["issue_counts"].as_object() {
        for (severity, count) in counts {
            out.push_str(&format!(
                "| {} | {} |\n",
                md_cell(severity),
                display_value(count)
            ));
        }
    }

    out.push_str("\n## Content analysis\n\n");
    let content = &summary["content_analysis"];
    out.push_str(&format!(
        "- Pages with text: {}\n- Thin content pages: {}\n- Exact duplicate groups: {}\n- Similar page groups: {}\n- Keyword overlap groups: {}\n\n",
        display_value(&content["pages_with_content"]),
        display_value(&content["thin_content_pages"]),
        content["exact_duplicate_groups"].as_array().map_or(0, Vec::len),
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

    out.push_str(
        "\n### Thin content pages\n\n| Page | Words | Internal links |\n|---|---:|---:|\n",
    );
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
        "Exact duplicate content groups",
        &content["exact_duplicate_groups"],
    );
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

    let mut speed_pages = scan
        .pages
        .iter()
        .filter(|page| {
            !page["partial_content"].as_bool().unwrap_or(false)
                && !page["is_dead_page"].as_bool().unwrap_or(false)
        })
        .filter_map(|page| {
            page["load_duration_ms"]
                .as_u64()
                .map(|duration| (duration, page))
        })
        .collect::<Vec<_>>();
    speed_pages.sort_by(|a, b| b.0.cmp(&a.0));
    out.push_str("\n## Page speed\n\n");
    if speed_pages.is_empty() {
        out.push_str("No complete page timing data was available.\n\n");
    } else {
        let durations = speed_pages
            .iter()
            .map(|(duration, _)| *duration)
            .collect::<Vec<_>>();
        let middle = durations.len() / 2;
        let median = if durations.len() % 2 == 0 {
            (durations[middle - 1] + durations[middle]) / 2
        } else {
            durations[middle]
        };
        let slow_count = durations
            .iter()
            .filter(|duration| **duration >= 3_000)
            .count();
        let median_ttfb = {
            let mut values = speed_pages
                .iter()
                .filter_map(|(_, page)| page["ttfb_ms"].as_u64())
                .collect::<Vec<_>>();
            values.sort_unstable();
            (!values.is_empty()).then(|| {
                let mid = values.len() / 2;
                if values.len() % 2 == 0 {
                    (values[mid - 1] + values[mid]) / 2
                } else {
                    values[mid]
                }
            })
        };
        out.push_str(&format!(
            "- **Pages measured:** {}\n- **Median fetch duration:** {median} ms\n- **Median TTFB:** {}\n- **Fetches taking 3 seconds or more:** {slow_count}\n\n",
            speed_pages.len(),
            median_ttfb.map(|value| format!("{value} ms")).unwrap_or_else(|| "—".into()),
        ));
        out.push_str("Slowest pages (single scanner request):\n\n| Page | Fetch duration | TTFB | Response body |\n|---|---:|---:|---:|\n");
        for (duration, page) in speed_pages.iter().take(10) {
            out.push_str(&format!(
                "| {} | {} ms | {} | {} bytes |\n",
                md_cell(page["url"].as_str().unwrap_or("")),
                duration,
                page["ttfb_ms"]
                    .as_u64()
                    .map(|value| format!("{value} ms"))
                    .unwrap_or_else(|| "—".into()),
                page["response_size_bytes"].as_u64().unwrap_or_default(),
            ));
        }
        out.push_str("\nThese are single-request scanner measurements. Fetch duration does not represent the full browser experience or Core Web Vitals; the 3-second mark is a review flag, not a search ranking threshold.\n\n");
    }

    out.push_str("\n## Special files\n\n");
    if scan.special_files.is_empty() {
        out.push_str("No special files were checked.\n\n");
    } else {
        out.push_str("| File | Status | Final URL | Type | Duration | Redirects |\n|---|---:|---|---|---:|---|\n");
        for file in &scan.special_files {
            let redirects = file["redirect_chain"]
                .as_array()
                .map(|chain| {
                    chain
                        .iter()
                        .filter_map(Value::as_str)
                        .map(md_cell)
                        .collect::<Vec<_>>()
                        .join(" → ")
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} ms | {} |\n",
                md_cell(file["name"].as_str().unwrap_or("")),
                display_value(&file["status_code"]),
                md_cell(file["final_url"].as_str().unwrap_or("—")),
                md_cell(file["content_type"].as_str().unwrap_or("—")),
                file["duration_ms"].as_u64().unwrap_or_default(),
                if redirects.is_empty() {
                    "—".into()
                } else {
                    redirects
                },
            ));
        }
        out.push_str("\n`robots.txt` is checked for HTTP availability only; its crawler rules are not evaluated.\n\n");
    }

    out.push_str("\n## Issues\n\n");
    if scan.issues.is_empty() {
        out.push_str("No issues found.\n\n");
    } else {
        out.push_str(
            "| Severity | Finding | Affected source pages | Target |\n|---|---|---|---|\n",
        );
        for issue in &scan.issues {
            out.push_str(&format!(
                "| {} | {} ({}) | {} | {} |\n",
                md_cell(issue["severity"].as_str().unwrap_or("")),
                md_cell(issue["message"].as_str().unwrap_or("")),
                md_cell(issue["code"].as_str().unwrap_or("")),
                issue["source_urls"]
                    .as_array()
                    .map(|sources| sources
                        .iter()
                        .filter_map(Value::as_str)
                        .map(md_cell)
                        .collect::<Vec<_>>()
                        .join("; "))
                    .filter(|sources| !sources.is_empty())
                    .unwrap_or_else(|| md_cell(issue["url"].as_str().unwrap_or(""))),
                md_cell(issue["target_url"].as_str().unwrap_or("")),
            ));
        }
        out.push('\n');
    }

    out.push_str("## Pages\n\n| Page | HTTP (initial → final) | Load (ms) | TTFB (ms) | Decoded size (bytes) | Wire size (bytes) | Encoding | Cache control | Redirect chain | H1s | Partial response | Broken internal links | External links |\n|---|---:|---:|---:|---:|---:|---|---|---|---:|---|---:|---:|\n");
    for page in &scan.pages {
        out.push_str(&format!(
            "| {} | {} → {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(page["url"].as_str().unwrap_or("")),
            display_value(&page["status_code"]),
            display_value(&page["final_status_code"]),
            display_value(&page["load_duration_ms"]),
            display_value(&page["ttfb_ms"]),
            display_value(&page["response_size_bytes"]),
            display_value(&page["raw_response_size_bytes"]),
            display_value(&page["content_encoding"]),
            display_value(&page["cache_control"]),
            page["redirect_chain"]
                .as_array()
                .map(|chain| chain
                    .iter()
                    .filter_map(Value::as_str)
                    .map(md_cell)
                    .collect::<Vec<_>>()
                    .join(" → "))
                .unwrap_or_default(),
            display_value(&page["h1_count"]),
            display_value(&page["partial_content"]),
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
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
    let scan = state.scans.read().await.get(&id).cloned();
    if let Some(scan) = scan
        && let Err(error) = record_scan_metric(&state.analytics, &scan).await
    {
        eprintln!("Could not update scan metrics: {error}");
    }
}

async fn record_scan_metric(store: &AnalyticsStore, scan: &ScanView) -> std::io::Result<()> {
    let domain = reqwest::Url::parse(&scan.start_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_owned())
        .unwrap_or_else(|| "unknown".into());
    let pages = scan
        .summary
        .as_ref()
        .and_then(|summary| summary["pages_analyzed"].as_u64())
        .or_else(|| {
            scan.progress
                .as_ref()
                .and_then(|progress| progress["crawled"].as_u64())
        })
        .unwrap_or_default() as usize;
    store
        .append(&ScanMetric {
            scan_id: scan.scan_id,
            started_at: scan.started_at,
            domain,
            status: scan.status.clone(),
            pages,
        })
        .await
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
            scan.progress = Some(crawl["progress"].clone());
            scan.special_files = crawl["special_files"]
                .as_array()
                .cloned()
                .unwrap_or_default();
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
            scan.summary = report["summary"].as_object().map(|_| {
                let mut summary = report["summary"].clone();
                let reached_limit =
                    summary["pages_analyzed"].as_u64().unwrap_or_default() >= scan.max_pages as u64;
                summary["page_limit"] = json!(scan.max_pages);
                summary["page_limit_reached"] = json!(reached_limit);
                summary
            })
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
        let mut summary = report["summary"].clone();
        let reached_limit =
            summary["pages_analyzed"].as_u64().unwrap_or_default() >= scan.max_pages as u64;
        summary["page_limit"] = json!(scan.max_pages);
        summary["page_limit_reached"] = json!(reached_limit);
        scan.summary = Some(summary);
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
