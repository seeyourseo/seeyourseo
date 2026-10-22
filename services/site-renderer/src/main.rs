use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware::from_fn_with_state,
    routing::{get, post},
};
use chromiumoxide::{
    Browser, BrowserConfig,
    cdp::browser_protocol::{
        fetch::{ContinueRequestParams, EventRequestPaused, FailRequestParams},
        network::ErrorReason,
    },
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, lookup_host},
    process::{Child, Command},
    sync::Semaphore,
};
use url::Url;

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    api_key: Option<String>,
    concurrency: usize,
    timeout: Duration,
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let listen: SocketAddr = std::env::var("RENDERER_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8092".into())
            .parse()?;
        let api_key = std::env::var("RENDERER_API_KEY")
            .ok()
            .filter(|key| !key.is_empty());
        if !listen.ip().is_loopback() && api_key.is_none() {
            return Err(
                "RENDERER_API_KEY is required when listening on a non-loopback address".into(),
            );
        }
        Ok(Self {
            listen,
            api_key,
            concurrency: env_usize("RENDERER_CONCURRENCY", 2).clamp(1, 8),
            timeout: Duration::from_secs(
                env_usize("RENDERER_TIMEOUT_SECONDS", 20).clamp(5, 60) as u64
            ),
        })
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    slots: Arc<Semaphore>,
    obscura_cdp: Option<String>,
}

#[derive(Deserialize)]
struct RenderRequest {
    url: String,
}

#[derive(Serialize)]
struct RenderResponse {
    url: String,
    status_code: Option<u16>,
    accessible: bool,
    challenge: bool,
    title: Option<String>,
    html: Option<String>,
    error: Option<String>,
    duration_ms: u128,
}

#[derive(Deserialize)]
struct Snapshot {
    url: String,
    status: u16,
    title: String,
    html: String,
    body: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let (obscura_cdp, _obscura_process) = start_obscura().await;
    if obscura_cdp.is_some() {
        eprintln!("using Obscura as the primary rendering engine");
    } else {
        eprintln!("Obscura unavailable; falling back to installed Chrome/Chromium");
    }
    let state = AppState {
        slots: Arc::new(Semaphore::new(config.concurrency)),
        config: config.clone(),
        obscura_cdp,
    };
    let api = Router::new()
        .route("/v1/render", post(render))
        .layer(from_fn_with_state(config.api_key.clone(), require_api_key));
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(api)
        .with_state(state);
    let listener = TcpListener::bind(config.listen).await?;
    eprintln!("site renderer listening on {}", config.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn render(
    State(state): State<AppState>,
    Json(request): Json<RenderRequest>,
) -> (StatusCode, Json<RenderResponse>) {
    let started = std::time::Instant::now();
    let fallback = |error: String| RenderResponse {
        url: request.url.clone(),
        status_code: None,
        accessible: false,
        challenge: false,
        title: None,
        html: None,
        error: Some(error),
        duration_ms: started.elapsed().as_millis(),
    };
    let url = match validate_public_url(&request.url).await {
        Ok(url) => url,
        Err(error) => return (StatusCode::BAD_REQUEST, Json(fallback(error))),
    };
    let _permit = match state.slots.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(fallback("renderer is shutting down".into())),
            );
        }
    };
    let result = tokio::time::timeout(state.config.timeout, async {
        if let Some(endpoint) = state.obscura_cdp.as_deref() {
            match render_page(url.clone(), Some(endpoint)).await {
                Ok(snapshot) => Ok(snapshot),
                Err(error) => {
                    eprintln!("Obscura render failed; trying Chrome/Chromium: {error}");
                    render_page(url, None).await
                }
            }
        } else {
            render_page(url, None).await
        }
    })
    .await;
    match result {
        Ok(Ok(snapshot)) => {
            let challenge = is_challenge(&snapshot.title, &snapshot.body);
            let accessible = (200..400).contains(&snapshot.status) && !challenge;
            let error = if challenge {
                Some("Browser received an access challenge".into())
            } else if snapshot.status >= 400 {
                Some(format!("Browser returned HTTP {}", snapshot.status))
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(RenderResponse {
                    url: snapshot.url,
                    status_code: Some(snapshot.status),
                    accessible,
                    challenge,
                    title: Some(snapshot.title),
                    html: Some(snapshot.html),
                    error,
                    duration_ms: started.elapsed().as_millis(),
                }),
            )
        }
        Ok(Err(error)) => (StatusCode::OK, Json(fallback(error))),
        Err(_) => (
            StatusCode::OK,
            Json(fallback("browser render timed out".into())),
        ),
    }
}

async fn start_obscura() -> (Option<String>, Option<Child>) {
    let port = env_usize("RENDERER_OBSCURA_PORT", 19222).clamp(1024, 65535);
    let cdp_url = format!("http://127.0.0.1:{port}");
    let binary = std::env::var_os("OBSCURA_BIN")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()?
                .parent()
                .map(|parent| parent.join("obscura"))
        });
    let Some(binary) = binary.filter(|path| path.is_file()) else {
        return (None, None);
    };
    let child = match Command::new(binary)
        .arg("serve")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("could not start Obscura: {error}");
            return (None, None);
        }
    };
    for _ in 0..40 {
        if Browser::connect(cdp_url.clone()).await.is_ok() {
            return (Some(cdp_url), Some(child));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    eprintln!("Obscura did not become ready; using Chrome/Chromium fallback");
    (None, Some(child))
}

async fn render_page(url: Url, obscura_cdp: Option<&str>) -> Result<Snapshot, String> {
    let config = BrowserConfig::builder()
        .new_headless_mode()
        .window_size(1365, 768)
        .arg("--lang=zh-CN")
        .arg("--force-color-profile=srgb")
        .enable_request_intercept()
        .build()
        .map_err(|e| e.to_string())?;
    let (mut browser, mut handler) = if let Some(endpoint) = obscura_cdp {
        Browser::connect(endpoint.to_owned()).await.map_err(|e| e.to_string())?
    } else {
        Browser::launch(config).await.map_err(|e| e.to_string())?
    };
    let remote = obscura_cdp.is_some();
    let handler_task = tokio::spawn(async move {
        while let Some(event) = handler.next().await {
            if event.is_err() {
                break;
            }
        }
    });
    let page = browser
        .new_page("about:blank")
        .await
        .map_err(|e| e.to_string())?;
    let mut requests = page
        .event_listener::<EventRequestPaused>()
        .await
        .map_err(|e| e.to_string())?;
    let intercept_page = page.clone();
    let intercept_task = tokio::spawn(async move {
        while let Some(event) = requests.next().await {
            let request_id = event.request_id.clone();
            let allowed = if ["about:", "blob:", "data:"]
                .iter()
                .any(|scheme| event.request.url.starts_with(scheme))
            {
                true
            } else {
                validate_public_url(&event.request.url).await.is_ok()
            };
            if allowed {
                let _ = intercept_page
                    .execute(ContinueRequestParams::new(request_id))
                    .await;
            } else {
                let _ = intercept_page
                    .execute(FailRequestParams::new(
                        request_id,
                        ErrorReason::BlockedByClient,
                    ))
                    .await;
            }
        }
    });
    page.goto(url.as_str()).await.map_err(|e| e.to_string())?;
    // Give hydration and deferred scripts time to update the DOM, as a normal
    // desktop tab would after its load event.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let challenge_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let snapshot = loop {
        let json = page.evaluate_expression("JSON.stringify({url: location.href, status: performance.getEntriesByType('navigation')[0]?.responseStatus || 0, title: document.title || '', html: document.documentElement?.outerHTML || '', body: document.body?.innerText || ''})")
            .await.map_err(|e| e.to_string())?.into_value::<String>().map_err(|e| e.to_string())?;
        let snapshot: Snapshot = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        if !is_challenge(&snapshot.title, &snapshot.body)
            || tokio::time::Instant::now() >= challenge_deadline
        {
            break snapshot;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    if remote {
        let _ = page.close().await;
    } else {
        let _ = browser.close().await;
    }
    handler_task.abort();
    intercept_task.abort();
    Ok(snapshot)
}

async fn validate_public_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.username() != "" || url.password().is_some()
    {
        return Err("Only public HTTP(S) URLs are allowed".into());
    }
    let host = url.host_str().ok_or("URL has no host")?;
    let port = url.port_or_known_default().ok_or("URL has no port")?;
    let addresses = lookup_host((host, port))
        .await
        .map_err(|e| e.to_string())?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("URL resolves to a non-public address".into());
    }
    Ok(url)
}

fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 224)
        }
        std::net::IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| !is_public_ip(v4.into())))
        }
    }
}

fn is_challenge(title: &str, body: &str) -> bool {
    let text = format!("{title} {body}").to_ascii_lowercase();
    [
        "just a moment...",
        "verify you are human",
        "captcha challenge",
        "checking your browser before accessing",
        "performing security verification",
        "attention required! | cloudflare",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

async fn require_api_key(
    State(expected): State<Option<String>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use std::str::FromStr;
    let Some(expected) = expected else {
        return next.run(request).await;
    };
    let valid = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| bool::from_str(if value == expected { "true" } else { "false" }).ok())
        .unwrap_or(false);
    if valid {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
