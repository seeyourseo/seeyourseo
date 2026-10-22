use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use site_analyzer::{AppState, Config, router};
use tower::ServiceExt;
use uuid::Uuid;

fn app(api_key: Option<&str>) -> Router {
    let config = Config {
        listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        api_key: api_key.map(str::to_owned),
        max_analyses: 8,
        max_pages: 100,
        max_batch_pages: 10,
        max_body_bytes: 1_000_000,
        task_ttl: Duration::from_secs(600),
    };
    router(Arc::new(AppState::new(config)))
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    payload: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if payload.is_some() {
        request = request.header("content-type", "application/json");
    }
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = payload
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, value)
}

#[tokio::test]
async fn submitted_crawl_pages_produce_paginated_seo_and_link_issues() {
    let app = app(None);
    let (status, created) = call(
        &app,
        "POST",
        "/v1/analyses",
        Some(json!({"source_crawl_id":"crawl-1","expected_pages":3})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["analysis_id"].as_str().unwrap();
    let root = json!({
        "url":"https://example.com/",
        "status_code":200,
        "title":"Shared title",
        "description":"Home page",
        "canonical":"https://example.com/",
        "depth":0,
        "links":[
            {"url":"https://example.com/missing#section","text":"Missing","rel":[],"is_internal":true},
            {"url":"https://outside.test/","text":"Outside","rel":["nofollow"],"is_internal":false}
        ]
    });
    let missing = json!({
        "url":"https://example.com/missing",
        "status_code":404,
        "depth":1,
        "links":[]
    });
    let orphan = json!({
        "url":"https://example.com/orphan",
        "status_code":200,
        "title":"Shared title",
        "description":"Another page",
        "canonical":"https://example.com/orphan",
        "depth":2,
        "links":[]
    });

    let (status, first) = call(
        &app,
        "POST",
        &format!("/v1/analyses/{id}/pages"),
        Some(json!({"pages":[root,missing]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["pages_received"], 2);

    let (status, second) = call(
        &app,
        "POST",
        &format!("/v1/analyses/{id}/pages"),
        Some(json!({"pages":[missing,orphan]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["pages_received"], 3);

    let (status, _) = call(
        &app,
        "POST",
        &format!("/v1/analyses/{id}/complete"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let report = loop {
        let (status, report) = call(&app, "GET", &format!("/v1/analyses/{id}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        if report["status"] == "completed" {
            break report;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "analysis did not finish"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(report["summary"]["pages_analyzed"], 3);
    assert_eq!(report["pages_received"], 3);
    assert_eq!(report["summary"]["failed_pages"], 1);
    assert_eq!(report["summary"]["internal_links"], 1);
    assert_eq!(report["summary"]["external_links"], 1);
    assert_eq!(report["summary"]["orphan_pages"], 1);

    let mut cursor = "0".to_string();
    let mut issues = Vec::new();
    loop {
        let (status, batch) = call(
            &app,
            "GET",
            &format!("/v1/analyses/{id}/issues?limit=2&cursor={cursor}"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        issues.extend(batch["issues"].as_array().unwrap().iter().cloned());
        if !batch["has_more"].as_bool().unwrap() {
            break;
        }
        cursor = batch["next_cursor"].as_str().unwrap().to_string();
    }
    let codes = issues
        .iter()
        .filter_map(|issue| issue["code"].as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"http_error"));
    assert!(codes.contains(&"missing_title"));
    assert!(codes.contains(&"broken_internal_link"));
    assert!(codes.contains(&"duplicate_title"));
    assert!(codes.contains(&"orphan_page"));

    let (status, _) = call(
        &app,
        "POST",
        &format!("/v1/analyses/{id}/pages"),
        Some(json!({"pages":[]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn configured_api_key_guards_analysis_routes() {
    let app = app(Some("secret"));
    let id = Uuid::new_v4();
    let (status, _) = call(&app, "GET", &format!("/v1/analyses/{id}"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(
        &app,
        "GET",
        &format!("/v1/analyses/{id}"),
        None,
        Some("secret"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
