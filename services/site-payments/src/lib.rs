use std::{collections::HashMap, env, fs, path::PathBuf, time::Duration};

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::Mailbox,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};
use rand::{RngCore, rngs::OsRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{MySqlPool, Row, mysql::MySqlPoolOptions};
use uuid::Uuid;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub paypal_client_id: String,
    pub paypal_client_secret: String,
    pub paypal_webhook_id: String,
    pub paypal_mode: String,
    pub public_base_url: String,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub from_email: Option<String>,
    pub from_name: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let file_values = read_config_file();
        let required = |key: &str| {
            env::var(key).ok().or_else(|| file_values.get(key).cloned())
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| format!("Missing required setting {key}"))
        };
        let from_config = |key: &str, default: &str| env::var(key).ok().or_else(|| file_values.get(key).cloned()).unwrap_or_else(||default.to_owned());
        let paypal_mode = from_config("PAYPAL_MODE", "sandbox");
        if !matches!(paypal_mode.as_str(), "sandbox" | "live") {
            return Err("PAYPAL_MODE must be sandbox or live".into());
        }
        Ok(Self {
            database_url: required("PAYMENTS_DATABASE_URL")?,
            paypal_client_id: required("PAYPAL_CLIENT_ID")?,
            paypal_client_secret: required("PAYPAL_CLIENT_SECRET")?,
            paypal_webhook_id: required("PAYPAL_WEBHOOK_ID")?,
            paypal_mode,
            public_base_url: from_config("PUBLIC_BASE_URL", "https://seeyourseo.com"),
            smtp_host: env::var("SMTP_HOST").ok().or_else(|| file_values.get("SMTP_HOST").cloned()),
            smtp_port: from_config("SMTP_PORT", "465")
                .parse()
                .map_err(|_| "SMTP_PORT must be a valid port".to_owned())?,
            smtp_username: env::var("SMTP_USERNAME").ok().or_else(|| file_values.get("SMTP_USERNAME").cloned()),
            smtp_password: env::var("SMTP_PASSWORD").ok().or_else(|| file_values.get("SMTP_PASSWORD").cloned()),
            from_email: env::var("MAIL_FROM").ok().or_else(|| file_values.get("MAIL_FROM").cloned()),
            from_name: env::var("MAIL_FROM_NAME").unwrap_or_else(|_| "SeeYourSEO".into()),
        })
    }

    fn paypal_api(&self) -> &'static str {
        if self.paypal_mode == "live" {
            "https://api-m.paypal.com"
        } else {
            "https://api-m.sandbox.paypal.com"
        }
    }
}

fn read_config_file() -> HashMap<String,String> {
    let path=env::var_os("PAYMENTS_ENV_FILE").map(PathBuf::from).or_else(||env::var_os("HOME").map(|home|PathBuf::from(home).join(".config/seeyourseo/payments.env")));
    let Some(path)=path else{return HashMap::new()};
    fs::read_to_string(path).ok().into_iter().flat_map(|contents|contents.lines().map(str::to_owned).collect::<Vec<_>>()).filter_map(|line|{
        let line=line.trim();
        if line.is_empty()||line.starts_with('#'){return None}
        let (key,value)=line.split_once('=')?;
        let key=key.trim();
        if !key.chars().all(|c|c.is_ascii_uppercase()||c.is_ascii_digit()||c=='_'){return None}
        let value=value.trim();
        let value=if value.len()>=2&&((value.starts_with('"')&&value.ends_with('"'))||(value.starts_with('\'')&&value.ends_with('\''))){&value[1..value.len()-1]}else{value};
        Some((key.to_owned(),value.to_owned()))
    }).collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub amount: &'static str,
    pub currency: &'static str,
    pub page_limit: usize,
}

pub const PLANS: [Plan; 3] = [
    Plan { id: "starter", name: "Starter", description: "One website scan · up to 100 pages", amount: "4.99", currency: "USD", page_limit: 100 },
    Plan { id: "standard", name: "Standard", description: "One website scan · up to 500 pages", amount: "9.99", currency: "USD", page_limit: 500 },
    Plan { id: "deep", name: "Deep scan", description: "One website scan · up to 2,000 pages", amount: "24.99", currency: "USD", page_limit: 2_000 },
];

#[derive(Clone)]
pub struct PaymentService {
    config: Config,
    pool: MySqlPool,
    http: Client,
}

#[derive(Debug, Serialize)]
pub struct CheckoutStarted {
    pub checkout_id: String,
    pub email: String,
    pub plan: Plan,
}

#[derive(Debug, Serialize)]
pub struct VerifiedCheckout {
    pub checkout_id: String,
    pub email: String,
    pub plan: Plan,
}

#[derive(Debug, Serialize)]
pub struct CapturedPayment {
    pub email: String,
    pub plan: Plan,
    pub scan_credits: u64,
    #[serde(skip_serializing)]
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct AccountSummary {
    pub email: String,
    pub scan_credits: u64,
    pub page_limit: usize,
    pub receipts: Vec<PaymentReceipt>,
}

pub enum EmailLoginResult {
    SignedIn { account: AccountSummary, session_token: String },
    NoPayment,
    CreditUsed,
}

#[derive(Debug, Clone)]
pub struct ScanCredit {
    pub paypal_order_id: String,
    pub page_limit: usize,
}

#[derive(Debug, Serialize)]
pub struct PaymentReceipt {
    pub paypal_order_id: String,
    pub paypal_capture_id: String,
    pub plan_id: String,
    pub amount: String,
    pub currency: String,
    pub status: String,
    pub usage_status: String,
    pub confirmed_by: String,
    pub captured_at: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

impl PaymentService {
    pub async fn new(config: Config) -> Result<Self, String> {
        let pool = MySqlPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(8))
            .connect(&config.database_url)
            .await
            .map_err(|e| format!("Could not connect to the payments database: {e}"))?;
        let service = Self {
            config,
            pool,
            http: Client::builder()
                .timeout(Duration::from_secs(20))
                .user_agent("SeeYourSEO-Payments/1.0")
                .build()
                .map_err(|e| e.to_string())?,
        };
        service.initialize_schema().await?;
        service.cleanup_expired().await?;
        Ok(service)
    }

    async fn initialize_schema(&self) -> Result<(), String> {
        for query in [
            "CREATE TABLE IF NOT EXISTS payment_checkouts (id CHAR(36) PRIMARY KEY, email VARCHAR(320) NOT NULL, site_url TEXT NULL, plan_id VARCHAR(32) NOT NULL, verify_hash CHAR(64) NOT NULL UNIQUE, verified_at DATETIME NULL, immediate_consent_at DATETIME NULL, paypal_order_id VARCHAR(64) NULL UNIQUE, status VARCHAR(24) NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_checkout_email (email)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS payment_users (email VARCHAR(320) PRIMARY KEY, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, scan_credits BIGINT UNSIGNED NOT NULL DEFAULT 0, page_limit INT UNSIGNED NOT NULL DEFAULT 20, last_paid_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS payment_credits (paypal_order_id VARCHAR(64) PRIMARY KEY, email VARCHAR(320) NOT NULL, page_limit INT UNSIGNED NOT NULL, consumed_at DATETIME NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_credit_available (email,consumed_at,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS payments (paypal_order_id VARCHAR(64) PRIMARY KEY, paypal_capture_id VARCHAR(64) NOT NULL UNIQUE, email VARCHAR(320) NOT NULL, plan_id VARCHAR(32) NOT NULL, amount DECIMAL(10,2) NOT NULL, currency CHAR(3) NOT NULL, status VARCHAR(24) NOT NULL, confirmed_by VARCHAR(16) NOT NULL, webhook_event_id VARCHAR(128) NULL, captured_at DATETIME NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_payment_email (email)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS payment_webhook_events (event_id VARCHAR(128) PRIMARY KEY, event_type VARCHAR(128) NOT NULL, processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS payment_login_tokens (token_hash CHAR(64) PRIMARY KEY, email VARCHAR(320) NOT NULL, expires_at DATETIME NOT NULL, consumed_at DATETIME NULL, INDEX idx_login_email (email)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS payment_sessions (token_hash CHAR(64) PRIMARY KEY, email VARCHAR(320) NOT NULL, expires_at DATETIME NOT NULL, INDEX idx_session_email (email)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        ] {
            sqlx::query(query)
                .execute(&self.pool)
                .await
                .map_err(|e| format!("Could not initialize payments schema: {e}"))?;
        }
        let site_url_nullable: Option<String> = sqlx::query_scalar("SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='payment_checkouts' AND COLUMN_NAME='site_url'")
            .fetch_optional(&self.pool).await.map_err(db_error)?;
        if site_url_nullable.as_deref() == Some("NO") {
            sqlx::query("ALTER TABLE payment_checkouts MODIFY COLUMN site_url TEXT NULL")
                .execute(&self.pool).await.map_err(db_error)?;
        }
        Ok(())
    }

    pub fn client_id(&self) -> &str { &self.config.paypal_client_id }
    pub fn is_sandbox(&self) -> bool { self.config.paypal_mode == "sandbox" }
    pub fn public_base_url(&self) -> &str { &self.config.public_base_url }

    async fn cleanup_expired(&self)->Result<(),String>{
        sqlx::query("DELETE FROM payment_checkouts WHERE expires_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 30 DAY)").execute(&self.pool).await.map_err(db_error)?;
        sqlx::query("DELETE FROM payment_login_tokens WHERE expires_at<UTC_TIMESTAMP()").execute(&self.pool).await.map_err(db_error)?;
        sqlx::query("DELETE FROM payment_sessions WHERE expires_at<UTC_TIMESTAMP()").execute(&self.pool).await.map_err(db_error)?;
        Ok(())
    }

    pub async fn request_checkout(
        &self,
        email: &str,
        plan_id: &str,
    ) -> Result<CheckoutStarted, String> {
        self.cleanup_expired().await?;
        let email = normalize_email(email)?;
        let plan = find_plan(plan_id).ok_or("Select a valid scan plan")?;
        let checkout_id = Uuid::new_v4().to_string();
        let hash = token_hash(&checkout_id);
        sqlx::query("INSERT INTO payment_checkouts (id,email,site_url,plan_id,verify_hash,status,verified_at,expires_at) VALUES (?,?,NULL,?, ?, 'verified',UTC_TIMESTAMP(),DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 MINUTE))")
            .bind(&checkout_id).bind(&email).bind(plan.id).bind(&hash)
            .execute(&self.pool).await.map_err(db_error)?;
        Ok(CheckoutStarted { checkout_id, email, plan })
    }

    pub async fn verify_checkout(&self, token: &str) -> Result<VerifiedCheckout, String> {
        let hash = token_hash(token);
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let row = sqlx::query("SELECT id,email,plan_id,status FROM payment_checkouts WHERE verify_hash=? AND status IN ('email_pending','verified','order_created') AND expires_at>UTC_TIMESTAMP() FOR UPDATE")
            .bind(hash).fetch_optional(&mut *tx).await.map_err(db_error)?
            .ok_or("This verification link is invalid or expired")?;
        let id: String = row.try_get("id").map_err(db_error)?;
        let email: String = row.try_get("email").map_err(db_error)?;
        let plan_id: String = row.try_get("plan_id").map_err(db_error)?;
        let checkout_status:String=row.try_get("status").map_err(db_error)?;
        if checkout_status=="email_pending" {
            sqlx::query("UPDATE payment_checkouts SET status='verified', verified_at=UTC_TIMESTAMP() WHERE id=?")
                .bind(&id).execute(&mut *tx).await.map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(VerifiedCheckout { checkout_id: id, email, plan: find_plan(&plan_id).ok_or("Invalid plan")? })
    }

    pub async fn create_paypal_order(&self, checkout_id: &str, immediate_consent: bool) -> Result<Value, String> {
        if !immediate_consent { return Err("Please confirm immediate access to your scan credit before continuing to payment".into()); }
        let row = sqlx::query("SELECT plan_id,paypal_order_id,status FROM payment_checkouts WHERE id=? AND status IN ('verified','order_created') AND verified_at>DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 MINUTE) AND expires_at>UTC_TIMESTAMP()")
            .bind(checkout_id).fetch_optional(&self.pool).await.map_err(db_error)?
            .ok_or("Start a new checkout from the pricing page")?;
        let plan_id: String = row.try_get("plan_id").map_err(db_error)?;
        let status:String=row.try_get("status").map_err(db_error)?;
        if status=="order_created" {
            let order_id:String=row.try_get("paypal_order_id").map_err(db_error)?;
            return Ok(json!({"id":order_id,"status":"CREATED"}));
        }
        let plan = find_plan(&plan_id).ok_or("Invalid plan")?;
        sqlx::query("UPDATE payment_checkouts SET immediate_consent_at=UTC_TIMESTAMP() WHERE id=? AND status='verified' AND immediate_consent_at IS NULL")
            .bind(checkout_id).execute(&self.pool).await.map_err(db_error)?;
        let access_token = self.access_token().await?;
        let response = self.http.post(format!("{}/v2/checkout/orders", self.config.paypal_api()))
            .bearer_auth(access_token)
            .header("PayPal-Request-Id", checkout_id)
            .json(&json!({
                "intent":"CAPTURE",
                "purchase_units":[{"custom_id":checkout_id,"description":plan.description,
                    "amount":{"currency_code":plan.currency,"value":plan.amount}}],
                "application_context":{"brand_name":"SeeYourSEO","user_action":"PAY_NOW",
                    "return_url":format!("{}/checkout",self.config.public_base_url.trim_end_matches('/')),
                    "cancel_url":format!("{}/pricing",self.config.public_base_url.trim_end_matches('/'))}
            })).send().await.map_err(|e| format!("PayPal order request failed: {e}"))?;
        let status = response.status();
        let body: Value = response.json().await.map_err(|e| format!("Invalid PayPal response: {e}"))?;
        if !status.is_success() { return Err(format!("PayPal could not create the order ({status})")); }
        let order_id = body["id"].as_str().ok_or("PayPal response did not include an order ID")?;
        sqlx::query("UPDATE payment_checkouts SET paypal_order_id=?,status='order_created' WHERE id=? AND status='verified'")
            .bind(order_id).bind(checkout_id).execute(&self.pool).await.map_err(db_error)?;
        Ok(body)
    }

    pub async fn capture_order(&self, paypal_order_id: &str) -> Result<CapturedPayment, String> {
        let row = sqlx::query("SELECT id,email,plan_id FROM payment_checkouts WHERE paypal_order_id=? AND status IN ('order_created','paid') AND expires_at>DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)")
            .bind(paypal_order_id).fetch_optional(&self.pool).await.map_err(db_error)?
            .ok_or("Order not found or expired")?;
        let checkout_id: String = row.try_get("id").map_err(db_error)?;
        let email: String = row.try_get("email").map_err(db_error)?;
        let plan_id: String = row.try_get("plan_id").map_err(db_error)?;
        let plan = find_plan(&plan_id).ok_or("Invalid plan")?;
        let access_token = self.access_token().await?;
        let response = self.http.post(format!("{}/v2/checkout/orders/{}/capture", self.config.paypal_api(), paypal_order_id))
            .bearer_auth(access_token)
            .header("PayPal-Request-Id", format!("capture-{paypal_order_id}"))
            .json(&json!({}))
            .send().await.map_err(|e| format!("PayPal capture request failed: {e}"))?;
        let status = response.status();
        let body: Value = response.json().await.map_err(|e| format!("Invalid PayPal response: {e}"))?;
        if !status.is_success() && body["status"] != "COMPLETED" {
            return Err(format!("PayPal could not capture the order ({status})"));
        }
        validate_capture(&body, paypal_order_id, &checkout_id, &plan)?;
        let capture_id=body["purchase_units"][0]["payments"]["captures"][0]["id"].as_str().ok_or("PayPal capture reference is missing")?;
        self.mark_paid(paypal_order_id,capture_id,&email,&plan,"capture_api",None).await?;
        let session_token = random_token();
        sqlx::query("INSERT INTO payment_sessions (token_hash,email,expires_at) VALUES (?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY))")
            .bind(token_hash(&session_token)).bind(&email).execute(&self.pool).await.map_err(db_error)?;
        Ok(CapturedPayment { email, plan, scan_credits: 1, session_token })
    }

    pub async fn verify_webhook(&self, headers: &[(String, String)], event: &Value) -> Result<(), String> {
        let mut paypal_headers = serde_json::Map::new();
        for (name, value) in headers { paypal_headers.insert(name.to_ascii_lowercase().replace('-', "_"), json!(value)); }
        let access_token = self.access_token().await?;
        let response = self.http.post(format!("{}/v1/notifications/verify-webhook-signature", self.config.paypal_api()))
            .bearer_auth(access_token)
            .json(&json!({"auth_algo":paypal_headers.get("paypal_auth_algo").and_then(Value::as_str).unwrap_or_default(),
                "cert_url":paypal_headers.get("paypal_cert_url").and_then(Value::as_str).unwrap_or_default(),
                "transmission_id":paypal_headers.get("paypal_transmission_id").and_then(Value::as_str).unwrap_or_default(),
                "transmission_sig":paypal_headers.get("paypal_transmission_sig").and_then(Value::as_str).unwrap_or_default(),
                "transmission_time":paypal_headers.get("paypal_transmission_time").and_then(Value::as_str).unwrap_or_default(),
                "webhook_id":self.config.paypal_webhook_id,"webhook_event":event}))
            .send().await.map_err(|e| format!("PayPal webhook verification failed: {e}"))?;
        let status = response.status();
        let result: Value = response.json().await.map_err(|e| e.to_string())?;
        if !status.is_success() || result["verification_status"] != "SUCCESS" { return Err("PayPal webhook signature is invalid".into()); }
        let event_id = event["id"].as_str().ok_or("Webhook event is missing id")?;
        let event_type = event["event_type"].as_str().unwrap_or("unknown");
        let already_processed=sqlx::query("SELECT event_id FROM payment_webhook_events WHERE event_id=?")
            .bind(event_id).fetch_optional(&self.pool).await.map_err(db_error)?.is_some();
        if already_processed { return Ok(()); }
        if event_type == "PAYMENT.CAPTURE.COMPLETED" {
            let resource = &event["resource"];
            let paypal_order_id = resource["supplementary_data"]["related_ids"]["order_id"].as_str().ok_or("Webhook is missing its order reference")?;
            let row = sqlx::query("SELECT email,plan_id FROM payment_checkouts WHERE paypal_order_id=?")
                .bind(paypal_order_id).fetch_optional(&self.pool).await.map_err(db_error)?
                .ok_or("Webhook order does not match a local checkout")?;
            let email: String = row.try_get("email").map_err(db_error)?;
            let plan_id: String = row.try_get("plan_id").map_err(db_error)?;
            let plan = find_plan(&plan_id).ok_or("Invalid webhook plan")?;
            let amount = &resource["amount"]["value"];
            let currency = resource["amount"]["currency_code"].as_str().unwrap_or_default();
            if amount.as_str() != Some(plan.amount) || currency != plan.currency { return Err("Webhook amount or currency does not match the local order".into()); }
            let capture_id=resource["id"].as_str().ok_or("Webhook capture reference is missing")?;
            self.mark_paid(paypal_order_id,capture_id,&email,&plan,"webhook",Some(event_id)).await?;
        }
        sqlx::query("INSERT IGNORE INTO payment_webhook_events (event_id,event_type) VALUES (?,?)")
            .bind(event_id).bind(event_type).execute(&self.pool).await.map_err(db_error)?;
        Ok(())
    }

    pub async fn request_login(&self, email: &str) -> Result<(), String> {
        let email = normalize_email(email)?;
        let exists = sqlx::query("SELECT email FROM payment_users WHERE email=?").bind(&email).fetch_optional(&self.pool).await.map_err(db_error)?.is_some();
        if !exists { return Ok(()); }
        let recent:i64=sqlx::query_scalar("SELECT COUNT(*) FROM payment_login_tokens WHERE email=? AND expires_at>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE)")
            .bind(&email).fetch_one(&self.pool).await.map_err(db_error)?;
        if recent>=3{return Ok(())}
        let token = random_token();
        let hash = token_hash(&token);
        sqlx::query("INSERT INTO payment_login_tokens (token_hash,email,expires_at) VALUES (?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 20 MINUTE))")
            .bind(hash).bind(&email).execute(&self.pool).await.map_err(db_error)?;
        let link = format!("{}/login#token={token}", self.config.public_base_url.trim_end_matches('/'));
        self.send_email(&email,"Your SeeYourSEO sign-in link",&format!("Sign in to your SeeYourSEO account: {link}\n\nThis link expires in 20 minutes. If you did not request it, ignore this message.")).await
    }

    pub async fn consume_login(&self, token: &str) -> Result<(String, String), String> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let row = sqlx::query("SELECT email FROM payment_login_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP() FOR UPDATE")
            .bind(token_hash(token)).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or("Sign-in link is invalid or expired")?;
        let email: String = row.try_get("email").map_err(db_error)?;
        sqlx::query("UPDATE payment_login_tokens SET consumed_at=UTC_TIMESTAMP() WHERE token_hash=?").bind(token_hash(token)).execute(&mut *tx).await.map_err(db_error)?;
        let session = random_token();
        sqlx::query("INSERT INTO payment_sessions (token_hash,email,expires_at) VALUES (?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY))")
            .bind(token_hash(&session)).bind(&email).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok((email,session))
    }

    pub async fn account_for_session(&self, token: &str) -> Result<Option<AccountSummary>, String> {
        let row = sqlx::query("SELECT u.email,u.scan_credits,u.page_limit FROM payment_sessions s JOIN payment_users u ON u.email=s.email WHERE s.token_hash=? AND s.expires_at>UTC_TIMESTAMP()")
            .bind(token_hash(token)).fetch_optional(&self.pool).await.map_err(db_error)?;
        let Some(row)=row else{return Ok(None)};
        let email:String=row.try_get("email").map_err(db_error)?;
        let scan_credits=row.try_get("scan_credits").map_err(db_error)?;
        let page_limit=row.try_get::<u32,_>("page_limit").map_err(db_error)? as usize;
        let receipt_rows=sqlx::query("SELECT p.paypal_order_id,p.paypal_capture_id,p.plan_id,CAST(p.amount AS CHAR) AS amount,p.currency,p.status,CASE WHEN c.consumed_at IS NULL THEN 'unused' ELSE 'used' END AS usage_status,p.confirmed_by,DATE_FORMAT(p.captured_at,'%Y-%m-%d %H:%i:%s UTC') AS captured_at FROM payments p LEFT JOIN payment_credits c ON c.paypal_order_id=p.paypal_order_id WHERE p.email=? ORDER BY p.captured_at DESC LIMIT 100")
            .bind(&email).fetch_all(&self.pool).await.map_err(db_error)?;
        let receipts=receipt_rows.into_iter().map(|r|Ok(PaymentReceipt{
            paypal_order_id:r.try_get("paypal_order_id").map_err(db_error)?,paypal_capture_id:r.try_get("paypal_capture_id").map_err(db_error)?,plan_id:r.try_get("plan_id").map_err(db_error)?,amount:r.try_get("amount").map_err(db_error)?,currency:r.try_get("currency").map_err(db_error)?,status:r.try_get("status").map_err(db_error)?,usage_status:r.try_get("usage_status").map_err(db_error)?,confirmed_by:r.try_get("confirmed_by").map_err(db_error)?,captured_at:r.try_get("captured_at").map_err(db_error)?,
        })).collect::<Result<Vec<_>,String>>()?;
        Ok(Some(AccountSummary{email,scan_credits,page_limit,receipts}))
    }

    pub async fn login_by_email(&self, raw_email: &str) -> Result<EmailLoginResult, String> {
        let email = normalize_email(raw_email)?;
        let paid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE email=? AND status='completed'")
            .bind(&email).fetch_one(&self.pool).await.map_err(db_error)?;
        if paid == 0 { return Ok(EmailLoginResult::NoPayment); }

        let available: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_credits c JOIN payments p ON p.paypal_order_id=c.paypal_order_id WHERE c.email=? AND c.consumed_at IS NULL AND p.status='completed'")
            .bind(&email).fetch_one(&self.pool).await.map_err(db_error)?;
        if available == 0 { return Ok(EmailLoginResult::CreditUsed); }

        let session_token = random_token();
        sqlx::query("INSERT INTO payment_sessions (token_hash,email,expires_at) VALUES (?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY))")
            .bind(token_hash(&session_token)).bind(&email).execute(&self.pool).await.map_err(db_error)?;
        let account = self.account_for_session(&session_token).await?.ok_or("Could not load the paid account")?;
        Ok(EmailLoginResult::SignedIn { account, session_token })
    }

    pub async fn revoke_session(&self, token:&str)->Result<(),String>{
        sqlx::query("DELETE FROM payment_sessions WHERE token_hash=?")
            .bind(token_hash(token)).execute(&self.pool).await.map_err(db_error)?;
        Ok(())
    }

    pub async fn consume_scan_credit(&self, token: &str) -> Result<Option<ScanCredit>, String> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let row = sqlx::query("SELECT u.email,c.paypal_order_id,c.page_limit FROM payment_sessions s JOIN payment_users u ON u.email=s.email JOIN payment_credits c ON c.email=u.email WHERE s.token_hash=? AND s.expires_at>UTC_TIMESTAMP() AND c.consumed_at IS NULL ORDER BY c.created_at,c.paypal_order_id LIMIT 1 FOR UPDATE")
            .bind(token_hash(token)).fetch_optional(&mut *tx).await.map_err(db_error)?;
        let Some(row) = row else { tx.commit().await.map_err(db_error)?; return Ok(None); };
        let email: String = row.try_get("email").map_err(db_error)?;
        let order_id: String = row.try_get("paypal_order_id").map_err(db_error)?;
        let limit: u32 = row.try_get("page_limit").map_err(db_error)?;
        sqlx::query("UPDATE payment_credits SET consumed_at=UTC_TIMESTAMP() WHERE paypal_order_id=? AND consumed_at IS NULL")
            .bind(&order_id).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE payment_users SET scan_credits=scan_credits-1 WHERE email=? AND scan_credits>0")
            .bind(&email).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(Some(ScanCredit{paypal_order_id:order_id,page_limit:limit as usize}))
    }

    pub async fn restore_scan_credit(&self, token: &str, order_id: &str) -> Result<(), String> {
        let mut tx=self.pool.begin().await.map_err(db_error)?;
        let email:Option<String>=sqlx::query_scalar("SELECT s.email FROM payment_sessions s JOIN payment_credits c ON c.email=s.email WHERE s.token_hash=? AND c.paypal_order_id=? AND s.expires_at>UTC_TIMESTAMP() AND c.consumed_at IS NOT NULL FOR UPDATE")
            .bind(token_hash(token)).bind(order_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
        if let Some(email)=email {
            sqlx::query("UPDATE payment_credits SET consumed_at=NULL WHERE paypal_order_id=?").bind(order_id).execute(&mut *tx).await.map_err(db_error)?;
            sqlx::query("UPDATE payment_users SET scan_credits=scan_credits+1 WHERE email=?").bind(email).execute(&mut *tx).await.map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn mark_paid(&self, order_id: &str, capture_id: &str, email: &str, plan: &Plan, confirmed_by: &str, webhook_event_id: Option<&str>) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let inserted = sqlx::query("INSERT IGNORE INTO payments (paypal_order_id,paypal_capture_id,email,plan_id,amount,currency,status,confirmed_by,webhook_event_id,captured_at) VALUES (?,?,?,?,?,?,'completed',?,?,UTC_TIMESTAMP())")
            .bind(order_id).bind(capture_id).bind(email).bind(plan.id).bind(plan.amount).bind(plan.currency).bind(confirmed_by).bind(webhook_event_id).execute(&mut *tx).await.map_err(db_error)?;
        if let Some(event_id)=webhook_event_id {
            sqlx::query("UPDATE payments SET webhook_event_id=?,confirmed_by=IF(confirmed_by='capture_api','capture+webhook',confirmed_by) WHERE paypal_order_id=?")
                .bind(event_id).bind(order_id).execute(&mut *tx).await.map_err(db_error)?;
        }
        if inserted.rows_affected() > 0 {
            sqlx::query("INSERT INTO payment_credits (paypal_order_id,email,page_limit) VALUES (?,?,?)")
                .bind(order_id).bind(email).bind(plan.page_limit as u32).execute(&mut *tx).await.map_err(db_error)?;
            sqlx::query("INSERT INTO payment_users (email,scan_credits,page_limit,last_paid_at) VALUES (?,1,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE scan_credits=scan_credits+1,page_limit=GREATEST(page_limit,VALUES(page_limit)),last_paid_at=UTC_TIMESTAMP()")
                .bind(email).bind(plan.page_limit as u32).execute(&mut *tx).await.map_err(db_error)?;
            sqlx::query("UPDATE payment_checkouts SET status='paid' WHERE paypal_order_id=?")
                .bind(order_id).execute(&mut *tx).await.map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)
    }

    async fn access_token(&self) -> Result<String, String> {
        let response = self.http.post(format!("{}/v1/oauth2/token", self.config.paypal_api()))
            .basic_auth(&self.config.paypal_client_id,Some(&self.config.paypal_client_secret))
            .header("Accept", "application/json")
            .header("Accept-Language", "en_US")
            .form(&[("grant_type","client_credentials")])
            .send().await.map_err(|e| format!("Could not connect to PayPal: {e}"))?;
        let status = response.status();
        let body: TokenResponse = response.json().await.map_err(|e| format!("Invalid PayPal token response ({status}): {e}"))?;
        if !status.is_success() { return Err(format!("PayPal authentication failed ({status})")); }
        Ok(body.access_token)
    }

    async fn send_email(&self, to: &str, subject: &str, text: &str) -> Result<(), String> {
        let smtp_host=self.config.smtp_host.as_deref().ok_or("Email delivery is not configured")?;
        let smtp_username=self.config.smtp_username.as_deref().ok_or("Email delivery is not configured")?;
        let smtp_password=self.config.smtp_password.as_deref().ok_or("Email delivery is not configured")?;
        let from_email=self.config.from_email.as_deref().ok_or("Email delivery is not configured")?;
        let from: Mailbox = format!("{} <{}>", self.config.from_name, from_email).parse().map_err(|e| format!("Invalid MAIL_FROM: {e}"))?;
        let recipient: Mailbox = to.parse().map_err(|e| format!("Invalid recipient address: {e}"))?;
        let message = Message::builder().from(from).to(recipient).subject(subject)
            .body(text.to_owned()).map_err(|e| e.to_string())?;
        let tls = TlsParameters::new(smtp_host.to_owned()).map_err(|e| format!("Invalid SMTP TLS configuration: {e}"))?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_host)
            .port(self.config.smtp_port)
            .tls(Tls::Wrapper(tls))
            .credentials(Credentials::new(smtp_username.to_owned(),smtp_password.to_owned()))
            .build();
        transport.send(message).await.map_err(|e| format!("Could not send email: {e}"))?;
        Ok(())
    }
}

pub fn find_plan(id: &str) -> Option<Plan> { PLANS.iter().find(|p| p.id==id).cloned() }

fn validate_capture(body: &Value, order_id: &str, checkout_id: &str, plan: &Plan) -> Result<(), String> {
    if body["id"].as_str() != Some(order_id) || body["status"] != "COMPLETED" { return Err("PayPal has not completed this payment".into()); }
    let purchase = body["purchase_units"].as_array().and_then(|a|a.first()).ok_or("PayPal payment details are missing")?;
    // PayPal's capture response can omit custom_id even though the order created
    // by us includes it. The order ID was already matched to this checkout in
    // payment_checkouts, so only reject custom IDs that PayPal actually returns
    // and that disagree with our local checkout binding.
    if let Some(custom_id) = purchase["custom_id"].as_str() {
        if custom_id != checkout_id { return Err("Payment does not match this checkout".into()); }
    }
    let capture = purchase["payments"]["captures"].as_array().and_then(|a|a.first()).ok_or("PayPal capture details are missing")?;
    if capture["status"]!="COMPLETED" || capture["amount"]["currency_code"].as_str()!=Some(plan.currency) || capture["amount"]["value"].as_str()!=Some(plan.amount) {
        return Err("Captured payment amount or currency does not match the selected plan".into());
    }
    Ok(())
}

fn normalize_email(value: &str) -> Result<String,String> {
    let email=value.trim().to_ascii_lowercase();
    if email.len()>320 || email.contains(['\r','\n']) || !email.parse::<Mailbox>().is_ok() { return Err("Enter a valid email address".into()); }
    Ok(email)
}

fn random_token()->String{let mut bytes=[0u8;32];OsRng.fill_bytes(&mut bytes);bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn token_hash(token:&str)->String{format!("{:x}",Sha256::digest(token.as_bytes()))}
fn db_error(error:sqlx::Error)->String{format!("Payments database error: {error}")}
