CREATE TABLE payment_checkouts (
    id CHAR(36) PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    site_url TEXT NULL,
    plan_id VARCHAR(32) NOT NULL,
    verify_hash CHAR(64) NOT NULL UNIQUE,
    verified_at DATETIME NULL,
    immediate_consent_at DATETIME NULL,
    paypal_order_id VARCHAR(64) NULL UNIQUE,
    status VARCHAR(24) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_checkout_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE payment_credits (
    paypal_order_id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    page_limit INT UNSIGNED NOT NULL,
    consumed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_credit_available (email, consumed_at, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE payment_users (
    email VARCHAR(320) PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_credits BIGINT UNSIGNED NOT NULL DEFAULT 0,
    page_limit INT UNSIGNED NOT NULL DEFAULT 20,
    last_paid_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE payments (
    paypal_order_id VARCHAR(64) PRIMARY KEY,
    paypal_capture_id VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(320) NOT NULL,
    plan_id VARCHAR(32) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    status VARCHAR(24) NOT NULL,
    confirmed_by VARCHAR(16) NOT NULL,
    webhook_event_id VARCHAR(128) NULL,
    captured_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_payment_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE payment_webhook_events (
    event_id VARCHAR(128) PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE payment_login_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    INDEX idx_login_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE payment_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    expires_at DATETIME NOT NULL,
    INDEX idx_session_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
