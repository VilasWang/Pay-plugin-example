-- Basic schema for payment system (PostgreSQL style)

CREATE TABLE IF NOT EXISTS pay_order (
    id BIGSERIAL PRIMARY KEY,
    order_no VARCHAR(64) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    amount DECIMAL(18,2) NOT NULL,
    currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    status VARCHAR(24) NOT NULL,
    channel VARCHAR(16) NOT NULL,
    title VARCHAR(128) NOT NULL,
    expire_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pay_payment (
    id BIGSERIAL PRIMARY KEY,
    order_no VARCHAR(64) NOT NULL,
    payment_no VARCHAR(64) NOT NULL UNIQUE,
    channel_trade_no VARCHAR(64),
    status VARCHAR(24) NOT NULL,
    amount DECIMAL(18,2) NOT NULL,
    request_payload TEXT,
    response_payload TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pay_payment_order_no ON pay_payment(order_no);

CREATE TABLE IF NOT EXISTS pay_callback (
    id BIGSERIAL PRIMARY KEY,
    payment_no VARCHAR(64) NOT NULL,
    raw_body TEXT NOT NULL,
    signature VARCHAR(512),
    serial_no VARCHAR(64),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    received_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pay_callback_payment_no ON pay_callback(payment_no);

CREATE TABLE IF NOT EXISTS pay_refund (
    id BIGSERIAL PRIMARY KEY,
    refund_no VARCHAR(64) NOT NULL UNIQUE,
    order_no VARCHAR(64) NOT NULL,
    payment_no VARCHAR(64) NOT NULL,
    channel_refund_no VARCHAR(64),
    status VARCHAR(24) NOT NULL,
    amount DECIMAL(18,2) NOT NULL,
    response_payload TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pay_refund_order_no ON pay_refund(order_no);

CREATE TABLE IF NOT EXISTS pay_ledger (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    order_no VARCHAR(64) NOT NULL,
    payment_no VARCHAR(64),
    entry_type VARCHAR(24) NOT NULL,
    amount DECIMAL(18,2) NOT NULL,
    balance DECIMAL(18,2),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pay_ledger_user_id ON pay_ledger(user_id);

CREATE TABLE IF NOT EXISTS pay_idempotency (
    idempotency_key VARCHAR(64) PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    response_snapshot TEXT,
    expires_at TIMESTAMP
);
