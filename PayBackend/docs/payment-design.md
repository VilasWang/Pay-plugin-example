# Payment System (WeChat Pay V3)

## Modules
- PayController: create payment, query order, refund
- WechatCallbackController: payment callback endpoint
- PayPlugin: core business logic, order state machine, idempotency
- WechatPayClient: WeChat Pay V3 request and signature logic

## Endpoints
- POST /pay/create
- GET /pay/query
- POST /pay/refund
- POST /pay/notify/wechat

## Status Flow
- Order: CREATED -> PAYING -> PAID | FAILED | CLOSED
- Payment: INIT -> PROCESSING -> SUCCESS | FAIL | TIMEOUT
- Refund: REFUND_INIT -> REFUNDING -> REFUND_SUCCESS | REFUND_FAIL

## Next Steps
- Generate ORM models (see models/README.md) before refactoring SQL access

## WeChat Config (config.json)
- wechat_pay.app_id: WeChat app id
- wechat_pay.mch_id: merchant id
- wechat_pay.serial_no: platform certificate serial
- wechat_pay.api_v3_key: 32-byte API v3 key
- wechat_pay.private_key_path: merchant private key (PEM)
- wechat_pay.platform_cert_path: platform certificate (PEM)
- wechat_pay.notify_url: callback URL, e.g. https://your.domain/pay/notify/wechat
- wechat_pay.api_base: defaults to https://api.mch.weixin.qq.com
- wechat_pay.timeout_ms: request timeout

## Certificates & Keys
- private_key_path: merchant API v3 private key (PEM)
- platform_cert_path: WeChat platform certificate (PEM)
- serial_no: must match platform certificate serial used to verify signatures
- api_v3_key: exactly 32 bytes, used for AES-GCM decrypt

## Idempotency
- create/refund support Idempotency-Key header
- use_redis_idempotency: enable Redis SET NX EX lock for create/refund
- idempotency_ttl_seconds: TTL for idempotency key (default 7 days)

## Config Flags
- use_redis_idempotency: enable Redis SET NX EX for idempotency
- idempotency_ttl_seconds: TTL for idempotency key
- reconcile_enabled: enable scheduled WeChat query reconciliation
- reconcile_interval_seconds: interval for scheduled reconciliation
- reconcile_batch_size: max orders to reconcile per tick
- pay.api_keys: allowed API keys for protected endpoints (can be empty)
- env PAY_API_KEY or PAY_API_KEYS: alternative API key sources
- pay.api_key_scopes: map key -> [scopes], supports refund/refund_query/order_query
- pay.api_key_default_scopes: scopes used when a key has no explicit mapping
- auth metrics endpoint: GET /pay/metrics/auth (protected by PayAuthFilter)
- auth metrics Prometheus: GET /pay/metrics/auth.prom (protected by PayAuthFilter)
- combined Prometheus endpoint: GET /metrics (includes base + auth metrics)
