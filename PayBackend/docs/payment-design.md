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
- Configure platform cert path for signature verification
- Implement AES-GCM decrypt for callback resource
- Implement idempotency with Redis or pay_idempotency table
- Generate ORM models (see models/README.md) before refactoring SQL access

## Config Flags
- use_redis_idempotency: enable Redis SET NX EX for callback idempotency
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
