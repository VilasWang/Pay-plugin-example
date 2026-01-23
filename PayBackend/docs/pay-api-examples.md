# Pay API Examples

## Create Payment

```
curl -X POST http://localhost:5566/pay/create \
  -H "Idempotency-Key: YOUR_IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "10001",
    "amount": "9.99",
    "currency": "CNY",
    "title": "Demo Order"
  }'
```

Response (sample):

```
{
  "order_no": "c2d7c8ad-6a4b-4f3f-9a31-32db0a3fcd82",
  "payment_no": "9abbb3e5-7b23-4a0f-a62d-4d534c2be9c0",
  "status": "PAYING",
  "wechat_response": {
    "code_url": "weixin://wxpay/bizpayurl?pr=xxxx"
  }
}
```

Note: `Idempotency-Key` is optional but recommended for retry safety.

## Query Order

```
curl "http://localhost:5566/pay/query?order_no=c2d7c8ad-6a4b-4f3f-9a31-32db0a3fcd82" \
  -H "X-Api-Key: YOUR_API_KEY"
```

## Refund

```
curl -X POST http://localhost:5566/pay/refund \
  -H "Idempotency-Key: YOUR_IDEMPOTENCY_KEY" \
  -H "X-Api-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "order_no": "c2d7c8ad-6a4b-4f3f-9a31-32db0a3fcd82",
    "payment_no": "9abbb3e5-7b23-4a0f-a62d-4d534c2be9c0",
    "amount": "9.99"
  }'
```

## Refund Query

```
curl "http://localhost:5566/pay/refund/query?refund_no=YOUR_REFUND_NO" \
  -H "X-Api-Key: YOUR_API_KEY"
```

## Auth Metrics

```
curl "http://localhost:5566/pay/metrics/auth" \
  -H "X-Api-Key: YOUR_API_KEY"
```

## Auth Metrics (Prometheus)

```
curl "http://localhost:5566/pay/metrics/auth.prom" \
  -H "X-Api-Key: YOUR_API_KEY"
```

## Combined Metrics (Prometheus)

```
curl "http://localhost:5566/metrics"
```

## WeChat Pay Callback (Sample Body)

```
{
  "id": "4200000000000000000000000000",
  "create_time": "2020-06-18T10:34:56+08:00",
  "resource_type": "encrypt-resource",
  "event_type": "TRANSACTION.SUCCESS",
  "summary": "Payment successful",
  "resource": {
    "algorithm": "AEAD_AES_256_GCM",
    "ciphertext": "BASE64_CIPHERTEXT_WITH_TAG",
    "nonce": "RANDOM_NONCE",
    "associated_data": "transaction"
  }
}
```

Required headers for signature verification:

- Wechatpay-Timestamp
- Wechatpay-Nonce
- Wechatpay-Signature
- Wechatpay-Serial
