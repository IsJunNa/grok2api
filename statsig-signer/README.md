# statsig-signer

Headless Chromium service that produces Grok Web `x-statsig-id` values by running grok.com’s own browser signer.

Adapted from [duanzhenyu/grok2api](https://github.com/duanzhenyu/grok2api) `statsig-signer` for use with this Go gateway.

## Why

Grok Web rejects API calls without a valid `x-statsig-id` (HTTP 403 / anti-bot code 7). Public shared signer endpoints are often blocked by Cloudflare. This service keeps one Chromium tab open and signs `method + path` on demand.

## API

```http
POST /sign
Content-Type: application/json

{"method":"POST","path":"/rest/app-chat/conversations/new"}
```

```json
{"statsig":"<base64 x-statsig-id>"}
```

```http
GET /health
```

```json
{"ready":true,"hasPage":true}
```

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | HTTP listen port |
| `GROK_SSO_TOKEN` | empty | Optional SSO cookie; signatures are anonymous, so empty is usually fine |
| `PROXY_URL` | empty | Proxy for Chromium (use the same egress as Grok Web when possible) |
| `SIGN_TTL_MS` | `45000` | In-memory signature cache TTL |
| `READY_TIMEOUT_MS` | `90000` | Boot wait for signer readiness |

## Compose

Started by the root `docker-compose.yml` as `statsig-signer`. Point Grok2API runtime settings to:

```text
http://statsig-signer:3000/sign
```

## Resource note

Expect roughly +0.5GB RAM for Chromium. CPU is capped at 0.5 core in the default Compose file.
