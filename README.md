# BlackRoad Rate Limiting

Protect APIs with configurable rate limits, quotas, and throttling.

## Live

- **Dashboard**: https://blackroad-ratelimit.amundsonalexa.workers.dev
- **API**: https://blackroad-ratelimit.amundsonalexa.workers.dev/api/rules

## Features

- **Sliding Window** - Accurate rate limiting algorithm
- **Multiple Matchers** - Path, IP, API key, user-based
- **Actions** - Block, throttle, or log only
- **Real-time Stats** - Requests, blocked, throttled counts
- **Test Endpoint** - Check limits before deploying
- **Standard Headers** - X-RateLimit-* response headers

## Default Rules

| Rule | Limit | Window | Action |
|------|-------|--------|--------|
| Global | 1000 | 1 hour | Block |
| GraphQL | 5000 | 1 hour | Throttle |
| Auth | 10 | 1 minute | Block |
| Webhooks | 100 | 1 minute | Block |
| Free Tier | 100 | 1 hour | Block |

## API

### GET /api/rules
List all rate limit rules.

### PUT /api/rules/:id
Update a rule (enable/disable, change limit).

### POST /api/check
Check if a request would be rate limited.

```json
{
  "key": "br_test_abc123",
  "path": "/api/users"
}
```

Response:
```json
{
  "allowed": true,
  "remaining": 95,
  "resetAt": 1708000000000,
  "rule": "rule_global"
}
```

### GET /api/stats
Get aggregated statistics.

## Response Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1708000000
```

## Matcher Types

| Type | Description | Example |
|------|-------------|---------|
| `path` | URL path pattern | `/api/*` |
| `ip` | Client IP | `192.168.1.*` |
| `api_key` | API key prefix | `br_test_*` |
| `user` | User ID | `usr_*` |

## Development

```bash
npm install
npm run dev
npm run deploy
```

## License

Proprietary - BlackRoad OS, Inc.
