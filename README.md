# Voight Trace — Official PHP SDK Collector (`sdk-php`)

[![packagist version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://voighttrace.com)
[![php version](https://img.shields.io/badge/php-%3E%3D8.0-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](https://voighttrace.com)

Official PHP SDK Collector for **Voight Trace** (`voight-trace/sdk-php`). It provides non-blocking, post-response telemetry capture to detect, classify, and audit AI Agents, LLM crawlers (OpenAI GPTBot, ClaudeBot, PerplexityBot, Google-Extended, ByteDance Bytespider), and human visitors recommended by generative AI platforms.

---

## 🚀 Quickstart & Framework Integrations

### 1. Installation

```bash
composer require voight-trace/sdk-php
```

Or without Composer, include [`src/VoightTraceCollector.php`](./src/VoightTraceCollector.php) directly via `require_once`.

---

### 2. Vanilla PHP / PHP-FPM Integration (`index.php`)

Register the collector at the entry point of your application:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use VoightTrace\VoightTraceCollector;

$tracker = new VoightTraceCollector([
    'apiKey' => getenv('VOIGHT_TRACE_API_KEY'), // e.g. "vt_live_9a8f4c2e..."
    'siteId' => getenv('VOIGHT_TRACE_SITE_ID'), // e.g. "018f2d5e-7a91..."
]);

// Non-blocking shutdown hook (calls fastcgi_finish_request() on PHP-FPM — 0ms added latency)
$tracker->register();
```

---

### 3. Laravel Integration

Create a lightweight middleware (`app/Http/Middleware/VoightTraceMiddleware.php`) or register in `public/index.php` right after `require __DIR__.'/../vendor/autoload.php'`:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use VoightTrace\VoightTraceCollector;

class VoightTraceMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $tracker = new VoightTraceCollector([
            'apiKey' => config('services.voight_trace.api_key', env('VOIGHT_TRACE_API_KEY')),
            'siteId' => config('services.voight_trace.site_id', env('VOIGHT_TRACE_SITE_ID')),
        ]);

        $tracker->register();

        return $next($request);
    }
}
```

---

### 4. Slim / Mezzio / PSR-15 Middleware Integration

For PSR-7 / PSR-15 frameworks, use `handlePsr15()`:

```php
<?php
use VoightTrace\VoightTraceCollector;

$tracker = new VoightTraceCollector([
    'apiKey' => getenv('VOIGHT_TRACE_API_KEY'),
    'siteId' => getenv('VOIGHT_TRACE_SITE_ID'),
]);

$app->add(function ($request, $handler) use ($tracker) {
    return $tracker->handlePsr15($request, $handler);
});
```

---

### 5. WordPress Integration (`mu-plugins`)

Create `wp-content/mu-plugins/voight-trace.php`:

```php
<?php
/**
 * Plugin Name: Voight Trace Telemetry Collector
 */

require_once ABSPATH . 'vendor/autoload.php'; // or path to VoightTraceCollector.php

use VoightTrace\VoightTraceCollector;

$tracker = new VoightTraceCollector([
    'apiKey' => defined('VOIGHT_TRACE_API_KEY') ? VOIGHT_TRACE_API_KEY : getenv('VOIGHT_TRACE_API_KEY'),
    'siteId' => defined('VOIGHT_TRACE_SITE_ID') ? VOIGHT_TRACE_SITE_ID : getenv('VOIGHT_TRACE_SITE_ID'),
]);

$tracker->register();
```

---

### 6. Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `apiKey` | `string` | `getenv('VOIGHT_TRACE_API_KEY')` | **Required.** Secret Ingestion Key (`vt_live_...` or `vt_test_...`). |
| `siteId` | `string` | `getenv('VOIGHT_TRACE_SITE_ID')` | **Required.** Site ID registered in the Voight dashboard. |
| `tenantId` | `string` | `siteId` | Optional tenant UUID. |
| `collectorId` | `string` | `php_<random>` | Custom collector instance identifier. |
| `ingestUrl` | `string` | `https://voighttrace.vercel.app/api/v1/ingestion/events` | Custom Ingestion API URL. |
| `sampleRate` | `float` | `1.0` | Sampling rate between `0.0` (0%) and `1.0` (100%). |
| `timeoutSeconds` | `float` | `1.5` | Maximum HTTP dispatch timeout in seconds. |
| `debug` | `bool` | `false` | Enables diagnostic logs via `error_log()`. |
| `disabled` | `bool` | `false` | Disables telemetry collection (useful in testing). |

---

## 🔒 Privacy & Security by Design (Header & Credential Sanitization)

To ensure maximum security and strict compliance with global privacy regulations (GDPR, LGPD) and enterprise SOC2 audits, **`sdk-php` enforces a strict Header Allowlist policy (`SAFE_AUDIT_HEADERS`)**.

The collector **never** collects, stores, or transmits client credentials, session tokens, or sensitive authentication headers.

### 🚫 Prohibited Headers — NEVER Collected
Any request header capable of carrying private credentials or personally identifiable authentication tokens is **strictly filtered out at the collector layer**:
* ❌ `Authorization` / `Proxy-Authorization` (Bearer tokens, JWTs, Basic Auth)
* ❌ `Cookie` / `Set-Cookie` (User session identifiers, login cookies)
* ❌ `X-Api-Key` / `Api-Key` / `X-Auth-Token` / `X-Access-Token` (Customer private API keys)
* ❌ Passwords, custom secret headers, or POST/PUT request bodies

### ✅ Permitted Headers (`SAFE_AUDIT_HEADERS`)
Only standardized, technical context headers strictly required for AI crawler classification, browser architecture detection, and content negotiation are extracted:
* **Core AI & Traffic Identification:** `user-agent` (identifies AI crawlers & LLM agents), `referer` (detects human referrals from ChatGPT, Claude, Perplexity), `host`, `origin`
* **Content Negotiation:** `accept`, `accept-encoding`, `accept-language`, `content-type`
* **Client Hints (Browser Architecture & Device Detection):** `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `sec-ch-ua-platform-version`, `sec-ch-ua-model`, `sec-ch-ua-arch`
* **Browser Request Metadata:** `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site`, `sec-fetch-user`

### 🔍 How to Audit in Code
The allowlist and sanitization logic are deliberately centralized and exposed for transparent security inspection:
* **Allowlist Constant:** `VoightTraceCollector::SAFE_AUDIT_HEADERS` in [`src/VoightTraceCollector.php`](./src/VoightTraceCollector.php)
* **Sanitizer Method:** `VoightTraceCollector::filterSafeHeaders(array $headers)` in [`src/VoightTraceCollector.php`](./src/VoightTraceCollector.php)
* **Clean IP Forwarding:** `VoightTraceCollector::extractClientIp()` forwards `network.client_ip` and `x-voight-client-ip` without client-side Geo/ASN enrichment; Country, ASN, FCrDNS verification, and HMAC-SHA256 IP hashing run server-side.

---

## ⚡ Non-Blocking Guarantee & Performance
- **Zero Latency Impact:** `register()` flushes telemetry inside `register_shutdown_function()` after invoking `fastcgi_finish_request()` (when running under PHP-FPM), so the visitor receives the full HTTP response before the ingestion call runs.
- **High-Precision Timing:** Uses `hrtime(true)` for accurate request latency (`duration_ms`) and detects response size (`bytes_sent`) via `Content-Length` / output buffering.
- **Fail-Safe:** Network errors or ingestion timeouts (`1.5s` cap) are caught silently and never interrupt or delay the host PHP application.

---

## 🧪 Running Tests

```bash
php -l src/VoightTraceCollector.php
php tests/run.php
```
