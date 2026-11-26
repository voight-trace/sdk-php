<?php

declare(strict_types=1);

namespace VoightTrace;

/**
 * Voight Trace — Official PHP SDK Collector
 *
 * Non-blocking HTTP telemetry collector for PHP 8.0+ (vanilla PHP, Laravel, Symfony, WordPress).
 * Forwards clean client IP and sanitized allowlisted headers to the Voight Trace Ingestion API;
 * Geo/ASN enrichment, FCrDNS verification, and HMAC-SHA256 IP hashing run server-side.
 */
class VoightTraceCollector
{
    public const VERSION = '1.0.0';
    public const DEFAULT_INGEST_URL = 'https://voighttrace.vercel.app/api/v1/ingestion/events';

    /**
     * Allowlisted non-sensitive HTTP headers strictly necessary for AI bot
     * classification, client hints, content negotiation, and routing.
     */
    public const SAFE_AUDIT_HEADERS = [
        'user-agent',
        'referer',
        'host',
        'origin',
        'accept',
        'accept-encoding',
        'accept-language',
        'content-type',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-platform-version',
        'sec-ch-ua-model',
        'sec-ch-ua-arch',
        'sec-fetch-dest',
        'sec-fetch-mode',
        'sec-fetch-site',
        'sec-fetch-user',
    ];

    private string $apiKey;
    private string $siteId;
    private string $tenantId;
    private string $collectorId;
    private string $ingestUrl;
    private float $sampleRate;
    private float $timeoutSeconds;
    private bool $debug;
    private bool $disabled;

    /** @var array<int, array<string, mixed>> */
    private array $queue = [];

    /** @var callable|null */
    private $transport;

    private bool $shutdownRegistered = false;

    /**
     * @param array{
     *   apiKey?: string,
     *   siteId?: string,
     *   tenantId?: string,
     *   collectorId?: string,
     *   ingestUrl?: string,
     *   sampleRate?: float,
     *   timeoutSeconds?: float,
     *   debug?: bool,
     *   disabled?: bool,
     *   transport?: callable
     * } $config
     */
    public function __construct(array $config = [])
    {
        $this->apiKey = (string) ($config['apiKey'] ?? getenv('VOIGHT_TRACE_API_KEY') ?: '');
        $this->siteId = (string) ($config['siteId'] ?? getenv('VOIGHT_TRACE_SITE_ID') ?: '');
        $this->tenantId = (string) ($config['tenantId'] ?? getenv('VOIGHT_TRACE_TENANT_ID') ?: ($this->siteId ?: 'default_tenant'));
        $this->collectorId = (string) ($config['collectorId'] ?? getenv('VOIGHT_TRACE_COLLECTOR_ID') ?: ('php_' . substr(self::uuidV4(), 0, 8)));

        $rawIngestUrl = (string) ($config['ingestUrl'] ?? getenv('VOIGHT_TRACE_INGEST_URL') ?: self::DEFAULT_INGEST_URL);
        if (str_contains($rawIngestUrl, 'api.voighttrace.com')) {
            $rawIngestUrl = self::DEFAULT_INGEST_URL;
        }
        $this->ingestUrl = $rawIngestUrl;

        $this->sampleRate = isset($config['sampleRate']) ? (float) $config['sampleRate'] : 1.0;
        $this->timeoutSeconds = isset($config['timeoutSeconds']) ? (float) $config['timeoutSeconds'] : 1.5;
        $this->debug = (bool) ($config['debug'] ?? (getenv('VOIGHT_TRACE_DEBUG') === 'true'));
        $this->disabled = (bool) ($config['disabled'] ?? (getenv('VOIGHT_TRACE_DISABLED') === 'true'));
        $this->transport = $config['transport'] ?? null;
    }

    /**
     * Registers a non-blocking shutdown hook to capture and flush the current HTTP request
     * after PHP finishes sending the response to the client (zero added user latency).
     */
    public function register(): void
    {
        if ($this->disabled || $this->apiKey === '' || $this->siteId === '') {
            return;
        }

        if ($this->sampleRate < 1.0 && (mt_rand() / mt_getrandmax()) > $this->sampleRate) {
            return;
        }

        $startTimeNs = hrtime(true);
        $server = $_SERVER;
        $headers = self::extractHeadersFromServer($server);

        $correlationId = $headers['x-voight-trace-correlation-id'] ?? ('vgt_' . self::uuidV4());
        if (!headers_sent()) {
            header('x-voight-trace-correlation-id: ' . $correlationId);
        }

        if (!$this->shutdownRegistered) {
            $this->shutdownRegistered = true;
            register_shutdown_function(function () use ($startTimeNs, $server, $headers, $correlationId): void {
                try {
                    if (function_exists('fastcgi_finish_request')) {
                        @fastcgi_finish_request();
                    }

                    $durationMs = (int) max(0, round((hrtime(true) - $startTimeNs) / 1_000_000));
                    $statusCode = http_response_code();
                    if (!is_int($statusCode) || $statusCode <= 0) {
                        $statusCode = 200;
                    }

                    $bytesSent = self::detectResponseBytesSent();
                    $event = $this->buildEventFromGlobals($server, $headers, $correlationId, $statusCode, $durationMs, $bytesSent);
                    $this->enqueue($event);
                    $this->flush();
                } catch (\Throwable $e) {
                    if ($this->debug) {
                        error_log('[Voight Trace PHP SDK] Shutdown capture error: ' . $e->getMessage());
                    }
                }
            });
        }
    }

    /**
     * PSR-15 compatible middleware handler (works with Slim, Mezzio, Laravel/Symfony bridges).
     *
     * @param object $request PSR-7 ServerRequestInterface
     * @param object $handler PSR-15 RequestHandlerInterface
     * @return object PSR-7 ResponseInterface
     */
    public function handlePsr15(object $request, object $handler): object
    {
        $startTimeNs = hrtime(true);
        $correlationId = method_exists($request, 'getHeaderLine')
            ? $request->getHeaderLine('x-voight-trace-correlation-id')
            : '';

        if ($correlationId === '') {
            $correlationId = 'vgt_' . self::uuidV4();
        }

        $response = $handler->handle($request);

        if (!$this->disabled && $this->apiKey !== '' && $this->siteId !== '') {
            if ($this->sampleRate >= 1.0 || (mt_rand() / mt_getrandmax()) <= $this->sampleRate) {
                try {
                    $durationMs = (int) max(0, round((hrtime(true) - $startTimeNs) / 1_000_000));
                    $event = $this->buildEventFromPsr7($request, $response, $correlationId, $durationMs);
                    $this->enqueue($event);
                    $this->flush();
                } catch (\Throwable $e) {
                    if ($this->debug) {
                        error_log('[Voight Trace PHP SDK] PSR-15 capture error: ' . $e->getMessage());
                    }
                }
            }
        }

        if (method_exists($response, 'withHeader')) {
            return $response->withHeader('x-voight-trace-correlation-id', $correlationId);
        }

        return $response;
    }

    /**
     * Builds a compliant Event Contract observation from PHP $_SERVER & extracted headers.
     *
     * @param array<string, mixed> $server
     * @param array<string, string> $rawHeaders
     * @return array<string, mixed>
     */
    public function buildEventFromGlobals(
        array $server,
        array $rawHeaders,
        string $correlationId,
        int $statusCode = 200,
        int $durationMs = 0,
        int $bytesSent = 0
    ): array {
        $isHttps = (!empty($server['HTTPS']) && $server['HTTPS'] !== 'off')
            || (($server['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
            || ((string) ($server['SERVER_PORT'] ?? '') === '443');

        $rawUri = (string) ($server['REQUEST_URI'] ?? '/');
        $parts = parse_url($rawUri);
        $path = $parts['path'] ?? '/';
        if ($path === '') {
            $path = '/';
        }

        $queryParams = [];
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $queryParams);
        }

        $host = (string) ($rawHeaders['host'] ?? $server['HTTP_HOST'] ?? $server['SERVER_NAME'] ?? 'localhost');
        $host = explode(':', $host)[0];

        $clientIp = self::extractClientIp($rawHeaders, $server);
        $selectedHeaders = self::filterSafeHeaders($rawHeaders);

        return [
            'event_id' => self::uuidV4(),
            'event_type' => 'http.request',
            'schema_version' => 1,
            'tenant_id' => $this->tenantId,
            'site_id' => $this->siteId,
            'collector_id' => $this->collectorId,
            'collector_type' => 'php_sdk',
            'observation_id' => self::uuidV4(),
            'request_id' => $rawHeaders['x-request-id'] ?? null,
            'correlation_id' => $correlationId,
            'occurred_at' => gmdate('Y-m-d\TH:i:s.v\Z'),
            'request' => [
                'method' => strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')),
                'scheme' => $isHttps ? 'https' : 'http',
                'host' => $host,
                'path' => $path,
                'query_params' => $queryParams ?: new \stdClass(),
                'referer' => $rawHeaders['referer'] ?? '',
                'user_agent' => $rawHeaders['user-agent'] ?? '',
                'selected_headers' => $selectedHeaders ?: new \stdClass(),
            ],
            'network' => [
                'client_ip' => $clientIp,
            ],
            'response' => [
                'status_code' => $statusCode,
                'duration_ms' => $durationMs,
                'bytes_sent' => $bytesSent,
            ],
        ];
    }

    /**
     * Builds an Event Contract observation from PSR-7 ServerRequest & Response objects.
     *
     * @return array<string, mixed>
     */
    private function buildEventFromPsr7(object $request, object $response, string $correlationId, int $durationMs): array
    {
        $rawHeaders = [];
        if (method_exists($request, 'getHeaders')) {
            foreach ($request->getHeaders() as $k => $vals) {
                $rawHeaders[strtolower((string) $k)] = is_array($vals) ? implode(', ', $vals) : (string) $vals;
            }
        }

        $server = method_exists($request, 'getServerParams') ? $request->getServerParams() : [];
        $uri = method_exists($request, 'getUri') ? $request->getUri() : null;
        $method = method_exists($request, 'getMethod') ? (string) $request->getMethod() : 'GET';

        $queryParams = [];
        if ($uri && method_exists($uri, 'getQuery') && $uri->getQuery() !== '') {
            parse_str((string) $uri->getQuery(), $queryParams);
        }

        $statusCode = method_exists($response, 'getStatusCode') ? (int) $response->getStatusCode() : 200;
        $bytesSent = 0;
        if (method_exists($response, 'getHeaderLine') && $response->getHeaderLine('Content-Length') !== '') {
            $bytesSent = (int) $response->getHeaderLine('Content-Length');
        } elseif (method_exists($response, 'getBody')) {
            $body = $response->getBody();
            if ($body && method_exists($body, 'getSize') && $body->getSize() !== null) {
                $bytesSent = (int) $body->getSize();
            }
        }

        $clientIp = self::extractClientIp($rawHeaders, $server);
        $selectedHeaders = self::filterSafeHeaders($rawHeaders);

        return [
            'event_id' => self::uuidV4(),
            'event_type' => 'http.request',
            'schema_version' => 1,
            'tenant_id' => $this->tenantId,
            'site_id' => $this->siteId,
            'collector_id' => $this->collectorId,
            'collector_type' => 'php_sdk',
            'observation_id' => self::uuidV4(),
            'request_id' => $rawHeaders['x-request-id'] ?? null,
            'correlation_id' => $correlationId,
            'occurred_at' => gmdate('Y-m-d\TH:i:s.v\Z'),
            'request' => [
                'method' => strtoupper($method),
                'scheme' => ($uri && method_exists($uri, 'getScheme') && $uri->getScheme() !== '') ? $uri->getScheme() : 'https',
                'host' => ($uri && method_exists($uri, 'getHost') && $uri->getHost() !== '') ? $uri->getHost() : 'localhost',
                'path' => ($uri && method_exists($uri, 'getPath') && $uri->getPath() !== '') ? $uri->getPath() : '/',
                'query_params' => $queryParams ?: new \stdClass(),
                'referer' => $rawHeaders['referer'] ?? '',
                'user_agent' => $rawHeaders['user-agent'] ?? '',
                'selected_headers' => $selectedHeaders ?: new \stdClass(),
            ],
            'network' => [
                'client_ip' => $clientIp,
            ],
            'response' => [
                'status_code' => $statusCode,
                'duration_ms' => $durationMs,
                'bytes_sent' => $bytesSent,
            ],
        ];
    }

    /**
     * Enqueues a single observation into the in-memory batch.
     *
     * @param array<string, mixed> $event
     */
    public function enqueue(array $event): void
    {
        $this->queue[] = $event;
    }

    /**
     * Dispatches pending observations to the Voight Trace Ingestion API.
     */
    public function flush(): bool
    {
        if (empty($this->queue) || $this->apiKey === '' || $this->disabled) {
            return false;
        }

        $batch = $this->queue;
        $this->queue = [];

        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->apiKey,
            'x-voight-collector-type: php_sdk',
            'x-voight-collector-version: ' . self::VERSION,
        ];

        if (count($batch) === 1 && !empty($batch[0]['network']['client_ip'])) {
            $singleIp = (string) $batch[0]['network']['client_ip'];
            if ($singleIp !== '127.0.0.1') {
                $headers[] = 'x-voight-client-ip: ' . $singleIp;
            }
        }

        $body = json_encode(['events' => $batch], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            return false;
        }

        if ($this->transport !== null) {
            return (bool) ($this->transport)($this->ingestUrl, $headers, $body);
        }

        return $this->sendHttp($this->ingestUrl, $headers, $body);
    }

    /**
     * Filters incoming headers down to the strict SAFE_AUDIT_HEADERS allowlist.
     *
     * @param array<string, mixed> $headers
     * @return array<string, string>
     */
    public static function filterSafeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $k => $v) {
            if ($v !== null && $v !== '') {
                $normalized[strtolower((string) $k)] = is_array($v) ? implode(', ', $v) : (string) $v;
            }
        }

        $filtered = [];
        foreach (self::SAFE_AUDIT_HEADERS as $allowed) {
            if (isset($normalized[$allowed]) && $normalized[$allowed] !== '') {
                $filtered[$allowed] = $normalized[$allowed];
            }
        }

        return $filtered;
    }

    /**
     * Extracts clean client IP without doing any Geo/ASN enrichment.
     *
     * @param array<string, string> $headers
     * @param array<string, mixed> $server
     */
    public static function extractClientIp(array $headers, array $server = []): string
    {
        $cf = $headers['cf-connecting-ip'] ?? ($server['HTTP_CF_CONNECTING_IP'] ?? null);
        if (is_string($cf) && trim($cf) !== '') {
            return trim($cf);
        }

        $realIp = $headers['x-real-ip'] ?? ($server['HTTP_X_REAL_IP'] ?? null);
        if (is_string($realIp) && trim($realIp) !== '') {
            return trim($realIp);
        }

        $xff = $headers['x-forwarded-for'] ?? ($server['HTTP_X_FORWARDED_FOR'] ?? null);
        if (is_string($xff) && trim($xff) !== '') {
            $first = trim(explode(',', $xff)[0]);
            if ($first !== '') {
                return $first;
            }
        }

        $remote = $server['REMOTE_ADDR'] ?? null;
        if (is_string($remote) && trim($remote) !== '') {
            return trim($remote);
        }

        return '127.0.0.1';
    }

    /**
     * Extracts lowercase HTTP headers from PHP $_SERVER superglobal.
     *
     * @param array<string, mixed> $server
     * @return array<string, string>
     */
    public static function extractHeadersFromServer(array $server): array
    {
        $headers = [];
        foreach ($server as $key => $value) {
            if (!is_string($value) && !is_numeric($value)) {
                continue;
            }
            if (str_starts_with((string) $key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
                $headers[$name] = (string) $value;
            } elseif ($key === 'CONTENT_TYPE') {
                $headers['content-type'] = (string) $value;
            } elseif ($key === 'CONTENT_LENGTH') {
                $headers['content-length'] = (string) $value;
            }
        }
        return $headers;
    }

    private static function detectResponseBytesSent(): int
    {
        if (function_exists('headers_list')) {
            foreach (headers_list() as $h) {
                if (stripos($h, 'Content-Length:') === 0) {
                    $val = (int) trim(substr($h, 15));
                    if ($val > 0) {
                        return $val;
                    }
                }
            }
        }

        if (function_exists('ob_get_length')) {
            $len = ob_get_length();
            if (is_int($len) && $len > 0) {
                return $len;
            }
        }

        return 0;
    }

    private function sendHttp(string $url, array $headers, string $body): bool
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch !== false) {
                curl_setopt_array($ch, [
                    CURLOPT_POST => true,
                    CURLOPT_HTTPHEADER => $headers,
                    CURLOPT_POSTFIELDS => $body,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_CONNECTTIMEOUT_MS => (int) ($this->timeoutSeconds * 1000),
                    CURLOPT_TIMEOUT_MS => (int) ($this->timeoutSeconds * 1000),
                ]);
                $res = curl_exec($ch);
                $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $err = curl_error($ch);
                curl_close($ch);

                if ($res === false || $status >= 400) {
                    if ($this->debug) {
                        error_log("[Voight Trace PHP SDK] Ingestion HTTP {$status}: {$err}");
                    }
                    return false;
                }
                return true;
            }
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers),
                'content' => $body,
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);

        $res = @file_get_contents($url, false, $context);
        return $res !== false;
    }

    public static function uuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12)
        );
    }
}
