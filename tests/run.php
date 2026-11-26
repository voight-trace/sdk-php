<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/VoightTraceCollector.php';

use VoightTrace\VoightTraceCollector;

function assertTrue(bool $cond, string $msg): void
{
    if (!$cond) {
        fwrite(STDERR, "FAIL: {$msg}\n");
        exit(1);
    }
}

// 1. Safe header filtering (never leaks Authorization, Cookie, X-Api-Key)
$safe = VoightTraceCollector::filterSafeHeaders([
    'User-Agent' => 'GPTBot/1.2',
    'Authorization' => 'Bearer super-secret',
    'Cookie' => 'session=secret123',
    'X-Api-Key' => 'vt_live_secret',
    'Referer' => 'https://chatgpt.com/',
    'Host' => 'arcv.in',
]);
assertTrue(($safe['user-agent'] ?? '') === 'GPTBot/1.2', 'Preserves user-agent');
assertTrue(($safe['referer'] ?? '') === 'https://chatgpt.com/', 'Preserves referer');
assertTrue(!isset($safe['authorization']), 'Strips authorization');
assertTrue(!isset($safe['cookie']), 'Strips cookie');
assertTrue(!isset($safe['x-api-key']), 'Strips x-api-key');

// 2. Clean IP extraction priority
$ip1 = VoightTraceCollector::extractClientIp(
    ['cf-connecting-ip' => '66.249.66.1', 'x-forwarded-for' => '1.1.1.1, 2.2.2.2'],
    ['REMOTE_ADDR' => '127.0.0.1']
);
assertTrue($ip1 === '66.249.66.1', 'Prefers cf-connecting-ip');

$ip2 = VoightTraceCollector::extractClientIp(
    ['x-forwarded-for' => '203.0.113.5, 10.0.0.1'],
    ['REMOTE_ADDR' => '127.0.0.1']
);
assertTrue($ip2 === '203.0.113.5', 'Uses first IP from x-forwarded-for');

// 3. Payload contract & clean network.client_ip + x-voight-client-ip header
$captured = null;
$collector = new VoightTraceCollector([
    'apiKey' => 'vt_test_123',
    'siteId' => 'site_test_1',
    'transport' => function (string $url, array $headers, string $body) use (&$captured): bool {
        $captured = ['url' => $url, 'headers' => $headers, 'body' => json_decode($body, true)];
        return true;
    },
]);

$event = $collector->buildEventFromGlobals(
    [
        'REQUEST_METHOD' => 'GET',
        'REQUEST_URI' => '/docs/api?utm_source=chatgpt.com',
        'HTTPS' => 'on',
        'HTTP_HOST' => 'example.com:443',
        'REMOTE_ADDR' => '10.0.0.5',
    ],
    [
        'user-agent' => 'Google',
        'x-forwarded-for' => '66.249.66.1',
        'authorization' => 'Bearer secret',
    ],
    'vgt_test-corr',
    200,
    42,
    12345
);

assertTrue($event['collector_type'] === 'php_sdk', 'collector_type is php_sdk');
assertTrue($event['network'] === ['client_ip' => '66.249.66.1'], 'network sends only clean client_ip');
assertTrue($event['response']['duration_ms'] === 42, 'duration_ms preserved');
assertTrue($event['response']['bytes_sent'] === 12345, 'bytes_sent preserved');

$collector->enqueue($event);
assertTrue($collector->flush() === true, 'flush succeeds');
assertTrue(in_array('x-voight-client-ip: 66.249.66.1', $captured['headers'], true), 'x-voight-client-ip header sent');
assertTrue(count($captured['body']['events']) === 1, 'batch envelope has 1 event');

echo "ALL PHP SDK TESTS PASSED\n";
