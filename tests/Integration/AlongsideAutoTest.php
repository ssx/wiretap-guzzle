<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Psr\Http\Message\RequestInterface;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Wiretap as Core;

/**
 * This middleware and ssx/wiretap-auto's curl hooks in one process, both
 * writing to the same recorder: each call must be recorded once, by the
 * middleware, on every hop it makes.
 */
const ALONGSIDE_PORT = 18793;

beforeAll(function (): void {
    if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
        return;
    }

    $docroot = sys_get_temp_dir() . '/wiretap-guzzle-alongside';
    @mkdir($docroot, 0o755, true);
    file_put_contents($docroot . '/index.php', <<<'ROUTER'
<?php
$uri = $_SERVER['REQUEST_URI'];
if (str_starts_with($uri, '/redirect')) {
    header('Location: /echo?from=redirect', true, 302);
    exit;
}
if (preg_match('~^/flaky/([a-z0-9]+)~', $uri, $m)) {
    $counter = sys_get_temp_dir() . '/wiretap-guzzle-flaky-' . $m[1];
    $seen = (int) @file_get_contents($counter);
    file_put_contents($counter, (string) ($seen + 1));
    if ($seen % 2 === 0) {
        http_response_code(503);
    }
}
header('Content-Type: application/json');
echo json_encode(['path' => $uri]);
ROUTER);

    $server = proc_open(
        sprintf('exec %s -S 127.0.0.1:%d -t %s', PHP_BINARY, ALONGSIDE_PORT, escapeshellarg($docroot)),
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
    );

    for ($i = 0; $i < 50; ++$i) {
        $socket = @fsockopen('127.0.0.1', ALONGSIDE_PORT, $errno, $errstr, 0.1);

        if ($socket !== false) {
            fclose($socket);

            break;
        }

        usleep(100_000);
    }

    register_shutdown_function(static function () use ($server): void {
        proc_terminate($server);
        proc_close($server);
    });
});

beforeEach(function (): void {
    if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
        $this->markTestSkipped('needs ext-opentelemetry and ssx/wiretap-auto');
    }

    // The package boots itself from its autoload file; this only makes sure
    // it did, and points both layers at one recorder.
    \Ssx\Wiretap\Auto\Wiretap::boot();
    $this->sink = new InMemorySink();
    $this->recorder = Core::setRecorder(new Recorder(sink: $this->sink, blocklist: new Blocklist()));
    $this->base = 'http://127.0.0.1:' . ALONGSIDE_PORT;
});

it('records a sync and an async call once each, as the middleware', function (): void {
    $client = new Client(['handler' => Stack::wrap(static fn (): Recorder => Core::recorder()), 'http_errors' => false]);

    $client->get($this->base . '/echo?sync=1');
    $client->getAsync($this->base . '/echo?async=1')->wait();
    $this->recorder->flush();

    $records = $this->sink->all();

    // Before the claim this was 4: two from the middleware, two from the
    // curl hooks, with nothing linking them.
    expect($records)->toHaveCount(2)
        ->and(array_map(static fn ($e): string => $e->transport, $records))->toBe(['guzzle', 'guzzle'])
        ->and($records[0]->responseBody->isPresent())->toBeTrue();
});

it('records a redirected and a retried call once each', function (): void {
    $stack = HandlerStack::create();
    $stack->push(Middleware::retry(
        static fn (int $retries, RequestInterface $request, $response = null): bool => $retries < 1 && $response?->getStatusCode() === 503,
    ));
    $client = new Client(['handler' => Stack::wrap(static fn (): Recorder => Core::recorder(), $stack), 'http_errors' => false]);

    $redirected = $client->get($this->base . '/redirect');
    $retried = $client->get($this->base . '/flaky/' . bin2hex(random_bytes(4)));
    $this->recorder->flush();

    expect([$redirected->getStatusCode(), $retried->getStatusCode()])->toBe([200, 200])
        ->and($this->sink->all())->toHaveCount(2)
        ->and(array_map(static fn ($e): string => $e->transport, $this->sink->all()))->toBe(['guzzle', 'guzzle']);
});

it('records a call through the PSR-18 decorator over Guzzle once', function (): void {
    // PSR-18 has no request options, so the decorator could not carry the
    // claim and the curl hooks recorded the same call again: 2 records.
    $client = new \Ssx\Wiretap\Guzzle\WiretapClient(new Client(), static fn (): Recorder => Core::recorder());

    $response = $client->sendRequest(new \GuzzleHttp\Psr7\Request('GET', $this->base . '/echo?psr18=1'));
    $this->recorder->flush();

    expect($response->getStatusCode())->toBe(200)
        ->and($this->sink->all())->toHaveCount(1)
        ->and($this->sink->all()[0]->transport)->toBe('psr18');
});

it('still leaves a redirect for the application to follow through the PSR-18 decorator', function (): void {
    $client = new \Ssx\Wiretap\Guzzle\WiretapClient(new Client(), static fn (): Recorder => Core::recorder());

    $response = $client->sendRequest(new \GuzzleHttp\Psr7\Request('GET', $this->base . '/redirect'));
    $this->recorder->flush();

    expect($response->getStatusCode())->toBe(302)
        ->and($this->sink->all())->toHaveCount(1);
});
