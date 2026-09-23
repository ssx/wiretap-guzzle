<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\TransferClaim;

/**
 * The middleware claims the requests it records so that ssx/wiretap-auto's
 * curl hooks, if they are running, do not record them a second time.
 */
beforeEach(fn () => TransferClaim::reset());
afterEach(fn () => TransferClaim::reset());

/**
 * A client whose handler answers 302, then 503, then 200, with redirect
 * and retry middleware in the stack, returning the options each hop reached
 * the handler with.
 *
 * @return list<array<string, mixed>>
 */
function hopOptions(?Recorder $recorder, array $requestOptions = []): array
{
    $hops = [];
    $responses = [
        new Response(302, ['Location' => 'https://api.example.com/final']),
        new Response(503),
        new Response(200, ['Content-Type' => 'application/json'], '{"ok":true}'),
    ];

    $handler = static function (RequestInterface $request, array $options) use (&$hops, &$responses) {
        $hops[] = $options;

        return Create::promiseFor(array_shift($responses));
    };

    $stack = HandlerStack::create($handler);
    $stack->push(Middleware::retry(
        static fn (int $retries, RequestInterface $request, $response = null): bool => $retries < 1 && $response?->getStatusCode() === 503,
    ), 'retry');

    if ($recorder !== null) {
        Stack::attach($stack, $recorder);
    }

    (new Client(['handler' => $stack, 'http_errors' => false]))
        ->get('https://api.example.com/start', $requestOptions);

    return $hops;
}

it('claims every hop, redirect and retry included, once the hooks honour it', function (): void {
    TransferClaim::honour();

    $hops = hopOptions(new Recorder(sink: new InMemorySink()));

    expect($hops)->toHaveCount(3)
        ->and(array_column($hops, TransferClaim::KEY))->toBe([true, true, true])
        // Never as a curl option: Guzzle deprecates unknown ones.
        ->and(array_map(static fn (array $o): array => $o['curl'] ?? [], $hops))->toBe([[], [], []]);
});

it('adds nothing at all when the hooks do not honour it', function (): void {
    $withWiretap = hopOptions(new Recorder(sink: new InMemorySink()));
    $without = hopOptions(null);

    // on_stats is how the middleware has always observed a hop, and handler
    // is the stack itself, which differs by construction. Beyond those, every
    // hop's options are exactly what they are with no wiretap at all.
    $strip = static function (array $options): array {
        unset($options['on_stats'], $options['handler']);

        return $options;
    };

    expect(array_map($strip, $withWiretap))->toEqual(array_map($strip, $without))
        // Same keys, in the same order, not merely equal values.
        ->and(array_map(static fn (array $o): array => array_keys($strip($o)), $withWiretap))
        ->toBe(array_map(static fn (array $o): array => array_keys($strip($o)), $without));
});

it('does not claim a request it is not recording, so the hooks still can', function (): void {
    TransferClaim::honour();

    $recorder = new Recorder(
        sink: new InMemorySink(),
        blocklist: new Blocklist([new ArrayBlocklistProvider(['api.example.com'])]),
    );

    expect(array_key_exists(TransferClaim::KEY, hopOptions($recorder)[0]))->toBeFalse();
});

it('leaves a claim value the application set alone', function (): void {
    TransferClaim::honour();

    $hops = hopOptions(new Recorder(sink: new InMemorySink()), [TransferClaim::KEY => false]);

    expect(array_column($hops, TransferClaim::KEY))->toBe([false, false, false]);
});
