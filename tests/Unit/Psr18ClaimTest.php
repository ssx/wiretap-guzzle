<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Guzzle\WiretapClient;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\TransferClaim;

/**
 * The PSR-18 decorator over a Guzzle client claims the request, as the
 * middleware does, so that ssx/wiretap-auto's curl hooks do not record it a
 * second time. PSR-18 has no options channel, so this goes through Guzzle's
 * own send() with the options its sendRequest() uses.
 */
beforeEach(fn () => TransferClaim::reset());
afterEach(fn () => TransferClaim::reset());

/**
 * A Guzzle client over a full default stack (redirect, http_errors, cookies)
 * whose transport answers from $responses and reports the options each
 * transfer reached it with.
 *
 * @param list<ResponseInterface|\Throwable> $responses
 * @param list<array<string, mixed>>         $seen
 */
function psr18Guzzle(array $responses, array &$seen, string $class = Client::class): Client
{
    $handler = static function (RequestInterface $request, array $options) use (&$seen, &$responses) {
        $seen[] = $options;
        $next = array_shift($responses);

        return $next instanceof \Throwable ? Create::rejectionFor($next) : Create::promiseFor($next);
    };

    return new $class(['handler' => HandlerStack::create($handler)]);
}

function psr18Recorder(?Blocklist $blocklist = null): Recorder
{
    return new Recorder(sink: new InMemorySink(), blocklist: $blocklist ?? new Blocklist());
}

/**
 * Send one request through a bare client and through the decorator, and
 * return what each path produced: status, the exception class, and the
 * options the transport saw.
 *
 * @param list<ResponseInterface|\Throwable> $responses
 *
 * @return array{direct: array<string, mixed>, decorated: array<string, mixed>}
 */
function bothPaths(array $responses, string $uri = 'https://api.example.com/thing'): array
{
    $run = static function (callable $send) use ($responses, $uri): array {
        $seen = [];
        $client = psr18Guzzle($responses, $seen);

        try {
            $response = $send($client, new Request('GET', $uri));
            $result = ['status' => $response->getStatusCode(), 'body' => (string) $response->getBody(), 'exception' => null];
        } catch (\Throwable $e) {
            $result = ['status' => null, 'body' => null, 'exception' => $e::class, 'network' => $e instanceof NetworkExceptionInterface];
        }

        // Each run builds its own client, so the handler stack in the
        // options is a different instance; compare it by class.
        $options = array_map(
            static fn (array $o): array => array_map(static fn ($v) => is_object($v) ? $v::class : $v, $o),
            $seen,
        );

        return $result + ['options' => $options];
    };

    return [
        'direct' => $run(static fn (Client $c, Request $r) => $c->sendRequest($r)),
        'decorated' => $run(static fn (Client $c, Request $r) => (new WiretapClient($c, psr18Recorder()))->sendRequest($r)),
    ];
}

/**
 * @param list<array<string, mixed>> $options
 *
 * @return list<array<string, mixed>>
 */
function withoutClaim(array $options): array
{
    return array_map(static function (array $o): array {
        unset($o[TransferClaim::KEY]);

        return $o;
    }, $options);
}

describe('when the hooks honour the claim', function (): void {
    beforeEach(fn () => TransferClaim::honour());

    it('claims a request it records through a Guzzle client', function (): void {
        $seen = [];
        $client = psr18Guzzle([new Response(200, [], 'ok')], $seen);

        (new WiretapClient($client, psr18Recorder()))->sendRequest(new Request('GET', 'https://api.example.com/thing'));

        expect($seen)->toHaveCount(1)
            ->and($seen[0][TransferClaim::KEY] ?? null)->toBeTrue();
    });

    it('sends with exactly the options Guzzle\'s own sendRequest() uses, plus the claim', function (): void {
        $paths = bothPaths([new Response(200, [], 'ok')]);

        expect(withoutClaim($paths['decorated']['options']))->toBe($paths['direct']['options'])
            ->and($paths['decorated']['options'][0][TransferClaim::KEY])->toBeTrue();
    });

    it('does not follow a redirect, as sendRequest() does not', function (): void {
        $paths = bothPaths([
            new Response(302, ['Location' => 'https://api.example.com/final']),
            new Response(200, [], 'followed'),
        ]);

        expect($paths['decorated']['status'])->toBe(302)
            ->and(array_diff_key($paths['decorated'], ['options' => 1]))
            ->toBe(array_diff_key($paths['direct'], ['options' => 1]));
    });

    it('returns an error status rather than throwing, as sendRequest() does', function (): void {
        $paths = bothPaths([new Response(404, [], 'missing')]);

        expect($paths['decorated']['status'])->toBe(404)
            ->and($paths['decorated']['exception'])->toBeNull()
            ->and(array_diff_key($paths['decorated'], ['options' => 1]))
            ->toBe(array_diff_key($paths['direct'], ['options' => 1]));
    });

    it('throws the same PSR-18 exception on a transport failure', function (): void {
        $paths = bothPaths([new ConnectException('Connection refused', new Request('GET', 'https://api.example.com/thing'))]);

        expect($paths['decorated']['exception'])->toBe(ConnectException::class)
            ->and($paths['decorated']['network'])->toBeTrue()
            ->and(array_diff_key($paths['decorated'], ['options' => 1]))
            ->toBe(array_diff_key($paths['direct'], ['options' => 1]));
    });

    it('does not claim a request it is not recording, so the hooks still can', function (): void {
        $seen = [];
        $client = psr18Guzzle([new Response(200, [], 'ok')], $seen);
        $blocklist = new Blocklist([new ArrayBlocklistProvider(['blocked.example'])]);

        (new WiretapClient($client, psr18Recorder($blocklist)))->sendRequest(new Request('GET', 'https://blocked.example/x'));

        expect($seen[0])->not->toHaveKey(TransferClaim::KEY);
    });

    it('leaves a subclass of the Guzzle client on its own sendRequest()', function (): void {
        // A subclass can override sendRequest(), and then send() with
        // Guzzle's options is not what the application would have run.
        $seen = [];
        $client = psr18Guzzle([new Response(200, [], 'ok')], $seen, CountingGuzzleClient::class);

        (new WiretapClient($client, psr18Recorder()))->sendRequest(new Request('GET', 'https://api.example.com/thing'));

        expect(CountingGuzzleClient::$calls)->toBe(1)
            ->and($seen[0])->not->toHaveKey(TransferClaim::KEY);
    });

    it('leaves a client that is not Guzzle on sendRequest()', function (): void {
        $inner = new class implements ClientInterface {
            public int $calls = 0;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                ++$this->calls;

                return new Response(200, [], 'ok');
            }
        };

        (new WiretapClient($inner, psr18Recorder()))->sendRequest(new Request('GET', 'https://api.example.com/thing'));

        expect($inner->calls)->toBe(1);
    });
});

describe('when the hooks do not honour it', function (): void {
    it('sends exactly what sendRequest() would', function (): void {
        $paths = bothPaths([new Response(200, [], 'ok')]);

        expect($paths['decorated']['options'])->toBe($paths['direct']['options'])
            ->and($paths['decorated']['options'][0])->not->toHaveKey(TransferClaim::KEY);
    });
});

class CountingGuzzleClient extends Client
{
    public static int $calls = 0;

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        ++self::$calls;

        return parent::sendRequest($request);
    }
}
