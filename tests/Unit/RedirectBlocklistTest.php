<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Guzzle\WiretapClient;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

function blockingRecorder(InMemorySink $sink): Recorder
{
    return new Recorder(
        sink: $sink,
        blocklist: new Blocklist([new ArrayBlocklistProvider(['blocked.example'])]),
    );
}

describe('a hop onto a blocked host', function (): void {
    it('stores nothing when a redirect lands on a blocked host', function (): void {
        // Only the original URI was gated. The blocked hop's status, headers
        // and URL were stored, because the record carried the allowed original
        // URI and so passed core's re-check too.
        $recorder = blockingRecorder($sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://blocked.example/end']),
            new Response(200, ['X-Private' => 'blocked-patient-data'], '{"private":true}'),
        ]));
        Stack::attach($stack, $recorder);

        $response = (new Client(['handler' => $stack]))->get('https://allowed.example/start');

        $recorder->flush();

        expect($response->getHeaderLine('X-Private'))->toBe('blocked-patient-data')
            ->and($sink->all())->toBe([]);
    });

    it('never reads a request body resent to a blocked host', function (): void {
        // A 307 resends the body. The first hop is allowed, so its body is
        // read; the second hop is blocked, so nothing may be read for it.
        $recorder = blockingRecorder($sink = new InMemorySink());
        $reads = 0;
        $hop = 0;

        $stack = HandlerStack::create(new MockHandler([
            new Response(307, ['Location' => 'https://blocked.example/end']),
            new Response(200, [], '{}'),
        ]));
        Stack::attach($stack, $recorder);
        // Below the redirect middleware, so it sees each hop. Counts reads of
        // the request body only once the blocked hop is in flight.
        $stack->push(Middleware::mapRequest(static function (RequestInterface $r) use (&$reads, &$hop): RequestInterface {
            ++$hop;

            if ($hop < 2) {
                return $r;
            }

            return $r->withBody(FnStream::decorate($r->getBody(), [
                'read' => static function (int $length) use (&$reads, $r): string {
                    ++$reads;

                    return $r->getBody()->read($length);
                },
            ]));
        }));

        (new Client(['handler' => $stack]))->post('https://allowed.example/start', ['body' => 'payload']);

        $recorder->flush();

        expect($reads)->toBe(0)
            ->and($sink->all())->toBe([]);
    });

    it('stores nothing when a lower middleware rewrites the request onto a blocked host', function (): void {
        $recorder = blockingRecorder($sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([new Response(200, ['X-Private' => 'x'], '{}')]));
        Stack::attach($stack, $recorder);
        $stack->push(Middleware::mapRequest(
            static fn (RequestInterface $r): RequestInterface => $r->withUri(new GuzzleHttp\Psr7\Uri('https://blocked.example/moved')),
        ));

        (new Client(['handler' => $stack]))->get('https://allowed.example/start');

        $recorder->flush();

        expect($sink->all())->toBe([]);
    });

    it('still records a redirect between allowed hosts', function (): void {
        $recorder = blockingRecorder($sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://other.example/end']),
            new Response(200, [], '{}'),
        ]));
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->get('https://allowed.example/start');

        $recorder->flush();

        expect($sink->all())->toHaveCount(1);
    });
});

/**
 * A PSR-18 client that followed a redirect internally. Symfony's Psr18Client
 * exposes where it ended up only through the body stream's wrapper.
 */
function psr18RedirectedTo(string $effectiveUrl): ClientInterface
{
    return new class($effectiveUrl) implements ClientInterface {
        public function __construct(private string $effectiveUrl)
        {
        }

        public function sendRequest(RequestInterface $request): ResponseInterface
        {
            $symfonyResponse = new class($this->effectiveUrl) {
                public function __construct(private string $url)
                {
                }

                public function getInfo(?string $type = null): mixed
                {
                    return $type === 'url' ? $this->url : null;
                }
            };

            $wrapper = new class($symfonyResponse) {
                public function __construct(private object $response)
                {
                }

                public function getResponse(): object
                {
                    return $this->response;
                }
            };

            $body = FnStream::decorate(Utils::streamFor('{"blocked":"BLOCKED-HOST-DATA"}'), [
                'getMetadata' => static fn (?string $key = null): mixed => $key === 'wrapper_data' ? $wrapper : null,
            ]);

            return new Response(200, ['X-Private' => 'blocked-host-hdr'], $body);
        }
    };
}

describe('a PSR-18 redirect onto a blocked host', function (): void {
    it('stores nothing when the client followed a redirect to a blocked host', function (): void {
        $recorder = blockingRecorder($sink = new InMemorySink());

        (new WiretapClient(psr18RedirectedTo('https://blocked.example/echo'), $recorder))
            ->sendRequest(new Request('GET', 'https://allowed.example/redir'));

        $recorder->flush();

        expect($sink->all())->toBe([]);
    });

    it('stores nothing when Guzzle\'s redirect history names a blocked host', function (): void {
        $recorder = blockingRecorder($sink = new InMemorySink());

        $inner = new class implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(200, [
                    'X-Guzzle-Redirect-History' => ['https://allowed.example/next', 'https://blocked.example/end'],
                ], '{}');
            }
        };

        (new WiretapClient($inner, $recorder))->sendRequest(new Request('GET', 'https://allowed.example/redir'));

        $recorder->flush();

        expect($sink->all())->toBe([]);
    });

    it('still records when the client ended where it was asked to go', function (): void {
        $recorder = blockingRecorder($sink = new InMemorySink());

        (new WiretapClient(psr18RedirectedTo('https://allowed.example/final'), $recorder))
            ->sendRequest(new Request('GET', 'https://allowed.example/redir'));

        $recorder->flush();

        expect($sink->all())->toHaveCount(1);
    });
});
