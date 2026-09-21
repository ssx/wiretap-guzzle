<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ssx\Wiretap\Guzzle\WiretapClient;
use Ssx\Wiretap\Guzzle\WiretapMiddleware;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

describe('redirects', function (): void {
    it('learns credentials from the original URI, not just the one it ended at', function (): void {
        // The effective URI used to replace the original, so the query
        // credentials were gone before the redactor could learn them — and a
        // response echoing one back reached the sink in plaintext.
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://api.example.com/final']),
            new Response(200, ['Content-Type' => 'application/json'], '{"echo":"ordinarysecretvalue"}'),
        ]));
        $stack->unshift(new WiretapMiddleware(static fn (): Recorder => $recorder));

        (new Client(['handler' => $stack, 'allow_redirects' => true]))
            ->get('https://api.example.com/start?api_key=ordinarysecretvalue');

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->responseBody->bytes)->not->toContain('ordinarysecretvalue')
            ->and($exchange->uri)->not->toContain('ordinarysecretvalue')
            // The recorded URI is the one the recorded method, headers and
            // body actually belong to.
            ->and($exchange->uri)->toStartWith('https://api.example.com/start');
    });

    it('keeps where the request ended up, in context', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://api.example.com/final']),
            new Response(200, ['Content-Type' => 'application/json'], '{}'),
        ]));
        $stack->unshift(new WiretapMiddleware(static fn (): Recorder => $recorder));

        (new Client(['handler' => $stack, 'allow_redirects' => true]))
            ->get('https://api.example.com/start');

        $recorder->flush();

        expect($sink->all()[0]->context['redirected_to'] ?? [])
            ->toContain('https://api.example.com/final');
    });

    it('records no redirect context when there was none', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], '{}')]));
        $stack->unshift(new WiretapMiddleware(static fn (): Recorder => $recorder));

        (new Client(['handler' => $stack]))->get('https://api.example.com/plain');

        $recorder->flush();

        expect($sink->all()[0]->context)->not->toHaveKey('redirected_to');
    });
});

describe('the PSR-18 client', function (): void {
    it('sends the request anyway when setup throws, exactly once', function (): void {
        // Resolving the recorder, asking the blocklist, generating an id and
        // reading the body all ran unguarded, so a resolver that threw took
        // the application's request down with it — reproduced with zero calls
        // to the inner client.
        $inner = new class implements ClientInterface {
            public int $calls = 0;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                ++$this->calls;

                return new Response(200, ['Content-Type' => 'application/json'], '{}');
            }
        };

        $client = new WiretapClient($inner, static function (): Recorder {
            throw new RuntimeException('resolver exploded');
        });

        $response = $client->sendRequest(new Request('GET', 'https://api.example.com/x'));

        expect($response->getStatusCode())->toBe(200)
            // Not zero, and not two: the inner call sits outside the guard so
            // our own bookkeeping can never retry the application's request.
            ->and($inner->calls)->toBe(1);
    });

    it('writes to the recorder that admitted the request, not whatever is current at completion', function (): void {
        // A request admitted under one recorder used to be written through
        // another's sink and redaction policy if the holder changed during the
        // inner call or a Fiber suspension.
        $admitting = new Recorder(sink: $admittingSink = new InMemorySink());
        $replacement = new Recorder(sink: $replacementSink = new InMemorySink());

        $current = $admitting;

        $inner = new class($current, $replacement) implements ClientInterface {
            public function __construct(private mixed &$current, private Recorder $replacement)
            {
            }

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                // The holder changes mid-flight.
                $this->current = $this->replacement;

                return new Response(200, [], '{}');
            }
        };

        $client = new WiretapClient($inner, static function () use (&$current): Recorder {
            return $current;
        });

        $client->sendRequest(new Request('GET', 'https://api.example.com/y'));

        $admitting->flush();
        $replacement->flush();

        expect($admittingSink->all())->toHaveCount(1)
            ->and($replacementSink->all())->toHaveCount(0);
    });

    it('still records normally', function (): void {
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $inner = new class implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(201, ['Content-Type' => 'application/json'], '{"created":true}');
            }
        };

        (new WiretapClient($inner, static fn (): Recorder => $recorder))
            ->sendRequest(new Request('POST', 'https://api.example.com/things'));

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->status)->toBe(201)
            ->and($sink->all()[0]->method)->toBe('POST');
    });
});

describe('retries', function (): void {
    it('does not report a failed attempt\'s error when a later one succeeded', function (): void {
        // stats() only set the error while it was still null and never cleared
        // it, so a connection failure followed by a successful retry was
        // recorded as a transport error beside an HTTP 200.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new Request('GET', 'https://api.example.com/flaky'),
                null,
                ['errno' => 7],
            ),
            new Response(200, ['Content-Type' => 'application/json'], '{"ok":true}'),
        ]));
        $stack->unshift(new WiretapMiddleware(static fn (): Recorder => $recorder));
        $stack->push(GuzzleHttp\Middleware::retry(
            static fn (int $retries, $request, $response, $reason): bool => $retries < 1 && $reason !== null,
            static fn (): int => 0,
        ));

        (new Client(['handler' => $stack]))->get('https://api.example.com/flaky');

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->status)->toBe(200)
            ->and($exchange->error)->toBeNull();
    });

    it('still records the error when every attempt failed', function (): void {
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new Request('GET', 'https://api.example.com/down'),
                null,
                ['errno' => 7],
            ),
        ]));
        $stack->unshift(new WiretapMiddleware(static fn (): Recorder => $recorder));

        try {
            (new Client(['handler' => $stack]))->get('https://api.example.com/down');
        } catch (\Throwable) {
            // Expected; the application still sees its exception.
        }

        $recorder->flush();

        expect($sink->all()[0]->error)->not->toBeNull();
    });
});
