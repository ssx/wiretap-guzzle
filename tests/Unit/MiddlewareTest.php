<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\TransferStats;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

describe('recording a request', function (): void {
    it('records exactly one exchange per call', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient([new Response(200, [], '{"ok":true}')], $sink);

        $client->get('https://api.example.com/v1/orders');
        $recorder->flush();

        expect($sink->all())->toHaveCount(1);
    });

    it('captures method, uri, status and both bodies', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient(
            [new Response(201, ['Content-Type' => 'application/json'], '{"id":42}')],
            $sink,
        );

        $client->post('https://api.example.com/v1/orders', [
            'headers' => ['Content-Type' => 'application/json'],
            'body' => '{"sku":"ABC"}',
        ]);
        $recorder->flush();

        $exchange = $sink->all()[0];

        expect($exchange->method)->toBe('POST')
            ->and($exchange->uri)->toBe('https://api.example.com/v1/orders')
            ->and($exchange->status)->toBe(201)
            ->and($exchange->transport)->toBe(Exchange::TRANSPORT_GUZZLE)
            ->and($exchange->requestBody->bytes)->toBe('{"sku":"ABC"}')
            ->and($exchange->responseBody->bytes)->toBe('{"id":42}');
    });

    it('leaves the response body readable by the application', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient([new Response(200, [], '{"ok":true}')], $sink);

        $response = $client->get('https://api.example.com/v1/orders');

        // This is the failure mode that matters: capturing must not drain the
        // stream the caller is about to read.
        expect((string) $response->getBody())->toBe('{"ok":true}');
    });

    it('does not disturb the request body position or size', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient([new Response(200)], $sink);

        $request = new Request('POST', 'https://api.example.com/v1', [], 'payload-here');
        $body = $request->getBody();
        $body->seek(4);

        $client->send($request);

        expect($body->tell())->toBe(4)
            ->and($body->getSize())->toBe(12)
            ->and($body->isSeekable())->toBeTrue();
    });

    it('records the status of an error response', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient([new Response(502, [], 'upstream died')], $sink);

        $client->get('https://api.example.com/v1/orders');
        $recorder->flush();

        expect($sink->all()[0]->status)->toBe(502)
            ->and($sink->all()[0]->failed())->toBeTrue();
    });

    it('records a transport failure with the exception detail', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([
            new ConnectException('Connection refused', new Request('GET', 'https://api.example.com/v1')),
        ]));
        Stack::attach($stack, $recorder);
        $client = new Client(['handler' => $stack]);

        try {
            $client->get('https://api.example.com/v1');
        } catch (ConnectException) {
            // expected
        }

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->error)->not->toBeNull()
            ->and($exchange->error->message)->toContain('Connection refused')
            ->and($exchange->status)->toBeNull()
            ->and($exchange->failed())->toBeTrue();
    });

    it('still rejects the promise after recording a failure', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([
            new ConnectException('nope', new Request('GET', 'https://api.example.com/v1')),
        ]));
        Stack::attach($stack, $recorder);
        $client = new Client(['handler' => $stack]);

        // Swallowing the rejection would silently turn a failure into a
        // success for the calling application.
        expect(fn () => $client->get('https://api.example.com/v1'))
            ->toThrow(ConnectException::class);
    });

    it('numbers calls within one correlation', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient(
            [new Response(200), new Response(200), new Response(200)],
            $sink,
        );

        $client->get('https://api.example.com/1');
        $client->get('https://api.example.com/2');
        $client->get('https://api.example.com/3');
        $recorder->flush();

        $correlations = array_unique(array_map(fn ($e) => $e->correlationId, $sink->all()));

        expect($correlations)->toHaveCount(1)
            ->and($sink->all()[0]->sequence)->toBeLessThan($sink->all()[2]->sequence);
    });
});

describe('the blocklist gate', function (): void {
    it('records nothing for a blocked host', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient(
            [new Response(200, [], '{"card":"4111111111111111"}')],
            $sink,
            new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]),
        );

        $client->post('https://api.stripe.com/v1/charges');
        $recorder->flush();

        expect($sink->all())->toBeEmpty();
    });

    it('still performs the request when blocked', function (): void {
        $sink = new InMemorySink();
        [$client] = mockedClient(
            [new Response(200, [], 'charged')],
            $sink,
            new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]),
        );

        $response = $client->post('https://api.stripe.com/v1/charges');

        // Blocking capture must never block traffic.
        expect((string) $response->getBody())->toBe('charged');
    });
});

describe('redaction through the stack', function (): void {
    it('never writes a secret from headers, url or body', function (): void {
        $sink = new InMemorySink();
        [$client, $recorder] = mockedClient(
            [new Response(200, ['Set-Cookie' => 'session=abc123'], '{"pan":"4111111111111111"}')],
            $sink,
        );

        $client->post('https://api.example.com/v1/pay?api_key=SUPERSECRET', [
            'headers' => ['Authorization' => 'Bearer TOPSECRET', 'Content-Type' => 'application/json'],
            'body' => '{"amount":100}',
        ]);
        $recorder->flush();

        $written = json_encode($sink->all()[0]);

        expect($written)->not->toContain('SUPERSECRET')
            ->and($written)->not->toContain('TOPSECRET')
            ->and($written)->not->toContain('session=abc123')
            ->and($written)->not->toContain('4111111111111111')
            ->and($written)->toContain('amount');
    });
});

describe('interoperability', function (): void {
    it('preserves an on_stats callback the caller already set', function (): void {
        $sink = new InMemorySink();
        $called = false;

        [$client, $recorder] = mockedClient([new Response(200)], $sink);

        $client->get('https://api.example.com/v1', [
            'on_stats' => function (TransferStats $stats) use (&$called): void {
                $called = true;
            },
        ]);
        $recorder->flush();

        expect($called)->toBeTrue()
            ->and($sink->all())->toHaveCount(1);
    });

    it('does not record twice when attached twice', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);
        $stack = HandlerStack::create(new MockHandler([new Response(200)]));

        Stack::attach($stack, $recorder);
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->get('https://api.example.com/v1');
        $recorder->flush();

        expect(Stack::isAttached($stack))->toBeTrue()
            ->and($sink->all())->toHaveCount(1);
    });

    it('can be detached again', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);
        $stack = HandlerStack::create(new MockHandler([new Response(200)]));

        Stack::attach($stack, $recorder);
        Stack::detach($stack);

        (new Client(['handler' => $stack]))->get('https://api.example.com/v1');
        $recorder->flush();

        expect($sink->all())->toBeEmpty();
    });
});
