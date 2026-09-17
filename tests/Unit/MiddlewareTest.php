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
use Ssx\Wiretap\Contract\ExchangeSink;
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

describe('lazy recorder resolution', function (): void {
    it('resolves the recorder per call, so a later swap is honoured', function (): void {
        // A handler stack is built once, at boot, frequently before the
        // application has finished deciding what its recorder should be — a
        // test calling Wiretap::fake() afterwards, for instance. Holding a
        // fixed instance means those later decisions are silently ignored.
        $first = new InMemorySink();
        $second = new InMemorySink();

        // A mutable holder, because an arrow function captures by value and
        // reassigning a local would never reach the closure.
        $holder = new class {
            public Recorder $recorder;
        };
        $holder->recorder = new Recorder(sink: $first);

        $stack = HandlerStack::create(new MockHandler([new Response(200), new Response(200)]));
        Stack::attach($stack, static fn (): Recorder => $holder->recorder);
        $client = new Client(['handler' => $stack]);

        $client->get('https://api.example.com/first');
        $holder->recorder->flush();

        // Swap the recorder after the stack was built.
        $holder->recorder = new Recorder(sink: $second);

        $client->get('https://api.example.com/second');
        $holder->recorder->flush();

        expect($first->all())->toHaveCount(1)
            ->and($first->all()[0]->uri)->toContain('/first')
            ->and($second->all())->toHaveCount(1)
            ->and($second->all()[0]->uri)->toContain('/second');
    });

    it('still accepts a recorder instance directly', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([new Response(200)]));
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->get('https://api.example.com/v1');
        $recorder->flush();

        expect($sink->all())->toHaveCount(1);
    });
});

describe('hardening found by review', function (): void {
    it('records the final response of a redirect, not the hop', function (): void {
        // on_stats fires once per transfer, so committing there recorded the
        // 302 Guzzle was about to follow and discarded the 200 the application
        // actually received.
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://api.example.com/final']),
            new Response(200, [], 'final body'),
        ]));
        Stack::attach($stack, $recorder);

        $response = (new Client(['handler' => $stack]))->get('https://api.example.com/start');
        $recorder->flush();

        expect($response->getStatusCode())->toBe(200)
            ->and($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->status)->toBe(200)
            ->and($sink->all()[0]->responseBody->bytes)->toBe('final body');
    });

    it('sends the request anyway when capture setup throws', function (): void {
        // tell() is called by capture and not by Guzzle, so an Error here
        // isolates instrumentation failure from transport failure. Guzzle
        // itself calls getSize(), so a stream that throws there would fail the
        // request with or without wiretap.
        $exploding = new class implements \Psr\Http\Message\StreamInterface {
            public function tell(): int
            {
                throw new Error('cannot tell position');
            }

            public function getSize(): ?int { return 9; }
            public function __toString(): string { return 'payload9'; }
            public function close(): void {}
            public function detach() { return null; }
            public function eof(): bool { return true; }
            public function isSeekable(): bool { return true; }
            public function seek($offset, $whence = SEEK_SET): void {}
            public function rewind(): void {}
            public function isWritable(): bool { return false; }
            public function write($string): int { return 0; }
            public function isReadable(): bool { return true; }
            public function read($length): string { return 'payload9'; }
            public function getContents(): string { return 'payload9'; }
            public function getMetadata($key = null) { return null; }
        };

        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'delivered')]));
        Stack::attach($stack, $recorder);

        $request = new Request('POST', 'https://api.example.com/v1', [], $exploding);
        $response = (new Client(['handler' => $stack]))->send($request);

        expect((string) $response->getBody())->toBe('delivered');
    });

    it('does not turn a successful response into a rejection when capture fails', function (): void {
        $sink = new class implements ExchangeSink {
            public function write(Exchange $exchange): void
            {
                throw new RuntimeException('sink exploded');
            }

            public function writeBatch(iterable $exchanges): void
            {
                throw new RuntimeException('sink exploded');
            }
        };

        $recorder = new Recorder(sink: $sink);
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
        Stack::attach($stack, $recorder);

        $response = (new Client(['handler' => $stack]))->get('https://api.example.com/v1');

        expect($response->getStatusCode())->toBe(200);
    });

    it('captures a body across short reads', function (): void {
        // StreamInterface::read() may return fewer bytes than asked for. The
        // first short read was treated as the whole body.
        $stream = new class implements \Psr\Http\Message\StreamInterface {
            private string $data = '0123456789';
            private int $pos = 0;

            public function read($length): string
            {
                // Three bytes at a time, however many are requested.
                $chunk = substr($this->data, $this->pos, min(3, $length));
                $this->pos += strlen($chunk);

                return $chunk;
            }

            public function getSize(): ?int { return strlen($this->data); }
            public function eof(): bool { return $this->pos >= strlen($this->data); }
            public function tell(): int { return $this->pos; }
            public function isSeekable(): bool { return true; }
            public function seek($offset, $whence = SEEK_SET): void { $this->pos = (int) $offset; }
            public function rewind(): void { $this->pos = 0; }
            public function isReadable(): bool { return true; }
            public function __toString(): string { return $this->data; }
            public function close(): void {}
            public function detach() { return null; }
            public function isWritable(): bool { return false; }
            public function write($string): int { return 0; }
            public function getContents(): string { return $this->data; }
            public function getMetadata($key = null) { return null; }
        };

        $captured = (new \Ssx\Wiretap\Guzzle\BodyCapture())->capture($stream, 'text/plain');

        expect($captured->bytes)->toBe('0123456789')
            ->and($captured->truncated)->toBeFalse();
    });

    it('captures enough for structural redaction to run on a large body', function (): void {
        // Capturing only 64 KiB handed the redactor unparseable JSON, so
        // configured body-path rules silently did nothing.
        $payload = json_encode([
            'password' => 'ordinary-secret-value',
            'padding' => str_repeat('x', 100_000),
        ]);

        $captured = (new \Ssx\Wiretap\Guzzle\BodyCapture())->capture(
            \GuzzleHttp\Psr7\Utils::streamFor($payload),
            'application/json',
        );

        $redacted = (new \Ssx\Wiretap\Redaction\Redactor(
            new \Ssx\Wiretap\Redaction\RedactionConfig(bodyPaths: ['password'])
        ))->redactBody($captured);

        expect($redacted->isPresent())->toBeTrue()
            ->and($redacted->bytes)->not->toContain('ordinary-secret-value');
    });
});

describe('resource fixes found by review', function (): void {
    it('records under the recorder the request was admitted with', function (): void {
        // An async request started under A and resolved after the holder moved
        // to B was writing to B — mixing concurrent scopes and sending the
        // capture to a policy that never admitted it.
        $admitted = new InMemorySink();
        $later = new InMemorySink();

        $holder = new class {
            public Recorder $recorder;
        };
        $holder->recorder = new Recorder(sink: $admitted);

        $stack = HandlerStack::create(new MockHandler([new Response(200)]));
        Stack::attach($stack, static fn (): Recorder => $holder->recorder);

        $promise = (new Client(['handler' => $stack]))->getAsync('https://api.example.com/v1');

        // Swap the holder before the promise settles.
        $original = $holder->recorder;
        $holder->recorder = new Recorder(sink: $later);

        $promise->wait();
        $original->flush();
        $holder->recorder->flush();

        expect($admitted->all())->toHaveCount(1)
            ->and($later->all())->toBeEmpty();
    });

    it('does not read the body of a host that became blocked after a redirect', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(
            sink: $sink,
            blocklist: new Blocklist([new ArrayBlocklistProvider(['blocked.example.com'])]),
        );

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://blocked.example.com/secret']),
            new Response(200, [], '{"card":"4111111111111111"}'),
        ]));
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->get('https://allowed.example.com/start');
        $recorder->flush();

        // Nothing stored, and the payload was never pulled into a record.
        expect(json_encode($sink->all()))->not->toContain('4111111111111111');
    });
});
