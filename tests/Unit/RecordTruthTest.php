<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Guzzle\BodyCapture;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

describe('a method-changing redirect', function (): void {
    it('records the request that was sent to the recorded URI, not the last hop\'s', function (): void {
        // A 302 after a POST is followed as a GET with no body. The record
        // kept the original URI but took the method, headers and body from
        // the final hop: "GET /orders, no body", a request never sent.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://api.example.com/orders/42']),
            new Response(200, ['Content-Type' => 'application/json'], '{"id":42}'),
        ]));
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->post('https://api.example.com/orders', [
            'json' => ['sku' => 'A1'],
            'headers' => ['X-Hop' => 'first'],
        ]);

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->uri)->toBe('https://api.example.com/orders')
            ->and($exchange->method)->toBe('POST')
            ->and($exchange->requestBody->bytes)->toBe('{"sku":"A1"}')
            ->and($exchange->requestHeaders->first('Content-Type'))->toBe('application/json')
            ->and($exchange->status)->toBe(200)
            ->and($exchange->context['redirected_to'] ?? [])->toBe(['https://api.example.com/orders/42']);
    });

    it('records the URI a lower middleware actually sent the first hop to', function (): void {
        // Method and headers already came from the request as sent. The URI
        // alone stayed the one the application built, so a middleware that
        // moved the request produced a record mixing two requests.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], '{}')]));
        Stack::attach($stack, $recorder);
        $stack->push(GuzzleHttp\Middleware::mapRequest(
            static fn (Psr\Http\Message\RequestInterface $r): Psr\Http\Message\RequestInterface => $r
                ->withUri(new GuzzleHttp\Psr7\Uri('https://api.example.com/v2/thing'))
                ->withMethod('PUT'),
        ));

        (new Client(['handler' => $stack]))->post('https://api.example.com/v1/thing?api_key=ordinarysecretvalue');

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->uri)->toBe('https://api.example.com/v2/thing')
            ->and($exchange->method)->toBe('PUT')
            // Not a redirect: the application's URI was never sent.
            ->and($exchange->context)->not->toHaveKey('redirected_to')
            ->and(json_encode($exchange))->not->toContain('ordinarysecretvalue');
    });

    it('still learns what the application\'s own URI carried when a lower middleware moved it', function (): void {
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{"echo":"ordinarysecretvalue"}'),
        ]));
        Stack::attach($stack, $recorder);
        $stack->push(GuzzleHttp\Middleware::mapRequest(
            static fn (Psr\Http\Message\RequestInterface $r): Psr\Http\Message\RequestInterface => $r
                ->withUri(new GuzzleHttp\Psr7\Uri('https://api.example.com/v2/thing')),
        ));

        (new Client(['handler' => $stack]))->get('https://api.example.com/v1/thing?api_key=ordinarysecretvalue');

        $recorder->flush();

        expect(json_encode($sink->all()[0]))->not->toContain('ordinarysecretvalue');
    });

    it('reports timings for the whole redirect chain, not the last hop', function (): void {
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://api.example.com/final']),
            new Response(200, [], 'ok'),
        ]));
        Stack::attach($stack, $recorder);

        // MockHandler reports this as each transfer's time.
        (new Client(['handler' => $stack]))->get('https://api.example.com/start', ['transfer_time' => 0.25]);

        $recorder->flush();

        expect($sink->all()[0]->timings->total)->toBe(500_000);
    });

    it('does not change the timings of a single transfer', function (): void {
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->get('https://api.example.com/start', ['transfer_time' => 0.25]);

        $recorder->flush();

        expect($sink->all()[0]->timings->total)->toBe(250_000);
    });
});

describe('a rejection that is not an exception', function (): void {
    it('records the exchange as failed', function (): void {
        // Guzzle wraps a non-Throwable reason only when the application
        // waits, so the rejection handler sees the raw value. The record
        // carried the server's 200 and no error: a success the application
        // never saw.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
        $stack->push(static fn (callable $h): callable => static fn ($req, $o) => $h($req, $o)
            ->then(static fn () => Create::rejectionFor('circuit-open')));
        Stack::attach($stack, $recorder);

        try {
            (new Client(['handler' => $stack]))->get('https://api.example.com/thing');
        } catch (\Throwable) {
        }

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->failed())->toBeTrue()
            ->and($exchange->error)->not->toBeNull()
            // The reason itself is arbitrary application data; only its type
            // is kept.
            ->and($exchange->error->message)->not->toContain('circuit-open')
            ->and($exchange->error->message)->toContain('string');
    });

    it('still rejects with the original reason', function (): void {
        $recorder = new Recorder(sink: new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
        $stack->push(static fn (callable $h): callable => static fn ($req, $o) => $h($req, $o)
            ->then(static fn () => Create::rejectionFor('circuit-open')));
        Stack::attach($stack, $recorder);

        $reason = null;
        (new Client(['handler' => $stack]))->getAsync('https://api.example.com/thing')
            ->otherwise(static function ($r) use (&$reason): void {
                $reason = $r;
            })->wait();

        expect($reason)->toBe('circuit-open');
    });
});

describe('stream => true', function (): void {
    it('records a request body it already had, rather than calling it streaming', function (): void {
        // `stream` is about the response. The request body is captured before
        // dispatch either way, but the as-sent pass replaced it with an
        // "omitted: streaming" marker.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
        Stack::attach($stack, $recorder);

        (new Client(['handler' => $stack]))->post('https://api.example.com/orders', [
            'json' => ['order' => 42],
            'stream' => true,
        ]);

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($exchange->requestBody->bytes)->toBe('{"order":42}')
            ->and($exchange->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_STREAMING);
    });
});

describe('a stream that reports its size as -1', function (): void {
    it('is treated as unknown, not as a size', function (): void {
        // Some PSR-7 implementations report an unknown length as -1. Taken as
        // a size, a readable body was compared against it and recorded with
        // size -1 and truncated false.
        $inner = Utils::streamFor('0123456789');

        $minusOne = new class($inner) implements StreamInterface {
            public function __construct(private StreamInterface $i) {}

            public function getSize(): ?int { return -1; }
            public function read($length): string { return $this->i->read($length); }
            public function eof(): bool { return $this->i->eof(); }
            public function tell(): int { return $this->i->tell(); }
            public function isSeekable(): bool { return true; }
            public function seek($offset, $whence = SEEK_SET): void { $this->i->seek($offset, $whence); }
            public function rewind(): void { $this->i->rewind(); }
            public function isReadable(): bool { return true; }
            public function __toString(): string { return ''; }
            public function close(): void {}
            public function detach() { return null; }
            public function isWritable(): bool { return false; }
            public function write($string): int { return 0; }
            public function getContents(): string { return ''; }
            public function getMetadata($key = null) { return null; }
        };

        $truncated = (new BodyCapture(maxBytes: 4))->capture($minusOne, 'text/plain');
        $minusOne->rewind();
        $whole = (new BodyCapture())->capture($minusOne, 'text/plain');
        $minusOne->rewind();
        $omitted = (new BodyCapture())->capture($minusOne, 'text/plain', streaming: true);

        expect($truncated->bytes)->toBe('0123')
            ->and($truncated->truncated)->toBeTrue()
            ->and($truncated->size)->toBeNull()
            ->and($whole->bytes)->toBe('0123456789')
            ->and($whole->truncated)->toBeFalse()
            ->and($whole->size)->toBe(10)
            ->and($omitted->size)->toBeNull();
    });
});
