<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\InMemorySink;

/**
 * @param list<Response> $responses
 */
function redirectingClient(Recorder $recorder, array $responses): Client
{
    $stack = HandlerStack::create(new MockHandler($responses));
    Stack::attach($stack, $recorder);

    return new Client(['handler' => $stack, 'http_errors' => false]);
}

describe('redirect hops and redaction', function (): void {
    it('redacts a credential in a redirect target stored in context', function (): void {
        // redirected_to is a list, and core only redacts string context
        // values, so the hop URI reached the sink with its query intact.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        redirectingClient($recorder, [
            new Response(302, ['Location' => 'https://other.example/end?api_key=redirectsecretvalue']),
            new Response(200, ['Content-Type' => 'application/json'], '{}'),
        ])->get('https://api.example.com/start');

        $recorder->flush();
        $json = json_encode($sink->all()[0]);

        expect($sink->all()[0]->context['redirected_to'])->toBe(['https://other.example/end?api_key=%5BREDACTED%5D'])
            ->and($json)->not->toContain('redirectsecretvalue');
    });

    it('learns a credential from a redirect target, so an echo of it is redacted', function (): void {
        // The hop URI was never seen by the redactor, so the value it carried
        // was never learned and a response echoing it back was stored.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        redirectingClient($recorder, [
            new Response(302, ['Location' => 'https://other.example/end?api_key=redirectsecretvalue']),
            new Response(200, ['Content-Type' => 'application/json'], '{"echo":"redirectsecretvalue"}'),
        ])->get('https://api.example.com/start');

        $recorder->flush();

        expect(json_encode($sink->all()[0]))->not->toContain('redirectsecretvalue');
    });

    it('keeps a credential learned from a hop whose headers a later hop dropped', function (): void {
        // Guzzle strips Authorization on a cross-host redirect. Each hop
        // replaced the recorded headers, so by the time the redactor ran the
        // credential was gone and its echo in the final body survived.
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        redirectingClient($recorder, [
            new Response(302, ['Location' => 'https://other.example/end']),
            new Response(200, ['Content-Type' => 'application/json'], '{"echo":"originalsecretvalue"}'),
        ])->get('https://api.example.com/start', ['headers' => ['Authorization' => 'Bearer originalsecretvalue']]);

        $recorder->flush();

        expect(json_encode($sink->all()[0]))->not->toContain('originalsecretvalue');
    });

    it('leaves the record alone when redaction is disabled', function (): void {
        $recorder = new Recorder(
            sink: $sink = new InMemorySink(),
            redactor: new Redactor(new RedactionConfig(enabled: false)),
        );

        redirectingClient($recorder, [
            new Response(302, ['Location' => 'https://other.example/end?api_key=redirectsecretvalue']),
            new Response(200, ['Content-Type' => 'application/json'], '{"echo":"redirectsecretvalue"}'),
        ])->get('https://api.example.com/start');

        $recorder->flush();

        expect($sink->all()[0]->responseBody->bytes)->toBe('{"echo":"redirectsecretvalue"}')
            ->and($sink->all()[0]->context['redirected_to'])->toBe(['https://other.example/end?api_key=redirectsecretvalue']);
    });
});

describe('an exception from a lower middleware', function (): void {
    it('does not store its message, which can carry the response body', function (): void {
        // A middleware below wiretap turned a 200 into an exception whose
        // message embedded the payload. TransferError::fromThrowable() stored
        // that message verbatim, past the body-path rules, and the 200 the
        // server actually sent was lost.
        $recorder = new Recorder(
            sink: $sink = new InMemorySink(),
            redactor: new Redactor(new RedactionConfig(bodyPaths: ['customer.national_id'])),
        );
        $body = '{"customer":{"national_id":"QQ123456C-private"},"status":"declined"}';

        $stack = HandlerStack::create(new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $body),
        ]));
        $stack->push(static fn (callable $handler): callable => static fn ($request, array $options) => $handler($request, $options)
            ->then(static function ($response) {
                throw new RuntimeException('API declined: ' . $response->getBody());
            }));
        Stack::attach($stack, $recorder);

        $thrown = null;

        try {
            (new Client(['handler' => $stack]))->get('https://api.example.com/verify');
        } catch (RuntimeException $e) {
            $thrown = $e;
        }

        $recorder->flush();
        $exchange = $sink->all()[0];

        expect($thrown?->getMessage())->toContain('QQ123456C-private')
            ->and(json_encode($exchange))->not->toContain('QQ123456C-private')
            ->and($exchange->error?->class)->toBe(RuntimeException::class)
            ->and($exchange->status)->toBe(200);
    });
});
