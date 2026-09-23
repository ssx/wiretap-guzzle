<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\CachingStream;
use GuzzleHttp\Psr7\PumpStream;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Guzzle\WiretapClient;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

/**
 * A response body backed by the network rather than by memory, the way
 * Symfony's Psr18Client returns one: readable and seekable, but every read
 * waits on the server. Counts reads so a test can prove none happened.
 */
function liveNetworkStream(): StreamInterface
{
    return new class implements StreamInterface {
        public int $reads = 0;

        public function __toString(): string
        {
            ++$this->reads;

            return '';
        }

        public function close(): void
        {
        }

        public function detach()
        {
            return null;
        }

        public function getSize(): ?int
        {
            return null;
        }

        public function tell(): int
        {
            return 0;
        }

        public function eof(): bool
        {
            return false;
        }

        public function isSeekable(): bool
        {
            return true;
        }

        public function seek(int $offset, int $whence = SEEK_SET): void
        {
        }

        public function rewind(): void
        {
        }

        public function isWritable(): bool
        {
            return false;
        }

        public function write(string $string): int
        {
            throw new RuntimeException('not writable');
        }

        public function isReadable(): bool
        {
            return true;
        }

        public function read(int $length): string
        {
            // An SSE or long-poll endpoint: the next event arrives when the
            // server sends it, which may be never.
            ++$this->reads;

            return "data: event\n\n";
        }

        public function getContents(): string
        {
            ++$this->reads;

            return '';
        }

        public function getMetadata(?string $key = null)
        {
            $meta = ['uri' => 'symfony://https://api.example.com/events', 'seekable' => true];

            return $key === null ? $meta : ($meta[$key] ?? null);
        }
    };
}

function psr18ReturningBody(StreamInterface $body): ClientInterface
{
    return new class($body) implements ClientInterface {
        public function __construct(private StreamInterface $body)
        {
        }

        public function sendRequest(RequestInterface $request): ResponseInterface
        {
            return (new Response(200, ['Content-Type' => 'text/event-stream']))->withBody($this->body);
        }
    };
}

describe('PSR-18 response bodies', function (): void {
    it('never reads a body that is still arriving over the network', function (): void {
        // Reading up to 1 MiB of the response before returning it turned an
        // SSE call that returns in 0.01s into one that returned after 3s, and
        // an endless stream into one that never returned at all.
        $recorder = new Recorder(sink: $sink = new InMemorySink());
        $body = liveNetworkStream();

        $response = (new WiretapClient(psr18ReturningBody($body), $recorder))
            ->sendRequest(new Request('GET', 'https://api.example.com/events'));

        $recorder->flush();

        expect($response->getBody())->toBe($body)
            ->and($body->reads)->toBe(0)
            ->and($sink->all()[0]->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_STREAMING);
    });

    it('never reads through a caching decorator whose source is still live', function (): void {
        // CachingStream forwards getMetadata() to its php://temp cache, so it
        // looks buffered while every read past the cached prefix pulls from
        // the network source underneath.
        $recorder = new Recorder(sink: $sink = new InMemorySink());
        $sourceReads = 0;
        $body = new CachingStream(new PumpStream(static function () use (&$sourceReads): string {
            ++$sourceReads;

            return "data: event\n\n";
        }));

        (new WiretapClient(psr18ReturningBody($body), $recorder))
            ->sendRequest(new Request('GET', 'https://api.example.com/events'));

        $recorder->flush();

        expect($sourceReads)->toBe(0)
            ->and($sink->all()[0]->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_STREAMING);
    });

    it('still captures a body held in a local file', function (): void {
        $path = tempnam(sys_get_temp_dir(), 'wiretap');
        file_put_contents($path, '{"from":"file"}');
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        try {
            (new WiretapClient(psr18ReturningBody(Utils::streamFor(fopen($path, 'rb'))), $recorder))
                ->sendRequest(new Request('GET', 'https://api.example.com/download'));
        } finally {
            @unlink($path);
        }

        $recorder->flush();

        expect($sink->all()[0]->responseBody->bytes)->toBe('{"from":"file"}');
    });

    it('still captures a body the client has already buffered in memory', function (): void {
        $recorder = new Recorder(sink: $sink = new InMemorySink());

        (new WiretapClient(psr18ReturningBody(Utils::streamFor('{"ok":true}')), $recorder))
            ->sendRequest(new Request('GET', 'https://api.example.com/things'));

        $recorder->flush();

        expect($sink->all()[0]->responseBody->bytes)->toBe('{"ok":true}');
    });
});
