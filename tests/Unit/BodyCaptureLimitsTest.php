<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\CachingStream;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
use Ssx\Wiretap\Guzzle\BodyCapture;

/**
 * A readable, seekable stream that does not know its own length — a pipe, a
 * chunked response, or anything wrapped so getSize() returns null.
 */
function unknownLengthStream(string $body): StreamInterface
{
    $handle = fopen('php://temp', 'r+b');
    fwrite($handle, $body);
    rewind($handle);

    return new class(Utils::streamFor($handle)) implements StreamInterface {
        public function __construct(private StreamInterface $inner)
        {
        }

        public function getSize(): ?int
        {
            return null;
        }

        public function __toString(): string
        {
            return $this->inner->__toString();
        }

        public function close(): void
        {
            $this->inner->close();
        }

        public function detach()
        {
            return $this->inner->detach();
        }

        public function tell(): int
        {
            return $this->inner->tell();
        }

        public function eof(): bool
        {
            return $this->inner->eof();
        }

        public function isSeekable(): bool
        {
            return true;
        }

        public function seek(int $offset, int $whence = SEEK_SET): void
        {
            $this->inner->seek($offset, $whence);
        }

        public function rewind(): void
        {
            $this->inner->rewind();
        }

        public function isWritable(): bool
        {
            return false;
        }

        public function write(string $string): int
        {
            return 0;
        }

        public function isReadable(): bool
        {
            return true;
        }

        public function read(int $length): string
        {
            return $this->inner->read($length);
        }

        public function getContents(): string
        {
            return $this->inner->getContents();
        }

        public function getMetadata(?string $key = null)
        {
            return $this->inner->getMetadata($key);
        }
    };
}

describe('digests', function (): void {
    it('does not hash the body by default', function (): void {
        // The digest is taken before redaction runs. An unkeyed SHA-256 of the
        // plaintext sitting beside [REDACTED] is an offline oracle — a
        // four-digit PIN falls to ten thousand guesses.
        $result = (new BodyCapture())->capture(Utils::streamFor('{"pin":"1234"}'), 'application/json');

        expect($result->sha256)->toBeNull()
            ->and($result->bytes)->toBe('{"pin":"1234"}');
    });

    it('hashes the whole body when asked explicitly', function (): void {
        $result = (new BodyCapture(hashFullBody: true))->capture(Utils::streamFor('hello'), 'text/plain');

        expect($result->sha256)->toBe(hash('sha256', 'hello'));
    });

    it('hashes past the stored prefix, so truncated captures stay comparable', function (): void {
        $body = str_repeat('z', 25);

        $result = (new BodyCapture(maxBytes: 10, hashFullBody: true))
            ->capture(unknownLengthStream($body), 'text/plain');

        expect($result->bytes)->toHaveLength(10)
            ->and($result->truncated)->toBeTrue()
            ->and($result->sha256)->toBe(hash('sha256', $body));
    });

    it('reports no digest rather than reading an unbounded stream', function (): void {
        // getSize() cannot be trusted as a threshold: a caching wrapper makes
        // it meaningless, and a four-byte capture over Guzzle's CachingStream
        // read and retained 3 MiB. The budget is enforced against bytes
        // actually read.
        $stream = new CachingStream(Utils::streamFor(str_repeat('x', 3 * 1024 * 1024)));

        $before = memory_get_usage();
        $result = (new BodyCapture(maxBytes: 4, hashFullBody: true, maxHashBytes: 65536))
            ->capture($stream, 'application/octet-stream');
        $used = memory_get_usage() - $before;

        expect($result->bytes)->toHaveLength(4)
            ->and($result->sha256)->toBeNull()
            ->and($used)->toBeLessThan(1024 * 1024);
    });

    it('still produces a digest when the body fits the budget', function (): void {
        $body = str_repeat('y', 1000);
        $stream = new CachingStream(Utils::streamFor($body));

        $result = (new BodyCapture(maxBytes: 4, hashFullBody: true, maxHashBytes: 65536))
            ->capture($stream, 'text/plain');

        expect($result->sha256)->toBe(hash('sha256', $body));
    });

    it('produces a digest for a body exactly the size of the budget', function (): void {
        // A stream at its last byte does not report eof until something reads
        // past it, so reaching the budget used to read as "the body did not
        // end in time" for a body that ended exactly there.
        $body = str_repeat('b', 1_048_576);

        $result = (new BodyCapture(hashFullBody: true))->capture(Utils::streamFor($body), 'text/plain');

        expect($result->sha256)->toBe(hash('sha256', $body))
            ->and($result->truncated)->toBeFalse();
    });

    it('does the same for an unknown-length body exactly the size of the budget', function (): void {
        $body = str_repeat('b', 1_048_576);

        $result = (new BodyCapture(hashFullBody: true))->capture(unknownLengthStream($body), 'text/plain');

        expect($result->sha256)->toBe(hash('sha256', $body));
    });

    it('still refuses a digest for one byte over the budget', function (): void {
        $result = (new BodyCapture(maxBytes: 4, hashFullBody: true, maxHashBytes: 16))
            ->capture(unknownLengthStream(str_repeat('c', 17)), 'text/plain');

        expect($result->sha256)->toBeNull();
    });

    it('does not read past the capture for a body it already knows is over the budget', function (): void {
        // A known size over the budget can never produce a digest, so hashing
        // it only spent the reads (and the CPU) to reach the same null.
        $inner = Utils::streamFor(str_repeat('d', 100));
        $counting = new class($inner) implements StreamInterface {
            use \GuzzleHttp\Psr7\StreamDecoratorTrait;

            public int $bytesRead = 0;

            public function __construct(private StreamInterface $stream)
            {
            }

            public function read(int $length): string
            {
                $chunk = $this->stream->read($length);
                $this->bytesRead += strlen($chunk);

                return $chunk;
            }
        };

        $result = (new BodyCapture(maxBytes: 4, hashFullBody: true, maxHashBytes: 16))
            ->capture($counting, 'text/plain');

        expect($result->sha256)->toBeNull()
            ->and($result->bytes)->toBe('dddd')
            ->and($counting->bytesRead)->toBe(4);
    });
});

describe('truncation of unknown-length bodies', function (): void {
    it('does not call a body truncated when it is exactly the limit', function (): void {
        // Treating "filled the buffer" as truncated marked a body we had in
        // full as a prefix, and reported its size as unknown — two wrong
        // answers about the same body.
        $result = (new BodyCapture(maxBytes: 10))->capture(unknownLengthStream(str_repeat('z', 10)), 'text/plain');

        expect($result->truncated)->toBeFalse()
            ->and($result->size)->toBe(10)
            ->and($result->bytes)->toHaveLength(10);
    });

    it('does call it truncated when there is one more byte', function (): void {
        $result = (new BodyCapture(maxBytes: 10))->capture(unknownLengthStream(str_repeat('z', 11)), 'text/plain');

        expect($result->truncated)->toBeTrue()
            ->and($result->size)->toBeNull()
            ->and($result->bytes)->toHaveLength(10);
    });

    it('leaves a short body alone', function (): void {
        $result = (new BodyCapture(maxBytes: 10))->capture(unknownLengthStream('zzzzz'), 'text/plain');

        expect($result->truncated)->toBeFalse()
            ->and($result->size)->toBe(5);
    });

    it('restores the stream position it started from', function (): void {
        $stream = unknownLengthStream(str_repeat('z', 40));
        $stream->seek(7);

        (new BodyCapture(maxBytes: 10))->capture($stream, 'text/plain');

        expect($stream->tell())->toBe(7);
    });
});
