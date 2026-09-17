<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use Psr\Http\Message\StreamInterface;
use Ssx\Wiretap\CapturedBody;

/**
 * Reads a PSR-7 body without disturbing it.
 *
 * Three rules govern everything here, and all three have cost someone a
 * production incident somewhere:
 *
 * 1. Never cast a body to string. `(string) $stream` rewinds and drains it.
 * 2. Restore the exact prior position, not position zero. A signing
 *    middleware or a partially-consumed upload may have left the pointer
 *    mid-stream, and rewinding changes what the application sends.
 * 3. Never read a non-seekable stream. Reading it steals bytes the
 *    application has not consumed yet, which corrupts the transfer.
 */
final readonly class BodyCapture
{
    /**
     * @param int $maxBytes A hard memory ceiling, not the redaction limit.
     *
     * These are deliberately different numbers. Capturing only 64 KiB here
     * would hand the redactor a truncated JSON body it cannot parse, so
     * configured body-path rules would silently do nothing — and the core then
     * has to drop the body entirely to stay safe. Reading a larger bounded
     * amount lets structural redaction actually run, and the core truncates to
     * its own limit afterwards.
     */
    public function __construct(
        private int $maxBytes = 1_048_576,
        private bool $hashFullBody = true,
    ) {
    }

    public function capture(?StreamInterface $stream, ?string $contentType, bool $streaming = false): CapturedBody
    {
        if ($stream === null) {
            return CapturedBody::none();
        }

        $size = $stream->getSize();

        if ($size === 0) {
            return CapturedBody::none();
        }

        // The caller asked for a live stream. Reading it here would consume
        // bytes they have not seen yet.
        if ($streaming) {
            return CapturedBody::omitted(CapturedBody::OMITTED_STREAMING, $size, $contentType);
        }

        if (!$stream->isReadable()) {
            return CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE, $size, $contentType);
        }

        // Without seek we cannot put back what we take.
        if (!$stream->isSeekable()) {
            return CapturedBody::omitted(CapturedBody::OMITTED_NOT_SEEKABLE, $size, $contentType);
        }

        try {
            $position = $stream->tell();
        } catch (\RuntimeException) {
            return CapturedBody::omitted(CapturedBody::OMITTED_NOT_SEEKABLE, $size, $contentType);
        }

        try {
            $stream->rewind();

            $bytes = $this->readUpTo($stream, $this->maxBytes);
            $sha256 = null;

            if ($this->hashFullBody) {
                $sha256 = $this->hashRemaining($stream, $bytes);
            }

            // getSize() is null for pipes and unknown-length streams, which is
            // why the truncation test has to be written twice.
            $truncated = $size === null
                ? !$stream->eof()
                : $size > strlen($bytes);

            return CapturedBody::captured(
                bytes: $bytes,
                size: $size ?? ($truncated ? null : strlen($bytes)),
                contentType: $contentType,
                truncated: $truncated,
                sha256: $sha256,
            );
        } catch (\Throwable) {
            return CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE, $size, $contentType);
        } finally {
            // Always, even if the read threw halfway through.
            try {
                $stream->seek($position);
            } catch (\Throwable) {
                // Nothing further we can safely do; better to leave the
                // stream alone than to keep poking at it.
            }
        }
    }

    /**
     * Read up to $limit bytes, tolerating short reads.
     *
     * StreamInterface::read() may return fewer bytes than asked for before
     * EOF. Treating the first short read as the whole body stored a three-byte
     * prefix of a ten-byte payload and marked it complete.
     */
    private function readUpTo(StreamInterface $stream, int $limit): string
    {
        $buffer = '';

        while (strlen($buffer) < $limit && !$stream->eof()) {
            $chunk = $stream->read($limit - strlen($buffer));

            if ($chunk === '') {
                // No progress. Stop rather than spin.
                break;
            }

            $buffer .= $chunk;
        }

        return $buffer;
    }

    /**
     * Hash the whole body even when only a prefix is stored.
     *
     * This is what makes truncation tolerable: two exchanges can still be
     * compared for an identical payload, and a reader can tell whether what
     * they are looking at is all of it.
     */
    private function hashRemaining(StreamInterface $stream, string $alreadyRead): ?string
    {
        try {
            $context = hash_init('sha256');
            hash_update($context, $alreadyRead);

            while (!$stream->eof()) {
                $chunk = $stream->read(8192);

                if ($chunk === '') {
                    break;
                }

                hash_update($context, $chunk);
            }

            return hash_final($context);
        } catch (\Throwable) {
            return null;
        }
    }
}
