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
    /**
     * @param bool $hashFullBody Off by default, and not a performance setting.
     *
     * The digest is taken over the body as sent, before redaction has run.
     * Core drops it whenever redaction rewrote the body, precisely because an
     * unkeyed SHA-256 of the plaintext sitting beside `[REDACTED]` is an
     * offline oracle — a four-digit PIN falls to ten thousand guesses. But a
     * truncated capture is the case core cannot see: the stored prefix may be
     * unchanged while the digest still covers a tail that was never redacted
     * and never stored.
     *
     * So this is opt-in. Core's own hash hints work the same way and refuse to
     * emit anything without a per-install `hashSalt`; turn this on only where
     * comparing payloads across exchanges is worth that, and set a salt.
     *
     * @param int $maxHashBytes A read budget, not a size threshold.
     *
     * Hashing used to read to EOF, which bounded memory but not I/O: a 512 MiB
     * upload was read end to end before the request was even dispatched. The
     * size check that replaced it trusted getSize(), which a caching wrapper
     * makes meaningless — a four-byte capture over Guzzle's CachingStream read
     * and retained 3 MiB. This is now enforced against bytes actually read, so
     * a stream that lies about its length, or does not know it, cannot exceed
     * it. A body that does not finish within the budget reports no digest
     * rather than an incomplete one.
     */
    public function __construct(
        private int $maxBytes = 1_048_576,
        private bool $hashFullBody = false,
        private int $maxHashBytes = 1_048_576,
    ) {
    }

    public function capture(?StreamInterface $stream, ?string $contentType, bool $streaming = false): CapturedBody
    {
        if ($stream === null) {
            return CapturedBody::none();
        }

        $size = $stream->getSize();

        // Some implementations report an unknown length as -1 rather than
        // null. Taken as a size, a readable body was compared against it and
        // stored as complete, with size -1.
        if ($size !== null && $size < 0) {
            $size = null;
        }

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

            // One byte past the limit, to settle the unknown-length case.
            //
            // getSize() is null for pipes and unknown-length streams, so the
            // truncation test has to be written twice. Treating "filled the
            // buffer" as truncated marked a body that was exactly the limit
            // as a prefix, and then reported its size as unknown — two wrong
            // answers about a body we had in full. eof() cannot settle it
            // either: a stream at its last byte does not report eof until
            // something reads past it. Asking for one more byte does, and the
            // byte is not thrown away — it is hashed, just not stored.
            $overflow = $size === null ? $this->readUpTo($stream, 1) : '';

            $truncated = $size === null
                ? $overflow !== ''
                : $size > strlen($bytes);

            $sha256 = null;

            // A body already known to be over the budget can never produce a
            // digest, so hashing it only spent reads and CPU to reach null. A
            // stream that overstates its size can only talk us out of hashing,
            // never into reading more.
            if ($this->hashFullBody && ($size === null || $size <= $this->maxHashBytes)) {
                $sha256 = $this->hashRemaining($stream, $bytes . $overflow);
            }

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
     *
     * Bounded by bytes actually read, including the prefix the caller already
     * has. Returns null rather than a partial digest if the body does not end
     * within the budget — a digest that silently covered only part of a body
     * would compare unequal payloads as equal.
     */
    private function hashRemaining(StreamInterface $stream, string $alreadyRead): ?string
    {
        if (strlen($alreadyRead) > $this->maxHashBytes) {
            return null;
        }

        try {
            $context = hash_init('sha256');
            hash_update($context, $alreadyRead);

            $read = strlen($alreadyRead);

            while (!$stream->eof()) {
                if ($read >= $this->maxHashBytes) {
                    // A stream at its last byte does not report eof until
                    // something reads past it, so a body exactly the size of
                    // the budget looks unfinished here. One more byte settles
                    // it, as it does for the capture; the caller restores the
                    // position either way.
                    if ($stream->read(1) === '') {
                        break;
                    }

                    // Budget spent before the body ended.
                    return null;
                }

                $chunk = $stream->read(min(8192, $this->maxHashBytes - $read));

                if ($chunk === '') {
                    break;
                }

                $read += strlen($chunk);
                hash_update($context, $chunk);
            }

            return hash_final($context);
        } catch (\Throwable) {
            return null;
        }
    }
}
