<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Recorder;

/**
 * Everything decided at admission, carried to completion unchanged.
 *
 * The PSR-18 path used to resolve the recorder twice and read the correlation
 * id at completion, so a request admitted under one recorder could be written
 * through another's sink and redaction policy if the holder changed during the
 * inner call or a Fiber suspension. Holding the decisions here is what makes
 * the two ends of a request agree, and mirrors what PendingExchange does for
 * the Guzzle middleware.
 */
final readonly class PendingPsrExchange
{
    public function __construct(
        public Recorder $recorder,
        public string $id,
        public string $correlationId,
        public int $sequence,
        public float $startedAt,
        public CapturedBody $requestBody,
    ) {
    }
}
