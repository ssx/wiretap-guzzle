<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use GuzzleHttp\TransferStats;
use Psr\Http\Message\ResponseInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Timings;
use Ssx\Wiretap\TransferError;

/**
 * An exchange being assembled.
 *
 * Mutable, unlike the Exchange it produces. The parts arrive at different
 * moments — the request up front, the timings and response in `on_stats`, an
 * exception in the promise's rejection handler — and forcing immutability
 * across those boundaries buys nothing but ceremony.
 *
 * Ordering note, because it is not obvious and it is easy to get wrong:
 * `on_stats` runs inside `CurlFactory::finish()`, which is *before* the
 * promise settles and therefore before any `then()` handler. Recording from
 * `then()` alone would miss a promise nobody waits on; recording from
 * `on_stats` alone would miss the exception class on a failure. So both call
 * `markRecorded()` and the first one to arrive wins.
 */
final class PendingExchange
{
    public bool $streaming = false;

    private ?int $status = null;

    private ?string $reason = null;

    private Headers $responseHeaders;

    private CapturedBody $responseBody;

    private Timings $timings;

    private ?TransferError $error = null;

    private bool $recorded = false;

    public function __construct(
        private readonly \Ssx\Wiretap\Recorder $recorder,
        private readonly string $id,
        private readonly string $correlationId,
        private readonly int $sequence,
        private readonly string $method,
        private string $uri,
        private readonly Headers $requestHeaders,
        private readonly CapturedBody $requestBody,
        private readonly float $startedAt,
    ) {
        $this->responseHeaders = Headers::empty();
        $this->responseBody = CapturedBody::none();
        $this->timings = new Timings();
    }

    public function recorder(): \Ssx\Wiretap\Recorder
    {
        return $this->recorder;
    }

    /**
     * The URI as it currently stands — the original request, or the effective
     * one once stats have been seen.
     */
    public function uri(): string
    {
        return $this->uri;
    }

    public function response(ResponseInterface $response, CapturedBody $body): void
    {
        $this->status = $response->getStatusCode();
        $this->reason = $response->getReasonPhrase() ?: null;
        $this->responseHeaders = Headers::fromMap($response->getHeaders());
        $this->responseBody = $body;
    }

    public function error(TransferError $error): void
    {
        $this->error = $error;
    }

    public function stats(TransferStats $stats): void
    {
        // The effective URI is what a redirect chain actually reached.
        $this->uri = (string) $stats->getEffectiveUri();

        $handlerStats = $stats->getHandlerStats();

        $this->timings = isset($handlerStats['total_time'])
            ? Timings::fromCurlInfo($handlerStats)
            : Timings::fromElapsedSeconds($stats->getTransferTime() ?? 0.0);

        // A ConnectException carries no response, so the curl errno is the
        // only description of what went wrong.
        //
        // getHandlerErrorData() is where Guzzle puts it. Reading `errno` out
        // of the stats array happened to work with some handlers and returned
        // nothing with others.
        if ($this->error === null && !$stats->hasResponse()) {
            $this->error = $this->errorFrom($stats, $handlerStats);
        }
    }

    /**
     * @param array<string, mixed> $handlerStats
     */
    private function errorFrom(TransferStats $stats, array $handlerStats): ?TransferError
    {
        $data = $stats->getHandlerErrorData();

        if (is_int($data) && $data !== 0) {
            return new TransferError($data, 'curl error ' . $data);
        }

        if (is_string($data) && $data !== '') {
            return new TransferError(-1, $data);
        }

        $errno = $handlerStats['errno'] ?? null;

        if (is_int($errno) && $errno !== 0) {
            return new TransferError(
                errno: $errno,
                message: is_string($handlerStats['error'] ?? null) && $handlerStats['error'] !== ''
                    ? $handlerStats['error']
                    : 'Transfer failed',
            );
        }

        return null;
    }

    /**
     * True the first time it is called, false every time after.
     *
     * Both completion signals fire for a normal request, and the record must
     * be written once.
     */
    public function markRecorded(): bool
    {
        if ($this->recorded) {
            return false;
        }

        return $this->recorded = true;
    }

    public function isRecorded(): bool
    {
        return $this->recorded;
    }

    public function toExchange(): Exchange
    {
        return new Exchange(
            id: $this->id,
            correlationId: $this->correlationId,
            transport: Exchange::TRANSPORT_GUZZLE,
            method: $this->method,
            uri: $this->uri,
            requestHeaders: $this->requestHeaders,
            requestBody: $this->requestBody,
            status: $this->status,
            reason: $this->reason,
            responseHeaders: $this->responseHeaders,
            responseBody: $this->responseBody,
            timings: $this->timings,
            error: $this->error,
            startedAt: $this->startedAt,
            sequence: $this->sequence,
            pid: getmypid() ?: null,
        );
    }
}
