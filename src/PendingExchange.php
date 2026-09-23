<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use GuzzleHttp\TransferStats;
use Psr\Http\Message\RequestInterface;
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

    /**
     * Every URI this exchange has been seen at, original first.
     *
     * @var list<string>
     */
    private array $hops = [];

    private bool $recorded = false;

    private bool $blocked = false;

    public function __construct(
        private readonly \Ssx\Wiretap\Recorder $recorder,
        private readonly string $id,
        private readonly string $correlationId,
        private readonly int $sequence,
        private string $method,
        private string $uri,
        private Headers $requestHeaders,
        private CapturedBody $requestBody,
        private readonly float $startedAt,
    ) {
        $this->responseHeaders = Headers::empty();
        $this->responseBody = CapturedBody::none();
        $this->timings = new Timings();
        $this->hops[] = $uri;
        $this->originalUri = $uri;
    }

    /**
     * The URI the application actually asked for.
     *
     * This is what the recorded method, headers and body belong to, and it is
     * what the redactor has to see: overwriting it with the effective URI
     * after a redirect threw away the credentials in the original query
     * string before the redactor could learn them, so a response echoing one
     * back reached the sink in plaintext.
     */
    private readonly string $originalUri;

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
        // A response means this attempt reached the server. Any errno from an
        // earlier attempt belongs to that attempt — leaving it made every
        // request retried after a connection failure read as failed, which is
        // exactly backwards for always-keep-failures sampling.
        $this->error = null;
        $this->status = $response->getStatusCode();
        $this->reason = $response->getReasonPhrase() ?: null;
        $this->responseHeaders = Headers::fromMap($response->getHeaders());
        $this->responseBody = $body;
    }

    public function error(TransferError $error): void
    {
        $this->error = $error;
    }

    /**
     * Replace the recorded request with the one actually sent.
     *
     * The middleware sits at the top of the handler stack so it never
     * decorates a body upstream of a signing middleware — but that also means
     * it observes the request as the application *built* it, and anything
     * pushed below it can rewrite the request before it goes out. Through
     * Laravel's HTTP client, where withRequestMiddleware() and beforeSending()
     * both run beneath a global middleware, that was routine:
     *
     *     server actually saw : PUT  {"actual":true}   X-Api-Key: <credential>
     *     wiretap recorded    : POST {"original":true}
     *
     * Two things wrong at once. The record described a request that never
     * happened, and the credential header was never recorded — so the redactor
     * never learned that value, and a response echoing it back was stored in
     * plaintext.
     *
     * TransferStats::getRequest() is the request as sent, and on_stats fires
     * for it even under Http::fake(). The original is not simply discarded:
     * its URI is kept as the recorded one, because credentials in the query
     * string the application built still have to be learned.
     */
    public function requestAsSent(RequestInterface $request, CapturedBody $body): void
    {
        $this->method = $request->getMethod();
        $this->requestHeaders = Headers::fromMap($request->getHeaders());
        $this->requestBody = $body;

        $sent = (string) $request->getUri();

        if (!in_array($sent, $this->hops, true)) {
            $this->hops[] = $sent;
        }
    }

    public function stats(TransferStats $stats): void
    {
        // The effective URI is what a redirect chain actually reached. It is
        // tracked as a hop rather than overwriting the original, so the
        // blocklist can be checked against where the request ended up while
        // the record still describes what the application sent.
        $this->uri = (string) $stats->getEffectiveUri();

        if (!in_array($this->uri, $this->hops, true)) {
            $this->hops[] = $this->uri;
        }

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
        //
        // An error from an earlier attempt is cleared by response(), so a
        // retry that succeeds does not report the failed attempt's errno.
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

    /**
     * Some hop of this exchange went to a blocked URI. Permanent: a later hop
     * back onto an allowed host does not make the blocked one capturable.
     */
    public function block(): void
    {
        $this->blocked = true;
    }

    public function isBlocked(): bool
    {
        return $this->blocked;
    }

    /**
     * Where the request ended up, when that is not where it started.
     *
     * The effective URI is worth keeping — it is the whole point of following
     * a redirect — but it does not belong in `uri`, which has to agree with
     * the recorded method, headers and body. Context is redacted like
     * everything else, so credentials in a redirect target are not exempt.
     *
     * @return array<array-key, mixed>
     */
    private function context(): array
    {
        $redirects = array_values(array_slice($this->hops, 1));

        return $redirects === [] ? [] : ['redirected_to' => $redirects];
    }

    public function toExchange(): Exchange
    {
        return new Exchange(
            id: $this->id,
            correlationId: $this->correlationId,
            transport: Exchange::TRANSPORT_GUZZLE,
            method: $this->method,
            uri: $this->originalUri,
            requestHeaders: $this->requestHeaders,
            requestBody: $this->requestBody,
            status: $this->status,
            reason: $this->reason,
            responseHeaders: $this->responseHeaders,
            responseBody: $this->responseBody,
            timings: $this->timings,
            error: $this->error,
            startedAt: $this->startedAt,
            context: $this->context(),
            sequence: $this->sequence,
            pid: getmypid() ?: null,
        );
    }
}
