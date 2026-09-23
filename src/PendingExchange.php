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
 * `on_stats` runs inside `CurlFactory::finish()` once per transfer — every
 * redirect hop and retry attempt — and *before* the promise settles. It only
 * folds that transfer's request, stats and timings in here. The record is
 * written from the promise handlers, once the application's own promise
 * settles; `markRecorded()` keeps that to a single write.
 */
final class PendingExchange
{
    public bool $streaming = false;

    private ?int $status = null;

    private ?string $reason = null;

    private Headers $responseHeaders;

    private CapturedBody $responseBody;

    private Timings $timings;

    /**
     * How many transfers on_stats has reported: more than one for a redirect
     * chain or a retry.
     */
    private int $transfers = 0;

    /**
     * The URI the recorded request was actually sent to: the first hop's, once
     * on_stats has seen it. Null until then, when the application's URI
     * stands in.
     */
    private ?string $sentUri = null;

    private ?TransferError $error = null;

    /**
     * Every URI this exchange was sent to or ended at, in order: each hop's
     * request as sent, and each transfer's effective URI.
     *
     * @var list<string>
     */
    private array $hops = [];

    /**
     * Every request observed for this exchange — the one the application
     * built, then each one actually sent — as URI and headers. Held only so
     * redaction can learn what each hop carried; never stored.
     *
     * @var list<array{0: string, 1: Headers}>
     */
    private array $requests = [];

    /**
     * The response the most recent transfer received, if any. A middleware
     * below this one can turn a received response into an exception that
     * carries none, and this is then the only record of what the server
     * sent.
     */
    private ?ResponseInterface $transferResponse = null;

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
        $this->originalUri = $uri;
        $this->requests[] = [$uri, $requestHeaders];
    }

    /**
     * The URI the application actually asked for.
     *
     * Not necessarily a URI anything was sent to — a middleware below this
     * one can move the request — but the redactor still has to see it:
     * dropping it threw away the credentials in the query string the
     * application built, so a response echoing one back reached the sink in
     * plaintext. It stays in the requests learned from, and stands in as the
     * recorded URI until on_stats reports the real one.
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
     * Fold in a request that was actually sent: one per transfer.
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
     * for it even under Http::fake().
     *
     * Only the first transfer becomes the recorded request, URI, method,
     * headers and body together. Taking the method, headers and body from
     * every hop while keeping the original URI described a request nobody
     * sent: a POST answered with a 302 is followed as a bodyless GET, and the
     * record read "GET <the POST's URI>, no body". Later hops are listed in
     * `redirected_to`. A retry resends the same request, so its first attempt
     * describes it as well as the last.
     *
     * The body is read only for the first transfer, so $body is a closure.
     *
     * @param \Closure(): CapturedBody $body
     */
    public function requestAsSent(RequestInterface $request, \Closure $body): void
    {
        $sent = (string) $request->getUri();
        $headers = Headers::fromMap($request->getHeaders());

        if ($this->sentUri === null) {
            $this->sentUri = $sent;
            $this->method = $request->getMethod();
            $this->requestHeaders = $headers;
            $this->requestBody = $body();
        }

        // What every hop carried must still be learned: Guzzle strips
        // Authorization on a cross-host redirect, and the token then echoed
        // in the final body survived.
        $this->requests[] = [$sent, $headers];

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

        $this->transferResponse = $stats->hasResponse() ? $stats->getResponse() : null;

        $handlerStats = $stats->getHandlerStats();

        $timings = isset($handlerStats['total_time'])
            ? Timings::fromCurlInfo($handlerStats)
            : Timings::fromElapsedSeconds($stats->getTransferTime() ?? 0.0);

        // A redirect chain or a retry is several transfers, and each one
        // overwrote the last, so a chain that spent seconds on its first hops
        // was reported as fast as its final one. The total is summed across
        // them. The phase timings stay the first transfer's: they are offsets
        // from its start, which is the start of the whole exchange, so they
        // remain true for it — a later hop's would be offsets from a moment
        // the record does not show.
        $this->timings = $this->transfers++ === 0
            ? $timings
            : new Timings(
                dns: $this->timings->dns,
                connect: $this->timings->connect,
                tls: $this->timings->tls,
                ttfb: $this->timings->ttfb,
                total: $this->timings->total === null && $timings->total === null
                    ? null
                    : ($this->timings->total ?? 0) + ($timings->total ?? 0),
            );

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

    public function transferResponse(): ?ResponseInterface
    {
        return $this->transferResponse;
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

    public function toExchange(): Exchange
    {
        // Where the request ended up, when that is not where it started, goes
        // in context as `redirected_to`. The effective URI is worth keeping —
        // it is the whole point of following a redirect — but it does not
        // belong in `uri`, which has to agree with the recorded method,
        // headers and body. HopSecrets emits those URIs already redacted:
        // core does not walk a list in context.
        //
        // The application's URI is not a hop when a lower middleware moved
        // the request before it was sent; it is still learned from, as one of
        // the requests.
        $uri = $this->recordedUri();

        return HopSecrets::apply(
            $this->recorder->redactor(),
            $this->baseExchange(),
            array_values(array_filter($this->hops, static fn (string $hop): bool => $hop !== $uri)),
            $this->requests,
        );
    }

    private function recordedUri(): string
    {
        return $this->sentUri ?? $this->originalUri;
    }

    private function baseExchange(): Exchange
    {
        return new Exchange(
            id: $this->id,
            correlationId: $this->correlationId,
            transport: Exchange::TRANSPORT_GUZZLE,
            method: $this->method,
            uri: $this->recordedUri(),
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
