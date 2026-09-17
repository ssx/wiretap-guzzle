<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\TransferStats;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Support\Ulid;
use Ssx\Wiretap\TransferError;

/**
 * Guzzle middleware that records the exchange.
 *
 * Push this with `unshift()` rather than `push()`. At the top of the stack it
 * observes the request as the application built it and, critically, never
 * decorates the request body — anything that changes `getSize()` or
 * `isSeekable()` upstream of a signing middleware breaks AWS SigV4, OAuth1
 * body hashes and `prepare_body`'s Content-Length. If `getSize()` becomes
 * null, Guzzle switches to `Transfer-Encoding: chunked` and some APIs reject
 * the request outright.
 *
 * Two completion signals are wired, because neither is sufficient alone:
 *
 * - `on_stats` fires inside `CurlFactory::finish()`, before the promise
 *   settles. It carries the transfer timings, the effective URI after
 *   redirects, and the response — and it still runs for a promise nobody ever
 *   waits on, such as a Pool whose results are discarded.
 * - The promise handlers carry the exception, which `on_stats` cannot see.
 *
 * Whichever arrives first writes the record; the other is a no-op.
 */
final class WiretapMiddleware
{
    /** @var \Closure(): Recorder */
    private readonly \Closure $resolveRecorder;

    /**
     * The recorder may be passed directly, or as a closure resolved per call.
     *
     * The closure form matters more than it looks. Middleware is pushed onto a
     * handler stack once, at boot, and a stack is frequently built before the
     * application has finished deciding what its recorder should be — a test
     * calling Wiretap::fake() afterwards, for instance. Holding a fixed
     * instance means those later decisions are silently ignored and the
     * records go somewhere nobody is looking.
     *
     * @param Recorder|\Closure(): Recorder $recorder
     */
    public function __construct(
        Recorder|\Closure $recorder,
        private readonly BodyCapture $bodyCapture = new BodyCapture(),
    ) {
        $this->resolveRecorder = $recorder instanceof Recorder
            ? static fn (): Recorder => $recorder
            : $recorder;
    }

    /**
     * @param Recorder|\Closure(): Recorder $recorder
     */
    public static function create(Recorder|\Closure $recorder, ?BodyCapture $bodyCapture = null): self
    {
        return new self($recorder, $bodyCapture ?? new BodyCapture());
    }

    private function recorder(): Recorder
    {
        return ($this->resolveRecorder)();
    }

    public function __invoke(callable $next): callable
    {
        return function (RequestInterface $request, array $options) use ($next): PromiseInterface {
            try {
                $prepared = $this->prepare($request, $options);
            } catch (\Throwable) {
                // Capture setup failed — a body whose getSize() throws, for
                // instance. Send the request uninstrumented rather than let
                // instrumentation stop it.
                return $next($request, $options);
            }

            if ($prepared === null) {
                return $next($request, $options);
            }

            [$pending, $options] = $prepared;

            return $this->dispatch($next, $request, $options, $pending);
        };
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{0: PendingExchange, 1: array<string, mixed>}|null
     */
    private function prepare(RequestInterface $request, array $options): ?array
    {
        $url = (string) $request->getUri();

        // Resolved once, here, and carried on the pending exchange.
        $recorder = $this->recorder();

        // The gate runs before anything is read. A blocked payload should
        // never exist in process memory, not merely never be stored.
        if (!$recorder->shouldCapture($url)) {
            return null;
        }

        $streaming = (bool) ($options['stream'] ?? false);

        $pending = new PendingExchange(
            recorder: $recorder,
            id: Ulid::generate(),
            correlationId: Correlation::id(),
            sequence: Correlation::nextSequence(),
            method: $request->getMethod(),
            uri: $url,
            requestHeaders: Headers::fromMap($request->getHeaders()),
            requestBody: $this->bodyCapture->capture(
                $request->getBody(),
                $request->getHeaderLine('Content-Type') ?: null,
            ),
            startedAt: microtime(true),
        );
        $pending->streaming = $streaming;

        return [$pending, $this->chainStatsHandler($options, $pending)];
    }

    /**
     * @param array<string, mixed> $options
     */
    private function dispatch(callable $next, RequestInterface $request, array $options, PendingExchange $pending): PromiseInterface
    {
        return $next($request, $options)->then(
            function (ResponseInterface $response) use ($pending): ResponseInterface {
                // Every line here is wrapped: a capture failure must not
                // turn a successful response into a rejected promise.
                try {
                    if (!$pending->isRecorded()) {
                        $pending->response($response, $this->captureResponseBody($pending, $response));
                        $this->commit($pending);
                    }
                } catch (\Throwable) {
                }

                return $response;
            },
            function (mixed $reason) use ($pending): PromiseInterface {
                try {
                    if (!$pending->isRecorded()) {
                        if ($reason instanceof RequestException && $reason->getResponse() !== null) {
                            $response = $reason->getResponse();
                            $pending->response($response, $this->captureResponseBody($pending, $response));
                        }

                        if ($reason instanceof \Throwable) {
                            $pending->error($this->errorFor($reason));
                        }

                        $this->commit($pending);
                    }
                } catch (\Throwable) {
                    // Must not replace the application's own failure with
                    // an instrumentation one.
                }

                // Returning anything but a rejection here would turn a
                // failure into a success and break the calling code.
                return Create::rejectionFor($reason);
            },
        );
    }

    /**
     * Chain onto any `on_stats` the caller already set rather than replacing
     * it — silently dropping their callback would be a nasty surprise.
     *
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    private function chainStatsHandler(array $options, PendingExchange $pending): array
    {
        $existing = $options['on_stats'] ?? null;

        $options['on_stats'] = function (TransferStats $stats) use ($existing, $pending): void {
            try {
                // Stats only. Committing here recorded the wrong exchange:
                // on_stats fires once per transfer, so a 302 that Guzzle was
                // about to follow was committed as the finished exchange, and
                // the 200 the application actually received was discarded as a
                // duplicate. Retry middleware has the same shape.
                //
                // The cost is that a promise nobody ever waits on — a Pool
                // whose results are discarded — is no longer recorded. That is
                // a smaller problem than confidently recording a redirect hop
                // as the response.
                $pending->stats($stats);
            } catch (\Throwable) {
                // Instrumentation must never change application behaviour.
            }

            if (is_callable($existing)) {
                $existing($stats);
            }
        };

        return $options;
    }

    /**
     * Turn a rejection reason into a transport error, or nothing.
     *
     * Guzzle embeds the first 120 bytes of the response body verbatim in a
     * BadResponseException message. Storing that message put the raw body into
     * error.message, where neither the configured body-path rules nor the
     * content-type gate apply — so a 422 whose JSON body was correctly
     * redacted in responseBody appeared in full a few fields later.
     *
     * A response means this is an HTTP error, not a transport failure. The
     * status already says so, so only the exception class is kept.
     */
    private function errorFor(\Throwable $reason): TransferError
    {
        if ($reason instanceof RequestException && $reason->getResponse() !== null) {
            $response = $reason->getResponse();

            return new TransferError(
                errno: 0,
                message: sprintf('HTTP %d response', $response->getStatusCode()),
                class: $reason::class,
            );
        }

        return TransferError::fromThrowable($reason);
    }

    private function commit(PendingExchange $pending): void
    {
        if ($pending->markRecorded()) {
            // The recorder this request was admitted under, not whatever is
            // current now. An async request started under recorder A and
            // resolved after the holder moved to B was writing its record to
            // B — mixing concurrent scopes, and sending a capture to a sink
            // and redaction policy that never admitted it.
            $pending->recorder()->record($pending->toExchange());
        }
    }

    private function captureResponseBody(PendingExchange $pending, ResponseInterface $response): CapturedBody
    {
        // Re-gate on the effective URI before reading anything.
        //
        // Wiretap sits above Guzzle's redirect middleware, so a redirected hop
        // never re-enters the gate. An allowed URL redirecting to a blocked
        // host had the blocked body read into memory, and only then did the
        // recorder reject the record. Nothing was stored, but the payload
        // existed — which is precisely what the gate exists to prevent.
        if (!$pending->recorder()->shouldCapture($pending->uri())) {
            return CapturedBody::omitted(CapturedBody::OMITTED_DISABLED);
        }

        return $this->bodyCapture->capture(
            $response->getBody(),
            $response->getHeaderLine('Content-Type') ?: null,
            $pending->streaming,
        );
    }
}
