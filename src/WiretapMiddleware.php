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

        // The gate runs before anything is read. A blocked payload should
        // never exist in process memory, not merely never be stored.
        if (!$this->recorder()->shouldCapture($url)) {
            return null;
        }

        $streaming = (bool) ($options['stream'] ?? false);

        $pending = new PendingExchange(
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
                        $pending->response($response, $this->captureResponseBody($response, $pending->streaming));
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
                            $pending->response($response, $this->captureResponseBody($response, $pending->streaming));
                        }

                        if ($reason instanceof \Throwable) {
                            $pending->error(TransferError::fromThrowable($reason));
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

    private function commit(PendingExchange $pending): void
    {
        if ($pending->markRecorded()) {
            $this->recorder()->record($pending->toExchange());
        }
    }

    private function captureResponseBody(ResponseInterface $response, bool $streaming): CapturedBody
    {
        return $this->bodyCapture->capture(
            $response->getBody(),
            $response->getHeaderLine('Content-Type') ?: null,
            $streaming,
        );
    }
}
