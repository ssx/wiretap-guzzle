<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\RequestOptions;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Support\Ulid;
use Ssx\Wiretap\Timings;
use Ssx\Wiretap\TransferClaim;
use Ssx\Wiretap\TransferError;

/**
 * A PSR-18 decorator, for clients that are not Guzzle.
 *
 * Portable, but it only sees calls made through the instance you decorated.
 * PSR-18 has no middleware concept and no async, so this is a strictly
 * smaller tool than the Guzzle middleware — it exists so that a project
 * standardised on PSR-18 is not excluded.
 */
final readonly class WiretapClient implements ClientInterface
{
    /** @var \Closure(): Recorder */
    private \Closure $resolveRecorder;

    /**
     * @param Recorder|\Closure(): Recorder $recorder See WiretapMiddleware
     */
    public function __construct(
        private ClientInterface $inner,
        Recorder|\Closure $recorder,
        private BodyCapture $bodyCapture = new BodyCapture(),
    ) {
        $this->resolveRecorder = $recorder instanceof Recorder
            ? static fn (): Recorder => $recorder
            : $recorder;
    }

    private function recorder(): Recorder
    {
        return ($this->resolveRecorder)();
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $url = (string) $request->getUri();

        // The whole setup phase is guarded, and the inner call is not.
        //
        // Resolving the recorder, asking the blocklist, generating an id and
        // reading the request body all used to run unguarded, so a resolver
        // that threw took the application's request down with it — reproduced
        // with zero calls to the inner client. Instrumentation that can stop a
        // request is worse than no instrumentation. On any failure here the
        // call is delegated uninstrumented instead.
        //
        // The inner call stays outside the guard for the opposite reason: if
        // it were inside, a failure in our own bookkeeping could be caught and
        // retried, and the application's request would be sent twice.
        $pending = null;
        $claim = false;

        try {
            $recorder = $this->recorder();

            if ($recorder->shouldCapture($url)) {
                $pending = new PendingPsrExchange(
                    // Resolved once, at admission, and kept.
                    //
                    // Resolving again at completion meant a request admitted
                    // under one recorder was written through another's sink
                    // and redaction policy if the holder changed during the
                    // inner call or a Fiber suspension. Reproduced: the
                    // admitting recorder received zero records and the other
                    // received one.
                    recorder: $recorder,
                    id: Ulid::generate(),
                    // Snapshotted for the same reason.
                    correlationId: Correlation::id(),
                    sequence: Correlation::nextSequence(),
                    startedAt: microtime(true),
                    requestBody: $this->bodyCapture->capture(
                        $request->getBody(),
                        $request->getHeaderLine('Content-Type') ?: null,
                    ),
                );

                $claim = TransferClaim::isHonoured() && $this->inner::class === GuzzleClient::class;
            }
        } catch (\Throwable) {
            $pending = null;
            $claim = false;
        }

        if ($pending === null) {
            return $this->inner->sendRequest($request);
        }

        try {
            $response = $claim && $this->inner instanceof GuzzleClient
                ? $this->inner->send($request, self::claimedSendRequestOptions())
                : $this->inner->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            $this->record($pending, $request, $url, response: null, error: TransferError::fromThrowable($e));

            throw $e;
        }

        $this->record($pending, $request, $url, response: $response, error: null);

        return $response;
    }

    /**
     * What Guzzle's own Client::sendRequest() passes to sendAsync(), plus the
     * claim that tells ssx/wiretap-auto's curl hooks this request is
     * recorded here.
     *
     * PSR-18 has no request options, so behind this decorator a Guzzle
     * client could not carry the claim, and with wiretap-auto running every
     * call was recorded twice. Guzzle's sendRequest() is
     * `sendAsync($request, [synchronous, allow_redirects => false,
     * http_errors => false])->wait()`, and send() is
     * `sendAsync($request, $options + synchronous)->wait()`, in every 7.x
     * release this package supports. So send() with these options is the same
     * call — same redirect and error handling, same exceptions — with one
     * extra request option. Psr18ClaimTest compares the two paths against
     * the installed Guzzle, so a release that changed sendRequest() fails
     * there rather than silently diverging.
     *
     * Only for exactly GuzzleHttp\Client, not a subclass: a subclass may
     * override sendRequest(), and then send() is not what the application
     * would have run. Guzzle marks the class @final, so the exact check costs
     * nothing in practice.
     *
     * @return array<string, mixed>
     */
    private static function claimedSendRequestOptions(): array
    {
        return [
            RequestOptions::SYNCHRONOUS => true,
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HTTP_ERRORS => false,
            TransferClaim::KEY => true,
        ];
    }

    private function record(
        PendingPsrExchange $pending,
        RequestInterface $request,
        string $url,
        ?ResponseInterface $response,
        ?TransferError $error,
    ): void {
        try {
            if ($response !== null && $this->endedOnBlockedUri($pending->recorder, $response)) {
                return;
            }

            $pending->recorder->record(new Exchange(
                id: $pending->id,
                correlationId: $pending->correlationId,
                transport: Exchange::TRANSPORT_PSR18,
                method: $request->getMethod(),
                uri: $url,
                requestHeaders: Headers::fromMap($request->getHeaders()),
                requestBody: $pending->requestBody,
                status: $response?->getStatusCode(),
                reason: $response?->getReasonPhrase() ?: null,
                responseHeaders: $response !== null ? Headers::fromMap($response->getHeaders()) : Headers::empty(),
                responseBody: $response !== null
                    ? $this->captureResponseBody($response)
                    : CapturedBody::none(),
                timings: Timings::fromElapsedSeconds(microtime(true) - $pending->startedAt),
                error: $error,
                startedAt: $pending->startedAt,
                sequence: $pending->sequence,
                pid: getmypid() ?: null,
            ));
        } catch (\Throwable) {
            // Never change application behaviour.
        }
    }

    /**
     * Whether the inner client followed a redirect onto a blocked URI.
     *
     * Only the request URI was gated. A client that follows redirects itself —
     * Symfony's Psr18Client does by default — could land on a blocked host,
     * and that host's status, headers and body were stored under the allowed
     * original URI, which core's own re-check then accepted.
     *
     * PSR-18 has no standard way to say where a response came from, so this
     * checks what the common clients expose without reading the body:
     * Guzzle's redirect history header, and the effective URL Symfony keeps
     * on the response behind its body stream. A hop onto a blocked URI means
     * no record at all. A client exposing neither cannot be checked, and only
     * its request URI is gated.
     */
    private function endedOnBlockedUri(Recorder $recorder, ResponseInterface $response): bool
    {
        foreach ($response->getHeader('X-Guzzle-Redirect-History') as $hop) {
            if (!$recorder->shouldCapture($hop)) {
                return true;
            }
        }

        $wrapper = $response->getBody()->getMetadata('wrapper_data');

        if (is_object($wrapper) && method_exists($wrapper, 'getResponse')) {
            $inner = $wrapper->getResponse();

            if (is_object($inner) && method_exists($inner, 'getInfo')) {
                $url = $inner->getInfo('url');

                if (is_string($url) && $url !== '' && !$recorder->shouldCapture($url)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Read the response body only if it is already sitting in memory.
     *
     * The Guzzle middleware knows whether the caller asked for a live stream;
     * a PSR-18 client gives no such signal, and sendRequest() returns as soon
     * as the headers arrive. Symfony's Psr18Client hands back a body that is
     * still being received, so reading up to the capture limit here made the
     * application wait for bytes it had not asked for yet: an SSE call that
     * returns in 0.01s took 3s, and an endless stream never returned.
     *
     * A body held in php://temp, php://memory or a local file has already been
     * received in full, and reading it cannot wait on the network. Anything
     * else is recorded as streaming, the same answer the middleware gives for
     * `stream => true`. On this path it means "not shown to have been
     * received": a fully buffered body from an unfamiliar PSR-7
     * implementation is recorded that way too, which loses a body rather
     * than stall a request.
     *
     * The stream's own class is checked as well as its metadata. A decorator
     * forwards getMetadata() to whatever it wraps: Guzzle's CachingStream
     * reports its php://temp cache while every read past the cached prefix
     * still pulls from the network. Only the plain resource-backed streams of
     * the common PSR-7 implementations are trusted, compared by exact class so
     * that a subclass adding its own read() is not.
     */
    private function captureResponseBody(ResponseInterface $response): CapturedBody
    {
        $body = $response->getBody();
        $contentType = $response->getHeaderLine('Content-Type') ?: null;

        if (!self::isAlreadyReceived($body)) {
            $size = $body->getSize();

            // Known to be empty: nothing to wait for, and nothing to omit.
            if ($size === 0) {
                return CapturedBody::none();
            }

            return CapturedBody::omitted(
                CapturedBody::OMITTED_STREAMING,
                $size !== null && $size >= 0 ? $size : null,
                $contentType,
            );
        }

        return $this->bodyCapture->capture($body, $contentType);
    }

    private const PLAIN_STREAM_CLASSES = [
        'GuzzleHttp\\Psr7\\Stream',
        'Nyholm\\Psr7\\Stream',
        'Laminas\\Diactoros\\Stream',
    ];

    private static function isAlreadyReceived(StreamInterface $body): bool
    {
        if (!in_array($body::class, self::PLAIN_STREAM_CLASSES, true)) {
            return false;
        }

        return in_array($body->getMetadata('stream_type'), ['TEMP', 'MEMORY'], true)
            || $body->getMetadata('wrapper_type') === 'plainfile';
    }
}
