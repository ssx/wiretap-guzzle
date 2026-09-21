<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Support\Ulid;
use Ssx\Wiretap\Timings;
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
            }
        } catch (\Throwable) {
            $pending = null;
        }

        if ($pending === null) {
            return $this->inner->sendRequest($request);
        }

        try {
            $response = $this->inner->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            $this->record($pending, $request, $url, response: null, error: TransferError::fromThrowable($e));

            throw $e;
        }

        $this->record($pending, $request, $url, response: $response, error: null);

        return $response;
    }

    private function record(
        PendingPsrExchange $pending,
        RequestInterface $request,
        string $url,
        ?ResponseInterface $response,
        ?TransferError $error,
    ): void {
        try {
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
                    ? $this->bodyCapture->capture(
                        $response->getBody(),
                        $response->getHeaderLine('Content-Type') ?: null,
                    )
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
}
