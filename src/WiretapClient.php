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

        if (!$this->recorder()->shouldCapture($url)) {
            return $this->inner->sendRequest($request);
        }

        $startedAt = microtime(true);
        $id = Ulid::generate();
        $sequence = Correlation::nextSequence();

        $requestBody = $this->bodyCapture->capture(
            $request->getBody(),
            $request->getHeaderLine('Content-Type') ?: null,
        );

        try {
            $response = $this->inner->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            $this->record(
                $id, $sequence, $request, $url, $requestBody, $startedAt,
                response: null,
                error: TransferError::fromThrowable($e),
            );

            throw $e;
        }

        $this->record(
            $id, $sequence, $request, $url, $requestBody, $startedAt,
            response: $response,
            error: null,
        );

        return $response;
    }

    private function record(
        string $id,
        int $sequence,
        RequestInterface $request,
        string $url,
        CapturedBody $requestBody,
        float $startedAt,
        ?ResponseInterface $response,
        ?TransferError $error,
    ): void {
        try {
            $this->recorder()->record(new Exchange(
                id: $id,
                correlationId: Correlation::id(),
                transport: Exchange::TRANSPORT_PSR18,
                method: $request->getMethod(),
                uri: $url,
                requestHeaders: Headers::fromMap($request->getHeaders()),
                requestBody: $requestBody,
                status: $response?->getStatusCode(),
                reason: $response?->getReasonPhrase() ?: null,
                responseHeaders: $response !== null ? Headers::fromMap($response->getHeaders()) : Headers::empty(),
                responseBody: $response !== null
                    ? $this->bodyCapture->capture(
                        $response->getBody(),
                        $response->getHeaderLine('Content-Type') ?: null,
                    )
                    : CapturedBody::none(),
                timings: Timings::fromElapsedSeconds(microtime(true) - $startedAt),
                error: $error,
                startedAt: $startedAt,
                sequence: $sequence,
                pid: getmypid() ?: null,
            ));
        } catch (\Throwable) {
            // Never change application behaviour.
        }
    }
}
