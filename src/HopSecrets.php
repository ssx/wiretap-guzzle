<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\KnownSecrets;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Timings;
use Ssx\Wiretap\TransferError;

/**
 * Redaction for what core cannot see: the hops a record does not describe.
 *
 * A record describes one request, but a redirect chain or a lower middleware
 * sends several. Core learns secrets only from the record itself, so two
 * things escaped it:
 *
 * - A redirect target's query string. `redirected_to` is a list, and core
 *   redacts only string context values, so the hop URI was stored as sent.
 *   Its credential was never learned either, so a response echoing it back
 *   was stored in plaintext.
 * - A credential that a later hop dropped. Guzzle strips Authorization on a
 *   cross-host redirect, and the record carries the last hop's headers, so
 *   the token was gone before the redactor ran and its echo survived.
 *
 * This runs the redactor's own public rules over every hop first, learning
 * what each one carried, and sweeps the record with that before core's usual
 * pass. The hop URIs are emitted already redacted rather than relying on core
 * to walk the context list.
 *
 * It only runs when some hop differs from the recorded request. Redacting
 * twice is not free: a body that the first pass truncates can no longer be
 * parsed by the second, so with body-path rules configured core drops it
 * rather than store it. That is fail-closed, but it should cost only the
 * exchanges that need this.
 *
 * @internal
 */
final class HopSecrets
{
    /**
     * @param list<string>                         $redirects Hop URIs after the recorded one
     * @param list<array{0: string, 1: Headers}>   $requests  Every request observed: URI and headers
     */
    public static function apply(Redactor $redactor, Exchange $exchange, array $redirects, array $requests): Exchange
    {
        $extra = array_values(array_filter(
            $requests,
            static fn (array $r): bool => $r[0] !== $exchange->uri || $r[1]->pairs() !== $exchange->requestHeaders->pairs(),
        ));

        if ($redirects === [] && $extra === []) {
            return $exchange;
        }

        // Disabled redaction means core stores the exchange untouched, and
        // so must this. redact() is the only public signal of that: it
        // returns the same instance when disabled and a copy otherwise.
        $probe = self::probe();

        if ($redactor->redact($probe) === $probe) {
            return self::withRedirects($exchange, $redirects);
        }

        $known = new KnownSecrets();

        // A hop's own host and path describe it; they are never the secret.
        foreach ([$exchange->uri, ...$redirects, ...array_column($requests, 0)] as $uri) {
            $parts = parse_url($uri);

            if (is_array($parts)) {
                foreach (['host', 'path', 'scheme'] as $part) {
                    if (isset($parts[$part])) {
                        $known->protect((string) $parts[$part]);
                    }
                }
            }
        }

        foreach ($redirects as $uri) {
            $redactor->redactUrl($uri, $known);
        }

        foreach ($extra as [$uri, $headers]) {
            $redactor->redactUrl($uri, $known);

            foreach ($headers as [$name, $value]) {
                // Credential headers by name, as core's own learning pass
                // does. The configured allowlist is deliberately not used:
                // in allowlist mode it marks Host and User-Agent as
                // sensitive, which is right for removing a header and wrong
                // for deciding what is a secret everywhere else.
                if (in_array(strtolower($name), RedactionConfig::DEFAULT_HEADERS, true)) {
                    $known->remember($value);
                    $known->rememberCredentialValue($value);
                    $known->rememberCookieValues($value);
                }
            }
        }

        $replacement = (new RedactionConfig())->replacement;

        // Each sweep gets its own copy, so that sweeping never teaches the
        // set anything: redactHeaders() remembers what it removes.
        $hops = array_map(
            static fn (string $uri): string => $known->scrub(
                $redactor->applyPatterns($redactor->redactUrl($uri, clone $known)),
                $replacement,
            ),
            $redirects,
        );

        if (!$known->isEmpty()) {
            $exchange = $exchange
                ->withRequestHeaders($redactor->redactHeaders($exchange->requestHeaders, clone $known))
                ->withResponseHeaders($redactor->redactHeaders($exchange->responseHeaders, clone $known))
                ->withRequestBody($redactor->redactBody($exchange->requestBody, clone $known))
                ->withResponseBody($redactor->redactBody($exchange->responseBody, clone $known))
                ->withReason($exchange->reason === null ? null : $known->scrub($exchange->reason, $replacement))
                ->withError($exchange->error === null ? null : new TransferError(
                    $exchange->error->errno,
                    $known->scrub($exchange->error->message, $replacement),
                    $exchange->error->class,
                ));
        }

        return self::withRedirects($exchange, $hops);
    }

    /**
     * @param list<string> $redirects
     */
    private static function withRedirects(Exchange $exchange, array $redirects): Exchange
    {
        if ($redirects === []) {
            return $exchange;
        }

        // A list, as redirected_to has always been. Core's docblock admits
        // only scalar context values, but a list round-trips through every
        // sink, and these entries are already redacted here.
        // @phpstan-ignore-next-line argument.type
        return $exchange->withContext(['redirected_to' => $redirects]);
    }

    private static function probe(): Exchange
    {
        return new Exchange(
            id: '',
            correlationId: '',
            transport: Exchange::TRANSPORT_GUZZLE,
            method: 'GET',
            uri: '',
            requestHeaders: Headers::empty(),
            requestBody: CapturedBody::none(),
            status: null,
            reason: null,
            responseHeaders: Headers::empty(),
            responseBody: CapturedBody::none(),
            timings: new Timings(),
            error: null,
            startedAt: 0.0,
        );
    }
}
