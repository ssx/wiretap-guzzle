<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Guzzle;

use GuzzleHttp\HandlerStack;
use Ssx\Wiretap\Recorder;

/**
 * The one-liner entry points.
 *
 * Whatever else wiretap gets right, if wiring it into an existing client
 * takes more than a line nobody will bother.
 */
final class Stack
{
    public const MIDDLEWARE_NAME = 'wiretap';

    /**
     * A ready-to-use handler stack.
     *
     *     $client = new Client(['handler' => Stack::wrap($recorder)]);
     */
    public static function wrap(Recorder $recorder, ?HandlerStack $stack = null, ?BodyCapture $bodyCapture = null): HandlerStack
    {
        return self::attach($stack ?? HandlerStack::create(), $recorder, $bodyCapture);
    }

    /**
     * Attach to a stack that already exists, leaving its middleware alone.
     *
     *     Stack::attach($existingStack, $recorder);
     *
     * Uses unshift, not push: the recorder must sit above any middleware that
     * signs the request or sets Content-Length, and it must never wrap the
     * request body. See WiretapMiddleware.
     */
    public static function attach(HandlerStack $stack, Recorder $recorder, ?BodyCapture $bodyCapture = null): HandlerStack
    {
        // Attaching twice would record every exchange twice.
        if (self::isAttached($stack)) {
            return $stack;
        }

        $stack->unshift(WiretapMiddleware::create($recorder, $bodyCapture), self::MIDDLEWARE_NAME);

        return $stack;
    }

    public static function detach(HandlerStack $stack): HandlerStack
    {
        if (self::isAttached($stack)) {
            $stack->remove(self::MIDDLEWARE_NAME);
        }

        return $stack;
    }

    public static function isAttached(HandlerStack $stack): bool
    {
        // HandlerStack exposes no way to ask whether a named middleware is
        // present, and remove() on an absent name is a silent no-op, so its
        // string form is the only thing available to inspect. Match the
        // quoted name exactly so a middleware called "wiretap-something"
        // cannot be mistaken for ours.
        return str_contains((string) $stack, sprintf("Name: '%s'", self::MIDDLEWARE_NAME));
    }
}
