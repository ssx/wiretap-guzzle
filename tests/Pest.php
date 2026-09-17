<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

/**
 * A client whose transport is mocked but whose middleware stack is real, so
 * the tests exercise the same code path production does.
 *
 * @param list<mixed> $queue
 */
function mockedClient(array $queue, InMemorySink $sink, ?Blocklist $blocklist = null, array $config = []): array
{
    $recorder = new Recorder(
        sink: $sink,
        blocklist: $blocklist ?? new Blocklist(),
    );

    $stack = HandlerStack::create(new MockHandler($queue));
    Stack::attach($stack, $recorder);

    $client = new Client([...$config, 'handler' => $stack, 'http_errors' => false]);

    return [$client, $recorder];
}
