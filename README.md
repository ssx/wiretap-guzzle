# wiretap-guzzle

Guzzle capture for [wiretap](https://github.com/ssx/wiretap). Records outbound
requests and responses from Guzzle clients you construct yourself.

```
composer require ssx/wiretap-guzzle
```

> **This captures only clients you wire up.** It cannot see a
> `new GuzzleHttp\Client()` created inside your vendor directory, and it cannot
> see raw `curl_exec()` at all. For that, use
> [`ssx/wiretap-auto`](https://github.com/ssx/wiretap-auto), which hooks the
> functions themselves and needs no application changes.

## Alongside wiretap-auto

Both can run in one process, and each call is still recorded once. The
middleware claims the requests it records (a request option,
`Ssx\Wiretap\TransferClaim::KEY`), Guzzle carries that to every redirect and
retry hop, and wiretap-auto (v0.0.8 or later) records nothing for a claimed
transfer. You get the middleware's record, with bodies, and wiretap-auto keeps
covering the clients this package cannot see. The option is only added when
wiretap-auto's hooks are running; otherwise request options are exactly what
they would be without it.

One exception: `WiretapClient`, the PSR-18 decorator, has no request options
to carry the claim, so a Guzzle client behind it is recorded by both.

## Usage

One line on a new client:

```php
use GuzzleHttp\Client;
use Ssx\Wiretap\Guzzle\Stack;

$client = new Client(['handler' => Stack::wrap($recorder)]);
```

One line on a stack you already have:

```php
Stack::attach($existingStack, $recorder);
```

Attaching twice is a no-op, so it is safe to call from a service provider that
may run more than once.

For a non-Guzzle PSR-18 client:

```php
use Ssx\Wiretap\Guzzle\WiretapClient;

$client = new WiretapClient($psr18Client, $recorder);
```

## What it does not touch

The middleware is attached with `unshift()`, not `push()`, and it never
decorates the request body. Both matter:

- Anything that changes `getSize()` or `isSeekable()` on a request body,
  upstream of a signing middleware, breaks AWS SigV4, OAuth1 body hashes and
  `prepare_body`'s Content-Length. If `getSize()` becomes `null`, Guzzle
  switches to `Transfer-Encoding: chunked` and some APIs reject the request
  outright.
- Reading a body for capture restores the *exact* prior stream position rather
  than rewinding, because a signing middleware or a partially-consumed upload
  may have left the pointer mid-stream.

A non-seekable body is never read — doing so would steal bytes the application
has not consumed yet. It is recorded as `omitted: not-seekable` instead. The
same applies when you pass `'stream' => true`.

An existing `on_stats` callback is chained, not replaced.

## Completion signals

Two are wired, because neither is sufficient alone:

| Signal | Carries | Fires when |
| --- | --- | --- |
| `on_stats` | timings, effective URI after redirects, the response | inside `CurlFactory::finish()` — including for a promise nobody waits on |
| promise handlers | the exception | when the promise settles |

Whichever arrives first writes the record; the other is a no-op. A rejection
handler always returns `Create::rejectionFor($reason)` — returning anything
else would turn a failure into a success for the calling code.

## Licence

MIT.
