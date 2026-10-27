# Testing passkey ceremonies

The vault replaces the browser's WebAuthn client, so a passkey it makes or
uses has to pass the same checks a relying party's server applies to one from
Chrome, Safari or a security key. The test suite checks exactly that, from the
page's `navigator.credentials` call to the server's verification, and then
breaks things on purpose to see what still holds.

```bash
npm test                    # everything below except the browser suite, ~20 s
npm run test:e2e:webauthn   # the built extension in a real Chromium (needs openssl)
npm run test:e2e            # the popup in a real Chromium
```

## How a ceremony is tested

`tests/helpers/harness.ts` loads the real page shim, content script and
background worker into one jsdom page and connects them the way Chrome does:
`window.postMessage` with structured clone between the page and the content
script, and `chrome.runtime` messaging with Chrome's JSON hop and sender
objects to the background. Only the user is scripted (`vault.user` answers the
dialogs). A test calls `navigator.credentials.create()` or `.get()` and gets
what a page would get.

Every result is then verified twice:

| Oracle                         | What it is                                                                                                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tests/helpers/rp-verifier.ts` | WebAuthn Level 3 §7.1 and §7.2, plus what strict servers add: clientDataJSON in the exact §5.8.1.1 bytes, canonical CTAP2 CBOR, no trailing authenticator data, strict DER signatures, the Level 3 accessors and `toJSON()` agreeing with the binary fields. |
| `tests/helpers/oracle.ts`      | [`@simplewebauthn/server`](https://simplewebauthn.dev), a widely deployed server library, fed the credential's `toJSON()` as a page would POST it.                                                                                                           |

`tests/conformance/verifier.test.ts` tests the strict verifier itself: it
accepts the spec's §16 test vectors and rejects 37 single-field corruptions of
real vault credentials, so a green run means what it says.

## What is covered

| Area                                                                                                                                                       | Where                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Registration: attestation object, flags, AAGUID, COSE key, BufferSource forms, Advanced settings                                                           | `tests/conformance/registration.test.ts`                  |
| Sign-in: discoverable and allow-list flows, parent-domain RP IDs, counters, hand-offs to the browser                                                       | `tests/conformance/authentication.test.ts`                |
| Client checks (§5.1.3, §5.1.4.1, WebIDL): types, lengths, required members, `pubKeyCredParams`, RP IDs, exclude lists, abort, timeouts, Permissions Policy | `tests/conformance/client-checks.test.ts`                 |
| Extensions: `prf` and `credProps`, and the ones the vault ignores                                                                                          | `tests/conformance/extensions.test.ts`                    |
| 60 option payloads real sites and server libraries send, each with its source                                                                              | `tests/conformance/real-world.test.ts`, `tests/fixtures/` |
| Encoders, the background's message interface, corrupted options                                                                                            | `tests/fuzz/`                                             |
| The built extension in Chromium, and differential runs against Chrome's own client                                                                         | `tests/e2e/webauthn.e2e.ts`                               |

The real-world corpus (`tests/fixtures/real-world-options.json`) holds the
shapes that broke other passkey managers: Sony's string `alg` values,
Binance listing RS1 first, Google's PRF sign-in and `cable` transport,
Microsoft's and Meta's related-origin RP IDs (answered from their real
`/.well-known/webauthn` files), Sentry's views into one shared buffer, and
the defaults of SimpleWebAuthn, py_webauthn, webauthn-rs, go-webauthn and
others. To add one, append an entry with its `source` URL; the test picks it
up.

## Chaos experiments

Each experiment in `tests/chaos/` states a hypothesis and checks one steady
state: every page request settles, a credential the page receives verifies,
and the vault holds a passkey exactly when the site received it.

| Experiment         | Fault                                                                                                                                                          | Found                                                                                             |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `worker-lifecycle` | The service worker restarts between picker and signature, dies mid-message, is absent, restarts before every message; the vault locks while the picker is open | The browser's prompt opened after the user had picked a vault passkey                             |
| `storage-faults`   | Quota and I/O errors on the passkey write, on the bookkeeping after it, on the counter, on reads                                                               | A saved passkey was reported as failed when only the sync status write failed                     |
| `corrupt-records`  | null, bare-string and half-empty records, damaged keys, a damaged sync snapshot                                                                                | One null record broke sign-in on every site; a damaged peer snapshot failed every merge           |
| `concurrency`      | Parallel sign-ins and registrations, seeded storms of aborts at every protocol step                                                                            | Aborted registrations left passkeys the site never received                                       |
| `hostile-page`     | Forged page messages; a compromised renderer impersonating the content script                                                                                  | The background exported the vault, wiped it, or signed for another site on any web page's request |

## Differential testing against Chrome

`tests/e2e/webauthn.e2e.ts` runs each edge case twice: through the vault, and
through Chrome's own WebAuthn client (a browser without the extension, with a
CDP virtual authenticator). The vault must succeed or fail the same way, with
the same error. Pages are served over HTTPS for made-up `*.test` sites, so
they are real secure contexts with subdomains, cross-site iframes and related
origins. These runs found that the vault was skipped by calls made as a page
loads, and accepted RP IDs that differ in case, empty RP IDs, IP addresses,
undelegated iframes, and `prf` or `credProps` inputs that Chrome refuses.

Where Chrome is more lenient than the spec, the vault follows Chrome, so a
site that works without the vault keeps working with it: an empty `user.id` is
accepted (the spec asks for 1 to 64 bytes).

## Where the vault deliberately differs

| Behaviour                                                                                    | Why                                                                                                    |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| PRF outputs are HMAC-SHA-256 of the raw salt, not of `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt)` | Changing it would change every PRF output a site has derived keys from. A test pins the construction.  |
| A timeout of 0, or under 5 minutes, becomes 5 minutes                                        | The spec recommends 5 to 10 minutes; Chrome fails a timeout of 0 at once.                              |
| `mediation: 'conditional'` registration shows the vault's dialog                             | The vault cannot tell whether the user just signed in with a saved password; Chrome refuses instead.   |
| Extensions other than `prf` and `credProps` are ignored, not validated                       | The vault does not implement them; ignoring an odd value can only help a site that sends one.          |
| A public suffix the built-in list does not know (`github.io`) can be an RP ID                | The vault has no full Public Suffix List; this only admits an RP ID scoped to that suffix's own pages. |
| On Firefox the hook arrives a moment after the page's first script                           | Firefox's manifest still supports versions without MAIN-world content scripts.                         |
| UV is reported by default                                                                    | See issue #5; it can be turned off under Advanced.                                                     |
