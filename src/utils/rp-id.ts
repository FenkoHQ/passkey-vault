// Which RP IDs a page may claim (WebAuthn Level 3 §5.1.3 step 8 and
// §5.1.4.1 step 8, through HTML's "is a registrable domain suffix of or is
// equal to").
import { isDomainName, registrableDomain } from './domain';

/**
 * Whether a page on `host` may use `rpId`: the host itself, or one of its
 * parent domains down to the registrable domain. A single label such as
 * localhost only matches itself, an IP address matches nothing, and a
 * public suffix (com, co.uk, github.io) is never an RP ID: a passkey scoped
 * to it would be offered to every site under that suffix.
 *
 * An empty RP ID is not the host either: the page asked for an RP ID, and
 * none is valid.
 *
 * Public suffixes come from the full Public Suffix List, private section
 * included, as in Chrome's OriginIsAllowedToClaimRelyingPartyId; a
 * top-level domain the list does not know counts as a public suffix of one
 * label. Like Chrome with kRejectRpIdsInsideCallersPublicSuffix, an RP ID
 * inside the page's own public suffix (railway.app for a page on
 * foo.up.railway.app) is refused even when it is registrable itself.
 */
export function isRpIdValidForHost(rpId: string, host: string): boolean {
  // Compared as given, like Chrome: an RP ID that differs from the host only
  // in case is refused, since its SHA-256 (the rpIdHash) is not the one the
  // relying party's server checks for.
  const id = rpId;
  const page = host.toLowerCase();
  // WebAuthn needs a domain: an address such as 127.0.0.1 is never an RP ID,
  // even its own (§5.1.3 step 7). Chrome throws "This is an invalid domain".
  if (!isDomainName(page)) {
    return false;
  }
  if (id === page) {
    return true;
  }
  if (!isDomainName(id) || !page.endsWith('.' + id)) {
    return false;
  }
  const registrable = registrableDomain(page);
  return registrable !== null && (id === registrable || id.endsWith('.' + registrable));
}
