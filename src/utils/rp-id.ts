// Which RP IDs a page may claim (WebAuthn Level 3 §5.1.3 step 8 and
// §5.1.4.1 step 8, through HTML's "is a registrable domain suffix of or is
// equal to").
import { baseDomain } from './domain';

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DOMAIN = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})*$`);
// The URL parser reads a host whose last label is numeric as IPv4.
const NUMERIC_LAST_LABEL = /(^|\.)(0x[0-9a-f]*|[0-9]+)$/;

/** A domain host, as opposed to an IPv4/IPv6 address or a malformed name. */
function isDomain(host: string): boolean {
  return DOMAIN.test(host) && !NUMERIC_LAST_LABEL.test(host);
}

/**
 * Whether a page on `host` may use `rpId`: the host itself, or one of its
 * parent domains down to the registrable domain. A single label such as
 * localhost only matches itself, an IP address matches nothing, and a
 * public suffix (com, co.uk) is never an RP ID: a passkey scoped to it
 * would be offered to every site under that suffix.
 *
 * An empty RP ID is not the host either: the page asked for an RP ID, and
 * none is valid.
 *
 * The registrable domain comes from baseDomain(), which knows the common
 * two-level public suffixes but not the full Public Suffix List. A suffix
 * it does not know (github.io, say) is treated as registrable, which can
 * only let a page claim an RP ID the browser would refuse; it never lets a
 * page claim an RP ID outside its own host's parents.
 */
export function isRpIdValidForHost(rpId: string, host: string): boolean {
  // Compared as given, like Chrome: an RP ID that differs from the host only
  // in case is refused, since its SHA-256 (the rpIdHash) is not the one the
  // relying party's server checks for.
  const id = rpId;
  const page = host.toLowerCase();
  // WebAuthn needs a domain: an address such as 127.0.0.1 is never an RP ID,
  // even its own (§5.1.3 step 7). Chrome throws "This is an invalid domain".
  if (!isDomain(page)) {
    return false;
  }
  if (id === page) {
    return true;
  }
  if (!isDomain(id) || !page.endsWith('.' + id)) {
    return false;
  }
  const registrable = baseDomain(page);
  return registrable !== null && (id === registrable || id.endsWith('.' + registrable));
}
