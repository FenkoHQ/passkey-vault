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
 * parent domains down to the registrable domain. An address or a single
 * label such as localhost only matches itself, and a public suffix (com,
 * co.uk) is never an RP ID: a passkey scoped to it would be offered to
 * every site under that suffix.
 *
 * The registrable domain comes from baseDomain(), which knows the common
 * two-level public suffixes but not the full Public Suffix List. A suffix
 * it does not know (github.io, say) is treated as registrable, which can
 * only let a page claim an RP ID the browser would refuse; it never lets a
 * page claim an RP ID outside its own host's parents.
 */
export function isRpIdValidForHost(rpId: string, host: string): boolean {
  const id = rpId.toLowerCase();
  const page = host.toLowerCase();
  if (id === page) {
    return id.length > 0;
  }
  if (!isDomain(page) || !isDomain(id) || !page.endsWith('.' + id)) {
    return false;
  }
  const registrable = baseDomain(page);
  return registrable !== null && (id === registrable || id.endsWith('.' + registrable));
}
