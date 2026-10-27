/**
 * Where the calling document sits among its ancestors.
 *
 * WebAuthn records this in clientDataJSON (crossOrigin, topOrigin) so a
 * relying party can tell a ceremony inside a third-party iframe from one on
 * its own page. A document is "same-origin with its ancestors" only when
 * every frame above it has its origin; one foreign frame anywhere in the
 * chain makes the call cross-origin.
 */

export interface FrameContext {
  sameOriginWithAncestors: boolean;
  /** Origin of the top-level document, or null when it cannot be read. */
  topOrigin: string | null;
}

export function describeFrame(win: Window = window): FrameContext {
  const origin = win.location.origin;
  if (win.top === win) {
    return { sameOriginWithAncestors: true, topOrigin: origin };
  }

  // Chromium and WebKit list every ancestor's origin, nearest first.
  const ancestors = (win.location as Location & { ancestorOrigins?: DOMStringList })
    .ancestorOrigins;
  if (ancestors && ancestors.length > 0) {
    const origins: string[] = [];
    for (let i = 0; i < ancestors.length; i++) origins.push(ancestors[i]);
    return {
      sameOriginWithAncestors: origins.every((ancestor) => ancestor === origin),
      topOrigin: origins[origins.length - 1],
    };
  }

  // Firefox has no ancestorOrigins. Reading a cross-origin ancestor's origin
  // throws, which answers the question just as well.
  try {
    let sameOriginWithAncestors = true;
    for (let frame: Window = win; frame !== frame.top; ) {
      frame = frame.parent;
      if (frame.location.origin !== origin) sameOriginWithAncestors = false;
    }
    return { sameOriginWithAncestors, topOrigin: win.top!.location.origin };
  } catch {
    return { sameOriginWithAncestors: false, topOrigin: null };
  }
}
