/**
 * When a click in the vault's dialog may count as the user's consent.
 *
 * The dialog page cannot be read by the page that frames it, but the page
 * still controls the frame's surroundings: it can fade the frame, cover it
 * with a decoy, move most of it off screen, or shrink it with CSS zoom,
 * and then wait for the user to click where the button happens to be.
 * The user's click is trusted all the same. So a click on Continue or
 * Create counts only when the dialog has been fully on screen, unobscured
 * and at its real size, without a break, for CONSENT_DWELL_MS before it:
 *
 * - IntersectionObserver v2 (trackVisibility) says whether the browser
 *   painted the frame with nothing over it and no opacity, filter or
 *   transform on it or any ancestor, and the ratio says it is all in view.
 * - It does not see CSS zoom, which shrinks the frame without a
 *   transform. Zoom does change the frame's devicePixelRatio, so that must
 *   match the top-level page's, which the background reads from the top
 *   frame's content script.
 * - Nor does it see a frame made too small for the dialog: the dialog
 *   still fills it, its content cropped. So the title, the message, the
 *   selected passkey and the buttons must all be in view (`fits`).
 *
 * Any lapse restarts the wait, and a dialog that has only just appeared
 * has not waited yet, so a click aimed at the page as the dialog pops up
 * under the pointer does not count either.
 *
 * A dialog in a window of its own (where the browser has no
 * IntersectionObserver v2) cannot be covered by a page, so there it only
 * has to have been showing for the same time.
 */

import { CONSENT_DWELL_MS } from '../utils/vault-dialog';

export interface ConsentGate {
  isReady(): boolean;
  /** Called whenever isReady() may have changed. */
  onChange(listener: () => void): void;
  /** The dialog's layout changed (a new selection): check that it still fits. */
  refresh(): void;
  dispose(): void;
}

export interface GateClock {
  now(): number;
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const realClock: GateClock = {
  now: () => performance.now(),
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** How far the frame's pixel ratio may stray from the top page's (rounding). */
const SCALE_TOLERANCE = 0.02;
/** Visible means this much of the dialog is in the viewport. */
const MIN_RATIO = 0.99;

/**
 * Ready once every condition has held, without a break, for the dwell
 * time. Each condition starts out false.
 */
export class DwellGate {
  private conditions = new Map<string, boolean>();
  private since: number | null = null;
  private timer: unknown = null;
  private listeners: Array<() => void> = [];
  private disposed = false;

  constructor(
    names: string[],
    private readonly dwellMs = CONSENT_DWELL_MS,
    private readonly clock: GateClock = realClock
  ) {
    for (const name of names) this.conditions.set(name, false);
  }

  set(name: string, value: boolean): void {
    if (this.disposed || this.conditions.get(name) === value) return;
    this.conditions.set(name, value);
    const all = Array.from(this.conditions.values()).every(Boolean);
    if (all && this.since === null) {
      this.since = this.clock.now();
      this.timer = this.clock.setTimeout(() => this.emit(), this.dwellMs);
    } else if (!all && this.since !== null) {
      this.since = null;
      this.clock.clearTimeout(this.timer);
      this.timer = null;
      this.emit();
    }
  }

  isReady(): boolean {
    return !this.disposed && this.since !== null && this.clock.now() - this.since >= this.dwellMs;
  }

  onChange(listener: () => void): void {
    this.listeners.push(listener);
  }

  dispose(): void {
    this.disposed = true;
    this.clock.clearTimeout(this.timer);
    this.listeners = [];
  }

  private emit(): void {
    for (const listener of this.listeners) listener();
  }
}

interface VisibilityEntry {
  isIntersecting: boolean;
  intersectionRatio: number;
  isVisible?: boolean;
}

export interface FrameGateOptions {
  win: Window;
  /** The top-level page's devicePixelRatio, or undefined if unknown. */
  reference(): Promise<number | undefined>;
  /** Whether everything the user decides on is in view. */
  fits(): boolean;
  clock?: GateClock;
  dwellMs?: number;
}

/** Whether this browser reports frame visibility (IntersectionObserver v2). */
export function hasVisibilityTracking(win: Window): boolean {
  const entry = (win as unknown as { IntersectionObserverEntry?: { prototype: object } })
    .IntersectionObserverEntry;
  return !!entry && 'isVisible' in entry.prototype;
}

/** The gate for a dialog framed in a page. */
export function createFrameGate(target: Element, options: FrameGateOptions): ConsentGate {
  const { win } = options;
  const gate = new DwellGate(['visible', 'scale', 'fits'], options.dwellMs, options.clock);
  const checkFit = () => gate.set('fits', options.fits());
  win.addEventListener?.('resize', checkFit);
  let observer: IntersectionObserver | null = null;
  let media: MediaQueryList | null = null;
  let disposed = false;

  if (hasVisibilityTracking(win)) {
    const init = { trackVisibility: true, delay: 100, threshold: [0, 0.5, MIN_RATIO, 1] };
    const Observer = (win as unknown as { IntersectionObserver: typeof IntersectionObserver })
      .IntersectionObserver;
    observer = new Observer((entries) => {
      const entry = entries[entries.length - 1] as unknown as VisibilityEntry;
      checkFit();
      gate.set(
        'visible',
        entry.isIntersecting && entry.isVisible === true && entry.intersectionRatio >= MIN_RATIO
      );
    }, init as IntersectionObserverInit);
    observer.observe(target);
  }
  // Without IntersectionObserver v2 the frame is never "visible": the
  // dialog then offers to move to a window.

  const checkScale = async () => {
    const reference = await options.reference().catch(() => undefined);
    if (disposed) return;
    const ratio = win.devicePixelRatio;
    gate.set(
      'scale',
      typeof reference === 'number' &&
        reference > 0 &&
        Math.abs(ratio / reference - 1) <= SCALE_TOLERANCE
    );
  };
  // Zoom on an ancestor, or the user zooming the browser, changes the
  // ratio: check again, against a fresh reading of the top page.
  const watchScale = () => {
    media?.removeEventListener('change', onScaleChange);
    media = win.matchMedia?.(`(resolution: ${win.devicePixelRatio}dppx)`) ?? null;
    media?.addEventListener('change', onScaleChange);
  };
  const onScaleChange = () => {
    gate.set('scale', false);
    watchScale();
    void checkScale();
  };
  watchScale();
  void checkScale();
  checkFit();

  return {
    isReady: () => gate.isReady(),
    onChange: (listener) => gate.onChange(listener),
    refresh: checkFit,
    dispose() {
      disposed = true;
      win.removeEventListener?.('resize', checkFit);
      observer?.disconnect();
      media?.removeEventListener('change', onScaleChange);
      gate.dispose();
    },
  };
}

/**
 * The gate for a dialog in a window of its own: it only has to be showing,
 * with what the user decides on in view (the user can resize the window).
 */
export function createWindowGate(
  doc: Document,
  options: { fits?: () => boolean; clock?: GateClock; dwellMs?: number } = {}
): ConsentGate {
  const gate = new DwellGate(['shown', 'fits'], options.dwellMs, options.clock);
  const win = doc.defaultView;
  const update = () => gate.set('shown', doc.visibilityState === 'visible');
  const checkFit = () => gate.set('fits', options.fits?.() ?? true);
  doc.addEventListener('visibilitychange', update);
  win?.addEventListener('resize', checkFit);
  update();
  checkFit();
  return {
    isReady: () => gate.isReady(),
    onChange: (listener) => gate.onChange(listener),
    refresh: checkFit,
    dispose() {
      doc.removeEventListener('visibilitychange', update);
      win?.removeEventListener('resize', checkFit);
      gate.dispose();
    },
  };
}
