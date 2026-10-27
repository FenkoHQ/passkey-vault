/**
 * Clickjacking: when a click in the vault's dialog may count as consent.
 *
 * The page frames the dialog and controls everything around the frame. A
 * click counts only when the browser has reported the frame fully visible
 * (IntersectionObserver v2), at the top page's scale (no CSS zoom), for
 * 500 ms without a break before it.
 */

import {
  DwellGate,
  createFrameGate,
  createWindowGate,
  type GateClock,
} from '../src/ui/consent-gate';

/** A clock the test moves by hand. */
function manualClock() {
  let now = 0;
  let timers: Array<{ at: number; run: () => void; id: number }> = [];
  let nextId = 1;
  const clock: GateClock = {
    now: () => now,
    setTimeout: (run, ms) => {
      const id = nextId++;
      timers.push({ at: now + ms, run, id });
      return id;
    },
    clearTimeout: (id) => {
      timers = timers.filter((timer) => timer.id !== id);
    },
  };
  const advance = (ms: number) => {
    now += ms;
    const due = timers.filter((timer) => timer.at <= now);
    timers = timers.filter((timer) => timer.at > now);
    due.forEach((timer) => timer.run());
  };
  return { clock, advance };
}

interface Report {
  isIntersecting?: boolean;
  intersectionRatio?: number;
  isVisible?: boolean;
}

/** A frame's window, with an IntersectionObserver the test reports through. */
function frameWindow(options: { v2?: boolean; dpr?: number } = {}) {
  let callback: ((entries: unknown[]) => void) | null = null;
  let init: Record<string, unknown> | undefined;
  const mediaListeners: Array<() => void> = [];
  const win = {
    devicePixelRatio: options.dpr ?? 1,
    IntersectionObserverEntry:
      options.v2 === false
        ? class {}
        : class {
            get isVisible() {
              return false;
            }
          },
    IntersectionObserver: class {
      constructor(cb: (entries: unknown[]) => void, options: Record<string, unknown>) {
        callback = cb;
        init = options;
      }
      observe() {}
      disconnect() {}
    },
    matchMedia: () => ({
      addEventListener: (_type: string, listener: () => void) => mediaListeners.push(listener),
      removeEventListener: () => undefined,
    }),
  };
  const report = (entry: Report) =>
    callback?.([{ isIntersecting: true, intersectionRatio: 1, isVisible: true, ...entry }]);
  const rescale = (dpr: number) => {
    win.devicePixelRatio = dpr;
    mediaListeners.splice(0).forEach((listener) => listener());
  };
  return { win: win as unknown as Window, report, rescale, init: () => init };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

async function frameGate(
  options: { v2?: boolean; dpr?: number; reference?: number | undefined } = {}
) {
  const { clock, advance } = manualClock();
  const frame = frameWindow(options);
  const reference = jest.fn(async () => ('reference' in options ? options.reference : 1));
  const layout = { fits: true };
  const gate = createFrameGate(document.body, {
    win: frame.win,
    reference,
    fits: () => layout.fits,
    clock,
  });
  await flush();
  return { gate, advance, reference, layout, ...frame };
}

describe('a dialog framed in a page', () => {
  it('asks the browser to track the frame’s visibility, as often as it allows', async () => {
    const { init } = await frameGate();

    expect(init()).toMatchObject({ trackVisibility: true, delay: 100 });
  });

  it('takes no click before the frame has been seen for 500 ms', async () => {
    const { gate, report, advance } = await frameGate();
    expect(gate.isReady()).toBe(false);

    report({});
    advance(499);
    expect(gate.isReady()).toBe(false);

    advance(1);
    expect(gate.isReady()).toBe(true);
  });

  it.each<[string, Report]>([
    ['faded or filtered (opacity 0, a decoy beneath)', { isVisible: false }],
    ['covered by something the page drew over it', { isVisible: false }],
    ['mostly off screen', { intersectionRatio: 0.4 }],
    ['scrolled or clipped away', { isIntersecting: false, intersectionRatio: 0 }],
  ])('takes no click while the frame is %s', async (_label, entry) => {
    const { gate, report, advance } = await frameGate();

    report(entry);
    advance(5000);

    expect(gate.isReady()).toBe(false);
  });

  it('starts the wait again after any lapse', async () => {
    const { gate, report, advance } = await frameGate();
    const changes = jest.fn();
    gate.onChange(changes);
    report({});
    advance(500);
    expect(gate.isReady()).toBe(true);

    // The page fades the frame for a moment, then shows it again just
    // before the click it expects.
    report({ isVisible: false });
    expect(gate.isReady()).toBe(false);
    report({});
    advance(300);
    expect(gate.isReady()).toBe(false);
    advance(200);
    expect(gate.isReady()).toBe(true);
    expect(changes).toHaveBeenCalledTimes(3);
  });

  it('takes no click while CSS zoom shrinks the frame, which the browser still calls visible', async () => {
    const { gate, report, advance } = await frameGate({ dpr: 0.2, reference: 1 });

    report({});
    advance(5000);

    expect(gate.isReady()).toBe(false);
  });

  it('checks again against the top page when the scale changes', async () => {
    const { gate, report, advance, rescale, reference } = await frameGate();
    report({});
    advance(500);
    expect(gate.isReady()).toBe(true);

    rescale(0.5);
    await flush();

    expect(reference).toHaveBeenCalledTimes(2);
    expect(gate.isReady()).toBe(false);
    advance(5000);
    expect(gate.isReady()).toBe(false);
  });

  it('follows the user zooming the whole browser', async () => {
    const { gate, report, advance, rescale, reference } = await frameGate();
    report({});
    reference.mockResolvedValue(1.25);
    rescale(1.25);
    await flush();
    advance(500);

    expect(gate.isReady()).toBe(true);
  });

  it('takes no click while the frame is too small to show the whole dialog', async () => {
    const { gate, report, advance, layout } = await frameGate();
    layout.fits = false;

    report({});
    advance(5000);
    expect(gate.isReady()).toBe(false);

    // The user scrolls the selection into view, or the page gives the
    // frame room again: the wait starts from there.
    layout.fits = true;
    gate.refresh();
    advance(499);
    expect(gate.isReady()).toBe(false);
    advance(1);
    expect(gate.isReady()).toBe(true);
  });

  it('takes no click when the top page’s scale is unknown', async () => {
    const { gate, report, advance } = await frameGate({ reference: undefined });

    report({});
    advance(5000);

    expect(gate.isReady()).toBe(false);
  });

  it('takes no click where the browser cannot report visibility', async () => {
    const { gate, report, advance } = await frameGate({ v2: false });

    report({ isVisible: undefined });
    advance(5000);

    expect(gate.isReady()).toBe(false);
  });

  it('takes nothing once disposed', async () => {
    const { gate, report, advance } = await frameGate();
    report({});
    advance(500);

    gate.dispose();

    expect(gate.isReady()).toBe(false);
  });
});

describe('a dialog in a window of its own', () => {
  it('takes a click once it has been showing for 500 ms', () => {
    const { clock, advance } = manualClock();
    const gate = createWindowGate(document, { clock });

    advance(499);
    expect(gate.isReady()).toBe(false);
    advance(1);
    expect(gate.isReady()).toBe(true);
  });
});

describe('a resized window', () => {
  it('takes no click while the window is too small for the dialog', () => {
    const { clock, advance } = manualClock();
    const gate = createWindowGate(document, { clock, fits: () => false });

    advance(5000);

    expect(gate.isReady()).toBe(false);
  });
});

describe('the dwell', () => {
  it('needs every condition at once', () => {
    const { clock, advance } = manualClock();
    const gate = new DwellGate(['a', 'b'], 500, clock);

    gate.set('a', true);
    advance(1000);
    expect(gate.isReady()).toBe(false);

    gate.set('b', true);
    advance(500);
    expect(gate.isReady()).toBe(true);
  });
});
