/**
 * describeFrame decides crossOrigin/topOrigin for clientDataJSON. Real
 * frames cannot be built in jsdom, so these model the window graph a
 * browser exposes to a content script: same-origin ancestors are readable,
 * a cross-origin ancestor's location.origin throws.
 */

import { describeFrame } from '../../src/content/frame';

type FakeWindow = { top: FakeWindow; parent: FakeWindow; location: any };

function frames(origins: string[], options: { ancestorOrigins?: boolean } = {}): FakeWindow {
  // origins[0] is the top-level document, the last one the caller.
  const windows: FakeWindow[] = [];
  origins.forEach((origin, index) => {
    const win = {} as FakeWindow;
    windows.push(win);
    win.parent = index === 0 ? win : windows[index - 1];
    win.top = windows[0];
    win.location = {};
  });
  const caller = windows[windows.length - 1];
  windows.forEach((win, index) => {
    const origin = origins[index];
    Object.defineProperty(win.location, 'origin', {
      get() {
        if (win !== caller && origin !== origins[origins.length - 1]) {
          throw new DOMException(
            'Blocked a frame from accessing a cross-origin frame.',
            'SecurityError'
          );
        }
        return origin;
      },
    });
  });
  if (options.ancestorOrigins) {
    const list = origins.slice(0, -1).reverse();
    caller.location.ancestorOrigins = Object.assign([...list], { item: (i: number) => list[i] });
  }
  return caller;
}

describe('describeFrame', () => {
  it('reports a top-level document as same-origin with itself', () => {
    expect(describeFrame(frames(['https://a.example']) as unknown as Window)).toEqual({
      sameOriginWithAncestors: true,
      topOrigin: 'https://a.example',
    });
  });

  describe.each([
    ['Chromium (ancestorOrigins)', true],
    ['Firefox (no ancestorOrigins)', false],
  ])('in %s', (_browser, ancestorOrigins) => {
    it('treats a same-origin iframe as same-origin', () => {
      const win = frames(['https://a.example', 'https://a.example'], { ancestorOrigins });

      expect(describeFrame(win as unknown as Window)).toEqual({
        sameOriginWithAncestors: true,
        topOrigin: 'https://a.example',
      });
    });

    it('reports a third-party iframe as cross-origin', () => {
      const win = frames(['https://shop.example', 'https://pay.example'], { ancestorOrigins });
      const frame = describeFrame(win as unknown as Window);

      expect(frame.sameOriginWithAncestors).toBe(false);
      if (ancestorOrigins) expect(frame.topOrigin).toBe('https://shop.example');
      else expect(frame.topOrigin).toBeNull();
    });

    it('catches a foreign frame anywhere in the chain (A inside B inside A)', () => {
      const win = frames(['https://a.example', 'https://b.example', 'https://a.example'], {
        ancestorOrigins,
      });

      expect(describeFrame(win as unknown as Window).sameOriginWithAncestors).toBe(false);
    });
  });
});
