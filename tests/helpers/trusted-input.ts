/**
 * Input as the user makes it: events with isTrusted set.
 *
 * The vault's dialogs act only on trusted events, and script cannot make
 * one: dispatchEvent() always clears isTrusted, in jsdom as in browsers.
 * jsdom keeps the flag on its internal event object, so these helpers set
 * it there and dispatch through the internal path the browser's own input
 * would take. Use them only to stand in for the user; a test of what a page
 * can do must use dispatchEvent().
 */

function impl(wrapper: object): any {
  const symbol = Object.getOwnPropertySymbols(wrapper).find((s) => String(s) === 'Symbol(impl)');
  if (!symbol) throw new Error('Not a jsdom wrapper');
  return (wrapper as Record<symbol, unknown>)[symbol];
}

export function dispatchTrusted(target: EventTarget, event: Event): void {
  const eventImpl = impl(event);
  eventImpl.isTrusted = true;
  impl(target)._dispatch(eventImpl);
}

export function trustedClick(target: Element): void {
  dispatchTrusted(target, new MouseEvent('click', { bubbles: true, cancelable: true }));
}

export function trustedKey(target: EventTarget, key: string): void {
  dispatchTrusted(target, new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }));
}
