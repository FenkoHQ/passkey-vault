export const THEME_STORAGE_KEY = 'ui_theme';

export type SupportedTheme = 'system' | 'light' | 'dark';
export type ResolvedTheme = Exclude<SupportedTheme, 'system'>;

export const SUPPORTED_THEMES: Array<{ code: SupportedTheme; labelKey: string }> = [
  { code: 'system', labelKey: 'themeSystem' },
  { code: 'light', labelKey: 'themeLight' },
  { code: 'dark', labelKey: 'themeDark' },
];

function normalizeTheme(theme: unknown): SupportedTheme {
  return theme === 'light' || theme === 'dark' || theme === 'system' ? theme : 'system';
}

export function resolveTheme(theme: SupportedTheme): ResolvedTheme {
  if (theme === 'light' || theme === 'dark') return theme;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export async function getStoredTheme(): Promise<SupportedTheme> {
  const result = await chrome.storage.local.get(THEME_STORAGE_KEY);
  return normalizeTheme(result[THEME_STORAGE_KEY]);
}

export async function setStoredTheme(theme: SupportedTheme): Promise<void> {
  await chrome.storage.local.set({ [THEME_STORAGE_KEY]: theme });
}

function applyTheme(theme: SupportedTheme): ResolvedTheme {
  const resolved = resolveTheme(theme);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = theme;
  return resolved;
}

export async function initTheme(): Promise<ResolvedTheme> {
  const stored = await getStoredTheme();
  const resolved = applyTheme(stored);

  if (stored === 'system' && window.matchMedia) {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    media.addEventListener?.('change', () => {
      void getStoredTheme().then((theme) => {
        if (theme === 'system') applyTheme(theme);
      });
    });
  }

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local' || !changes[THEME_STORAGE_KEY]) return;
    applyTheme(normalizeTheme(changes[THEME_STORAGE_KEY].newValue));
  });

  return resolved;
}
