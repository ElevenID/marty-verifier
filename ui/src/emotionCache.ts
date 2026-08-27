import createCache from '@emotion/cache';

export function createAppEmotionCache(documentRoot: Document = document) {
  // Tauri injects a per-load nonce into build-time styles and its CSP rejects
  // runtime styles without it. Reuse that nonce so Emotion's MUI rules are
  // accepted by the packaged webview instead of silently remaining inactive.
  const nonce = documentRoot.querySelector<HTMLStyleElement>('style[nonce]')?.nonce;
  return createCache({
    key: 'css',
    ...(nonce ? { nonce } : {}),
  });
}

export const appEmotionCache = createAppEmotionCache();
