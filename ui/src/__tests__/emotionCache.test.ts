import { describe, expect, it } from 'vitest';
import { createAppEmotionCache } from '@/emotionCache';

describe('Tauri Emotion cache', () => {
  it('reuses the Tauri style nonce for runtime MUI styles', () => {
    const page = document.implementation.createHTMLDocument();
    const tauriStyle = page.createElement('style');
    tauriStyle.nonce = 'tauri-generated-nonce';
    page.head.append(tauriStyle);

    const cache = createAppEmotionCache(page);

    expect(cache.key).toBe('css');
    expect(cache.sheet.nonce).toBe('tauri-generated-nonce');
  });

  it('supports non-Tauri documents without a nonce', () => {
    const page = document.implementation.createHTMLDocument();

    const cache = createAppEmotionCache(page);

    expect(cache.key).toBe('css');
    expect(cache.sheet.nonce).toBeUndefined();
  });
});
