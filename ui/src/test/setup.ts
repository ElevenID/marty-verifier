/**
 * Vitest setup file for unit and component tests.
 * Sets up testing-library matchers and Tauri IPC mocks.
 */
import '@testing-library/jest-dom';
import { vi, beforeEach } from 'vitest';

// Mock Tauri IPC for unit tests
// This allows testing React components that call Tauri commands
const mockInvoke = vi.fn();

// Create window.__TAURI_INTERNALS__ mock
const tauriMock = {
  invoke: mockInvoke,
  convertFileSrc: vi.fn((src: string) => src),
  transformCallback: vi.fn(),
};

// Set up global Tauri mock
Object.defineProperty(window, '__TAURI_INTERNALS__', {
  value: tauriMock,
  writable: true,
});

// Mock @tauri-apps/api/core
vi.mock('@tauri-apps/api/core', () => ({
  invoke: mockInvoke,
  convertFileSrc: vi.fn((src: string) => src),
  transformCallback: vi.fn(),
}));

// Helper to set up mock responses for multiple commands
export function mockTauriCommands(commands: Record<string, unknown>) {
  mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
    if (cmd in commands) {
      const handler = commands[cmd];
      // If it's a function, call it with args
      if (typeof handler === 'function') {
        return Promise.resolve(handler(args));
      }
      // If it has __error property, reject with that error
      if (handler && typeof handler === 'object' && '__error' in handler) {
        return Promise.reject(new Error((handler as { __error: string }).__error));
      }
      return Promise.resolve(handler);
    }
    return Promise.reject(new Error(`Unmocked command: ${cmd}`));
  });
}

// Reset mocks before each test
beforeEach(() => {
  mockInvoke.mockReset();
  
  // Default: return empty/safe values
  mockInvoke.mockImplementation((cmd: string) => {
    console.warn(`Unmocked Tauri command: ${cmd}`);
    return Promise.resolve(null);
  });
});

// Export mocks for direct access in tests
export { mockInvoke };
