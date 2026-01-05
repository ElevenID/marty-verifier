import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for Marty Verifier E2E testing.
 * Supports agentic development with live reload and watch mode.
 * 
 * Usage:
 *   pnpm test:e2e         - Run all tests
 *   pnpm test:e2e:ui      - Open Playwright UI for interactive testing
 *   pnpm test:e2e:headed  - Run tests with visible browser
 *   pnpm test:e2e:debug   - Debug mode with inspector
 */
export default defineConfig({
  testDir: './playwright/tests',
  
  // Run tests in parallel
  fullyParallel: true,
  
  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,
  
  // Retry on CI only
  retries: process.env.CI ? 2 : 0,
  
  // Opt out of parallel tests on CI
  workers: process.env.CI ? 1 : undefined,
  
  // Reporter - JSON for agentic parsing, HTML for debugging
  reporter: [
    ['list'],
    ['json', { outputFile: './test-results/playwright-results.json' }],
    ['html', { outputFolder: './test-results/playwright-report', open: 'never' }],
  ],
  
  // Shared settings for all projects
  use: {
    // Base URL for navigation
    baseURL: 'http://localhost:5173',
    
    // Collect trace when retrying failed test
    trace: 'retain-on-failure',
    
    // Capture screenshot on failure
    screenshot: 'only-on-failure',
    
    // Record video on failure
    video: 'retain-on-failure',
    
    // Default timeout for actions
    actionTimeout: 10000,
  },
  
  // Output directory for test artifacts
  outputDir: './test-results/artifacts',
  
  // Configure projects for major browsers
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    // Uncomment for cross-browser testing
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },
    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] },
    // },
  ],
  
  // Web server configuration - starts Vite dev server
  webServer: {
    command: 'pnpm dev',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
  
  // Global timeout for each test
  timeout: 30000,
  
  // Expect timeout
  expect: {
    timeout: 5000,
  },
});
