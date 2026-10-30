/**
 * H05 staging E2E — REAL BROWSER through the REAL OIDC provider.
 *
 * Drives actual Chromium against the staging nginx origin
 * (http://127.0.0.1:18080): the R13 institutional gate renders the PKCE login
 * screen, oidc-client-ts redirects to the Keycloak realm "burhan" (loopback
 * 18081), the operator signs in on the REAL Keycloak login form, the
 * code+state callback completes the Authorization Code + PKCE (S256) exchange,
 * and identity/me is fetched from the engine with the resulting Bearer token —
 * which the institutional identity gate requires before it ever renders the
 * console (spec section 8).
 *
 * NO MOCKS: no route interception, no fake provider, no token pasting. Every
 * hop is real HTTP against the running staging stack. (The companion API-level
 * suite tests/integration/test_oidc_provider_staging.py covers the wallet
 * challenge/bind leg with a deterministic dev-network key.)
 *
 * Run (staging stack up):
 *   set STAGING_OIDC_USER_PASSWORD=<gitignored infra/staging/.env value>
 *   npx playwright test tests/e2e/oidc-staging.spec.js --reporter=list
 *
 * Env contract (skips without the operator secret — it lives in the gitignored
 * infra/staging/.env, never committed):
 *   STAGING_OIDC_USER_PASSWORD   required — operator password
 *   STAGING_OIDC_USERNAME        default "staging-operator"
 *   H05_STAGING_ORIGIN           default http://127.0.0.1:18080 (nginx)
 *   H05_KEYCLOAK_ORIGIN          default http://127.0.0.1:18081 (issuer)
 */

const { test, expect } = require('@playwright/test');

const STAGING_ORIGIN = (process.env.H05_STAGING_ORIGIN || 'http://127.0.0.1:18080').replace(/\/$/, '');
const KEYCLOAK_ORIGIN = (process.env.H05_KEYCLOAK_ORIGIN || 'http://127.0.0.1:18081').replace(/\/$/, '');
const USERNAME = process.env.STAGING_OIDC_USERNAME || 'staging-operator';
const PASSWORD = process.env.STAGING_OIDC_USER_PASSWORD || '';

test.skip(!PASSWORD, 'H05 browser E2E requires STAGING_OIDC_USER_PASSWORD (gitignored infra/staging/.env) and a running staging stack');

test('real browser Keycloak PKCE login lands an institutional identity through nginx', async ({ page }) => {
  const identityMeRequests = [];

  page.on('request', (request) => {
    // The identity fetch the frontend issues with the exchanged access token.
    if (new URL(request.url()).pathname.endsWith('/api/v2/identity/me')) {
      identityMeRequests.push({
        url: request.url(),
        authorization: request.headers()['authorization'] || '',
      });
    }
  });

  // 1. The SPA in institutional mode renders the R13 gate — never the console.
  await page.goto(`${STAGING_ORIGIN}/`);
  await expect(page.getByTestId('login-screen')).toBeVisible();
  await expect(page.getByTestId('login-button')).toBeVisible();

  // 2. Begin login: oidc-client-ts redirects the browser to the REAL provider.
  await page.getByTestId('login-button').click();
  await page.waitForURL(`${KEYCLOAK_ORIGIN}/realms/burhan/protocol/openid-connect/auth**`, { timeout: 30000 });
  const authUrl = new URL(page.url());
  // PKCE S256 + the registered client/redirect — the exact application
  // registration documented in the H05 runbook (docs/verification/program/staging-h05.md).
  expect(authUrl.searchParams.get('client_id')).toBe('iraq-aml-frontend');
  expect(authUrl.searchParams.get('response_type')).toBe('code');
  expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authUrl.searchParams.get('code_challenge')).toBeTruthy();
  expect(authUrl.searchParams.get('redirect_uri')).toBe(`${STAGING_ORIGIN}/auth/callback`);
  expect(authUrl.searchParams.get('scope')).toContain('openid');
  expect(authUrl.searchParams.get('state')).toBeTruthy();

  // 3. Sign in on the REAL Keycloak login form.
  await page.waitForSelector('#username', { timeout: 15000 });
  await page.fill('#username', USERNAME);
  await page.fill('#password', PASSWORD);
  await page.locator('#kc-login, input[type="submit"], button[type="submit"]').first().click();

  // 4. Back through the callback with code+state; the SPA handler completes
  //    the token exchange (code_verifier) and replaces the URL with '/'.
  await page.waitForURL(`${STAGING_ORIGIN}/auth/callback**`, { timeout: 30000 });
  const callbackUrl = new URL(page.url());
  expect(callbackUrl.searchParams.get('code')).toBeTruthy();
  expect(callbackUrl.searchParams.get('state')).toBeTruthy();
  expect(callbackUrl.searchParams.get('error')).toBeNull();

  // 5. The institutional gate resolved identity/me and renders the console.
  await page.waitForURL(`${STAGING_ORIGIN}/`, { timeout: 30000 });
  await expect(page.locator('[data-testid="identity-loading"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="login-screen"]')).toHaveCount(0);
  await expect(page.getByText('BURHAN', { exact: false }).first()).toBeVisible();

  // 6. The frontend's identity/me went through nginx with a Bearer JWT (three
  //    dot-separated segments) minted by the real provider — and the browser
  //    holds the oidc-client-ts session store entry.
  const me = identityMeRequests.find((r) => /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(r.authorization));
  expect(me, 'identity/me must be fetched with a real 3-segment Bearer JWT').toBeTruthy();
  expect(me.url.startsWith(STAGING_ORIGIN), 'identity/me must go through the nginx origin').toBe(true);

  const hasOidcSession = await page.evaluate(() =>
    Object.keys(sessionStorage).some((k) => k.startsWith('oidc.user:'))
  );
  expect(hasOidcSession, 'oidc-client-ts session store must hold the logged-in user').toBe(true);
});
