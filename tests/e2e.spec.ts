import { test, expect } from '@playwright/test';

test.describe('Local auth', () => {
  test('success login sets session and shows dashboard', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL(/\/login$/);
    await page.fill('input[name="user"]', 'admin');
    await page.fill('input[name="pass"]', 'secret');
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL('http://localhost:3000/');
    await expect(page.locator('text=GW Dashboard')).toBeVisible();
  });

  test('wrong password shows error', async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name="user"]', 'admin');
    await page.fill('input[name="pass"]', 'nope');
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe('Upstream OAuth', () => {
  test('start auth and complete callback', async ({ page }) => {
    // Login locally
    await page.goto('/login');
    await page.fill('input[name="user"]', 'admin');
    await page.fill('input[name="pass"]', 'secret');
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL('http://localhost:3000/');

    // Start upstream login - this will redirect current page to IdP
    await page.click('form[action="/upstream/start"] button');
    
    // Should now be on the IdP authorize page
    await expect(page.url()).toContain('http://localhost:4000/authorize');
    
    // Submit the mock IdP login form
    await page.click('button[type="submit"]');
    
    // Should redirect back to dashboard and show connected
    await expect(page).toHaveURL('http://localhost:3000/');
    await expect(page.locator('text=Upstream: ✅ Connected')).toBeVisible();
  });
});

test.describe('Proxy API + SSE', () => {
  test('profile API returns data', async ({ page }) => {
    // Login and connect
    await page.goto('/login');
    await page.fill('input[name="user"]', 'admin');
    await page.fill('input[name="pass"]', 'secret');
    await page.click('button[type="submit"]');
    
    // Start upstream OAuth flow
    await page.click('form[action="/upstream/start"] button');
    
    // Should be redirected to IdP, complete the login
    await expect(page.url()).toContain('http://localhost:4000/authorize');
    await page.click('button[type="submit"]');
    
    // Should be back on dashboard with connection
    await expect(page).toHaveURL('http://localhost:3000/');
    await expect(page.locator('text=Upstream: ✅ Connected')).toBeVisible();
    
    // Call profile via GW
    const resp = await page.request.get('http://localhost:3000/api/profile');
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json).toHaveProperty('user');
  });

  test('SSE stream receives events and heartbeats', async ({ page }) => {
    // Login and connect
    await page.goto('/login');
    await page.fill('input[name="user"]', 'admin');
    await page.fill('input[name="pass"]', 'secret');
    await page.click('button[type="submit"]');
    
    // Start upstream OAuth flow
    await page.click('form[action="/upstream/start"] button');
    
    // Should be redirected to IdP, complete the login
    await expect(page.url()).toContain('http://localhost:4000/authorize');
    await page.click('button[type="submit"]');
    
    // Should be back on dashboard with connection
    await expect(page).toHaveURL('http://localhost:3000/');
    await expect(page.locator('text=Upstream: ✅ Connected')).toBeVisible();

    // Fetch SSE endpoint
    const resp = await page.request.get('http://localhost:3000/sse/stream');
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    expect(body).toContain('data: tick');
    expect(body).toContain(': ping');
  });
});

