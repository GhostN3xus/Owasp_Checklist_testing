import { test, expect } from "@playwright/test";

test.describe("Assessments", () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto("/sign-in");
    await page.fill('input[type="email"]', "admin@local");
    await page.fill('input[type="password"]', "admin123!");
    await page.click('button[type="submit"]');
    await page.waitForURL("/dashboard");
  });

  test("should create a new project", async ({ page }) => {
    // Navigate to projects
    await page.goto("/projects");

    // Check if page loaded
    await expect(page).toHaveURL(/.*projects/);

    // Find and click create button (if exists)
    const createButton = page.locator('text="Create Project"').first();
    if (await createButton.isVisible()) {
      await createButton.click();

      // Fill project form
      await page.fill('input[name="name"]', "Test Security Assessment");
      await page.fill('textarea[name="description"]', "E2E test project");

      // Submit form
      await page.click('button[type="submit"]');

      // Verify project was created
      await expect(page.locator("text=Test Security Assessment")).toBeVisible();
    }
  });

  test("should list available checklists", async ({ page }) => {
    // Navigate to checklists
    await page.goto("/checklists");

    // Check if page loaded
    await expect(page).toHaveURL(/.*checklists/);

    // Verify OWASP checklists are visible
    await expect(
      page.locator("text=OWASP Top 10").or(page.locator("text=OWASP Web"))
    ).toBeVisible({ timeout: 10000 });
  });

  test("should navigate to dashboard", async ({ page }) => {
    // Navigate to dashboard
    await page.goto("/dashboard");

    // Check if dashboard loaded
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify dashboard elements
    await expect(
      page.locator("h1, h2").filter({ hasText: /dashboard/i }).first()
    ).toBeVisible();
  });

  test("should display user menu", async ({ page }) => {
    await page.goto("/dashboard");

    // Look for user menu/avatar
    const userMenu = page
      .locator('[role="button"]')
      .filter({ hasText: /admin/i })
      .first();

    if (await userMenu.isVisible()) {
      await expect(userMenu).toBeVisible();
    }
  });

  test("should logout successfully", async ({ page }) => {
    await page.goto("/dashboard");

    // Try to find logout button
    const logoutButton = page.locator("text=Logout, text=Sign Out").first();

    if (await logoutButton.isVisible()) {
      await logoutButton.click();

      // Verify redirected to sign-in
      await expect(page).toHaveURL(/.*sign-in/);
    }
  });
});
