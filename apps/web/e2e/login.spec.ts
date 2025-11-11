import { test, expect } from "@playwright/test";

test.describe("Login Flow", () => {
  test("should login with valid credentials", async ({ page }) => {
    await page.goto("http://localhost:3000/sign-in");

    await page.fill('input[id="email"]', "admin@local");
    await page.fill('input[id="password"]', "admin123!");

    await page.click('button[type="submit"]');

    await page.waitForURL("http://localhost:3000/dashboard", {
      timeout: 5000,
    });

    expect(page.url()).toContain("/dashboard");
  });

  it("should display error with invalid credentials", async ({ page }) => {
    await page.goto("http://localhost:3000/sign-in");

    await page.fill('input[id="email"]', "invalid@example.com");
    await page.fill('input[id="password"]', "wrongpassword");

    await page.click('button[type="submit"]');

    const errorElement = await page.waitForSelector('div:has-text("Login failed")');
    expect(errorElement).toBeTruthy();
  });
});

test.describe("Dashboard Flow", () => {
  test("should display dashboard after login", async ({ page }) => {
    await page.goto("http://localhost:3000/sign-in");

    await page.fill('input[id="email"]', "admin@local");
    await page.fill('input[id="password"]', "admin123!");
    await page.click('button[type="submit"]');

    await page.waitForURL("**/dashboard");

    const heading = await page.waitForSelector("h1:has-text('Dashboard')");
    expect(heading).toBeTruthy();
  });
});
