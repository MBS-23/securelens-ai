import { expect, test } from "@playwright/test";

// One story, in order, against a fresh database: first-run setup, the account
// page, a password change, signing out and back in, and the not-found page.
test.describe.configure({ mode: "serial" });

const OWNER = { org: "Shop Team", name: "Olivia Owner", email: "owner@example.com", password: "correct-horse-battery-7" };
const NEW_PASSWORD = "a-new-longer-passphrase-42";

test("first run: setup creates the organization and signs the owner in", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await page.getByLabel("Organization").fill(OWNER.org);
  await page.getByLabel("Your name").fill(OWNER.name);
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password", { exact: true }).fill(OWNER.password);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page).toHaveURL(/\/$/);
  // Setup works only once: the signed-in owner is sent on to the dashboard.
  await page.goto("/setup");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Set up SecureLens" })).toHaveCount(0);
});

test("account page shows the profile and changes the password", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);

  await page.goto("/account");
  await expect(page.getByRole("heading", { name: "Account" })).toBeVisible();
  await expect(page.getByText(OWNER.email)).toBeVisible();
  await expect(page.getByRole("listitem").filter({ hasText: OWNER.org })).toContainText("Owner");

  // A weak password is rejected by the server's policy, and the message is shown.
  await page.getByLabel("Current password").fill(OWNER.password);
  await page.getByLabel(/^New password/).fill("password1234");
  await page.getByLabel("Confirm new password").fill("password1234");
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("alert")).toContainText(/Password/);

  await page.getByLabel("Current password").fill(OWNER.password);
  await page.getByLabel(/^New password/).fill(NEW_PASSWORD);
  await page.getByLabel("Confirm new password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText(/Other sessions were signed out/)).toBeVisible();
});

test("the old password stops working and the new one signs in", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel("Password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
});

test("unknown pages show a not-found page inside the app", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
  await page.goto("/no/such/page");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await page.getByRole("link", { name: "Go to the dashboard" }).click();
  await expect(page).toHaveURL(/\/$/);
});

test("page changes play the logo transition, and reduced motion turns it off", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("route-transition")).toHaveCount(0);

  await page.getByRole("navigation").getByRole("link", { name: "Projects", exact: true }).click();
  await expect(page.getByTestId("route-transition")).toBeVisible();
  await expect(page.getByTestId("route-transition")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await page.getByRole("navigation").getByRole("link", { name: "Security dashboard", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Security dashboard" })).toBeVisible();
  await expect(page.getByTestId("route-transition")).toHaveCount(0);
});
