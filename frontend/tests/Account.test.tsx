import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PrefsProvider } from "../src/lib/prefs";
import type { Me } from "../src/lib/types";

const authState: { me: Me | null } = { me: null };
vi.mock("../src/lib/auth", () => ({ useAuth: () => authState }));

import Account from "../src/pages/Account";

const ME: Me = {
  user: {
    id: "u1",
    email: "dev@example.com",
    display_name: "Dev User",
    is_active: true,
    last_login_at: "2026-09-29T10:00:00Z",
    created_at: "2026-09-01T10:00:00Z",
  },
  api_key_prefix: null,
  memberships: [
    { organization_id: "o1", organization_name: "Shop Team", organization_slug: "shop-team", role: "DEVELOPER", permissions: [] },
  ],
  csrf_token: "t",
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <PrefsProvider>
      <QueryClientProvider client={client}>
        <Account />
      </QueryClientProvider>
    </PrefsProvider>,
  );
}

beforeEach(() => {
  authState.me = ME;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Account page", () => {
  it("shows the profile and organization roles from /auth/me", () => {
    renderPage();
    expect(screen.getByText("dev@example.com")).toBeInTheDocument();
    expect(screen.getByText("Shop Team")).toBeInTheDocument();
    expect(screen.getByText("Developer")).toBeInTheDocument();
  });

  it("refuses to submit when the confirmation does not match", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await userEvent.type(screen.getByLabelText("Current password"), "old-password-123");
    await userEvent.type(screen.getByLabelText(/^New password/), "a-much-better-passphrase");
    await userEvent.type(screen.getByLabelText("Confirm new password"), "a-different-passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("do not match");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends only the current and new password and shows the server's message", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ message: "Password changed. Other sessions were signed out." }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await userEvent.type(screen.getByLabelText("Current password"), "old-password-123");
    await userEvent.type(screen.getByLabelText(/^New password/), "a-much-better-passphrase");
    await userEvent.type(screen.getByLabelText("Confirm new password"), "a-much-better-passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(screen.getByText(/Other sessions were signed out/)).toBeInTheDocument());
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/change-password");
    expect(JSON.parse(init.body)).toEqual({ current_password: "old-password-123", new_password: "a-much-better-passphrase" });
  });

  it("explains that API-key sessions have no account settings", () => {
    authState.me = { ...ME, user: null, api_key_prefix: "slk_ab12" };
    renderPage();
    expect(screen.getByText(/signed in with an API key/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Change password" })).not.toBeInTheDocument();
  });
});
