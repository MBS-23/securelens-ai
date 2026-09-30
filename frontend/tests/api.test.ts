import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, buildQuery, onUnauthorized, readCookie } from "../src/lib/api";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("CSRF handling", () => {
  it("sends the CSRF cookie as a header on state-changing requests only", async () => {
    document.cookie = "sl_csrf=token%2Fwith%3Dchars; path=/";
    const fetchMock = vi.fn().mockImplementation(async () => jsonResponse(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await api.get("/projects");
    await api.post("/projects", { name: "shop" });

    const [getUrl, getInit] = fetchMock.mock.calls[0];
    const [, postInit] = fetchMock.mock.calls[1];
    expect(getUrl).toBe("/api/v1/projects");
    expect(getInit.headers["X-CSRF-Token"]).toBeUndefined();
    expect(postInit.headers["X-CSRF-Token"]).toBe("token/with=chars");
    expect(postInit.headers["Content-Type"]).toBe("application/json");
    expect(postInit.credentials).toBe("same-origin");
    expect(postInit.body).toBe(JSON.stringify({ name: "shop" }));
  });

  it("omits the header when there is no CSRF cookie", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, {}));
    vi.stubGlobal("fetch", fetchMock);
    await api.patch("/projects/1", { name: "x" });
    expect(fetchMock.mock.calls[0][1].headers["X-CSRF-Token"]).toBeUndefined();
  });
});

describe("errors", () => {
  it("turns the server's error envelope into an ApiError", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () =>
      jsonResponse(422, { error: { code: "weak_password", message: "Password is too repetitive" } })));
    const failure = api.post("/auth/change-password", {});
    await expect(failure).rejects.toBeInstanceOf(ApiError);
    await expect(failure).rejects.toMatchObject({ status: 422, code: "weak_password", message: "Password is too repetitive" });
  });

  it("notifies listeners on 401 except for the login and bootstrap calls", async () => {
    const listener = vi.fn();
    const stop = onUnauthorized(listener);
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => jsonResponse(401, { error: { code: "unauthorized", message: "no" } })));
    await expect(api.get("/auth/me")).rejects.toBeInstanceOf(ApiError);
    await expect(api.post("/auth/login", {})).rejects.toBeInstanceOf(ApiError);
    stop();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("returns undefined for 204 responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(api.del("/projects/1")).resolves.toBeUndefined();
  });
});

describe("helpers", () => {
  it("builds query strings, skipping empty values and repeating arrays", () => {
    expect(buildQuery({ severity: ["HIGH", "CRITICAL"], q: "", page: 2, status: null })).toBe(
      "?severity=HIGH&severity=CRITICAL&page=2",
    );
    expect(buildQuery({ q: "a&b=c" })).toBe("?q=a%26b%3Dc");
    expect(buildQuery()).toBe("");
  });

  it("reads cookies by exact name", () => {
    document.cookie = "sl_csrf_other=nope; path=/";
    document.cookie = "sl_csrf=yes; path=/";
    expect(readCookie("sl_csrf")).toBe("yes");
    expect(readCookie("missing")).toBeNull();
  });
});
