import { act, render, screen } from "@testing-library/react";
import { lazy } from "react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { COVER_MIN_MS, OPEN_MS, RouteTransition } from "../src/components/RouteTransition";
import { PrefsProvider } from "../src/lib/prefs";

function Nav() {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate("/b")}>
      go
    </button>
  );
}

function renderApp(initial = "/a", pages?: Record<string, React.ReactNode>) {
  return render(
    <PrefsProvider>
      <MemoryRouter initialEntries={[initial]}>
        <Nav />
        <RouteTransition>
          <Routes>
            <Route path="/a" element={pages?.a ?? <p>Page A</p>} />
            <Route path="/b" element={pages?.b ?? <p>Page B</p>} />
          </Routes>
        </RouteTransition>
      </MemoryRouter>
    </PrefsProvider>,
  );
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

describe("RouteTransition", () => {
  it("covers the page with the mark, then opens it after the minimum time", () => {
    renderApp();
    expect(screen.getByTestId("route-transition")).toHaveAttribute("data-phase", "cover");
    expect(screen.getByRole("main")).toHaveAttribute("data-phase", "cover");

    act(() => vi.advanceTimersByTime(COVER_MIN_MS));
    expect(screen.getByTestId("route-transition")).toHaveAttribute("data-phase", "open");
    expect(screen.getByText("Page A")).toBeInTheDocument();

    act(() => vi.advanceTimersByTime(OPEN_MS));
    expect(screen.queryByTestId("route-transition")).toBeNull();
    expect(screen.getByRole("main")).toHaveAttribute("data-phase", "idle");
  });

  it("plays again when the path changes", () => {
    renderApp();
    act(() => vi.advanceTimersByTime(COVER_MIN_MS + OPEN_MS));
    expect(screen.queryByTestId("route-transition")).toBeNull();

    act(() => screen.getByRole("button", { name: "go" }).click());
    expect(screen.getByTestId("route-transition")).toHaveAttribute("data-phase", "cover");
    act(() => vi.advanceTimersByTime(COVER_MIN_MS + OPEN_MS));
    expect(screen.getByText("Page B")).toBeInTheDocument();
    expect(screen.queryByTestId("route-transition")).toBeNull();
  });

  it("waits for a page that is still loading before opening", async () => {
    let resolve: (value: { default: () => React.ReactElement }) => void = () => {};
    const Slow = lazy(() => new Promise<{ default: () => React.ReactElement }>((r) => (resolve = r)));
    renderApp("/a", { a: <Slow /> });

    act(() => vi.advanceTimersByTime(COVER_MIN_MS * 4));
    expect(screen.getByTestId("route-transition")).toHaveAttribute("data-phase", "cover");

    await act(async () => resolve({ default: () => <p>Slow page</p> }));
    expect(screen.getByTestId("route-transition")).toHaveAttribute("data-phase", "open");
    expect(screen.getByText("Slow page")).toBeInTheDocument();
  });

  it("shows pages immediately when the viewer prefers reduced motion", () => {
    localStorage.setItem("sl.motion", "reduced");
    renderApp();
    expect(screen.queryByTestId("route-transition")).toBeNull();
    expect(screen.getByText("Page A")).toBeVisible();
  });
});
