import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BrandMark3D } from "../src/components/BrandMark3D";
import { MARK } from "../src/components/brand-paths";
import { Logo, LogoMark, Tagline } from "../src/components/Logo";

describe("Logo", () => {
  it("exposes one accessible name for the whole lockup", () => {
    render(<Logo />);
    expect(screen.getByRole("img", { name: "SecureLens AI" })).toBeInTheDocument();
  });

  it("draws both ribbon hooks, the lens and the three glyphs of </>", () => {
    const { container } = render(<LogoMark />);
    expect(container.querySelector(`path[d="${MARK.upper}"]`)).not.toBeNull();
    expect(container.querySelector(`path[d="${MARK.lower}"]`)).not.toBeNull();
    expect(container.querySelectorAll("circle").length).toBeGreaterThanOrEqual(2);
    expect(MARK.glyphs).toHaveLength(3);
    MARK.glyphs.forEach((d) => expect(container.querySelector(`path[d="${d}"]`)).not.toBeNull());
  });

  it("gives every instance its own gradient and mask ids", () => {
    const { container } = render(
      <>
        <LogoMark />
        <LogoMark />
      </>,
    );
    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
    ids.forEach((id) => expect(id).toMatch(/^[A-Za-z0-9_-]+$/));
  });

  it("can be decorative when a visible label is next to it", () => {
    render(<LogoMark title={null} />);
    expect(screen.queryByRole("img")).toBeNull();
  });
});

describe("BrandMark3D", () => {
  it("is labelled once and hides its many layers from assistive technology", () => {
    const { container } = render(<BrandMark3D label="SecureLens AI" animation="idle" />);
    expect(screen.getByRole("img", { name: "SecureLens AI" })).toBeInTheDocument();
    const planes = container.querySelectorAll("svg.sl3d-plane");
    expect(planes.length).toBeGreaterThan(10);
    planes.forEach((plane) => expect(plane).toHaveAttribute("aria-hidden"));
  });

  it("applies the requested animation state", () => {
    const { container, rerender } = render(<BrandMark3D label={null} animation="loading" />);
    expect(container.firstElementChild).toHaveClass("sl3d-loading");
    rerender(<BrandMark3D label={null} animation="open" />);
    expect(container.firstElementChild).toHaveClass("sl3d-open");
    rerender(<BrandMark3D label={null} animation="none" />);
    expect(container.firstElementChild).toHaveClass("sl3d-none");
  });
});

describe("Tagline", () => {
  it("renders the primary and secondary taglines as text with decorative separators", () => {
    const { container, rerender } = render(<Tagline />);
    expect(container.textContent?.replace(/\s+/g, " ").trim()).toBe("CODE | ANALYZE | REMEDIATE | VERIFY");
    container.querySelectorAll("[aria-hidden]").forEach((bar) => expect(bar.textContent).toBe("|"));
    rerender(<Tagline variant="secondary" />);
    expect(container.textContent?.replace(/\s+/g, " ").trim()).toBe("SEE | UNDERSTAND | FIX | SECURE");
  });
});
