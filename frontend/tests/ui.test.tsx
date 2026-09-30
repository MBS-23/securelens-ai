import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ErrorBox, Field, validationProblems } from "../src/components/ui";
import { ApiError } from "../src/lib/api";

describe("ErrorBox", () => {
  it("lists field-level validation problems from the server", () => {
    const error = new ApiError(422, "validation_error", "The request is invalid", {
      problems: [{ location: ["body", "email"], message: "value is not a valid email address" }],
    });
    render(<ErrorBox error={error} title="Setup failed" />);
    expect(screen.getByRole("alert")).toHaveTextContent("The request is invalid");
    expect(screen.getByText("email: value is not a valid email address")).toBeInTheDocument();
  });

  it("ignores details that are not validation problems", () => {
    expect(validationProblems(new ApiError(403, "forbidden", "No", { reason: "x" }))).toEqual([]);
    expect(validationProblems(new Error("boom"))).toEqual([]);
  });
});

describe("Field", () => {
  it("names the control by its label and describes it with the hint", () => {
    render(
      <Field label="Password" hint="At least 12 characters.">
        <input type="password" />
      </Field>,
    );
    const input = screen.getByLabelText("Password");
    expect(input).toHaveAccessibleName("Password");
    expect(input).toHaveAccessibleDescription("At least 12 characters.");
  });
});
