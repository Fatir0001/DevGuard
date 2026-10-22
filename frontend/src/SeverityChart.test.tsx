// @vitest-environment jsdom
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import SeverityChart from "./SeverityChart";

describe("severity chart accessibility", () => {
  afterEach(cleanup);

  it("exposes severity labels and counts without relying on bar color", () => {
    render(
      <SeverityChart
        data={[
          { name: "Critical", count: 2 },
          { name: "High", count: 1 },
          { name: "Medium", count: 0 },
          { name: "Low", count: 3 },
          { name: "Informational", count: 4 },
        ]}
      />,
    );

    const chart = screen.getByRole("list", { name: "Findings by severity" });
    expect(within(chart).getAllByRole("listitem")).toHaveLength(5);
    expect(
      within(chart)
        .getByRole("meter", { name: "Medium findings" })
        .getAttribute("aria-valuetext"),
    ).toBe("0 Medium findings");
    expect(within(chart).getByText("Informational")).toBeTruthy();
    expect(within(chart).getByText("4")).toBeTruthy();
  });

  it("keeps zero-count bars at zero when there are no findings", () => {
    render(
      <SeverityChart
        data={[
          { name: "Critical", count: 0 },
          { name: "High", count: 0 },
        ]}
      />,
    );
    expect(
      screen
        .getByRole("meter", { name: "Critical findings" })
        .getAttribute("aria-valuemax"),
    ).toBe("1");
    expect(
      screen
        .getByRole("meter", { name: "Critical findings" })
        .getAttribute("aria-valuenow"),
    ).toBe("0");
  });
});
