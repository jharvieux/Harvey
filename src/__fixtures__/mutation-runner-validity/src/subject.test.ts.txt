import { describe, expect, it } from "vitest";
import { assertionKilled, completedSurvivor } from "./subject.js";

describe("installed mutation runner validity fixture", () => {
  it("asserts the killed arithmetic result", () => {
    expect(assertionKilled(1)).toBe(2);
  });

  it("executes the survivor without asserting its value", () => {
    expect(typeof completedSurvivor(1)).toBe("number");
  });
});
